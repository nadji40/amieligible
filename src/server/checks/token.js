import { b64url, b64urlDecode, hmac, timingSafeEqual, randomId } from '../util/crypto.js';

const KID_RE = /^[a-zA-Z0-9_-]{1,16}$/;
export class Keyring {
  constructor({ secret, keys, activeKid } = {}) {
    if (keys) {
      this.keys = { ...keys };
      this.activeKid = activeKid || Object.keys(keys)[0];
    } else if (secret) {
      this.keys = { v1: secret };
      this.activeKid = 'v1';
    } else {
      throw new Error('Keyring requires { secret } or { keys, activeKid }');
    }
    for (const [kid, key] of Object.entries(this.keys)) {
      if (!KID_RE.test(kid)) throw new Error(`invalid kid: ${kid}`);
      if (!key || key.length < 16) throw new Error(`key "${kid}" too short (>=16 chars)`);
    }
    if (!this.keys[this.activeKid]) throw new Error(`activeKid "${this.activeKid}" not in keys`);
  }
  active() { return { kid: this.activeKid, key: this.keys[this.activeKid] }; }
  get(kid) { return this.keys[kid] || null; }
}
export function signToken(kid, key, payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = b64url(hmac(key, `${kid}.${body}`));
  return `${kid}.${body}.${sig}`;
}

export function readToken(token, keyring) {
  if (typeof token !== 'string') return { error: 'malformed' };
  const parts = token.split('.');
  if (parts.length !== 3) return { error: 'malformed' };
  const [kid, body, sig] = parts;
  const key = keyring.get(kid);
  if (!key) return { error: 'unknown_kid' };
  const expected = b64url(hmac(key, `${kid}.${body}`));
  if (!timingSafeEqual(sig, expected)) return { error: 'bad_signature' };
  let payload;
  try { payload = JSON.parse(b64urlDecode(body).toString('utf8')); }
  catch { return { error: 'unparseable' }; }
  return { payload, kid, key };
}
function bindHash(key, { ip = '', ua = '' } = {}) {
  if (!ip && !ua) return '';
  const coarseUa = String(ua).slice(0, 40);
  return b64url(hmac(key, `bind|${ip}|${coarseUa}`)).slice(0, 12);
}

const NAME_ALPHABET = 'abcdefghijklmnopqrstuvwxyz';
function aliasName(hex) {
  let n = parseInt(hex.slice(0, 8), 16) >>> 0;
  const first = NAME_ALPHABET[n % 26];
  let rest = '';
  for (let i = 0; i < 6; i++) {
    n = (n * 33 + 7) >>> 0;
    rest += (n % 36).toString(36);
  }
  return first + rest;
}
export class ChallengeService {

  constructor({ keyring, ttlMs = 30 * 60 * 1000, minAgeMs = 1200, trapCount = 3, nonceStore }) {
    if (!(keyring instanceof Keyring)) throw new Error('ChallengeService requires a Keyring');
    this.keyring = keyring;
    this.ttlMs = ttlMs;
    this.minAgeMs = minAgeMs;
    this.trapCount = Math.min(3, Math.max(1, trapCount));
    this.nonceStore = nonceStore;
  }
  issue({ formId = 'default', bind = {}, powDifficulty = 0, powProtocol = 'sha256' } = {}) {
    const { kid, key } = this.keyring.active();
    const payload = {
      n: randomId(16),
      iat: Date.now(),
      f: formId,
      b: bindHash(key, bind),
      d: powDifficulty,
      pp: powProtocol,
    };
    return { token: signToken(kid, key, payload), ttl: this.ttlMs, nonce: payload.n, kid };
  }
  trapsFor(nonce, kid = this.keyring.activeKid) {
    const key = this.keyring.get(kid);
    if (!key || !nonce) return null;
    const hex = hmac(key, `traps:${nonce}`).toString('hex');
    const decoys = [];
    for (let i = 0; i < this.trapCount; i++) decoys.push(aliasName(hex.slice(i * 8, i * 8 + 8)));
    return {
      decoys,
      sentinelName: aliasName(hex.slice(24, 32)),
      sentinelValue: hex.slice(32, 48),
      checkboxName: aliasName(hex.slice(48, 56)),
    };
  }
  verify(token, { formId = 'default', bind = {}, at = Date.now() } = {}) {
    const parsed = readToken(token, this.keyring);
    if (parsed.error) return fail(`token_${parsed.error}`);
    const { payload, kid, key } = parsed;
    const reasons = [];
    const age = at - payload.iat;
    if (age > this.ttlMs) return fail('token_expired');
    if (age < 0) return fail('token_future_iat');
    if (payload.f !== formId) {
      reasons.push('token_form_mismatch');
    }
    if (payload.b && payload.b !== bindHash(key, bind)) {
      reasons.push('token_binding_mismatch');
    }
    let risk = 0;
    if (age < 400) {
      return { hardFail: true, risk: 100, reasons: ['token_submitted_impossibly_fast'], meta: { age } };
    }
    if (age < this.minAgeMs) {
      reasons.push('token_submitted_too_fast');
      risk += 70;
    }
    if (this.nonceStore) {
      const fresh = this.nonceStore.useOnce(payload.n, payload.iat + this.ttlMs);
      if (!fresh) {
        return { hardFail: true, risk: 100, reasons: ['token_replayed'], meta: { age } };
      }
    }
    if (reasons.includes('token_binding_mismatch')) risk += 20;
    if (reasons.includes('token_form_mismatch')) risk += 15;
    return {
      hardFail: false,
      risk: Math.min(risk, 100),
      reasons,
      meta: { age, nonce: payload.n, kid, powDifficulty: payload.d || 0, powProtocol: payload.pp || 'sha256' },
    };
    function fail(reason) {
      return { hardFail: true, risk: 100, reasons: [reason], meta: {} };
    }
  }
}
export function payloadDigest(key, payload) {
  if (payload === undefined || payload === null) return '';
  return b64url(hmac(key, `payload|${canonical(payload)}`)).slice(0, 16);
}

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

export class TicketService {
  constructor({ keyring, ttlMs = 2 * 60 * 1000, nonceStore }) {
    if (!(keyring instanceof Keyring)) throw new Error('TicketService requires a Keyring');
    this.keyring = keyring;
    this.ttlMs = ttlMs;
    this.nonceStore = nonceStore;
  }
  issue({ formId = 'default', ip = '', purpose = 'clearance', payload: data } = {}) {
    const { kid, key } = this.keyring.active();
    const payload = {
      n: randomId(12),
      iat: Date.now(),
      f: formId,
      p: purpose,
      b: bindHash(key, { ip }),
    };
    const h = payloadDigest(key, data);
    if (h) payload.h = h;
    return signToken(kid, key, payload);
  }
  redeem(ticket, { formId = 'default', ip = '', payload: data } = {}) {
    const parsed = readToken(ticket, this.keyring);
    if (parsed.error) return { ok: false, reason: `ticket_${parsed.error}` };
    const { payload, key } = parsed;

    const age = Date.now() - payload.iat;
    if (age > this.ttlMs || age < 0) return { ok: false, reason: 'ticket_expired' };
    if (payload.f !== formId) return { ok: false, reason: 'ticket_form_mismatch' };
    if (payload.b && payload.b !== bindHash(key, { ip })) {
      return { ok: false, reason: 'ticket_binding_mismatch' };
    }
    if (payload.h && data !== undefined && payload.h !== payloadDigest(key, data)) {
      return { ok: false, reason: 'ticket_payload_mismatch' };
    }
    if (this.nonceStore && !this.nonceStore.useOnce(`tkt:${payload.n}`, payload.iat + this.ttlMs)) {
      return { ok: false, reason: 'ticket_reused' };
    }
    return { ok: true, shadow: payload.p === 'deceive' };
  }
}
