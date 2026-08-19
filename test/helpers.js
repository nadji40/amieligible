import crypto from 'node:crypto';
import { AntiBotServer } from '../src/server/index.js';
import { runProgram } from '../src/shared/vm.js';

export function leadingZeroBits(buf) {
  let bits = 0;
  for (const b of buf) {
    if (b === 0) { bits += 8; continue; }
    let v = b;
    while ((v & 0x80) === 0) { bits++; v = (v << 1) & 0xff; }
    break;
  }
  return bits;
}

export function solvePow(pow) {
  if (!pow) return null;
  if (pow.protocol === 'rsw') return solveRsw(pow);
  const { salt, difficulty } = pow;
  for (let counter = 0; ; counter++) {
    const h = crypto.createHash('sha256').update(`${salt}.${counter}`).digest();
    if (leadingZeroBits(h) >= difficulty) return String(counter);
  }
}

export function solveRsw({ salt, difficulty, n }) {
  const N = BigInt(`0x${n}`);
  const digest = crypto.createHash('sha256').update(`rsw:${salt}`).digest();
  let x = 0n;
  for (const byte of digest) x = (x << 8n) | BigInt(byte);
  x %= N;
  if (x <= 1n) x = 3n;
  let y = x;
  for (let i = 0; i < difficulty; i++) y = (y * y) % N;
  return y.toString(16);
}

export function solveInstr(instr, mode = 'valid') {
  if (!instr || mode === 'missing') return undefined;
  let result = runProgram(instr.program, instr.seed >>> 0);
  if (mode === 'wrong') result = 'deadbeef';
  return {
    available: true,
    result,
    length: instr.program.length,
    ms: mode === 'slow' ? 900 : 2,
    tamper: mode === 'tamper' ? 'fetch' : false,
  };
}

export function geoResolver(ip) {
  if (ip === '41.0.0.1' || ip === '41.0.0.2' || ip === '41.0.0.3') return { country: 'DZ', isAnonymizer: false };
  if (ip === '41.230.0.1') return { country: 'TN', isAnonymizer: false };
  if (ip === '82.64.0.1') return { country: 'FR', isAnonymizer: false };
  if (ip === '8.8.8.8') return { country: 'US', isAnonymizer: false };
  if (ip === '5.5.5.5') return { country: 'DZ', isAnonymizer: true, asn: 'AS-VPN' };
  return { country: 'ZZ', isAnonymizer: false };
}

export function makeServer(extra = {}) {
  return new AntiBotServer({
    secret: 'test-secret-that-is-definitely-long-enough-123',
    allowCountries: ['DZ', 'TN', 'FR'],
    geoMode: 'deny',
    geoResolver: async (ip) => geoResolver(ip),
    minFillMs: 1200,
    ...extra,
  });
}

export function humanSignals(traps, fp = 'fp-human') {
  return {
    honeypot: {
      available: true,
      names: traps ? traps.decoys : [],
      filled: [], filledCount: 0,
      sentinelEcho: traps ? traps.sentinelValue : null,
      optinToggled: false,
    },
    timing: {
      timeToFirstInteraction: 800, fillTime: 6500, totalOnPage: 7300,
      keydownCount: 40, distinctFields: 4,
      cadence: { count: 39, mean: 160, min: 60, cv: 0.6 },
    },
    environment: { tells: [], tellCount: 0, cookieEnabled: true, hardware: { maxTouchPoints: 0, hardwareConcurrency: 8 }, screenAnomaly: null },
    behavior: { hadMovement: true, scrollEvents: 6, pointerSamples: 120, straightLineRatio: 0.1, pathEntropy: 0.7 },
    geo: { localeScore: 1, timezoneMatch: true, localeMatch: true },
    fingerprint: { visitorId: fp, components: {} },
  };
}

export function botSignals(traps, fp = 'fp-bot') {
  const s = humanSignals(traps, fp);
  s.honeypot.filled = traps ? [traps.decoys[0]] : ['x'];
  s.honeypot.filledCount = 1;
  s.timing = {
    timeToFirstInteraction: 20, fillTime: 120, totalOnPage: 140,
    keydownCount: 0, distinctFields: 4, cadence: { count: 0, mean: null, min: null, cv: null },
  };
  s.environment = { tells: ['navigator.webdriver', 'ua_headless'], tellCount: 2, cookieEnabled: false, hardware: { maxTouchPoints: 0, hardwareConcurrency: 0 }, screenAnomaly: 'no_screen' };
  s.behavior = { hadMovement: false, scrollEvents: 0, pointerSamples: 0, straightLineRatio: 0, pathEntropy: 0 };
  s.geo = { localeScore: 0 };
  return s;
}

export function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

export async function submit(server, {
  ip, fp = `fp-${ip}`, formId = 'signup', origin,
  makeSignals = humanSignals, waitMs = 1400,
  reuseToken = null, skipPow = false, overrideTraps = undefined, instrMode = 'valid', formData,
}) {
  let token; let traps; let pow = null; let instr = null;
  if (reuseToken) {
    ({ token, traps, instr } = reuseToken);
    pow = reuseToken.pow;
  } else {
    const ch = server.handleChallenge({ formId, ip, ua: 'Mozilla/5.0', origin });
    if (ch.error) return { challengeError: ch };
    token = ch.token;
    traps = ch.traps;
    instr = ch.instr;
    if (ch.pow && !skipPow) pow = solvePow(ch.pow);
  }
  if (waitMs) await sleep(waitMs);
  const signalTraps = overrideTraps !== undefined ? overrideTraps : traps;
  const signals = makeSignals(signalTraps, fp);
  signals.instrumentation = solveInstr(instr, instrMode);
  const envelope = { v: 1, token, pow, signals, collected: Object.keys(signals), clientTs: Date.now() };
  const decision = await server.handleVerify({ envelope, ip, ua: 'Mozilla/5.0', origin, formId, formData });
  return { decision, token, traps, pow, instr };
}
