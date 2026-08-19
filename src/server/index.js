import { validateEnvelope } from '../shared/schema.js';
import { ACTIONS } from '../shared/riskLevels.js';
import { ScoreEngine } from './engine/scoreEngine.js';
import { Keyring, ChallengeService, TicketService } from './checks/token.js';
import { evaluatePow } from './checks/pow.js';
import { b64url, hmac, generateRswKeypair } from './util/crypto.js';
import { MemoryNonceStore, MemoryRateStore } from './stores/memoryStore.js';

import { honeypotCheck } from './checks/honeypot.js';
import { timingCheck } from './checks/timing.js';
import { environmentCheck } from './checks/environment.js';
import { behaviorCheck } from './checks/behavior.js';
import { createGeoCheck } from './checks/geo.js';
import { createRateLimitCheck } from './checks/rateLimit.js';
import { createFingerprintReputationCheck } from './checks/fingerprintReputation.js';
import { createInstrumentationCheck, buildProgram } from './checks/instrumentation.js';

export class AntiBotServer {
  constructor(config = {}) {
    this.keyring = new Keyring(config);
    this.nonceStore = config.nonceStore || new MemoryNonceStore();
    this.rateStore = config.rateStore || new MemoryRateStore();
    this.challenge = new ChallengeService({
      keyring: this.keyring,
      ttlMs: config.tokenTtlMs,
      minAgeMs: config.minFillMs ?? 1200,
      trapCount: config.trapCount,
      nonceStore: this.nonceStore,
    });
    this.tickets = new TicketService({
      keyring: this.keyring,
      ttlMs: config.ticketTtlMs,
      nonceStore: this.nonceStore,
    });

    this.allowedOrigins = config.allowedOrigins || null;

    this.pow = {
      enabled: true,
      protocol: 'sha256',
      baseDifficulty: 12, maxDifficulty: 18,
      rswBits: 1024, rswBaseT: 30_000, rswMaxT: 150_000,
      ...(config.pow || {}),
    };
    this._rsw = this.pow.enabled && this.pow.protocol === 'rsw'
      ? generateRswKeypair(this.pow.rswBits)
      : null;
    this.deception = { enabled: false, tarpitMs: 2500, ...(config.deception || {}) };
    this.mintLimit = { windowMs: 60_000, hard: 30, ...(config.mintLimit || {}) };

    this.hashIps = config.hashIps !== false;
    this.instrumentation = { enabled: true, length: 24, maxSolveMs: 250, ...(config.instrumentation || {}) };
    this.engine = new ScoreEngine({
      weights: config.weights,
      thresholds: config.thresholds,
      checkConfig: config.checkConfig,
    });
    this._registerDefaultChecks(config);
  }
  _registerDefaultChecks(config) {
    this.engine.register(honeypotCheck);
    this.engine.register(timingCheck);
    this.engine.register(environmentCheck);
    this.engine.register(behaviorCheck);
    if (config.geoResolver) {
      this.engine.register(createGeoCheck({
        resolver: config.geoResolver,
        allowCountries: config.allowCountries || ['DZ'],
        mode: config.geoMode || 'deny',
        blockAnonymizers: config.blockAnonymizers !== false,
      }));
    }
    this.engine.register(createRateLimitCheck({
      store: this.rateStore,
      limits: config.rateLimits,
    }));
    if (this.instrumentation.enabled) {
      this.engine.register(createInstrumentationCheck({
        challenge: this.challenge,
        maxSolveMs: this.instrumentation.maxSolveMs,
        length: this.instrumentation.length,
      }));
    }
    if (config.reputation) {
      this.engine.register(createFingerprintReputationCheck({ reputation: config.reputation }));
    }
  }
  use(check) {
    this.engine.register(check);
    return this;
  }
  _originOk(origin) {
    if (!this.allowedOrigins) return true;
    return !!origin && this.allowedOrigins.includes(origin);
  }
  _rateKeyIp(ip) {
    if (!this.hashIps || !ip) return ip || 'noip';
    const { key } = this.keyring.active();
    return b64url(hmac(key, `ip|${ip}`)).slice(0, 16);
  }

  handleChallenge({ formId = 'default', ip, ua, origin } = {}) {
    if (!this._originOk(origin)) {
      return { error: 'origin_forbidden', status: 403 };
    }
    const mint = this.rateStore.hit(`mint:${this._rateKeyIp(ip)}`, this.mintLimit.windowMs);
    if (mint.count > this.mintLimit.hard) {
      return { error: 'rate_limited', status: 429 };
    }
    let difficulty = 0;
    if (this.pow.enabled) {
      const escalation = Math.floor(mint.count / 5);
      difficulty = this.pow.protocol === 'rsw'
        ? Math.min(this.pow.rswMaxT, Math.round(this.pow.rswBaseT * (1 + escalation * 0.5)))
        : Math.min(this.pow.maxDifficulty, this.pow.baseDifficulty + escalation);
    }
    const issued = this.challenge.issue({
      formId, bind: { ip, ua },
      powDifficulty: difficulty,
      powProtocol: this.pow.protocol,
    });
    const traps = this.challenge.trapsFor(issued.nonce, issued.kid);
    let instr = null;
    if (this.instrumentation.enabled) {
      const key = this.keyring.get(issued.kid);
      instr = buildProgram(key, issued.nonce, this.instrumentation.length);
    }
    return {
      status: 200,
      token: issued.token,
      ttl: issued.ttl,
      traps,
      instr,
      pow: difficulty > 0 ? {
        salt: issued.nonce,
        difficulty,
        protocol: this.pow.protocol,
        ...(this._rsw ? { n: this._rsw.N.toString(16) } : {}),
      } : null,
    };
  }
  async handleVerify({ envelope, ip, ua, origin, formId = 'default', formData } = {}) {
    if (!this._originOk(origin)) {
      return this._denied('origin_forbidden', 403);
    }
    const valid = validateEnvelope(envelope);
    if (!valid.ok) {
      return this._denied('envelope_invalid', 400, valid.errors);
    }

    const tokenResult = this.challenge.verify(envelope.token, { formId, bind: { ip, ua } });
    const meta = tokenResult.meta || {};
    const powResult = this.pow.enabled
      ? evaluatePow({
        solution: envelope.pow,
        salt: meta.nonce,
        difficulty: meta.powDifficulty,
        protocol: meta.powProtocol || 'sha256',
        rsw: this._rsw,
      })
      : { risk: 0, reasons: [] };
    const ctx = {
      ip, ua, formId,
      nonce: meta.nonce,
      kid: meta.kid,
      rateIp: this._rateKeyIp(ip),
      expectedTraps: meta.nonce ? this.challenge.trapsFor(meta.nonce, meta.kid) : null,
    };
    const decision = await this.engine.evaluate(envelope.signals, ctx, {
      token: tokenResult,
      pow: powResult,
    });
    return this._finalise(decision, { formId, ip, formData });
  }
  redeemTicket(ticket, { formId = 'default', ip = '', formData } = {}) {
    return this.tickets.redeem(ticket, { formId, ip, payload: formData });
  }
  _finalise(decision, { formId, ip, formData }) {
    let publicAction = decision.action;
    let ticket = null;
    let status;
    if (decision.action === ACTIONS.ALLOW) {
      ticket = this.tickets.issue({ formId, ip, purpose: 'clearance', payload: formData });
      status = 200;
    } else if (decision.action === ACTIONS.DENY && this.deception.enabled) {
      publicAction = ACTIONS.ALLOW;
      ticket = this.tickets.issue({ formId, ip, purpose: 'deceive', payload: formData });
      status = 200;
    } else {
      status = decision.action === ACTIONS.CHALLENGE ? 428 : 403;
    }
    decision.public = {
      status,
      body: { action: publicAction, ...(ticket ? { ticket } : {}) },
    };
    decision.tarpitMs = (decision.action !== ACTIONS.ALLOW && this.deception.enabled)
      ? this.deception.tarpitMs
      : 0;
    return decision;
  }
  _denied(reason, status, detail) {
    return {
      action: ACTIONS.DENY,
      status,
      risk: 100,
      hardFail: true,
      reasons: [reason],
      detail,
      breakdown: [],
      public: { status, body: { action: ACTIONS.DENY } },
      tarpitMs: this.deception.enabled ? this.deception.tarpitMs : 0,
    };
  }
}
export { ScoreEngine } from './engine/scoreEngine.js';
export { Keyring, ChallengeService, TicketService } from './checks/token.js';
export { evaluatePow } from './checks/pow.js';
export { MemoryNonceStore, MemoryRateStore } from './stores/memoryStore.js';
export { createGeoCheck } from './checks/geo.js';
export { createRateLimitCheck } from './checks/rateLimit.js';
export { createFingerprintReputationCheck } from './checks/fingerprintReputation.js';
export { createInstrumentationCheck } from './checks/instrumentation.js';
export { ACTIONS } from '../shared/riskLevels.js';
