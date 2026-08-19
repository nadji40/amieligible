import { Registry } from './core/registry.js';
import { ClientContext, now } from './core/context.js';
import { HttpTransport } from './core/transport.js';
import { solvePow } from './core/pow.js';

import { HoneypotCollector } from './collectors/honeypot.js';
import { TimingCollector } from './collectors/timing.js';
import { BehaviorCollector } from './collectors/behavior.js';
import { EnvironmentCollector } from './collectors/environment.js';
import { FingerprintCollector } from './collectors/fingerprint.js';
import { GeoSignalCollector } from './collectors/geo.js';
import { GuardCollector } from './collectors/guard.js';

export class AntiBotClient {
  constructor(config = {}) {
    this.config = config;
    this.registry = new Registry();
    this.transport = config.transport || new HttpTransport({
      challengeUrl: config.challengeUrl || '/antibot/challenge',
      verifyUrl: config.verifyUrl || '/antibot/verify',
    });
    this.consentGranted = config.consentGranted === true;
    this.privacyMode = config.privacyMode || 'standard';
    this._registerDefaults(config);
  }
  _registerDefaults(config) {
    const opt = config.collectors || {};
    if (opt.honeypot !== false) this.registry.register(new HoneypotCollector());
    if (opt.timing !== false) this.registry.register(new TimingCollector());
    if (opt.environment !== false) this.registry.register(new EnvironmentCollector());
    if (opt.geo !== false) this.registry.register(new GeoSignalCollector(opt.geoOptions));
    if (opt.guard !== false) this.registry.register(new GuardCollector());
    if (this.privacyMode === 'minimal') return;
    if (opt.behavior !== false) this.registry.register(new BehaviorCollector());
    if (opt.fingerprint !== false) this.registry.register(new FingerprintCollector());
  }

  use(collector) {
    this.registry.register(collector);
    return this;
  }
  setConsent(granted) {
    this.consentGranted = !!granted;
  }
  async protect(form, { autoIntercept = true, onDecision } = {}) {
    if (!form) throw new Error('protect() needs a form element');
    const mountedAt = now();
    const ctx = new ClientContext({
      form, mountedAt, consentGranted: this.consentGranted, config: this.config,
    });

    let challenge = null;
    let token = null;
    try {
      challenge = await this.transport.fetchChallenge({ formId: this.config.formId });
      token = challenge.token;
    } catch (err) {
      token = null;
      if (this.config.debug) console.warn(err && err.message);
    }

    const aliasMap = applyFieldAliases(form);

    const hp = this.registry.get('honeypot');
    if (hp && hp.installTraps && challenge && challenge.traps) {
      hp.installTraps(form, challenge.traps);
    }
    const guard = this.registry.get('instrumentation');
    if (guard && guard.setProgram && challenge && challenge.instr) {
      guard.setProgram(challenge.instr);
    }
    for (const c of this.registry.list()) {
      if (typeof c.attach === 'function') c.attach(ctx);
    }
    const powPromise = (challenge && challenge.pow)
      ? solvePow(challenge.pow).catch(() => null)
      : Promise.resolve(null);

    const runVerify = async () => {
      const { signals, collected } = await this._collectAll(ctx);
      const pow = await powPromise;
      const trapNames = new Set(hp && hp.trapNames ? hp.trapNames() : []);
      const formData = serialiseForm(form, trapNames, aliasMap);
      const result = await this.transport.submit({
        token, pow, signals, collected, formData,
      });
      if (onDecision) onDecision(result);
      return result;
    };

    if (autoIntercept) {
      form.addEventListener('submit', async (e) => {
        if (form.__antibotVerified) return;
        e.preventDefault();
        if (form.__antibotBusy) return;
        form.__antibotBusy = true;
        let result;
        try {
          result = await runVerify();
        } finally {
          form.__antibotBusy = false;
        }
        const body = (result && result.body) || {};
        if (body.action === 'allow') {
          restoreFieldAliases(form, aliasMap);
          if (hp && hp.trapNames) removeByName(form, hp.trapNames());
          if (body.ticket) injectHidden(form, 'antibot_ticket', body.ticket);
          form.__antibotVerified = true;
          form.submit();
        }
      });
    }
    return { verify: runVerify, context: ctx };
  }
  async _collectAll(ctx) {
    const signals = {};
    const collected = [];
    for (const c of this.registry.list()) {
      if (!c.enabled) continue;
      if (c.requiresConsent && !ctx.consentGranted) continue;
      const { data } = await c.run(ctx);
      signals[c.name] = data;
      collected.push(c.name);
    }
    return { signals, collected };
  }
}

function applyFieldAliases(form) {
  const map = {};
  const used = new Set();
  const inputs = form.querySelectorAll('[data-fld]');
  for (const el of inputs) {
    const canonical = el.getAttribute('data-fld');
    if (!canonical) continue;
    let alias;
    do { alias = randName(); } while (used.has(alias));
    used.add(alias);
    map[alias] = { canonical, original: el.getAttribute('name') };
    el.setAttribute('name', alias);
  }
  return map;
}

function restoreFieldAliases(form, map) {
  if (!map) return;
  for (const alias of Object.keys(map)) {
    const el = form.querySelector(`[name="${cssEscape(alias)}"]`);
    if (el) el.setAttribute('name', map[alias].canonical);
  }
}

function randName() {
  const a = 'abcdefghijklmnopqrstuvwxyz';
  let n = (Math.random() * 0xffffffff) >>> 0;
  let out = a[n % 26];
  for (let i = 0; i < 6; i++) { n = (n * 33 + 7) >>> 0; out += (n % 36).toString(36); }
  return out;
}

function cssEscape(s) {
  if (typeof CSS !== 'undefined' && CSS.escape) return CSS.escape(s);
  return String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
}

function serialiseForm(form, trapNames = new Set(), aliasMap = null) {
  const out = {};
  const fd = new FormData(form);
  for (const [k, v] of fd.entries()) {
    if (trapNames.has(k)) continue;
    const key = aliasMap && aliasMap[k] ? aliasMap[k].canonical : k;
    out[key] = typeof v === 'string' ? v : '[file]';
  }
  return out;
}

function injectHidden(form, name, value) {
  let el = form.querySelector(`input[name="${cssEscape(name)}"]`);
  if (!el) {
    el = document.createElement('input');
    el.type = 'hidden';
    el.name = name;
    form.appendChild(el);
  }
  el.value = value;
}

function removeByName(form, names) {
  for (const n of names) {
    const el = form.querySelector(`[name="${cssEscape(n)}"]`);
    if (el && el.parentNode) el.parentNode.removeChild(el);
  }
}

export { HoneypotCollector, TimingCollector, BehaviorCollector, EnvironmentCollector, FingerprintCollector, GeoSignalCollector, GuardCollector };
export { Collector } from './core/collector.js';
