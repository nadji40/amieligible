(function (root) {
  function now() {
    try { if (typeof performance !== 'undefined' && performance.now) return performance.now(); } catch (e) { }
    return Date.now();
  }
  function randName() {
    var a = 'abcdefghijklmnopqrstuvwxyz';
    var n = (Math.random() * 0xffffffff) >>> 0;
    var out = a[n % 26];
    for (var i = 0; i < 6; i++) { n = (n * 33 + 7) >>> 0; out += (n % 36).toString(36); }
    return out;
  }
  function cssEscape(s) {
    if (typeof CSS !== 'undefined' && CSS.escape) return CSS.escape(s);
    return String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
  }
  function runProgram(program, seed) {
    var r = new Uint32Array(4);
    var s = seed >>> 0;
    for (var i = 0; i < 4; i++) { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; r[i] = s; }
    for (var k = 0; k < program.length; k++) {
      var op = program[k][0] | 0, aa = program[k][1] >>> 0, idx = k & 3, j = aa & 3;
      if (op === 0) r[idx] = (r[idx] + aa) >>> 0;
      else if (op === 1) r[idx] = (r[idx] ^ aa) >>> 0;
      else if (op === 2) r[idx] = Math.imul(r[idx] || 1, (aa | 1)) >>> 0;
      else if (op === 3) { var nn = aa & 31; r[idx] = ((r[idx] << nn) | (r[idx] >>> (32 - nn))) >>> 0; }
      else if (op === 4) r[idx] = (r[idx] + r[j]) >>> 0;
      else if (op === 5) r[idx] = (r[idx] ^ ((r[j] << 1) | 1)) >>> 0;
      else r[idx] = (r[idx] + 1) >>> 0;
    }
    var acc = 0x9e3779b9;
    for (var m = 0; m < 4; m++) {
      acc = (acc ^ r[m]) >>> 0;
      acc = Math.imul(acc, 2654435761) >>> 0;
      acc = ((acc << 13) | (acc >>> 19)) >>> 0;
    }
    return (acc >>> 0).toString(16);
  }
  function lzb(bytes) {
    var bits = 0;
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      if (b === 0) { bits += 8; continue; }
      var v = b;
      while ((v & 0x80) === 0) { bits++; v = (v << 1) & 0xff; }
      break;
    }
    return bits;
  }
  function solveSha(salt, difficulty) {
    if (typeof crypto === 'undefined' || !crypto.subtle) return Promise.resolve(null);
    var enc = new TextEncoder();
    var counter = 0;
    function step() {
      return crypto.subtle.digest('SHA-256', enc.encode(salt + '.' + counter)).then(function (buf) {
        if (lzb(new Uint8Array(buf)) >= difficulty) return String(counter);
        counter++;
        if (counter > 4194304) return null;
        if ((counter & 63) === 0) return new Promise(function (r) { setTimeout(r, 0); }).then(step);
        return step();
      });
    }
    return step();
  }
  function tamper() {
    var flags = [];
    function native(fn) {
      try { return /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn)); } catch (e) { return false; }
    }
    try {
      if (typeof fetch === 'function' && !native(fetch)) flags.push('fetch');
      if (JSON && !native(JSON.parse)) flags.push('json');
    } catch (e) { flags.push('probe'); }
    return flags.length ? flags.join(',') : false;
  }
  function environment() {
    var nav = navigator || {}, win = root || {};
    var tells = [];
    if (nav.webdriver === true) tells.push('navigator.webdriver');
    if (/HeadlessChrome/i.test(nav.userAgent || '')) tells.push('ua_headless');
    if ((nav.languages || []).length === 0) tells.push('no_languages');
    var keys = ['callPhantom', '_phantom', '__nightmare', 'domAutomation', 'domAutomationController', '__selenium_unwrapped', '__webdriver_evaluate'];
    for (var i = 0; i < keys.length; i++) { if (keys[i] in win) tells.push('win.' + keys[i]); }
    return { userAgent: nav.userAgent || null, languages: nav.languages || [], tells: tells, tellCount: tells.length, cookieEnabled: nav.cookieEnabled, hardware: { hardwareConcurrency: nav.hardwareConcurrency || null, maxTouchPoints: nav.maxTouchPoints || null }, screenAnomaly: null };
  }
  function geo(cfg) {
    cfg = cfg || {};
    var zones = cfg.timezones || ['Africa/Algiers'];
    var prefixes = cfg.localePrefixes || ['ar', 'fr', 'kab'];
    var offset = cfg.utcOffsetMinutes === undefined ? -60 : cfg.utcOffsetMinutes;
    var nav = navigator || {}, tz = null;
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { }
    var langs = nav.languages && nav.languages.length ? nav.languages : [nav.language].filter(Boolean);
    var off = null; try { off = new Date().getTimezoneOffset(); } catch (e) { }
    var tzMatch = zones.indexOf(tz) !== -1;
    var locMatch = langs.some(function (l) {
      return prefixes.some(function (p) { return String(l).toLowerCase().indexOf(p.toLowerCase()) === 0; });
    });
    var score = (tzMatch ? 0.5 : 0) + (off === offset ? 0.25 : 0) + (locMatch ? 0.25 : 0);
    return { timezone: tz, timezoneMatch: tzMatch, utcOffsetMinutes: off, languages: langs, localeMatch: locMatch, localeScore: Number(score.toFixed(2)) };
  }

  function protect(form, opts) {
    opts = opts || {};
    var mountedAt = now();
    var challengeUrl = opts.challengeUrl || '/antibot/challenge';
    var verifyUrl = opts.verifyUrl || '/antibot/verify';
    var formId = opts.formId || 'default';
    var token = null, traps = null, instr = null, powP = Promise.resolve(null);
    var aliasMap = {};
    var firstInteraction = null, keyTimes = [], focused = {};

    function mark() { if (firstInteraction === null) firstInteraction = now(); }
    form.addEventListener('keydown', function (e) { mark(); keyTimes.push(now()); if (e.target && e.target.name) focused[e.target.name] = 1; }, { passive: true });
    form.addEventListener('pointerdown', mark, { passive: true });
    form.addEventListener('focusin', function (e) { mark(); if (e.target && e.target.name) focused[e.target.name] = 1; }, { passive: true });

    function applyAliases() {
      var used = {};
      var inputs = form.querySelectorAll('[data-fld]');
      for (var i = 0; i < inputs.length; i++) {
        var el = inputs[i], canonical = el.getAttribute('data-fld');
        if (!canonical) continue;
        var alias; do { alias = randName(); } while (used[alias]);
        used[alias] = 1;
        aliasMap[alias] = canonical;
        el.setAttribute('name', alias);
      }
    }
    function installTraps() {
      if (!traps) return;
      var cls = 'c' + Math.random().toString(36).slice(2, 10);
      var style = document.createElement('style');
      style.textContent = '.' + cls + '{position:absolute!important;left:-9999px!important;width:1px!important;height:1px!important;overflow:hidden!important;opacity:0!important;}';
      document.head.appendChild(style);
      function add(type, name, value) {
        var el = document.createElement('input');
        el.type = type; el.name = name;
        if (type === 'checkbox') el.checked = false; else el.value = value || '';
        el.className = cls;
        el.setAttribute('aria-hidden', 'true');
        el.setAttribute('tabindex', '-1');
        el.setAttribute('autocomplete', 'off');
        form.appendChild(el);
      }
      for (var i = 0; i < traps.decoys.length; i++) add('text', traps.decoys[i], '');
      add('text', traps.sentinelName, traps.sentinelValue);
      add('checkbox', traps.checkboxName);
    }
    function trapNames() { return traps ? traps.decoys.concat([traps.sentinelName, traps.checkboxName]) : []; }
    function readField(name) {
      var el = form.querySelector('[name="' + cssEscape(name) + '"]');
      if (!el) return null;
      return el.type === 'checkbox' ? el.checked : el.value;
    }
    function collectHoneypot() {
      if (!traps) return { available: false };
      var filled = [];
      for (var i = 0; i < traps.decoys.length; i++) { var v = readField(traps.decoys[i]); if (v && String(v).trim() !== '') filled.push(traps.decoys[i]); }
      return { available: true, names: traps.decoys, filled: filled, filledCount: filled.length, sentinelEcho: readField(traps.sentinelName), optinToggled: readField(traps.checkboxName) === true };
    }
    function collectTiming() {
      var submitAt = now(), intervals = [];
      for (var i = 1; i < keyTimes.length; i++) intervals.push(keyTimes[i] - keyTimes[i - 1]);
      var mean = null, cv = null, min = null;
      if (intervals.length) {
        mean = intervals.reduce(function (a, b) { return a + b; }, 0) / intervals.length;
        var vari = intervals.reduce(function (a, b) { return a + (b - mean) * (b - mean); }, 0) / intervals.length;
        cv = mean === 0 ? 0 : Number((Math.sqrt(vari) / mean).toFixed(3));
        min = Math.min.apply(null, intervals);
      }
      var distinct = 0; for (var k in focused) distinct++;
      return { timeToFirstInteraction: firstInteraction === null ? null : Math.round(firstInteraction - mountedAt), fillTime: firstInteraction === null ? null : Math.round(submitAt - firstInteraction), totalOnPage: Math.round(submitAt - mountedAt), keydownCount: keyTimes.length, distinctFields: distinct, cadence: { count: intervals.length, mean: mean === null ? null : Math.round(mean), min: min === null ? null : Math.round(min), cv: cv } };
    }
    function collectInstrumentation() {
      var out = { available: false, tamper: tamper() };
      if (instr && instr.program) {
        var t = now();
        out.available = true;
        out.result = runProgram(instr.program, instr.seed >>> 0);
        out.length = instr.program.length;
        out.ms = Math.round((now() - t) * 1000) / 1000;
      }
      return out;
    }
    function serialise() {
      var out = {}, trapSet = {}, tn = trapNames();
      for (var i = 0; i < tn.length; i++) trapSet[tn[i]] = 1;
      var fd = new FormData(form), it = fd.entries(), e;
      while (!(e = it.next()).done) {
        var kk = e.value[0], vv = e.value[1];
        if (trapSet[kk]) continue;
        var key = aliasMap[kk] || kk;
        out[key] = typeof vv === 'string' ? vv : '[file]';
      }
      return out;
    }
    function restore() {
      for (var alias in aliasMap) { var el = form.querySelector('[name="' + cssEscape(alias) + '"]'); if (el) el.setAttribute('name', aliasMap[alias]); }
      var tn = trapNames();
      for (var i = 0; i < tn.length; i++) { var t = form.querySelector('[name="' + cssEscape(tn[i]) + '"]'); if (t && t.parentNode) t.parentNode.removeChild(t); }
    }
    function injectTicket(value) {
      var el = form.querySelector('input[name="antibot_ticket"]');
      if (!el) { el = document.createElement('input'); el.type = 'hidden'; el.name = 'antibot_ticket'; form.appendChild(el); }
      el.value = value;
    }

    var ready = fetch(challengeUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ v: 1, formId: formId }) })
      .then(function (r) { return r.json(); })
      .then(function (ch) {
        token = ch.token; traps = ch.traps; instr = ch.instr;
        applyAliases();
        installTraps();
        if (ch.pow) powP = solveSha(ch.pow.salt, ch.pow.difficulty).catch(function () { return null; });
      })
      .catch(function () { });

    function verify() {
      return ready.then(function () {
        return powP.then(function (pow) {
          var signals = { honeypot: collectHoneypot(), timing: collectTiming(), environment: environment(), geo: geo(opts.geo), instrumentation: collectInstrumentation() };
          var envelope = { v: 1, token: token, pow: pow, signals: signals, collected: Object.keys(signals), clientTs: Date.now() };
          return fetch(verifyUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ envelope: envelope, formData: serialise() }) })
            .then(function (r) { return r.json().then(function (body) { return { status: r.status, body: body }; }); });
        });
      });
    }

    if (opts.autoIntercept !== false) {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        verify().then(function (result) {
          var body = result.body || {};
          if (opts.onDecision) opts.onDecision(result);
          if (body.action === 'allow') {
            restore();
            if (body.ticket) injectTicket(body.ticket);
            form.__ok = true;
            form.submit();
          }
        });
      });
    }
    return { verify: verify };
  }

  root.Amieligible = { protect: protect };
})(typeof window !== 'undefined' ? window : this);
