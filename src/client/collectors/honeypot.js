import { Collector } from '../core/collector.js';

export class HoneypotCollector extends Collector {
  constructor() {
    super('honeypot');
    this._traps = null;
  }
  installTraps(form, traps) {
    if (!form || !traps || form.__hpInstalled) return;
    form.__hpInstalled = true;
    this._traps = traps;
    const cls = `c${Math.random().toString(36).slice(2, 10)}`;
    const style = document.createElement('style');
    style.textContent =
      `.${cls}{position:absolute!important;left:-9999px!important;top:auto!important;` +
      'width:1px!important;height:1px!important;overflow:hidden!important;opacity:0!important;}';
    document.head.appendChild(style);

    const add = (type, name, value) => {
      const el = document.createElement('input');
      el.type = type;
      el.name = name;
      if (type === 'checkbox') el.checked = false;
      else el.value = value || '';
      el.className = cls;
      el.setAttribute('aria-hidden', 'true');
      el.setAttribute('tabindex', '-1');
      el.setAttribute('autocomplete', 'off');
      form.appendChild(el);
    };
    for (const name of traps.decoys) add('text', name, '');
    add('text', traps.sentinelName, traps.sentinelValue);
    add('checkbox', traps.checkboxName);
  }

  trapNames() {
    if (!this._traps) return [];
    return [...this._traps.decoys, this._traps.sentinelName, this._traps.checkboxName];
  }
  collect(ctx) {
    const form = ctx.form;
    if (!form || !this._traps) return { available: false };
    const read = (name) => {
      const el = form.querySelector(`[name="${CSS.escape(name)}"]`);
      if (!el) return null;
      return el.type === 'checkbox' ? el.checked : el.value;
    };
    const filled = [];
    for (const name of this._traps.decoys) {
      const v = read(name);
      if (v && String(v).trim() !== '') filled.push(name);
    }
    return {
      available: true,
      names: this._traps.decoys,
      filled,
      filledCount: filled.length,
      sentinelEcho: read(this._traps.sentinelName),
      optinToggled: read(this._traps.checkboxName) === true,
    };
  }
}
