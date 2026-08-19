import { Collector } from '../core/collector.js';
import { runProgram } from '../../shared/vm.js';

export class GuardCollector extends Collector {
  constructor() {
    super('instrumentation');
    this._instr = null;
  }
  setProgram(instr) {
    this._instr = instr;
  }
  collect() {
    const out = { available: false };
    if (this._instr && Array.isArray(this._instr.program)) {
      const t = perfNow();
      const result = runProgram(this._instr.program, this._instr.seed >>> 0);
      out.available = true;
      out.result = result;
      out.length = this._instr.program.length;
      out.ms = Math.round((perfNow() - t) * 1000) / 1000;
    }
    out.tamper = detectTamper();
    return out;
  }
}

function perfNow() {
  try {
    if (typeof performance !== 'undefined' && performance.now) return performance.now();
  } catch (e) { return Date.now(); }
  return Date.now();
}

function detectTamper() {
  const flags = [];
  const native = (fn) => {
    try { return /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn)); }
    catch (e) { return false; }
  };
  try {
    if (typeof fetch === 'function' && !native(fetch)) flags.push('fetch');
    if (JSON && !native(JSON.parse)) flags.push('json');
    if (typeof Function.prototype.toString !== 'function'
      || !native(Function.prototype.toString)) {
      flags.push('tostring');
    }
  } catch (e) { flags.push('probe'); }
  return flags.length ? flags.join(',') : false;
}
