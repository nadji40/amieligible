import { hmac } from '../util/crypto.js';
import { runProgram } from '../../shared/vm.js';

export function buildProgram(key, nonce, length = 24) {
  const seedBuf = hmac(key, `instr-seed:${nonce}`);
  const seed = seedBuf.readUInt32BE(0) >>> 0;
  const opsBuf = hmac(key, `instr-ops:${nonce}`);
  const program = [];
  let pool = Buffer.concat([opsBuf, hmac(key, `instr-ops2:${nonce}`)]);
  for (let i = 0; i < length; i++) {
    const base = (i * 5) % (pool.length - 5);
    const op = pool[base] % 6;
    const arg = pool.readUInt32BE(base + 1) >>> 0;
    program.push([op, arg]);
  }
  return { program, seed };
}

export function expectedResult(key, nonce, length = 24) {
  const { program, seed } = buildProgram(key, nonce, length);
  return runProgram(program, seed);
}

export function createInstrumentationCheck({ challenge, maxSolveMs = 250, length = 24 } = {}) {
  return {
    name: 'instrumentation',
    check(signals, cfg, ctx) {
      const report = signals && signals.instrumentation;
      const nonce = ctx && ctx.nonce;
      const kid = ctx && ctx.kid;
      if (!nonce || !challenge) return { risk: 0, reasons: [] };
      if (!report || typeof report.result !== 'string') {
        return { risk: 65, reasons: ['instr_missing'] };
      }
      const key = challenge.keyring.get(kid || challenge.keyring.activeKid);
      if (!key) return { risk: 0, reasons: [] };
      if (report.length !== undefined && report.length !== length) {
        return { hardFail: true, risk: 100, reasons: ['instr_length_mismatch'] };
      }
      const expected = expectedResult(key, nonce, length);
      const reasons = [];
      let risk = 0;
      if (report.result !== expected) {
        return { hardFail: true, risk: 100, reasons: ['instr_wrong'] };
      }
      if (typeof report.ms === 'number' && report.ms > maxSolveMs) {
        risk += 35; reasons.push('instr_slow');
      }
      if (report.tamper) {
        risk += 45; reasons.push('instr_tamper');
      }
      return { risk: Math.min(risk, 100), reasons };
    },
  };
}
