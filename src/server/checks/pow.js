import { sha256, countLeadingZeroBits, modPow, bufToBigInt } from '../util/crypto.js';

export function evaluatePow({ solution, salt, difficulty, protocol = 'sha256', rsw }) {
  if (!difficulty || difficulty <= 0) return { risk: 0, reasons: [] };
  if (solution === undefined || solution === null || solution === '') {
    return { risk: 70, reasons: ['pow_missing'] };
  }
  if (protocol === 'rsw') {
    if (!rsw || !rsw.N || !rsw.phi) return { risk: 0, reasons: ['pow_rsw_unconfigured'] };
    let y;
    try { y = BigInt(`0x${String(solution)}`); }
    catch { return { risk: 85, reasons: ['pow_invalid'] }; }
    const x = rswBase(salt, rsw.N);
    const e = modPow(2n, BigInt(difficulty), rsw.phi);
    const expected = modPow(x, e, rsw.N);
    if (y !== expected) return { risk: 85, reasons: ['pow_invalid'] };
    return { risk: 0, reasons: [] };
  }
  const digest = sha256(`${salt}.${solution}`);
  if (countLeadingZeroBits(digest) < difficulty) {
    return { risk: 85, reasons: ['pow_invalid'] };
  }
  return { risk: 0, reasons: [] };
}

export function rswBase(salt, N) {
  let x = bufToBigInt(sha256(`rsw:${salt}`)) % N;
  if (x <= 1n) x = 3n;
  return x;
}
