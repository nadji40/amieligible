import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { evaluatePow, rswBase } from '../src/server/checks/pow.js';
import { generateRswKeypair, modPow } from '../src/server/util/crypto.js';
import { solvePow, solveRsw, leadingZeroBits } from './helpers.js';

test('sha256 proof-of-work accepts a valid nonce and rejects a wrong one', () => {
  const salt = 'salt-abc';
  const difficulty = 12;
  const solution = solvePow({ protocol: 'sha256', salt, difficulty });
  const digest = crypto.createHash('sha256').update(`${salt}.${solution}`).digest();
  assert.ok(leadingZeroBits(digest) >= difficulty);
  assert.deepEqual(evaluatePow({ solution, salt, difficulty, protocol: 'sha256' }), { risk: 0, reasons: [] });
  assert.equal(evaluatePow({ solution: '0', salt, difficulty, protocol: 'sha256' }).reasons[0], 'pow_invalid');
});

test('missing solution scores risk without hard-failing', () => {
  const r = evaluatePow({ solution: '', salt: 's', difficulty: 12, protocol: 'sha256' });
  assert.equal(r.reasons[0], 'pow_missing');
  assert.ok(r.risk > 0 && !r.hardFail);
});

test('difficulty zero is a no-op', () => {
  assert.deepEqual(evaluatePow({ difficulty: 0 }), { risk: 0, reasons: [] });
});

test('rsw time-lock: sequential squaring solution verifies via the trapdoor', () => {
  const rsw = generateRswKeypair(1024);
  const salt = 'rsw-salt';
  const difficulty = 2000;
  const solution = solveRsw({ salt, difficulty, n: rsw.N.toString(16) });
  assert.deepEqual(evaluatePow({ solution, salt, difficulty, protocol: 'rsw', rsw }), { risk: 0, reasons: [] });
  assert.equal(evaluatePow({ solution: 'deadbeef', salt, difficulty, protocol: 'rsw', rsw }).reasons[0], 'pow_invalid');
});

test('rsw trapdoor matches the sequential computation', () => {
  const rsw = generateRswKeypair(1024);
  const x = rswBase('s', rsw.N);
  let seq = x;
  const t = 500;
  for (let i = 0; i < t; i++) seq = (seq * seq) % rsw.N;
  const e = modPow(2n, BigInt(t), rsw.phi);
  assert.equal(modPow(x, e, rsw.N), seq);
});
