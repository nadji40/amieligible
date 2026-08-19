import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runProgram } from '../src/shared/vm.js';
import { buildProgram, expectedResult } from '../src/server/checks/instrumentation.js';
import crypto from 'node:crypto';

test('runProgram is deterministic for the same program and seed', () => {
  const program = [[0, 5], [2, 9], [3, 7], [4, 2], [1, 1234]];
  assert.equal(runProgram(program, 42), runProgram(program, 42));
});

test('runProgram diverges for a different seed', () => {
  const program = [[0, 5], [2, 9], [3, 7]];
  assert.notEqual(runProgram(program, 1), runProgram(program, 2));
});

test('runProgram diverges for a different program', () => {
  assert.notEqual(runProgram([[0, 5]], 7), runProgram([[0, 6]], 7));
});

test('buildProgram is reproducible and expectedResult matches a fresh run', () => {
  const key = crypto.randomBytes(32);
  const nonce = 'abc123';
  const a = buildProgram(key, nonce, 24);
  const b = buildProgram(key, nonce, 24);
  assert.deepEqual(a.program, b.program);
  assert.equal(a.seed, b.seed);
  assert.equal(expectedResult(key, nonce, 24), runProgram(a.program, a.seed));
});

test('buildProgram differs per nonce', () => {
  const key = crypto.randomBytes(32);
  assert.notDeepEqual(buildProgram(key, 'n1', 24).program, buildProgram(key, 'n2', 24).program);
});
