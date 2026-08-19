import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScoreEngine } from '../src/server/engine/scoreEngine.js';

const fixed = (name, contrib) => ({ name, check: () => contrib });

test('a single high-confidence signal escalates past pure averaging', async () => {
  const engine = new ScoreEngine({ weights: { a: 2, b: 1, c: 1, d: 1 }, thresholds: { challengeAt: 45, denyAt: 75 } });
  engine.register(fixed('a', { risk: 70, reasons: ['strong'] }));
  engine.register(fixed('b', { risk: 0, reasons: [] }));
  engine.register(fixed('c', { risk: 0, reasons: [] }));
  engine.register(fixed('d', { risk: 0, reasons: [] }));
  const d = await engine.evaluate({});
  assert.ok(d.risk >= 45, `escalation should surface the strong signal, got ${d.risk}`);
  assert.equal(d.action, 'challenge');
});

test('hardFail forces deny regardless of score', async () => {
  const engine = new ScoreEngine();
  engine.register(fixed('x', { risk: 0, reasons: ['ok'], hardFail: true }));
  const d = await engine.evaluate({});
  assert.equal(d.action, 'deny');
  assert.equal(d.hardFail, true);
});

test('trust bonus lowers the aggregate risk', async () => {
  const engine = new ScoreEngine({ weights: { a: 1, t: 1 } });
  engine.register(fixed('a', { risk: 50, reasons: [] }));
  const withoutBonus = await engine.evaluate({});
  engine.register(fixed('t', { risk: 0, reasons: [], trustBonus: 40 }));
  const withBonus = await engine.evaluate({});
  assert.ok(withBonus.risk < withoutBonus.risk);
});

test('a throwing check is contained as moderate risk, not fail-open', async () => {
  const engine = new ScoreEngine({ weights: { boom: 1 } });
  engine.register({ name: 'boom', check: () => { throw new Error('kaboom'); } });
  const d = await engine.evaluate({});
  assert.ok(d.risk > 0);
  assert.ok(d.reasons.some((r) => r.startsWith('boom_check_error')));
});

test('precomputed contributions participate and override same-named checks', async () => {
  const engine = new ScoreEngine({ weights: { token: 2 } });
  engine.register(fixed('token', { risk: 0, reasons: ['registered'] }));
  const d = await engine.evaluate({}, {}, { token: { risk: 100, reasons: ['precomputed'], hardFail: true } });
  assert.equal(d.action, 'deny');
  assert.ok(d.reasons.includes('precomputed'));
  assert.ok(!d.reasons.includes('registered'));
});

test('thresholds map risk to allow, challenge, deny', async () => {
  const mk = (risk) => {
    const e = new ScoreEngine({ weights: { a: 1 }, thresholds: { challengeAt: 45, denyAt: 75 } });
    e.register(fixed('a', { risk, reasons: [] }));
    return e.evaluate({});
  };
  assert.equal((await mk(10)).action, 'allow');
  assert.equal((await mk(50)).action, 'challenge');
  assert.equal((await mk(90)).action, 'deny');
});
