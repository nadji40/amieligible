import { test } from 'node:test';
import assert from 'node:assert/strict';
import { honeypotCheck } from '../src/server/checks/honeypot.js';
import { timingCheck } from '../src/server/checks/timing.js';
import { environmentCheck } from '../src/server/checks/environment.js';
import { behaviorCheck } from '../src/server/checks/behavior.js';
import { createGeoCheck } from '../src/server/checks/geo.js';
import { createRateLimitCheck } from '../src/server/checks/rateLimit.js';
import { MemoryRateStore } from '../src/server/stores/memoryStore.js';

test('honeypot: a filled decoy is an immediate hard fail', () => {
  const r = honeypotCheck.check({ honeypot: { available: true, filled: ['x'], filledCount: 1 } }, {}, {});
  assert.equal(r.hardFail, true);
});

test('honeypot: mismatched session names and sentinel raise risk', () => {
  const expected = { decoys: ['a', 'b'], sentinelValue: 'secret' };
  const r = honeypotCheck.check(
    { honeypot: { available: true, names: ['x'], filled: [], filledCount: 0, sentinelEcho: 'wrong' } },
    {}, { expectedTraps: expected },
  );
  assert.ok(r.reasons.includes('honeypot_names_mismatch'));
  assert.ok(r.reasons.includes('honeypot_sentinel_mismatch'));
});

test('timing: fast fill and robotic cadence raise risk', () => {
  const r = timingCheck.check({ timing: { fillTime: 200, timeToFirstInteraction: 10, distinctFields: 3, cadence: { count: 10, cv: 0.01 } } });
  assert.ok(r.risk > 0);
  assert.ok(r.reasons.some((x) => x.startsWith('timing_fast_fill')));
});

test('timing: a natural fill scores zero', () => {
  const r = timingCheck.check({ timing: { fillTime: 6000, timeToFirstInteraction: 800, distinctFields: 4, cadence: { count: 40, cv: 0.6 } } });
  assert.equal(r.risk, 0);
});

test('environment: two high-severity automation tells compound', () => {
  const r = environmentCheck.check({ environment: { tells: ['navigator.webdriver', 'ua_headless'], hardware: {} } });
  assert.ok(r.risk >= 70);
});

test('behavior: a touch device is not penalised for lack of pointer movement', () => {
  const noMove = { behavior: { hadMovement: false, scrollEvents: 0, pointerSamples: 0 }, environment: { hardware: { maxTouchPoints: 5 } } };
  const desktop = { behavior: { hadMovement: false, scrollEvents: 0, pointerSamples: 0 }, environment: { hardware: { maxTouchPoints: 0 } } };
  assert.ok(behaviorCheck.check(noMove).risk < behaviorCheck.check(desktop).risk);
});

test('geo: eligible country passes, ineligible hard-fails in deny mode', async () => {
  const check = createGeoCheck({ resolver: async (ip) => ({ country: ip === 'dz' ? 'DZ' : 'ZZ' }), allowCountries: ['DZ'], mode: 'deny' });
  assert.equal((await check.check({}, {}, { ip: 'dz' })).hardFail, undefined);
  assert.equal((await check.check({}, {}, { ip: 'xx' })).hardFail, true);
});

test('geo: anonymizer is blocked when configured', async () => {
  const check = createGeoCheck({ resolver: async () => ({ country: 'DZ', isAnonymizer: true, asn: 'AS1' }), allowCountries: ['DZ'], blockAnonymizers: true });
  const r = await check.check({}, {}, { ip: '1' });
  assert.equal(r.hardFail, true);
  assert.ok(r.reasons.some((x) => x.startsWith('geo_anonymizer')));
});

test('geo: resolver is cached so repeated IPs do not re-resolve', async () => {
  let calls = 0;
  const check = createGeoCheck({ resolver: async () => { calls++; return { country: 'DZ' }; }, allowCountries: ['DZ'] });
  await check.check({}, {}, { ip: 'same' });
  await check.check({}, {}, { ip: 'same' });
  assert.equal(calls, 1);
});

test('rateLimit: per-fingerprint limit is stricter than per-ip (CGNAT aware)', () => {
  const store = new MemoryRateStore();
  const check = createRateLimitCheck({ store, limits: { fp: { windowMs: 60000, soft: 2, hard: 4 }, ip: { windowMs: 60000, soft: 100, hard: 200 }, ipForm: { windowMs: 60000, soft: 100, hard: 200 } } });
  let last;
  for (let i = 0; i < 5; i++) last = check.check({ fingerprint: { visitorId: 'dev' } }, {}, { ip: '1', formId: 'f' });
  assert.equal(last.hardFail, true);
});
