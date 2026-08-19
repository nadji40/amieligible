import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryNonceStore, MemoryRateStore } from '../src/server/stores/memoryStore.js';
import { sleep } from './helpers.js';

test('nonce store enforces single use', () => {
  const s = new MemoryNonceStore();
  const exp = Date.now() + 10000;
  assert.equal(s.useOnce('n', exp), true);
  assert.equal(s.useOnce('n', exp), false);
});

test('nonce store lets an entry be reused after expiry window elapses', () => {
  const s = new MemoryNonceStore();
  assert.equal(s.useOnce('n', Date.now() - 1), true);
  assert.equal(s.useOnce('n', Date.now() + 10000), true);
});

test('rate store counts hits within the window', () => {
  const s = new MemoryRateStore();
  for (let i = 0; i < 4; i++) s.hit('k', 60000);
  assert.equal(s.peek('k', 60000).count, 4);
});

test('rate store evicts stale keys and stays bounded', async () => {
  const stale = new MemoryRateStore({ gcIntervalMs: 0, staleMs: 1 });
  for (let i = 0; i < 500; i++) stale.hit(`k${i}`, 1);
  await sleep(10);
  stale.hit('trigger', 1);
  assert.ok(stale.size() < 100, `stale keys must be evicted, size=${stale.size()}`);

  const capped = new MemoryRateStore({ gcIntervalMs: 0, maxKeys: 50 });
  for (let i = 0; i < 400; i++) capped.hit(`k${i}`, 60000);
  assert.ok(capped.size() <= 100, `key count must stay bounded, size=${capped.size()}`);
});
