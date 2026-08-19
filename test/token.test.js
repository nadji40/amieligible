import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Keyring, signToken, readToken, ChallengeService, TicketService, payloadDigest,
} from '../src/server/checks/token.js';
import { MemoryNonceStore } from '../src/server/stores/memoryStore.js';

const SECRET = 'a-very-long-secret-value-for-tests-123';

test('Keyring rejects short or missing keys', () => {
  assert.throws(() => new Keyring({}));
  assert.throws(() => new Keyring({ secret: 'short' }));
  assert.doesNotThrow(() => new Keyring({ secret: SECRET }));
});

test('signed token round-trips and rejects tampering', () => {
  const kr = new Keyring({ secret: SECRET });
  const { kid, key } = kr.active();
  const token = signToken(kid, key, { n: '1', v: 2 });
  assert.equal(readToken(token, kr).payload.v, 2);
  assert.equal(readToken(token + 'x', kr).error, 'bad_signature');
  assert.equal(readToken('garbage', kr).error, 'malformed');
});

test('unknown key id is rejected', () => {
  const signer = new Keyring({ secret: SECRET });
  const verifier = new Keyring({ keys: { v9: 'another-long-enough-secret-value-xx' }, activeKid: 'v9' });
  const { kid, key } = signer.active();
  const token = signToken(kid, key, { n: '1' });
  assert.equal(readToken(token, verifier).error, 'unknown_kid');
});

test('key rotation: token from old key still verifies under a keyring holding it', () => {
  const oldKr = new Keyring({ keys: { v1: SECRET }, activeKid: 'v1' });
  const rotated = new Keyring({ keys: { v2: 'the-new-secret-value-long-enough-xx', v1: SECRET }, activeKid: 'v2' });
  const { kid, key } = oldKr.active();
  const token = signToken(kid, key, { n: '1' });
  assert.equal(readToken(token, rotated).payload.n, '1');
});

test('ChallengeService flags replay, expiry, and too-fast submission', () => {
  const kr = new Keyring({ secret: SECRET });
  const store = new MemoryNonceStore();
  const cs = new ChallengeService({ keyring: kr, minAgeMs: 1200, nonceStore: store });
  const { token } = cs.issue({ formId: 'f' });

  const impossibly = cs.verify(token, { formId: 'f', at: Date.now() });
  assert.equal(impossibly.hardFail, true);
  assert.deepEqual(impossibly.reasons, ['token_submitted_impossibly_fast']);

  const { token: t2 } = cs.issue({ formId: 'f' });
  const iat = readToken(t2, kr).payload.iat;
  const ok = cs.verify(t2, { formId: 'f', at: iat + 2000 });
  assert.equal(ok.hardFail, false);
  const replay = cs.verify(t2, { formId: 'f', at: iat + 2000 });
  assert.deepEqual(replay.reasons, ['token_replayed']);

  const { token: t3 } = cs.issue({ formId: 'f' });
  const iat3 = readToken(t3, kr).payload.iat;
  assert.deepEqual(cs.verify(t3, { formId: 'f', at: iat3 + 10 ** 9 }).reasons, ['token_expired']);
});

test('trap and alias-style names are opaque and derived from the nonce', () => {
  const kr = new Keyring({ secret: SECRET });
  const cs = new ChallengeService({ keyring: kr });
  const { nonce } = cs.issue({ formId: 'f' });
  const traps = cs.trapsFor(nonce);
  for (const name of [...traps.decoys, traps.sentinelName, traps.checkboxName]) {
    assert.match(name, /^[a-z][a-z0-9]{6}$/);
  }
  assert.deepEqual(cs.trapsFor(nonce).decoys, traps.decoys);
});

test('TicketService enforces single-use, IP binding, and payload binding', () => {
  const kr = new Keyring({ secret: SECRET });
  const store = new MemoryNonceStore();
  const ts = new TicketService({ keyring: kr, nonceStore: store });
  const data = { email: 'a@b.dz', name: 'X' };
  const ticket = ts.issue({ formId: 'f', ip: '1.1.1.1', payload: data });

  assert.equal(ts.redeem(ticket, { formId: 'f', ip: '2.2.2.2', payload: data }).reason, 'ticket_binding_mismatch');
  assert.equal(ts.redeem(ticket, { formId: 'f', ip: '1.1.1.1', payload: { email: 'evil@x' } }).reason, 'ticket_payload_mismatch');
  const good = ts.redeem(ticket, { formId: 'f', ip: '1.1.1.1', payload: data });
  assert.equal(good.ok, true);
  assert.equal(ts.redeem(ticket, { formId: 'f', ip: '1.1.1.1', payload: data }).reason, 'ticket_reused');
});

test('payloadDigest is order-independent over object keys', () => {
  const kr = new Keyring({ secret: SECRET });
  const { key } = kr.active();
  assert.equal(payloadDigest(key, { a: 1, b: 2 }), payloadDigest(key, { b: 2, a: 1 }));
  assert.notEqual(payloadDigest(key, { a: 1 }), payloadDigest(key, { a: 2 }));
});

test('deception tickets redeem as shadow', () => {
  const kr = new Keyring({ secret: SECRET });
  const ts = new TicketService({ keyring: kr, nonceStore: new MemoryNonceStore() });
  const ticket = ts.issue({ formId: 'f', ip: '1.1.1.1', purpose: 'deceive' });
  const r = ts.redeem(ticket, { formId: 'f', ip: '1.1.1.1' });
  assert.equal(r.ok, true);
  assert.equal(r.shadow, true);
});
