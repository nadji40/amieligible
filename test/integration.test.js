import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  makeServer, submit, humanSignals, botSignals, solvePow, solveInstr, sleep,
} from './helpers.js';
import { runProgram } from '../src/shared/vm.js';

test('legitimate eligible human is allowed and receives a single-use ticket', async () => {
  const server = makeServer();
  const { decision } = await submit(server, { ip: '41.0.0.1', fp: 'h1' });
  assert.equal(decision.action, 'allow');
  assert.deepEqual(Object.keys(decision.public.body).sort(), ['action', 'ticket']);
  const ticket = decision.public.body.ticket;
  assert.equal(server.redeemTicket(ticket, { formId: 'signup', ip: '41.0.0.1' }).ok, true);
  assert.equal(server.redeemTicket(ticket, { formId: 'signup', ip: '41.0.0.1' }).reason, 'ticket_reused');
});

test('the public verdict never leaks reasons', async () => {
  const server = makeServer();
  const { decision } = await submit(server, { ip: '41.0.0.1', fp: 'b1', makeSignals: botSignals, waitMs: 0 });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.public.body.reasons, undefined);
  assert.equal(decision.public.body.ticket, undefined);
});

test('honeypot-tripping headless bot is denied', async () => {
  const server = makeServer();
  const { decision } = await submit(server, { ip: '41.0.0.1', fp: 'b2', makeSignals: botSignals, waitMs: 0 });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.hardFail, true);
});

test('ineligible country and anonymizer are denied', async () => {
  const server = makeServer();
  assert.equal((await submit(server, { ip: '203.0.113.7', fp: 'x' })).decision.action, 'deny');
  assert.equal((await submit(server, { ip: '5.5.5.5', fp: 'v' })).decision.action, 'deny');
});

test('eligible neighbours TN and FR are allowed', async () => {
  const server = makeServer();
  assert.equal((await submit(server, { ip: '41.230.0.1', fp: 'tn' })).decision.action, 'allow');
  assert.equal((await submit(server, { ip: '82.64.0.1', fp: 'fr' })).decision.action, 'allow');
});

test('replayed token is denied even with perfect human signals', async () => {
  const server = makeServer();
  const first = await submit(server, { ip: '41.0.0.2', fp: 'r1' });
  assert.equal(first.decision.action, 'allow');
  const replay = await submit(server, {
    ip: '41.0.0.2', fp: 'r2', waitMs: 0,
    reuseToken: { token: first.token, traps: first.traps, pow: first.pow, instr: first.instr },
  });
  assert.equal(replay.decision.action, 'deny');
  assert.ok(replay.decision.reasons.includes('token_replayed'));
});

test('impossibly fast submission is denied', async () => {
  const server = makeServer();
  const { decision } = await submit(server, { ip: '41.0.0.1', fp: 'fast', waitMs: 100 });
  assert.equal(decision.action, 'deny');
});

test('missing proof-of-work escalates rather than allowing', async () => {
  const server = makeServer();
  const { decision } = await submit(server, { ip: '41.0.0.3', fp: 'np', skipPow: true });
  assert.notEqual(decision.action, 'allow');
  assert.ok(decision.reasons.includes('pow_missing'));
});

test('wrong instrumentation result hard-fails; declared length downgrade is refused', async () => {
  const server = makeServer();
  assert.equal((await submit(server, { ip: '41.0.0.1', fp: 'iw', instrMode: 'wrong' })).decision.action, 'deny');

  const ch = server.handleChallenge({ formId: 'signup', ip: '41.0.0.1', ua: 'UA' });
  const pow = solvePow(ch.pow);
  await sleep(1400);
  const sig = humanSignals(ch.traps, 'il');
  sig.instrumentation = { available: true, result: runProgram(ch.instr.program.slice(0, 4), ch.instr.seed >>> 0), length: 4, ms: 1, tamper: false };
  const d = await server.handleVerify({ envelope: { v: 1, token: ch.token, pow, signals: sig, collected: [], clientTs: Date.now() }, ip: '41.0.0.1', ua: 'UA', formId: 'signup' });
  assert.ok(d.reasons.includes('instr_length_mismatch'));
});

test('ticket is bound to the submitted content', async () => {
  const server = makeServer();
  const clean = { name: 'Amina', email: 'a@example.dz' };
  const { decision } = await submit(server, { ip: '41.0.0.1', fp: 'pl', formData: clean });
  assert.equal(decision.action, 'allow');
  const ticket = decision.public.body.ticket;
  assert.equal(server.redeemTicket(ticket, { formId: 'signup', ip: '41.0.0.1', formData: { name: 'Amina', email: 'spam@evil' } }).reason, 'ticket_payload_mismatch');
  assert.equal(server.redeemTicket(ticket, { formId: 'signup', ip: '41.0.0.1', formData: clean }).ok, true);
});

test('origin guard refuses foreign origins at both endpoints', async () => {
  const server = makeServer({ allowedOrigins: ['https://good.dz'] });
  assert.equal(server.handleChallenge({ formId: 'signup', ip: '41.0.0.1', origin: 'https://evil.example' }).status, 403);
  assert.equal(server.handleChallenge({ formId: 'signup', ip: '41.0.0.1', origin: 'https://good.dz' }).status, 200);
  const d = await server.handleVerify({ envelope: { v: 1, token: 'x', signals: {}, collected: [], clientTs: Date.now() }, ip: '41.0.0.1', origin: 'https://evil.example', formId: 'signup' });
  assert.equal(d.action, 'deny');
});

test('token minting is rate limited and proof-of-work escalates with velocity', async () => {
  const server = makeServer({ mintLimit: { windowMs: 60000, hard: 10 } });
  let last; let first; let latest;
  for (let i = 0; i < 12; i++) {
    last = server.handleChallenge({ formId: 'signup', ip: '41.0.0.1' });
    if (i === 0) first = last.pow.difficulty;
    if (!last.error) latest = last.pow.difficulty;
  }
  assert.equal(last.status, 429);
  assert.ok(latest > first);
});

test('deception mode returns a fake success with a shadow ticket', async () => {
  const server = makeServer({ deception: { enabled: true, tarpitMs: 0 } });
  const { decision } = await submit(server, { ip: '41.0.0.1', fp: 'dec', makeSignals: botSignals, waitMs: 0 });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.public.body.action, 'allow');
  const r = server.redeemTicket(decision.public.body.ticket, { formId: 'signup', ip: '41.0.0.1' });
  assert.equal(r.shadow, true);
});

test('rsw protocol end to end', async () => {
  const server = makeServer({ pow: { enabled: true, protocol: 'rsw', rswBits: 1024, rswBaseT: 2000, rswMaxT: 8000 } });
  const { decision } = await submit(server, { ip: '41.0.0.1', fp: 'rsw' });
  assert.equal(decision.action, 'allow');
});
