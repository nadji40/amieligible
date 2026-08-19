import crypto from 'node:crypto';
import { AntiBotServer } from '../src/server/index.js';
import { generateRswKeypair, modPow } from '../src/server/util/crypto.js';
import { runProgram } from '../src/shared/vm.js';

function bench(label, iterations, fn) {
  fn();
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) fn(i);
  const t1 = process.hrtime.bigint();
  const totalMs = Number(t1 - t0) / 1e6;
  const perOp = totalMs / iterations;
  const opsPerSec = 1000 / perOp;
  console.log(
    `${label.padEnd(42)} ${perOp.toFixed(4).padStart(10)} ms/op   ${Math.round(opsPerSec).toLocaleString().padStart(12)} ops/s`,
  );
  return perOp;
}

async function benchAsync(label, iterations, fn) {
  await fn();
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) await fn(i);
  const t1 = process.hrtime.bigint();
  const totalMs = Number(t1 - t0) / 1e6;
  const perOp = totalMs / iterations;
  console.log(
    `${label.padEnd(42)} ${perOp.toFixed(4).padStart(10)} ms/op   ${Math.round(1000 / perOp).toLocaleString().padStart(12)} ops/s`,
  );
  return perOp;
}

function leadingZeroBits(buf) {
  let bits = 0;
  for (const b of buf) { if (b === 0) { bits += 8; continue; } let v = b; while ((v & 0x80) === 0) { bits++; v = (v << 1) & 0xff; } break; }
  return bits;
}
function solveSha(salt, difficulty) {
  for (let c = 0; ; c++) { if (leadingZeroBits(crypto.createHash('sha256').update(`${salt}.${c}`).digest()) >= difficulty) return String(c); }
}

console.log(`node ${process.version}  ${process.platform}/${process.arch}  ${new Date().toISOString()}`);
console.log('='.repeat(80));

console.log('\nServer (per request, sha256 protocol)');
console.log('-'.repeat(80));

const server = new AntiBotServer({
  secret: 'bench-secret-value-long-enough-for-the-keyring',
  allowCountries: ['DZ', 'TN', 'FR'],
  geoMode: 'deny',
  geoResolver: async () => ({ country: 'DZ', isAnonymizer: false }),
  minFillMs: 1200,
  mintLimit: { windowMs: 60000, hard: 1e9 },
  rateLimits: { ip: { windowMs: 1, soft: 1e9, hard: 1e9 }, ipForm: { windowMs: 1, soft: 1e9, hard: 1e9 }, fp: { windowMs: 1, soft: 1e9, hard: 1e9 } },
});
const benchIp = (i) => `41.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;

bench('challenge issuance', 20000, (i) => server.handleChallenge({ formId: 'signup', ip: benchIp(i), ua: 'UA' }));

const ch = server.handleChallenge({ formId: 'signup', ip: '41.0.9.9', ua: 'UA' });
const pow = solveSha(ch.pow.salt, ch.pow.difficulty);
const instrResult = runProgram(ch.instr.program, ch.instr.seed >>> 0);
const baseSignals = {
  honeypot: { available: true, names: ch.traps.decoys, filled: [], filledCount: 0, sentinelEcho: ch.traps.sentinelValue, optinToggled: false },
  timing: { timeToFirstInteraction: 800, fillTime: 6500, totalOnPage: 7300, keydownCount: 40, distinctFields: 4, cadence: { count: 39, mean: 160, min: 60, cv: 0.6 } },
  environment: { tells: [], tellCount: 0, cookieEnabled: true, hardware: { maxTouchPoints: 0, hardwareConcurrency: 8 }, screenAnomaly: null },
  behavior: { hadMovement: true, scrollEvents: 6, pointerSamples: 120, straightLineRatio: 0.1, pathEntropy: 0.7 },
  geo: { localeScore: 1 },
  fingerprint: { visitorId: 'bench-fp' },
  instrumentation: { available: true, result: instrResult, length: ch.instr.program.length, ms: 2, tamper: false },
};

const N = 5000;
const prepared = [];
for (let i = 0; i < N; i++) {
  const ip = benchIp(i);
  const fresh = server.handleChallenge({ formId: 'signup', ip, ua: 'UA' });
  const p = solveSha(fresh.pow.salt, fresh.pow.difficulty);
  const sig = { ...baseSignals, fingerprint: { visitorId: `fp-${i}` } };
  sig.honeypot = { ...baseSignals.honeypot, names: fresh.traps.decoys, sentinelEcho: fresh.traps.sentinelValue };
  sig.instrumentation = { available: true, result: runProgram(fresh.instr.program, fresh.instr.seed >>> 0), length: fresh.instr.program.length, ms: 2, tamper: false };
  prepared.push({ ip, env: { v: 1, token: fresh.token, pow: p, signals: sig, collected: [], clientTs: Date.now() } });
}
const latencies = [];
let idx = 0;
await benchAsync('verify (full pipeline, cached geo)', N, async () => {
  const job = prepared[idx++ % N];
  const t0 = process.hrtime.bigint();
  await server.handleVerify({ envelope: job.env, ip: job.ip, ua: 'UA', formId: 'signup' });
  latencies.push(Number(process.hrtime.bigint() - t0) / 1e6);
});
latencies.sort((a, b) => a - b);
const pct = (p) => latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * p))].toFixed(3);
console.log(`verify latency                              p50 ${pct(0.5)} ms   p95 ${pct(0.95)} ms   p99 ${pct(0.99)} ms`);

console.log('\nCryptographic primitives');
console.log('-'.repeat(80));
bench('sha256 pow verify (server side)', 100000, () => leadingZeroBits(crypto.createHash('sha256').update('s.123').digest()));

const rsw = generateRswKeypair(1024);
const t0 = process.hrtime.bigint();
generateRswKeypair(1024);
console.log(`rsw keypair generation (1024-bit, once)     ${(Number(process.hrtime.bigint() - t0) / 1e6).toFixed(2)} ms`);
bench('rsw trapdoor verify (server side)', 20000, () => modPow(2n, 30000n, rsw.phi));

console.log('\nProof-of-work solve cost (client side, single thread)');
console.log('-'.repeat(80));
for (const d of [10, 12, 14, 16]) {
  const t = process.hrtime.bigint();
  solveSha('bench', d);
  console.log(`sha256 solve, difficulty ${String(d).padStart(2)} bits`.padEnd(42) + `${(Number(process.hrtime.bigint() - t) / 1e6).toFixed(1).padStart(10)} ms`);
}
console.log('\nNote: solve time is paid once by the visitor and runs in the background while they type.');
