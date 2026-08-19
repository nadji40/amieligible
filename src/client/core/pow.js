export async function solvePow(pow = {}, opts = {}) {
  if (!pow.salt || !pow.difficulty || pow.difficulty <= 0) return null;
  if (typeof crypto === 'undefined' || !crypto.subtle) return null;
  if (pow.protocol === 'rsw') return solveRsw(pow);
  return solveSha256(pow, opts);
}
async function solveSha256({ salt, difficulty }, { maxIterations = 2 ** 22 } = {}) {
  const enc = new TextEncoder();
  for (let counter = 0; counter < maxIterations; counter++) {
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', enc.encode(`${salt}.${counter}`)),
    );
    if (leadingZeroBits(digest) >= difficulty) return String(counter);
    if ((counter & 0x3f) === 0x3f) await new Promise((r) => setTimeout(r, 0));
  }
  return null;
}
async function solveRsw({ salt, difficulty, n }) {
  if (!n || typeof BigInt === 'undefined') return null;
  const N = BigInt(`0x${n}`);
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`rsw:${salt}`)),
  );
  let x = 0n;
  for (const byte of digest) x = (x << 8n) | BigInt(byte);
  x %= N;
  if (x <= 1n) x = 3n;
  let y = x;
  for (let i = 0; i < difficulty; i++) {
    y = (y * y) % N;
    if ((i & 0x3ff) === 0x3ff) await new Promise((r) => setTimeout(r, 0));
  }
  return y.toString(16);
}
function leadingZeroBits(bytes) {
  let bits = 0;
  for (const b of bytes) {
    if (b === 0) { bits += 8; continue; }
    let v = b;
    while ((v & 0x80) === 0) { bits++; v = (v << 1) & 0xff; }
    break;
  }
  return bits;
}
