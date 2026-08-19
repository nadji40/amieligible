import crypto from 'node:crypto';

export function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function b64urlDecode(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}
export function hmac(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest();
}

export function timingSafeEqual(a, b) {
  const ba = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
  const bb = Buffer.isBuffer(b) ? b : Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}
export function randomId(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}
export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

export function countLeadingZeroBits(buf) {
  let bits = 0;
  for (const byte of buf) {
    if (byte === 0) { bits += 8; continue; }
    let b = byte;
    while ((b & 0x80) === 0) { bits++; b = (b << 1) & 0xff; }
    break;
  }
  return bits;
}
export function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}
export function bufToBigInt(buf) {
  let n = 0n;
  for (const byte of buf) n = (n << 8n) | BigInt(byte);
  return n;
}
export function generateRswKeypair(bits = 1024) {
  const half = Math.floor(bits / 2);
  const p = crypto.generatePrimeSync(half, { bigint: true });
  const q = crypto.generatePrimeSync(half, { bigint: true });
  return { N: p * q, phi: (p - 1n) * (q - 1n) };
}
