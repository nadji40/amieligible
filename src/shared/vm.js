export function runProgram(program, seed) {
  const r = new Uint32Array(4);
  let s = seed >>> 0;
  for (let i = 0; i < 4; i++) {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    r[i] = s;
  }
  for (let i = 0; i < program.length; i++) {
    const op = program[i][0] | 0;
    const a = program[i][1] >>> 0;
    const idx = i & 3;
    const j = a & 3;
    switch (op) {
      case 0: r[idx] = (r[idx] + a) >>> 0; break;
      case 1: r[idx] = (r[idx] ^ a) >>> 0; break;
      case 2: r[idx] = Math.imul(r[idx] || 1, (a | 1)) >>> 0; break;
      case 3: { const n = a & 31; r[idx] = ((r[idx] << n) | (r[idx] >>> (32 - n))) >>> 0; break; }
      case 4: r[idx] = (r[idx] + r[j]) >>> 0; break;
      case 5: r[idx] = (r[idx] ^ ((r[j] << 1) | 1)) >>> 0; break;
      default: r[idx] = (r[idx] + 1) >>> 0;
    }
  }
  let acc = 0x9e3779b9;
  for (let i = 0; i < 4; i++) {
    acc = (acc ^ r[i]) >>> 0;
    acc = Math.imul(acc, 2654435761) >>> 0;
    acc = ((acc << 13) | (acc >>> 19)) >>> 0;
  }
  return (acc >>> 0).toString(16).padStart(8, '0');
}
