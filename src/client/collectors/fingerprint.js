import { Collector } from '../core/collector.js';

export class FingerprintCollector extends Collector {
  constructor() {
    super('fingerprint', { requiresConsent: true });
  }
  async collect() {
    const components = {
      canvas: safe(() => canvasHash()),
      webgl: safe(() => webglInfo()),
      audio: await safeAsync(() => audioHash()),
      fonts: safe(() => fontProbe()),
      timezone: safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone),
      colorDepth: safe(() => window.screen && window.screen.colorDepth),
      touch: safe(() => navigator.maxTouchPoints || 0),
    };
    const visitorId = await djb2Hex(JSON.stringify(components));
    return { visitorId, components };
  }
}
function safe(fn) { try { return fn(); } catch { return null; } }
async function safeAsync(fn) { try { return await fn(); } catch { return null; } }
function canvasHash() {
  const canvas = document.createElement('canvas');
  canvas.width = 240; canvas.height = 60;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;
  ctx.textBaseline = 'top';
  ctx.font = "16px 'Arial'";
  ctx.fillStyle = '#f60';
  ctx.fillRect(10, 10, 100, 30);
  ctx.fillStyle = '#069';
  ctx.fillText('eligible ✓ عربي', 12, 14);
  ctx.strokeStyle = 'rgba(0,120,200,0.7)';
  ctx.arc(60, 30, 20, 0, Math.PI * 2);
  ctx.stroke();
  return canvas.toDataURL().slice(-64);
}
function webglInfo() {
  const canvas = document.createElement('canvas');
  const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
  if (!gl) return null;
  const dbg = gl.getExtension('WEBGL_debug_renderer_info');
  return {
    vendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
    renderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
  };
}

async function audioHash() {
  const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (!Ctx) return null;
  const ctx = new Ctx(1, 44100, 44100);
  const osc = ctx.createOscillator();
  const comp = ctx.createDynamicsCompressor();
  osc.type = 'triangle';
  osc.frequency.value = 10000;
  osc.connect(comp);
  comp.connect(ctx.destination);
  osc.start(0);
  const buffer = await ctx.startRendering();
  const data = buffer.getChannelData(0).slice(4500, 4600);
  let sum = 0;
  for (const v of data) sum += Math.abs(v);
  return sum.toFixed(6);
}
function fontProbe() {
  const base = 'monospace';
  const test = ['Arial', 'Courier New', 'Tahoma', 'Times New Roman', 'Segoe UI', 'Amiri'];
  const span = document.createElement('span');
  span.style.position = 'absolute';
  span.style.left = '-9999px';
  span.style.fontSize = '72px';
  span.textContent = 'mmmmmmmmmmlliأبج';
  document.body.appendChild(span);
  span.style.fontFamily = base;
  const baseW = span.offsetWidth;
  const present = [];
  for (const f of test) {
    span.style.fontFamily = `'${f}',${base}`;
    if (span.offsetWidth !== baseW) present.push(f);
  }
  document.body.removeChild(span);
  return present;
}
async function djb2Hex(str) {
  try {
    if (crypto && crypto.subtle) {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
      return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
    }
  } catch {  }
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h) ^ str.charCodeAt(i);
  return (h >>> 0).toString(16).padStart(8, '0');
}
