import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AntiBotServer } from '../src/server/index.js';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = process.env.PORT || 3000;
async function geoResolver(ip) {
  if (ip === '127.0.0.1' || ip === '::1') return { country: 'DZ', isAnonymizer: false };
  return { country: 'ZZ', isAnonymizer: false };
}
const antibot = new AntiBotServer({
  secret: process.env.ANTIBOT_SECRET || randomBytes(32).toString('hex'),
  allowCountries: ['DZ', 'TN', 'FR'],
  geoMode: 'deny',
  geoResolver,
  allowedOrigins: null,
  pow: { enabled: true, protocol: 'sha256', baseDifficulty: 12, maxDifficulty: 18 },
  deception: { enabled: false, tarpitMs: 2500 },
});

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};
function clientIp(req) {
  const addr = req.socket.remoteAddress || '';
  return addr.startsWith('::ffff:') ? addr.slice(7) : addr;
}

function readBody(req, limit = 100 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
function json(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
const server = http.createServer(async (req, res) => {
  const ip = clientIp(req);
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (req.method === 'POST' && url.pathname === '/antibot/challenge') {
      const body = JSON.parse(await readBody(req) || '{}');
      const out = antibot.handleChallenge({
        formId: body.formId || 'signup',
        ip,
        ua: req.headers['user-agent'],
        origin: req.headers.origin,
      });
      return json(res, out.status || 200, out.error ? { error: out.error } : out);
    }
    if (req.method === 'POST' && url.pathname === '/antibot/verify') {
      const body = JSON.parse(await readBody(req) || '{}');
      const decision = await antibot.handleVerify({
        envelope: body.envelope,
        ip,
        ua: req.headers['user-agent'],
        origin: req.headers.origin,
        formId: 'signup',
        formData: body.formData,
      });

      console.log(`[verify] ip=${ip} action=${decision.action} risk=${decision.risk}`,
        decision.reasons.length ? decision.reasons : '');
      const respond = () => json(res, decision.public.status, decision.public.body);
      return decision.tarpitMs > 0 ? setTimeout(respond, decision.tarpitMs) : respond();
    }
    if (req.method === 'POST' && url.pathname === '/submit') {

      const raw = await readBody(req);
      const fields = Object.fromEntries(new URLSearchParams(raw));
      const ticket = fields.antibot_ticket;
      delete fields.antibot_ticket;
      const verdict = antibot.redeemTicket(ticket, { formId: 'signup', ip, formData: fields });
      if (!verdict.ok) {
        console.log(`[submit] REFUSED ip=${ip} reason=${verdict.reason}`);
        return json(res, 403, { error: 'not_authorized' });
      }
      if (verdict.shadow) {

        console.log(`[submit] SHADOW-QUEUED ip=${ip} name=${fields.name || ''}`);
        return json(res, 200, { ok: true });
      }
      console.log(`[submit] ACCEPTED ip=${ip} name=${fields.name || ''} email=${fields.email || ''}`);
      return json(res, 200, { ok: true });
    }
    if (req.method === 'GET') {
      let filePath = url.pathname === '/' ? '/examples/browser.html' : url.pathname;
      const resolved = path.join(ROOT, path.normalize(filePath));
      if (!resolved.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
      try {
        const data = await readFile(resolved);
        res.writeHead(200, { 'content-type': MIME[path.extname(resolved)] || 'application/octet-stream' });
        return res.end(data);
      } catch {
        res.writeHead(404); return res.end('not found');
      }
    }
    res.writeHead(405); res.end();
  } catch (err) {
    console.error('[server]', err);
    json(res, 400, { error: 'bad_request' });
  }
});
server.listen(PORT, () => {
  console.log(`anti-bot demo (zero dependencies) on http://localhost:${PORT}`);
});
