const DEFAULT_LIMITS = {
  ip: { windowMs: 60_000, soft: 15, hard: 60 },
  ipForm: { windowMs: 60_000, soft: 10, hard: 40 },
  fp: { windowMs: 60_000, soft: 4, hard: 10 },
};
export function createRateLimitCheck({ store, limits = {} } = {}) {
  if (!store || typeof store.hit !== 'function') {
    throw new Error('rateLimit check requires a store with hit(key, windowMs)');
  }
  const cfg = {
    ip: { ...DEFAULT_LIMITS.ip, ...(limits.ip || {}) },
    ipForm: { ...DEFAULT_LIMITS.ipForm, ...(limits.ipForm || {}) },
    fp: { ...DEFAULT_LIMITS.fp, ...(limits.fp || {}) },
  };
  return {
    name: 'rateLimit',
    check(signals, _c, ctx) {
      const ip = (ctx && (ctx.rateIp || ctx.ip)) || 'noip';
      const formId = (ctx && ctx.formId) || 'default';
      const fp = signals && signals.fingerprint && signals.fingerprint.visitorId;
      const dims = [
        ['ip', `ip:${ip}`],
        ['ipForm', `ipform:${ip}:${formId}`],
      ];
      if (fp) dims.push(['fp', `fp:${fp}`]);
      let worst = 0;
      const reasons = [];
      for (const [dim, key] of dims) {
        const { soft, hard, windowMs } = cfg[dim];
        const { count } = store.hit(key, windowMs);
        if (count > hard) {
          return { hardFail: true, risk: 100, reasons: [`rate_hard:${dim}:${count}`] };
        }
        if (count > soft) {
          const span = Math.max(1, hard - soft);
          const r = 40 + Math.round(((count - soft) / span) * 50);
          if (r > worst) worst = r;
          reasons.push(`rate_soft:${dim}:${count}`);
        }
      }
      return { risk: Math.min(worst, 100), reasons };
    },
  };
}
