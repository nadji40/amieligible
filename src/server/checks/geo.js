export function createGeoCheck({
  resolver,
  allowCountries = ['DZ'],
  mode = 'deny',
  blockAnonymizers = true,
  cacheTtlMs = 5 * 60 * 1000,
  cacheMax = 10000,
} = {}) {
  if (typeof resolver !== 'function') {
    throw new Error('geo check requires a resolver(ip) => { country, isAnonymizer, asn }');
  }
  const allow = new Set(allowCountries.map((c) => c.toUpperCase()));
  const cache = new Map();
  const resolveCached = async (ip) => {
    const hit = cache.get(ip);
    const t = Date.now();
    if (hit && hit.exp > t) return hit.info;
    const info = await resolver(ip);
    if (cache.size >= cacheMax) cache.clear();
    cache.set(ip, { info, exp: t + cacheTtlMs });
    return info;
  };
  return {
    name: 'geo',
    async check(signals, cfg, ctx) {
      const ip = ctx && ctx.ip;
      const reasons = [];
      if (!ip) {
        return { risk: 50, reasons: ['geo_no_ip'] };
      }
      let info;
      try {
        info = await resolveCached(ip);
      } catch (err) {
        return { risk: 40, reasons: [`geo_resolver_error:${err.message}`] };
      }
      const country = (info && info.country || '').toUpperCase();
      const eligible = allow.has(country);
      const soft = signals && signals.geo;
      if (eligible && soft && soft.localeScore === 0) {
        reasons.push('geo_ip_locale_mismatch');
      }
      if (blockAnonymizers && info && info.isAnonymizer) {
        reasons.push(`geo_anonymizer:${info.asn || 'unknown'}`);
        if (mode === 'deny') {
          return { hardFail: true, risk: 100, reasons, meta: { country, eligible } };
        }
      }

      if (!eligible) {
        reasons.push(`geo_not_eligible:${country || 'unknown'}`);
        if (mode === 'deny') {
          return { hardFail: true, risk: 100, reasons, meta: { country, eligible: false } };
        }
        return { risk: 80, reasons, meta: { country, eligible: false } };
      }
      let risk = 0;
      if (reasons.includes('geo_ip_locale_mismatch')) risk += 20;
      return { risk, reasons, meta: { country, eligible: true } };
    },
  };
}
