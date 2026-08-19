import { Collector } from '../core/collector.js';

export class GeoSignalCollector extends Collector {
  constructor(options = {}) {
    super('geo');
    this.timezones = options.timezones || ['Africa/Algiers'];
    this.localePrefixes = options.localePrefixes || ['ar-DZ', 'fr-DZ', 'ar', 'fr', 'kab'];
  }
  collect() {
    const nav = typeof navigator !== 'undefined' ? navigator : {};
    let tz = null;
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch {  }
    const langs = nav.languages && nav.languages.length ? nav.languages : [nav.language].filter(Boolean);
    const localeMatch = langs.some((l) =>
      this.localePrefixes.some((p) => String(l).toLowerCase().startsWith(p.toLowerCase())));
    let utcOffsetMinutes = null;
    try { utcOffsetMinutes = new Date().getTimezoneOffset(); } catch {  }
    return {
      timezone: tz,
      timezoneMatch: tz ? this.timezones.includes(tz) : false,
      utcOffsetMinutes,
      offsetMatch: utcOffsetMinutes === -60,
      languages: langs,
      localeMatch,
      localeScore: scoreLocal({ tzMatch: tz ? this.timezones.includes(tz) : false, localeMatch, offsetMatch: utcOffsetMinutes === -60 }),
    };
  }
}
function scoreLocal({ tzMatch, localeMatch, offsetMatch }) {
  let s = 0;
  if (tzMatch) s += 0.5;
  if (offsetMatch) s += 0.25;
  if (localeMatch) s += 0.25;
  return Number(s.toFixed(2));
}
