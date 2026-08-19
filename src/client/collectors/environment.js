import { Collector } from '../core/collector.js';

export class EnvironmentCollector extends Collector {
  constructor() {
    super('environment');
  }
  collect() {
    const nav = typeof navigator !== 'undefined' ? navigator : {};
    const win = typeof window !== 'undefined' ? window : {};
    const tells = [];
    const flag = (cond, name) => { if (cond) tells.push(name); };

    flag(nav.webdriver === true, 'navigator.webdriver');
    flag(/HeadlessChrome/i.test(nav.userAgent || ''), 'ua_headless');
    flag((nav.languages || []).length === 0, 'no_languages');
    flag(nav.plugins && nav.plugins.length === 0 && /Chrome/.test(nav.userAgent || ''), 'no_plugins');

    for (const key of [
      'callPhantom', '_phantom', '__nightmare', 'domAutomation',
      'domAutomationController', '__selenium_unwrapped', '__webdriver_evaluate',
      '__driver_evaluate', 'cdc_adoQpoasnfa76pfcZLmcfl_Array',
    ]) {
      flag(key in win, `win.${key}`);
    }
    let permissionMismatch = false;
    try {
      if (win.Notification && nav.permissions && Notification.permission === 'denied') {
        permissionMismatch = true;
      }
    } catch {  }
    flag(permissionMismatch, 'permission_mismatch');
    const hw = {
      deviceMemory: nav.deviceMemory ?? null,
      hardwareConcurrency: nav.hardwareConcurrency ?? null,
      maxTouchPoints: nav.maxTouchPoints ?? null,
    };
    flag(hw.hardwareConcurrency === 0, 'zero_cores');

    return {
      userAgent: nav.userAgent || null,
      language: nav.language || null,
      languages: nav.languages || [],
      platform: nav.platform || null,
      cookieEnabled: nav.cookieEnabled ?? null,
      webdriver: nav.webdriver ?? null,
      hardware: hw,
      viewport: {
        w: win.innerWidth ?? null,
        h: win.innerHeight ?? null,
        dpr: win.devicePixelRatio ?? null,
      },
      screenAnomaly: detectScreenAnomaly(win),
      tells,
      tellCount: tells.length,
    };
  }
}
function detectScreenAnomaly(win) {
  try {
    const s = win.screen || {};
    if (!s.width || !s.height) return 'no_screen';
    if (win.innerWidth > s.width || win.innerHeight > s.height) return 'window_gt_screen';
    return null;
  } catch {
    return 'screen_error';
  }
}
