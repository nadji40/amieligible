const HIGH_SEVERITY = new Set([
  'navigator.webdriver', 'ua_headless',
  'win.__selenium_unwrapped', 'win.__webdriver_evaluate',
  'win.domAutomationController', 'win.cdc_adoQpoasnfa76pfcZLmcfl_Array',
]);
export const environmentCheck = {
  name: 'environment',
  check(signals) {
    const env = signals && signals.environment;
    if (!env) return { risk: 10, reasons: ['env_absent'] };
    const tells = env.tells || [];
    const reasons = [];
    let risk = 0;
    let highs = 0;
    for (const t of tells) {
      if (HIGH_SEVERITY.has(t)) { highs++; risk += 35; reasons.push(`env_high:${t}`); }
      else { risk += 12; reasons.push(`env_low:${t}`); }
    }

    if (env.screenAnomaly) { risk += 15; reasons.push(`env_screen:${env.screenAnomaly}`); }
    if (env.cookieEnabled === false) { risk += 10; reasons.push('env_no_cookies'); }
    if (env.hardware && env.hardware.hardwareConcurrency === 0) { risk += 15; reasons.push('env_zero_cores'); }
    if (highs >= 2) risk += 25;
    return { risk: Math.min(risk, 100), reasons };
  },
};
