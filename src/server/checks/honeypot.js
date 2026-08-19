export const honeypotCheck = {
  name: 'honeypot',
  check(signals, cfg, ctx) {
    const hp = signals && signals.honeypot;
    const expected = ctx && ctx.expectedTraps;
    const reasons = [];
    if (!hp || hp.available === false) {
      return { risk: 20, reasons: ['honeypot_absent'] };
    }
    if ((hp.filled && hp.filled.length > 0) || hp.filledCount > 0) {
      return { hardFail: true, risk: 100, reasons: [`honeypot_filled:${(hp.filled || []).join(',')}`] };
    }
    let risk = 0;
    if (expected) {
      const reported = new Set(hp.names || []);
      const namesMatch = expected.decoys.length === reported.size
        && expected.decoys.every((n) => reported.has(n));
      if (!namesMatch) {
        risk += 45; reasons.push('honeypot_names_mismatch');
      }
      if (hp.sentinelEcho !== expected.sentinelValue) {
        risk += 45; reasons.push('honeypot_sentinel_mismatch');
      }
    }
    if (hp.optinToggled === true) {
      risk += 60; reasons.push('honeypot_optin_toggled');
    }
    if (risk >= 100) return { hardFail: true, risk: 100, reasons };
    return { risk, reasons };
  },
};
