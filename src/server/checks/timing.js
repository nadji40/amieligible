export const timingCheck = {
  name: 'timing',
  check(signals, cfg = {}) {
    const minFillMs = cfg.minFillMs ?? 1000;
    const minCadenceCv = cfg.minCadenceCv ?? 0.15;
    const t = signals && signals.timing;
    const reasons = [];
    if (!t) return { risk: 10, reasons: ['timing_absent'] };
    let risk = 0;
    if (t.fillTime !== null && t.fillTime < minFillMs) {
      risk += 30; reasons.push(`timing_fast_fill:${t.fillTime}ms`);
    }
    if (t.timeToFirstInteraction !== null && t.timeToFirstInteraction < 150) {
      risk += 20; reasons.push('timing_instant_interaction');
    }

    const cad = t.cadence || {};
    if (cad.count >= 5 && cad.cv !== null && cad.cv < minCadenceCv) {
      risk += 30; reasons.push(`timing_regular_cadence:cv=${cad.cv}`);
    }
    if (cad.count === 0 && t.distinctFields > 0) {
      risk += 15; reasons.push('timing_no_keystrokes');
    }
    return { risk: Math.min(risk, 100), reasons };
  },
};
