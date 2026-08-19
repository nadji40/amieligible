export const behaviorCheck = {
  name: 'behavior',
  check(signals) {
    const b = signals && signals.behavior;
    if (!b) return { risk: 0, reasons: [] };
    const env = signals && signals.environment;
    const isTouch = !!(env && env.hardware && env.hardware.maxTouchPoints > 0);
    const reasons = [];
    let risk = 0;
    if (!b.hadMovement && b.scrollEvents === 0) {
      if (isTouch) { risk += 8; reasons.push('behavior_no_movement_touch'); }
      else { risk += 30; reasons.push('behavior_no_movement'); }
    }
    if (b.pointerSamples >= 5 && b.straightLineRatio >= 0.9) {
      risk += 25; reasons.push(`behavior_straight_paths:${b.straightLineRatio}`);
    }
    if (b.pointerSamples >= 10 && b.pathEntropy <= 0.1) {
      risk += 20; reasons.push(`behavior_low_entropy:${b.pathEntropy}`);
    }
    return { risk: Math.min(risk, 100), reasons };
  },
};
