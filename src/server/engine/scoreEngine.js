import { ACTIONS, DEFAULT_THRESHOLDS, decideAction, clampRisk } from '../../shared/riskLevels.js';
import { DEFAULT_WEIGHTS, DEFAULT_CHECK_CONFIG } from './rules.js';

export class ScoreEngine {
  constructor({ weights = {}, thresholds = {}, checkConfig = {} } = {}) {
    this.checks = [];
    this.weights = { ...DEFAULT_WEIGHTS, ...weights };
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...thresholds };
    this.checkConfig = { ...DEFAULT_CHECK_CONFIG, ...checkConfig };
  }
  register(check) {
    if (!check || !check.name || typeof check.check !== 'function') {
      throw new Error('check must have a name and a check() function');
    }
    this.checks.push(check);
    return this;
  }
  async evaluate(signals, ctx = {}, precomputed = {}) {
    const breakdown = [];
    const reasons = [];
    let hardFail = false;
    let weightedSum = 0;
    let weightTotal = 0;
    let trustBonus = 0;
    let peak = 0;
    const units = [];
    for (const [name, contrib] of Object.entries(precomputed)) {
      units.push({ name, run: async () => contrib });
    }
    const precomputedNames = new Set(Object.keys(precomputed));
    for (const check of this.checks) {
      if (precomputedNames.has(check.name)) continue;
      const cfg = this.checkConfig[check.name] || {};
      units.push({ name: check.name, run: () => check.check(signals, cfg, ctx) });
    }
    const settled = await Promise.all(units.map(async (unit) => {
      try {
        const contrib = await unit.run();
        return { name: unit.name, contrib: contrib || { risk: 0, reasons: [] } };
      } catch (err) {
        return { name: unit.name, contrib: { risk: 40, reasons: [`${unit.name}_check_error:${err.message}`] } };
      }
    }));
    for (const { name, contrib } of settled) {
      const unit = { name };
      const weight = this.weights[unit.name] ?? 1.0;
      const risk = clampRisk(contrib.risk);
      if (contrib.hardFail) hardFail = true;
      if (contrib.trustBonus) trustBonus += contrib.trustBonus;

      weightedSum += risk * weight;
      weightTotal += weight;
      const peakContribution = risk * Math.min(1, weight);
      if (peakContribution > peak) peak = peakContribution;
      for (const r of contrib.reasons || []) reasons.push(r);
      breakdown.push({
        check: unit.name,
        risk,
        weight,
        hardFail: !!contrib.hardFail,
        reasons: contrib.reasons || [],
        meta: contrib.meta,
      });
    }
    const accumulation = weightTotal > 0 ? weightedSum / weightTotal : 0;

    let aggregate = clampRisk(Math.max(accumulation, peak) - trustBonus);

    const action = hardFail ? ACTIONS.DENY : decideAction(aggregate, this.thresholds);
    return {
      action,
      risk: Math.round(aggregate),
      accumulation: Math.round(accumulation),
      peak: Math.round(peak),
      hardFail,
      reasons,
      breakdown,
      thresholds: this.thresholds,
    };
  }
}
