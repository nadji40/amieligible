import { Collector } from '../core/collector.js';
import { now } from '../core/context.js';

export class TimingCollector extends Collector {
  constructor() {
    super('timing');
    this._firstInteraction = null;
    this._keyTimes = [];
    this._focused = new Set();
    this._bound = false;
  }
  attach(ctx) {
    if (this._bound || !ctx.form) return;
    this._bound = true;
    const mark = () => {
      if (this._firstInteraction === null) this._firstInteraction = now();
    };
    ctx.form.addEventListener('keydown', (e) => {
      mark();
      this._keyTimes.push(now());
      if (e.target && e.target.name) this._focused.add(e.target.name);
    }, { passive: true });
    ctx.form.addEventListener('pointerdown', mark, { passive: true });
    ctx.form.addEventListener('focusin', (e) => {
      mark();
      if (e.target && e.target.name) this._focused.add(e.target.name);
    }, { passive: true });
  }
  collect(ctx) {
    const submitAt = now();
    const intervals = [];
    for (let i = 1; i < this._keyTimes.length; i++) {
      intervals.push(this._keyTimes[i] - this._keyTimes[i - 1]);
    }
    return {
      timeToFirstInteraction: this._firstInteraction === null
        ? null
        : Math.round(this._firstInteraction - ctx.mountedAt),
      fillTime: this._firstInteraction === null
        ? null
        : Math.round(submitAt - this._firstInteraction),
      totalOnPage: Math.round(submitAt - ctx.mountedAt),
      keydownCount: this._keyTimes.length,
      distinctFields: this._focused.size,
      cadence: summariseIntervals(intervals),
    };
  }
}
function summariseIntervals(intervals) {
  if (intervals.length === 0) return { count: 0, mean: null, min: null, cv: null };
  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
  const std = Math.sqrt(variance);
  return {
    count: intervals.length,
    mean: Math.round(mean),
    min: Math.round(Math.min(...intervals)),
    cv: mean === 0 ? 0 : Number((std / mean).toFixed(3)),
  };
}
