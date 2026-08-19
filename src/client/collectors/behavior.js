import { Collector } from '../core/collector.js';

export class BehaviorCollector extends Collector {
  constructor() {
    super('behavior', { requiresConsent: true });
    this._points = [];
    this._scrolls = 0;
    this._maxScrollDepth = 0;
    this._bound = false;
    this._sampleEvery = 4;
    this._counter = 0;
  }
  attach() {
    if (this._bound || typeof window === 'undefined') return;
    this._bound = true;
    window.addEventListener('pointermove', (e) => {
      if ((this._counter++ % this._sampleEvery) !== 0) return;
      if (this._points.length < 512) {
        this._points.push([e.clientX, e.clientY, e.timeStamp]);
      }
    }, { passive: true });
    window.addEventListener('scroll', () => {
      this._scrolls++;
      const depth = window.scrollY || 0;
      if (depth > this._maxScrollDepth) this._maxScrollDepth = depth;
    }, { passive: true });
  }
  collect() {
    return {
      pointerSamples: this._points.length,
      scrollEvents: this._scrolls,
      maxScrollDepth: this._maxScrollDepth,
      pathEntropy: pathEntropy(this._points),
      straightLineRatio: straightLineRatio(this._points),

      hadMovement: this._points.length > 0,
    };
  }
}
function pathEntropy(points) {
  if (points.length < 3) return 0;
  const buckets = new Array(8).fill(0);
  let segments = 0;
  for (let i = 1; i < points.length; i++) {
    const dx = points[i][0] - points[i - 1][0];
    const dy = points[i][1] - points[i - 1][1];
    if (dx === 0 && dy === 0) continue;
    const angle = Math.atan2(dy, dx) + Math.PI;
    const b = Math.min(7, Math.floor((angle / (2 * Math.PI)) * 8));
    buckets[b]++;
    segments++;
  }
  if (segments === 0) return 0;
  let h = 0;
  for (const c of buckets) {
    if (c === 0) continue;
    const p = c / segments;
    h -= p * Math.log2(p);
  }
  return Number((h / 3).toFixed(3));
}
function straightLineRatio(points) {
  if (points.length < 3) return 0;
  let straight = 0;
  let total = 0;
  for (let i = 2; i < points.length; i++) {
    const a = points[i - 2];
    const b = points[i - 1];
    const c = points[i];
    const cross = Math.abs((b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0]));
    total++;
    if (cross < 1) straight++;
  }
  return total === 0 ? 0 : Number((straight / total).toFixed(3));
}
