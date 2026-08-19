export class MemoryNonceStore {
  constructor({ gcIntervalMs = 30000, maxEntries = 500000 } = {}) {
    this._seen = new Map();
    this._gcIntervalMs = gcIntervalMs;
    this._maxEntries = maxEntries;
    this._nextGc = Date.now() + gcIntervalMs;
  }
  useOnce(nonce, expiresAt) {
    const t = Date.now();
    if (t >= this._nextGc || this._seen.size > this._maxEntries) this._gc(t);
    const seen = this._seen.get(nonce);
    if (seen !== undefined && seen > t) return false;
    this._seen.set(nonce, expiresAt);
    return true;
  }
  _gc(t = Date.now()) {
    for (const [k, exp] of this._seen) if (exp <= t) this._seen.delete(k);
    this._nextGc = t + this._gcIntervalMs;
    if (this._seen.size > this._maxEntries) {
      const excess = this._seen.size - this._maxEntries;
      let i = 0;
      for (const k of this._seen.keys()) { if (i++ >= excess) break; this._seen.delete(k); }
    }
  }
  size() { return this._seen.size; }
}

export class MemoryRateStore {
  constructor({ gcIntervalMs = 60000, maxKeys = 200000, staleMs = 600000 } = {}) {
    this._buckets = new Map();
    this._gcIntervalMs = gcIntervalMs;
    this._maxKeys = maxKeys;
    this._staleMs = staleMs;
    this._nextGc = Date.now() + gcIntervalMs;
  }
  hit(key, windowMs) {
    const t = Date.now();
    if (t >= this._nextGc || this._buckets.size > this._maxKeys) this._gc(t);
    const cutoff = t - windowMs;
    const arr = this._buckets.get(key);
    const kept = arr ? arr.filter((ts) => ts > cutoff) : [];
    kept.push(t);
    this._buckets.set(key, kept);
    return { count: kept.length, windowMs };
  }
  peek(key, windowMs) {
    const t = Date.now();
    const arr = this._buckets.get(key) || [];
    return { count: arr.filter((ts) => ts > t - windowMs).length, windowMs };
  }
  _gc(t = Date.now()) {
    const horizon = t - this._staleMs;
    for (const [k, arr] of this._buckets) {
      if (!arr.length || arr[arr.length - 1] <= horizon) this._buckets.delete(k);
    }
    this._nextGc = t + this._gcIntervalMs;
    if (this._buckets.size > this._maxKeys) {
      const excess = this._buckets.size - this._maxKeys;
      let i = 0;
      for (const k of this._buckets.keys()) { if (i++ >= excess) break; this._buckets.delete(k); }
    }
  }
  size() { return this._buckets.size; }
}
