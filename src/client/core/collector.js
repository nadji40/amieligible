export class Collector {
  constructor(name, { requiresConsent = false } = {}) {
    if (!name) throw new Error('Collector requires a name');
    this.name = name;
    this.requiresConsent = requiresConsent;
    this.enabled = true;
  }
  collect(_ctx) {
    throw new Error(`Collector "${this.name}" must implement collect()`);
  }
  async run(ctx) {
    try {
      const data = await this.collect(ctx);
      return { ok: true, data: data ?? {} };
    } catch (err) {
      return { ok: false, data: { _error: String(err && err.message || err) } };
    }
  }
}
