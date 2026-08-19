export class ClientContext {
  constructor({ form, mountedAt, consentGranted, config }) {
    this.form = form;
    this.mountedAt = mountedAt;
    this.consentGranted = consentGranted;
    this.config = config || {};
  }
  elapsed() {
    return now() - this.mountedAt;
  }
}
export function now() {
  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    return performance.now();
  }
  return Date.now();
}
