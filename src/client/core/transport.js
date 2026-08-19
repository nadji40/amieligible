import { PROTOCOL_VERSION } from '../../shared/schema.js';

export class HttpTransport {
  constructor({ challengeUrl, verifyUrl, fetchImpl } = {}) {
    this.challengeUrl = challengeUrl;
    this.verifyUrl = verifyUrl;
    this._fetch = fetchImpl || (typeof fetch !== 'undefined' ? fetch.bind(globalThis) : null);
    if (!this._fetch) throw new Error('No fetch implementation available');
  }
  async fetchChallenge({ formId } = {}) {
    const res = await this._fetch(this.challengeUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ v: PROTOCOL_VERSION, formId }),
    });
    if (!res.ok) throw new Error(`challenge request failed: ${res.status}`);
    return res.json();
  }
  async submit({ token, pow, signals, collected, formData }) {
    const envelope = {
      v: PROTOCOL_VERSION,
      token,
      pow: pow ?? null,
      signals,
      collected,
      clientTs: Date.now(),
    };
    const res = await this._fetch(this.verifyUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ envelope, formData }),
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  }
}
