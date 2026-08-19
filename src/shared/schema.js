export const PROTOCOL_VERSION = 1;
export function validateEnvelope(env) {
  const errors = [];
  if (!env || typeof env !== 'object') {
    return { ok: false, errors: ['envelope missing or not an object'] };
  }
  if (env.v !== PROTOCOL_VERSION) errors.push(`unsupported protocol version: ${env.v}`);
  if (typeof env.token !== 'string' || env.token.length === 0) errors.push('token missing');
  if (typeof env.signals !== 'object' || env.signals === null) errors.push('signals missing');
  if (!Array.isArray(env.collected)) errors.push('collected must be an array');
  if (typeof env.clientTs !== 'number') errors.push('clientTs must be a number');
  if (env.pow !== undefined && env.pow !== null
      && typeof env.pow !== 'string' && typeof env.pow !== 'number') {
    errors.push('pow must be a string or number when present');
  }
  return { ok: errors.length === 0, errors };
}
