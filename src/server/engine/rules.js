export const DEFAULT_WEIGHTS = Object.freeze({
  token: 2.0,
  pow: 1.5,
  honeypot: 1.8,
  geo: 2.0,
  rateLimit: 1.6,
  environment: 1.0,
  timing: 1.0,
  behavior: 0.8,
  instrumentation: 1.6,
  fingerprintReputation: 1.4,
});
export const DEFAULT_CHECK_CONFIG = Object.freeze({
  timing: { minFillMs: 1000, minCadenceCv: 0.15 },
});
