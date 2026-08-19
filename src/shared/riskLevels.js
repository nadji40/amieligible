export const ACTIONS = Object.freeze({
  ALLOW: 'allow',
  CHALLENGE: 'challenge',
  DENY: 'deny',
});
export const DEFAULT_THRESHOLDS = Object.freeze({
  challengeAt: 45,
  denyAt: 75,
});
export function decideAction(risk, thresholds = DEFAULT_THRESHOLDS) {
  if (risk >= thresholds.denyAt) return ACTIONS.DENY;
  if (risk >= thresholds.challengeAt) return ACTIONS.CHALLENGE;
  return ACTIONS.ALLOW;
}
export function clampRisk(n) {
  if (Number.isNaN(n) || typeof n !== 'number') return 0;
  return Math.max(0, Math.min(100, n));
}
