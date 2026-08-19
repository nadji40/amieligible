export function createFingerprintReputationCheck({ reputation } = {}) {
  return {
    name: 'fingerprintReputation',
    async check(signals) {
      const fp = signals && signals.fingerprint;
      if (!fp || !fp.visitorId) {
        return { risk: 5, reasons: ['fp_absent'] };
      }
      if (!reputation) return { risk: 0, reasons: [] };
      const reasons = [];
      let risk = 0;
      const status = await reputation.status(fp.visitorId);
      if (status === 'blocked') {
        return { hardFail: true, risk: 100, reasons: ['fp_blocklisted'] };
      }
      if (status === 'trusted') {
        return { risk: 0, reasons: ['fp_trusted'], trustBonus: 15 };
      }
      const abuse = (await reputation.abuseCount?.(fp.visitorId)) || 0;
      if (abuse > 0) {
        risk += Math.min(60, abuse * 15);
        reasons.push(`fp_prior_abuse:${abuse}`);
      }
      return { risk, reasons };
    },
  };
}
