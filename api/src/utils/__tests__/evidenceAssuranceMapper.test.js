'use strict';

const { mapSignatureEvidence, mapProvenanceEvidence, mapVexEvidence, mapContextEvidence, mapExceptionEvidence, ASSURANCE_STATES } = require('../evidenceAssuranceMapper');

describe('evidenceAssuranceMapper', () => {
  describe('mapSignatureEvidence', () => {
    it('maps VERIFIED to VERIFIED_TRUSTED', () => {
      const res = mapSignatureEvidence({ verification_status: 'VERIFIED' });
      expect(res.normalized).toBe(ASSURANCE_STATES.VERIFIED_TRUSTED);
    });
    it('maps UNTRUSTED to VERIFIED_UNTRUSTED', () => {
      const res = mapSignatureEvidence({ verificationStatus: 'UNTRUSTED' });
      expect(res.normalized).toBe(ASSURANCE_STATES.VERIFIED_UNTRUSTED);
    });
    it('maps missing to MISSING', () => {
      expect(mapSignatureEvidence(null).normalized).toBe(ASSURANCE_STATES.MISSING);
    });
    it('maps unknown to NOT_EVALUATED', () => {
      expect(mapSignatureEvidence({}).normalized).toBe(ASSURANCE_STATES.NOT_EVALUATED);
    });
    it('maps random to INVALID', () => {
      expect(mapSignatureEvidence({ verification_status: 'FAKE' }).normalized).toBe(ASSURANCE_STATES.INVALID);
    });
  });

  describe('mapProvenanceEvidence', () => {
    it('maps VALID to VERIFIED_TRUSTED', () => {
      expect(mapProvenanceEvidence({ status: 'VALID' }).normalized).toBe(ASSURANCE_STATES.VERIFIED_TRUSTED);
    });
    it('maps UNTRUSTED to VERIFIED_UNTRUSTED', () => {
      expect(mapProvenanceEvidence({ status: 'UNTRUSTED' }).normalized).toBe(ASSURANCE_STATES.VERIFIED_UNTRUSTED);
    });

    it('maps UNTRUSTED with BND-002 to INVALID', () => {
      expect(mapProvenanceEvidence({ status: 'UNTRUSTED', reasonCodes: ['BND-002'] }).normalized).toBe(ASSURANCE_STATES.INVALID);
      expect(mapProvenanceEvidence({ status: 'UNTRUSTED', reason_codes: ['BND-002'] }).normalized).toBe(ASSURANCE_STATES.INVALID);
    });

    it('maps missing to MISSING', () => {
      expect(mapProvenanceEvidence(null).normalized).toBe(ASSURANCE_STATES.MISSING);
    });
  });

  describe('mapVexEvidence', () => {
    it('maps not_affected to VERIFIED_TRUSTED', () => {
      expect(mapVexEvidence({ status: 'not_affected' }).normalized).toBe(ASSURANCE_STATES.VERIFIED_TRUSTED);
    });
    it('maps under_investigation to NOT_EVALUATED', () => {
      expect(mapVexEvidence({ status: 'under_investigation' }).normalized).toBe(ASSURANCE_STATES.NOT_EVALUATED);
    });
    it('maps CONFLICTING to CONFLICTING', () => {
      expect(mapVexEvidence({ status: 'CONFLICTING' }).normalized).toBe(ASSURANCE_STATES.CONFLICTING);
    });
  });

  describe('mapContextEvidence', () => {
    it('maps to VERIFIED_UNTRUSTED currently', () => {
      expect(mapContextEvidence({ environment: 'PROD' }).normalized).toBe(ASSURANCE_STATES.VERIFIED_UNTRUSTED);
    });
  });

  describe('mapExceptionEvidence', () => {
    it('maps APPROVED to VERIFIED_TRUSTED', () => {
      expect(mapExceptionEvidence({ status: 'APPROVED' }).normalized).toBe(ASSURANCE_STATES.VERIFIED_TRUSTED);
    });
    it('maps EXPIRED to STALE', () => {
      const past = new Date(Date.now() - 10000).toISOString();
      expect(mapExceptionEvidence({ status: 'APPROVED', valid_until: past }).normalized).toBe(ASSURANCE_STATES.STALE);
    });
    it('maps REVOKED to INVALID', () => {
      expect(mapExceptionEvidence({ status: 'REVOKED' }).normalized).toBe(ASSURANCE_STATES.INVALID);
    });
  });
});
