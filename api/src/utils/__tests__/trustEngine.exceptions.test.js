const { evaluateTrust, TRUST_STATUS } = require('../trustEngine');
const baseEvidence = {
  sbomDocument: { sbom_id: '1', id: '1', sbom_json: { components: [{vulnerabilities: [{id: 'CVE-1', severity: 'CRITICAL', policyBlockingStatus: 'BLOCKING'}]}] } },
  provenance: [{ id: '1', status: 'VALID', slsa_level: 'SLSA_BUILD_LEVEL_3' }],
  signatures: [{ id: '1', verification_status: 'VERIFIED' }],
  deploymentContext: { environment: 'PROD', network_exposure: 'PUBLIC' }
};

describe('Exception Relief Governance Checks', () => {
  it('Scope mismatch does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-OTHER' }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
  it('Vulnerability mismatch does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017', vulnerability_ids: ['CVE-OTHER'] }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
  it('Component mismatch does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017', component_scope_mismatch: true }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
  it('Policy-version mismatch does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017', policy_version: '2.0' }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
  it('Missing remediation plan does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017', missing_remediation: true }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
  it('Excessive validity does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017', validity_days: 90 }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
});
