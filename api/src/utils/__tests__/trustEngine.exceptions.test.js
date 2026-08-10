const { evaluateTrust, TRUST_STATUS } = require('../trustEngine');
const baseEvidence = {
  sbomDocument: { sbom_id: '1', id: '1', sbom_json: { components: [{vulnerabilities: [{id: 'CVE-1', severity: 'CRITICAL', policyBlockingStatus: 'BLOCKING'}]}] } },
  provenance: [{ id: '1', status: 'VALID', slsa_level: 'SLSA_BUILD_LEVEL_3' }],
  signatures: [{ id: '1', verification_status: 'VERIFIED' }],
  activeContextAssertion: { id: 'ctx', status: 'ACTIVE', verification_status: 'VERIFIED', environment: 'PRODUCTION', internetExposure: 'PUBLIC', componentPresence: 'PRESENT', runtimeExecution: 'EXECUTED' }
};

describe('Exception Relief Governance Checks', () => {
  it('Scope mismatch does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-OTHER', vulnerability_ids: ['CVE-1'], remediation_plan: 'Fix', compensating_controls: ['WAF'], residual_risk: 'LOW', valid_until: new Date(Date.now() + 86400000).toISOString() }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
  it('Vulnerability mismatch does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017', vulnerability_ids: ['CVE-OTHER'], remediation_plan: 'Fix', compensating_controls: ['WAF'], residual_risk: 'LOW', valid_until: new Date(Date.now() + 86400000).toISOString() }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
  it('Component mismatch does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017', vulnerability_ids: ['CVE-1'], component_identifiers: ['OTHER'], remediation_plan: 'Fix', compensating_controls: ['WAF'], residual_risk: 'LOW', valid_until: new Date(Date.now() + 86400000).toISOString() }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
  it('Policy-version mismatch does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017', vulnerability_ids: ['CVE-1'], policy_version: '2.0', remediation_plan: 'Fix', compensating_controls: ['WAF'], residual_risk: 'LOW', valid_until: new Date(Date.now() + 86400000).toISOString() }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
  it('Missing remediation plan does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017', vulnerability_ids: ['CVE-1'], remediation_plan: '', compensating_controls: ['WAF'], residual_risk: 'LOW', valid_until: new Date(Date.now() + 86400000).toISOString() }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
  it('Excessive validity does not mitigate', async () => {
    const ev = { ...baseEvidence, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017', vulnerability_ids: ['CVE-1'], remediation_plan: 'Fix', compensating_controls: ['WAF'], residual_risk: 'LOW', valid_until: new Date(Date.now() + 86400000 * 90).toISOString() }] };
    const res = await evaluateTrust(ev);
    expect(res.trustStatus).toBe(TRUST_STATUS.REJECTED);
  });
});
