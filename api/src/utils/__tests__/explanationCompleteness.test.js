const { evaluateTrust } = require('../trustEngine');
const provenanceEngine = require('../provenanceEngine');

jest.mock('../provenanceEngine', () => ({
  getTrustPolicy: jest.fn(() => ({
    version: '3.0',
    hash: 'mock-hash',
    requireDeploymentContext: true,
    requireVexStatements: false
  }))
}));

describe('Explanation Completeness', () => {
  const baseEv = {
    sbomDocument: { sbom_id: '1', id: '1', sbom_json: { components: [] } },
    provenance: [{ id: '1', status: 'VALID', slsa_level: 'SLSA_BUILD_LEVEL_3' }],
    signatures: [{ id: '1', verification_status: 'VERIFIED' }]
  };

  it('Complete trusted context explanation', async () => {
    const res = await evaluateTrust({ ...baseEv, activeContextAssertion: { status: 'ACTIVE', signatureStatus: 'VERIFIED', environment: 'PROD', network_exposure: 'INTERNAL' } });
    console.log(res.explanationCompleteness);
    expect(res.explanationCompleteness.complete).toBe(true);
    const req = res.explanationCompleteness.requiredChecks;
    expect(req.contextPolicyResultPresent).toBe(true);
    expect(req.contextAssertionEvaluated).toBe(true);
    expect(req.trustPolicyHashPresent).toBe(true);
  });

  it('Missing context explanation', async () => {
    const res = await evaluateTrust(baseEv);
    expect(res.explanationCompleteness.complete).toBe(true); // Complete means all fields present, even if trust failed
    const req = res.explanationCompleteness.requiredChecks;
    expect(req.contextPolicyResultPresent).toBe(true);
    expect(req.contextAssertionEvaluated).toBe(true);
  });

  it('Conflicting context explanation', async () => {
    const res = await evaluateTrust({ ...baseEv, allActiveContextAssertions: [
      { status: 'ACTIVE', signatureStatus: 'VERIFIED', environment: 'PROD' },
      { status: 'ACTIVE', signatureStatus: 'VERIFIED', environment: 'DEV' }
    ] });
    expect(res.explanationCompleteness.complete).toBe(true);
  });

  it('Active exception explanation', async () => {
    const res = await evaluateTrust({ ...baseEv, activeContextAssertion: { status: 'ACTIVE', signatureStatus: 'VERIFIED', environment: 'PROD', network_exposure: 'INTERNAL' }, policyExceptions: [{ status: 'ACTIVE', assurance_state: 'VERIFIED_TRUSTED', policy_rule_id: 'CAECTD-R017' }] });
    expect(res.explanationCompleteness.complete).toBe(true);
  });

  it('Historical decision without context result (mocked)', async () => {
    // If contextRisk is missing from evidenceDependencies
    const policy = require('../provenanceEngine').getTrustPolicy();
    policy.requireDeploymentContext = false;
    const res = await evaluateTrust(baseEv);
    expect(res.explanationCompleteness.complete).toBe(true);
    policy.requireDeploymentContext = true; // reset
  });
});
