const { evaluate, verifyReplay } = require('../experiments/evaluators/caectdEvaluator');
const policyRepo = require('../repositories/policy.repository');
const trustPolicyLoader = require('../utils/trustPolicyLoader');

jest.mock('../repositories/policy.repository', () => ({
  insertObservabilityEvent: jest.fn(() => Promise.resolve())
}));

describe('Point 13 Deterministic Decision Reproducibility', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const sampleInput = {
    sbomPresent: true,
    sbomId: 'test-sbom',
    canonicalSbomHash: 'hash',
    ledgerAnchorHash: 'hash',
    vulnerabilities: [],
    provenance: [],
    signatures: [],
    vexStatements: [],
    policyExceptions: []
  };

  it('1 identical inputs yield identical outputs (replay verified) & 3 distinct observability event emitted', async () => {
    // Generate snapshot
    const result = await evaluate(sampleInput);
    expect(result.snapshot).toMatchObject({ hash: expect.any(String), payload: expect.any(Object) });
    
    // Verify replay
    const success = await verifyReplay(result.snapshot.hash, result.snapshot.payload);
    expect(success).toBe(true);
    expect(policyRepo.insertObservabilityEvent).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'DECISION_REPLAY_VERIFIED' })
    );
  });

  it('2 drift yields failure & 4 distinct fail observability event emitted', async () => {
    const result = await evaluate(sampleInput);
    
    // Introduce drift
    result.snapshot.payload.input.sbomId = 'drifted-sbom';
    
    const success = await verifyReplay(result.snapshot.hash, result.snapshot.payload);
    expect(success).toBe(false);
    expect(policyRepo.insertObservabilityEvent).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'DECISION_REPLAY_FAILED' })
    );
  });

  it('5 immutable decision snapshots bound to evidence manifest', async () => {
    const result = await evaluate(sampleInput);
    
    // Changing the result part should also fail
    result.snapshot.payload.result.trustStatus = 'TRUSTED';
    
    const success = await verifyReplay(result.snapshot.hash, result.snapshot.payload);
    expect(success).toBe(false);
  });

  it('6 fail-closed verification of snapshot payload vs replay recalculation', async () => {
    const result = await evaluate(sampleInput);
    
    // Malformed input causes evaluation to fail
    const success = await verifyReplay('bad-hash', { input: null, result: {}, policySnapshot: {} });
    expect(success).toBe(false);
  });
});
