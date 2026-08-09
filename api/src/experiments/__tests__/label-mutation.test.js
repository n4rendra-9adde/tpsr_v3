const { evaluate } = require('../evaluators/caectdEvaluator');

describe('Label Mutation Independence', () => {
  it('Evaluator outputs remain unchanged when only labels are mutated', async () => {
    const input = {
      sbomPresent: true,
      canonicalSbomHash: 'A',
      ledgerAnchorHash: 'A',
      vulnerabilities: [],
      provenance: [{ status: 'VALID', slsa_level: 'SLSA_BUILD_LEVEL_3' }],
      signatures: [{ status: 'VALID' }],
      expectedCAECTDDecision: 'TRUSTED' // initial label
    };
    const res1 = await evaluate(input);
    expect(res1.decision).toBe('TRUSTED');

    // Mutate label
    input.expectedCAECTDDecision = 'REJECTED';
    const res2 = await evaluate(input);
    
    // Outputs remain unchanged
    expect(res2.decision).toBe('TRUSTED');
    expect(res2.ruleIds).toEqual(res1.ruleIds);
    expect(res2.reasonCodes).toEqual(res1.reasonCodes);
  });
});
