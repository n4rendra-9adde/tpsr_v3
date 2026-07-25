const { evaluateDeploymentContext } = require('../contextEngine');

describe('TPSR v3 Deployment Context Policy Evaluation Engine', () => {
  test('Rejects invalid or missing deployment context', () => {
    const res = evaluateDeploymentContext(null);
    expect(res.compliant).toBe(false);
    expect(res.reasonCode).toBe('CTX-004');
  });

  test('PROD_CRITICAL: Rejects when highest effective severity is CRITICAL', () => {
    const res = evaluateDeploymentContext(
      { deploymentTier: 'PROD_CRITICAL' },
      { highestEffectiveSeverity: 'CRITICAL', effectiveRiskScore: 9.8 }
    );
    expect(res.compliant).toBe(false);
    expect(res.reasonCode).toBe('CTX-002');
  });

  test('PROD_CRITICAL: Rejects when provenance is below SLSA Level 3', () => {
    const res = evaluateDeploymentContext(
      { deploymentTier: 'PROD_CRITICAL' },
      { highestEffectiveSeverity: 'NONE', effectiveRiskScore: 0 },
      { status: 'VALID', slsaLevel: 'SLSA_BUILD_LEVEL_2' }
    );
    expect(res.compliant).toBe(false);
    expect(res.reasonCode).toBe('CTX-002');
  });

  test('Internet Exposed: Rejects asset when unmitigated HIGH or CRITICAL vulnerability exists', () => {
    const res = evaluateDeploymentContext(
      { deploymentTier: 'PROD', internetExposed: true },
      { highestEffectiveSeverity: 'HIGH', effectiveRiskScore: 7.5 }
    );
    expect(res.compliant).toBe(false);
    expect(res.reasonCode).toBe('CTX-003');
  });

  test('PROD: Approves asset when effective risk is below threshold and no critical exposure rules violated', () => {
    const res = evaluateDeploymentContext(
      { deploymentTier: 'PROD', internetExposed: false },
      { highestEffectiveSeverity: 'MEDIUM', effectiveRiskScore: 4.2 },
      { status: 'VALID', slsaLevel: 'SLSA_BUILD_LEVEL_3' }
    );
    expect(res.compliant).toBe(true);
    expect(res.reasonCode).toBe('CTX-001');
  });
});
