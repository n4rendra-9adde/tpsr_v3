const { evaluateDeploymentContext } = require('../contextEngine');

describe('TPSR v3 Deployment Context Policy Evaluation Engine', () => {
  test('Rejects invalid or missing deployment context', () => {
    const res = evaluateDeploymentContext(null);
    expect(res.compliant).toBe(false);
    expect(res.reasonCode).toBe('CTX-003');
  });

  test('PROD_CRITICAL: Rejects when highest effective severity is CRITICAL', () => {
    const res = evaluateDeploymentContext(
      { deploymentTier: 'PROD_CRITICAL' },
      { severity: 'CRITICAL', cvssScore: 9.8 },
      { policyBlockingStatus: 'BLOCKING' }
    );
    expect(res.compliant).toBe(false);
    expect(res.reasonCode).toBe('CTX-001');
  });

  test('PROD_CRITICAL: Approves when VEX mitigates a critical vulnerability', () => {
    const res = evaluateDeploymentContext(
      { deploymentTier: 'PROD_CRITICAL' },
      { severity: 'CRITICAL', cvssScore: 9.8 },
      { policyBlockingStatus: 'NON_BLOCKING' }
    );
    expect(res.compliant).toBe(true);
    expect(res.reasonCode).toBe('CTX-004');
  });

  test('Internet Exposed: Rejects asset when unmitigated HIGH or CRITICAL vulnerability exists', () => {
    const res = evaluateDeploymentContext(
      { deploymentTier: 'PROD', internetExposed: true },
      { severity: 'HIGH', cvssScore: 7.5 },
      { policyBlockingStatus: 'BLOCKING' }
    );
    expect(res.compliant).toBe(false);
    expect(res.reasonCode).toBe('CTX-001');
  });

  test('PROD: Approves asset when effective risk is below threshold and no critical exposure rules violated', () => {
    const res = evaluateDeploymentContext(
      { deploymentTier: 'PROD', internetExposed: false },
      { severity: 'MEDIUM', cvssScore: 4.2 },
      { policyBlockingStatus: 'BLOCKING' }
    );
    expect(res.compliant).toBe(true);
    expect(res.reasonCode).toBe('CTX-000');
  });
});
