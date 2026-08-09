const { evaluateContextRisk } = require('../contextRiskEngine');
const { normalizeEnvironment, normalizeExposure } = require('../contextCompatibilityMapper');

describe('Context Risk Constants and Mapper', () => {
  it('normalizes legacy DEV alias', () => {
    const res = normalizeEnvironment('DEV');
    expect(res.canonicalValue).toBe('DEVELOPMENT');
    expect(res.normalized).toBe(true);
  });

  it('rejects ambiguous alias', () => {
    const res = normalizeEnvironment('FOO');
    expect(res.canonicalValue).toBe(null);
    expect(res.normalized).toBe(false);
  });
});

describe('Context Risk Engine', () => {
  it('Production public exploitable sets CRITICAL/BLOCKING', () => {
    const input = {
      contextVector: { environment: 'PRODUCTION', internetExposure: 'PUBLIC', vexApplicability: 'AFFECTED', componentPresence: 'PRESENT', runtimeExecution: 'EXECUTED' },
    };
    const res = evaluateContextRisk(input);
    expect(res.contextualRisk).toBe('CRITICAL');
    expect(res.policyBlockingStatus).toBe('BLOCKING');
  });

  it('Trusted NOT_AFFECTED VEX makes it NON_BLOCKING', () => {
    const input = {
      vexTrusted: true, vexCurrent: true, vexExactScope: true,
      contextVector: { vexApplicability: 'NOT_AFFECTED' }
    };
    const res = evaluateContextRisk(input);
    expect(res.exploitability).toBe('NOT_EXPLOITABLE');
    expect(res.policyBlockingStatus).toBe('NON_BLOCKING');
  });

  it('Under investigation VEX produces REVIEW_REQUIRED', () => {
    const input = {
      contextVector: { vexApplicability: 'UNDER_INVESTIGATION' }
    };
    const res = evaluateContextRisk(input);
    expect(res.exploitability).toBe('UNDER_INVESTIGATION');
    expect(res.policyBlockingStatus).toBe('REVIEW_REQUIRED');
  });

  it('Missing or untrusted VEX ignores NOT_AFFECTED', () => {
    const input = {
      vexTrusted: false,
      contextVector: { vexApplicability: 'NOT_AFFECTED' }
    };
    const res = evaluateContextRisk(input);
    expect(res.exploitability).toBe('UNKNOWN');
    expect(res.policyBlockingStatus).toBe('REVIEW_REQUIRED');
  });

  it('Conflicting context produces REVIEW_REQUIRED', () => {
    const input = {
      conflict: true,
      contextVector: {}
    };
    const res = evaluateContextRisk(input);
    expect(res.contextAssuranceState).toBe('CONFLICTING');
    expect(res.policyBlockingStatus).toBe('REVIEW_REQUIRED');
  });

  it('Active exception produces CONDITIONALLY_ACCEPTED over Class B', () => {
    const input = {
      exceptionTrusted: true,
      contextVector: { environment: 'PRODUCTION', internetExposure: 'PUBLIC', vexApplicability: 'AFFECTED', componentPresence: 'PRESENT', runtimeExecution: 'EXECUTED', exceptionStatus: 'ACTIVE' }
    };
    const res = evaluateContextRisk(input);
    expect(res.policyBlockingStatus).toBe('BLOCKING');
    expect(res.exceptionContribution).toBe('CONDITIONALLY_ACCEPTED');
  });

  it('Exception does not override Class A', () => {
    const input = {
      classAFailure: true, exceptionTrusted: true,
      contextVector: { exceptionStatus: 'ACTIVE' }
    };
    const res = evaluateContextRisk(input);
    expect(res.policyBlockingStatus).toBe('BLOCKING');
    expect(res.exceptionContribution).toBe('NONE');
  });
});
