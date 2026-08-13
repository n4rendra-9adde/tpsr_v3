'use strict';

const contextRiskEvidenceAssembler = require('../contextRiskEvidenceAssembler');

describe('Point 10 CAECTD Integration', () => {
  test('authorized context reduces risk if it matches rules', () => {
    const assertions = [{
      environment: 'PRODUCTION',
      verification_status: 'AUTHORIZED', // New state from Point 10
      status: 'ACTIVE'
    }];
    const matrix = contextRiskEvidenceAssembler.assembleContextRiskEvidence({ sbomDocument: {}, contextAssertions: assertions, vexStatements: [], policyExceptions: [], policy: {} });
    expect(matrix.contextVector.environment).toBe('PRODUCTION');
  });

  test('unauthorized context cannot reduce risk', () => {
    const assertions = [{
      environment: 'PRODUCTION',
      verification_status: 'FAILED',
      status: 'INVALID'
    }];
    const matrix = contextRiskEvidenceAssembler.assembleContextRiskEvidence({ sbomDocument: {}, contextAssertions: assertions, vexStatements: [], policyExceptions: [], policy: {} });
    expect(matrix.contextVector.environment).toBeUndefined(); // Should not trust it
  });

  test('expired context does not contribute to risk reduction', () => {
    const assertions = [{
      environment: 'PRODUCTION',
      verification_status: 'AUTHORIZED',
      status: 'ACTIVE',
      valid_until: new Date(Date.now() - 1000).toISOString() // Expired
    }];
    const matrix = contextRiskEvidenceAssembler.assembleContextRiskEvidence({ sbomDocument: {}, contextAssertions: assertions, vexStatements: [], policyExceptions: [], policy: {} });
    expect(matrix.contextVector.environment).toBeUndefined();
  });
});
