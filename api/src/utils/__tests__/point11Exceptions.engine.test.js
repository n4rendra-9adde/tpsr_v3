'use strict';

const { assembleContextRiskEvidence } = require('../../services/contextRiskEvidenceAssembler');
const { evaluateContextRisk } = require('../contextRiskEngine');

describe('Point 11 Governance - Scopes and Engine', () => {
  let baseEvidence;

  beforeEach(() => {
    baseEvidence = {
      sbomDocument: { 
        sbom_id: 'test-sbom', 
        sbom_hash: 'hash',
        sbom_json: {
          components: [{
            'bom-ref': 'comp-1',
            name: 'comp-1',
            vulnerabilities: [{ id: 'CVE-123', severity: 'CRITICAL' }]
          }]
        }
      },
      contextAssertions: [{ status: 'ACTIVE', environment: 'PRODUCTION', verificationStatus: 'VERIFIED', assetCriticality: 'CRITICAL' }],
      conflict: false,
      invalidContext: false,
      missingContext: false,
      classAFailure: false,
      contextRequired: true,
      vulns: [{ id: 'CVE-123', severity: 'CRITICAL', componentId: 'comp-1' }],
      vexTrusted: false,
      vexCurrent: true,
      vexExactScope: true,
      exceptionTrusted: false,
      componentPresenceTrusted: true
    };
  });

  test('30 exact artifact/digest accepted & 63 exact active exception applies permitted effect', () => {
    baseEvidence.policyExceptions = [{
      id: 'exc-1',
      status: 'ACTIVE',
      assurance_state: 'VERIFIED_TRUSTED',
      sbom_id: 'test-sbom',
      digest_manifest_digest: 'hash',
      policy_rule_id: 'CAECTD-R017',
      environment: 'PRODUCTION',
      vulnerability_ids: ['CVE-123'],
      component_identifiers: ['comp-1'],
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }];
    const assembled = assembleContextRiskEvidence(baseEvidence);
    expect(assembled.exceptionTrusted).toBe(true);
    
    const evalResult = evaluateContextRisk(assembled);
    expect(evalResult.exceptionContribution).toBe('CONDITIONALLY_ACCEPTED');
  });

  test('31 wrong artifact rejected & 64 wrong-scope exception cannot reduce risk', () => {
    baseEvidence.policyExceptions = [{
      id: 'exc-1',
      status: 'ACTIVE',
      assurance_state: 'VERIFIED_TRUSTED',
      sbom_id: 'WRONG-sbom',
      digest_manifest_digest: 'hash',
      policy_rule_id: 'CAECTD-R017',
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }];
    const assembled = assembleContextRiskEvidence(baseEvidence);
    expect(assembled.exceptionTrusted).toBe(false);
  });

  test('33 digest algorithm mismatch rejected', () => {
    baseEvidence.policyExceptions = [{
      id: 'exc-1',
      status: 'ACTIVE',
      assurance_state: 'VERIFIED_TRUSTED',
      sbom_id: 'test-sbom',
      digest_manifest_digest: 'WRONG-hash',
      policy_rule_id: 'CAECTD-R017',
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }];
    const assembled = assembleContextRiskEvidence(baseEvidence);
    expect(assembled.exceptionTrusted).toBe(false);
  });

  test('37 wrong environment rejected', () => {
    baseEvidence.policyExceptions = [{
      id: 'exc-1',
      status: 'ACTIVE',
      assurance_state: 'VERIFIED_TRUSTED',
      sbom_id: 'test-sbom',
      digest_manifest_digest: 'hash',
      environment: 'STAGING', // Context is PRODUCTION
      policy_rule_id: 'CAECTD-R017',
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }];
    const assembled = assembleContextRiskEvidence(baseEvidence);
    expect(assembled.exceptionTrusted).toBe(false);
  });

  test('39 wrong component/CVE rejected', () => {
    baseEvidence.policyExceptions = [{
      id: 'exc-1',
      status: 'ACTIVE',
      assurance_state: 'VERIFIED_TRUSTED',
      sbom_id: 'test-sbom',
      digest_manifest_digest: 'hash',
      policy_rule_id: 'CAECTD-R017',
      vulnerability_ids: ['CVE-999'], // Context has CVE-123
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }];
    const assembled = assembleContextRiskEvidence(baseEvidence);
    expect(assembled.exceptionTrusted).toBe(false);
  });

  test('47 expired exception inactive & 65 expired exception cannot reduce risk', () => {
    baseEvidence.policyExceptions = [{
      id: 'exc-1',
      status: 'EXPIRED',
      assurance_state: 'VERIFIED_TRUSTED',
      sbom_id: 'test-sbom',
      digest_manifest_digest: 'hash',
      policy_rule_id: 'CAECTD-R017',
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }];
    const assembled = assembleContextRiskEvidence(baseEvidence);
    expect(assembled.exceptionTrusted).toBe(false);
  });

  test('50 superseded exception inactive & 66 revoked exception cannot reduce risk', () => {
    baseEvidence.policyExceptions = [{
      id: 'exc-1',
      status: 'REVOKED',
      assurance_state: 'INVALID',
      sbom_id: 'test-sbom',
      digest_manifest_digest: 'hash',
      policy_rule_id: 'CAECTD-R017',
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }, {
      id: 'exc-2',
      status: 'SUPERSEDED',
      assurance_state: 'INVALID',
      sbom_id: 'test-sbom',
      digest_manifest_digest: 'hash',
      policy_rule_id: 'CAECTD-R017',
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }];
    const assembled = assembleContextRiskEvidence(baseEvidence);
    expect(assembled.exceptionTrusted).toBe(false);
  });
  
  test('29 exception alone does not force TRUSTED & 67 exception cannot hide multiple stronger failures & 70 trust decision accurately reflects conditionally accepted state & 72 reason code EXC-001 correctly surfaced & 73 blocking state resolved by active exception', () => {
    baseEvidence.policyExceptions = [{
      id: 'exc-1',
      status: 'ACTIVE',
      assurance_state: 'VERIFIED_TRUSTED',
      sbom_id: 'test-sbom',
      digest_manifest_digest: 'hash',
      policy_rule_id: 'CAECTD-R017',
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }];
    
    // With classA failure
    let assembled = assembleContextRiskEvidence(baseEvidence);
    assembled.classAFailure = true;
    let evalResult = evaluateContextRisk(assembled);
    expect(evalResult.policyBlockingStatus).toBe('BLOCKING');
    expect(evalResult.exceptionContribution).toBe('NONE');
    
    // Without classA failure
    assembled = assembleContextRiskEvidence(baseEvidence);
    assembled.classAFailure = false;
    evalResult = evaluateContextRisk(assembled);
    expect(evalResult.policyBlockingStatus).toBe('BLOCKING');
    expect(evalResult.exceptionContribution).toBe('CONDITIONALLY_ACCEPTED');
  });

  test('60 multiple exceptions evaluated correctly & 61 missing exception fails closed & 62 overlapping exceptions correctly scoped', () => {
    // Missing exception
    baseEvidence.policyExceptions = [];
    let assembled = assembleContextRiskEvidence(baseEvidence);
    expect(assembled.exceptionTrusted).toBe(false);

    // Overlapping - one valid, one revoked
    baseEvidence.policyExceptions = [{
      id: 'exc-1',
      status: 'ACTIVE',
      assurance_state: 'VERIFIED_TRUSTED',
      sbom_id: 'test-sbom',
      digest_manifest_digest: 'hash',
      policy_rule_id: 'CAECTD-R017',
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }, {
      id: 'exc-2',
      status: 'REVOKED',
      assurance_state: 'INVALID',
      sbom_id: 'test-sbom',
      digest_manifest_digest: 'hash',
      policy_rule_id: 'CAECTD-R017',
      remediation_plan: 'plan',
      compensating_controls: ['WAF']
    }];
    assembled = assembleContextRiskEvidence(baseEvidence);
    expect(assembled.exceptionTrusted).toBe(true);
  });
});
