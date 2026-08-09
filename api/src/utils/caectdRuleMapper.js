'use strict';

/**
 * CAECTD 0.1 Rule Mapper
 *
 * Centralized rule dictionary mapping conditions to specific CAECTD rule IDs.
 */

const CAECTD_RULES = {
  'CAECTD-R002': {
    ruleId: 'CAECTD-R002',
    ruleName: 'SBOM integrity canonical hash mismatch',
    failureClass: 'Class A',
    defaultDecisionEffect: 'REJECTED',
    evidenceDependencies: ['integrity'],
    reasonCodes: ['INT-002', 'INT-004', 'INT-005'],
    reasonCodeStatus: 'EXISTING_AND_IMPLEMENTED',
    exceptionAllowed: false,
    lifecycleEffect: 'Blocked'
  },
  'CAECTD-R004': {
    ruleId: 'CAECTD-R004',
    ruleName: 'Invalid cryptographic signature',
    failureClass: 'Class A',
    defaultDecisionEffect: 'REJECTED',
    evidenceDependencies: ['signatureDecision'],
    reasonCodes: ['SIG-002'],
    reasonCodeStatus: 'EXISTING_AND_IMPLEMENTED',
    exceptionAllowed: false,
    lifecycleEffect: 'Blocked'
  },
  'CAECTD-R005': {
    ruleId: 'CAECTD-R005',
    ruleName: 'Valid signature from untrusted signer',
    failureClass: 'Class A',
    defaultDecisionEffect: 'REJECTED',
    evidenceDependencies: ['signatureDecision'],
    reasonCodes: ['SIG-003'],
    reasonCodeStatus: 'EXISTING_AND_IMPLEMENTED',
    exceptionAllowed: false,
    lifecycleEffect: 'Blocked'
  },
  'CAECTD-R006': {
    ruleId: 'CAECTD-R006',
    ruleName: 'Signature target mismatch',
    failureClass: 'Class A',
    defaultDecisionEffect: 'REJECTED',
    evidenceDependencies: ['signatureDecision'],
    reasonCodes: ['BND-003'],
    reasonCodeStatus: 'EXISTING_AND_IMPLEMENTED',
    exceptionAllowed: false,
    lifecycleEffect: 'Blocked'
  },
  'CAECTD-R008': {
    ruleId: 'CAECTD-R008',
    ruleName: 'Invalid provenance envelope',
    failureClass: 'Class A',
    defaultDecisionEffect: 'REJECTED',
    evidenceDependencies: ['provenanceDecision'],
    reasonCodes: ['PRV-002'],
    reasonCodeStatus: 'EXISTING_AND_IMPLEMENTED',
    exceptionAllowed: false,
    lifecycleEffect: 'Blocked'
  },
  'CAECTD-R009': {
    ruleId: 'CAECTD-R009',
    ruleName: 'Unauthorized builder',
    failureClass: 'Class A',
    defaultDecisionEffect: 'REJECTED',
    evidenceDependencies: ['provenanceDecision'],
    reasonCodes: ['PRV-003'],
    reasonCodeStatus: 'EXISTING_AND_IMPLEMENTED',
    exceptionAllowed: false,
    lifecycleEffect: 'Blocked'
  },
  'CAECTD-R012': {
    ruleId: 'CAECTD-R012',
    ruleName: 'Provenance subject mismatch',
    failureClass: 'Class A',
    defaultDecisionEffect: 'REJECTED',
    evidenceDependencies: ['provenanceDecision'],
    reasonCodes: ['BND-002'],
    reasonCodeStatus: 'EXISTING_AND_IMPLEMENTED',
    exceptionAllowed: false,
    lifecycleEffect: 'Blocked'
  },
  'CAECTD-R016': {
    ruleId: 'CAECTD-R016',
    ruleName: 'Trusted NOT_AFFECTED VEX',
    failureClass: 'None',
    defaultDecisionEffect: 'NON_BLOCKING',
    evidenceDependencies: ['vexApplicabilityDecision'],
    reasonCodes: ['VEX-001'],
    reasonCodeStatus: 'EXISTING_AND_IMPLEMENTED',
    exceptionAllowed: true,
    lifecycleEffect: 'None'
  },
  'CAECTD-R019': {
    ruleId: 'CAECTD-R019',
    ruleName: 'Under-investigation VEX',
    failureClass: 'Class C',
    defaultDecisionEffect: 'REVIEW_REQUIRED',
    evidenceDependencies: ['vexApplicabilityDecision'],
    reasonCodes: ['PROPOSED'],
    reasonCodeStatus: 'PROPOSED',
    exceptionAllowed: true,
    lifecycleEffect: 'Blocked'
  },
  'CAECTD-R024': {
    ruleId: 'CAECTD-R024',
    ruleName: 'Missing declared context',
    failureClass: 'Class C',
    defaultDecisionEffect: 'REVIEW_REQUIRED',
    evidenceDependencies: ['contextualPolicyDecision'],
    reasonCodes: ['CTX-005'],
    reasonCodeStatus: 'PROPOSED',
    exceptionAllowed: true,
    lifecycleEffect: 'Blocked'
  },
  'CAECTD-R031': {
    ruleId: 'CAECTD-R031',
    ruleName: 'All mandatory controls pass',
    failureClass: 'None',
    defaultDecisionEffect: 'TRUSTED',
    evidenceDependencies: ['conditionallyAccepted', 'contextualPolicyDecision', 'vexApplicabilityDecision', 'provenanceDecision', 'signatureDecision'],
    reasonCodes: ['GOV-001'],
    reasonCodeStatus: 'EXISTING_AND_IMPLEMENTED',
    exceptionAllowed: true,
    lifecycleEffect: 'Approval Eligible'
  }
};

function getRuleById(ruleId) {
  return CAECTD_RULES[ruleId] || null;
}

module.exports = {
  CAECTD_RULES,
  getRuleById
};
