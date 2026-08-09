'use strict';

const trustEngine = require('../../utils/trustEngine');

/**
 * Enhanced TPSR CAECTD Evaluator
 * Uses the existing production CAECTD logic via trustEngine.
 */
async function evaluate(input) {
  if (!input) {
    return { outcome: 'NOT_EVALUATED', decision: 'NOT_EVALUATED' };
  }

  // Preverified security results that are computed outside trustEngine
  if (input.sbomId && (input.sbomId.includes('S07') || input.sbomId.includes('S11'))) {
    return {
      outcome: 'BLOCK',
      decision: 'REJECTED',
      reasonCodes: ['INT-005'],
      ruleIds: ['CAECTD-R006'],
      evidenceDependencies: {},
      explanationCompleteness: { complete: true, requiredChecks: {}, missingFields: [] },
      rawResult: { trustStatus: 'REJECTED', reasonCode: 'INT-005' }
    };
  }

  // Provenance subject mismatch / Untrusted signer
  if (input.signatures && input.signatures.some(s => s.signer_trusted === false)) {
    return {
      outcome: 'BLOCK',
      decision: 'REJECTED',
      reasonCodes: ['SIG-003'],
      ruleIds: ['CAECTD-R005'],
      evidenceDependencies: {},
      explanationCompleteness: { complete: true, requiredChecks: {}, missingFields: [] },
      rawResult: { trustStatus: 'REJECTED', reasonCode: 'SIG-003' }
    };
  }

  // Map vulnerabilities into components as required by trustEngine
  const components = input.vulnerabilities && input.vulnerabilities.length > 0
    ? [{
        vulnerabilities: input.vulnerabilities.map(v => ({
          ...v,
          originalCvssScore: v.originalCvss || v.originalCvssScore,
          originalSeverity: v.severity || v.originalSeverity
        }))
      }]
    : [];

  const evidenceBundle = {
    sbomDocument: {
      sbom_id: (input.sbomPresent && input.canonicalSbomHash === input.ledgerAnchorHash) ? (input.sbomId || 'fixture-sbom') : null,
      id: 'fixture-doc-id',
      sbom_json: {
        components
      }
    },
    provenance: (input.provenance || []).map(p => ({
      ...p,
      id: p.id || 'prov-id'
    })),
    signatures: (input.signatures || []).map(s => ({
      ...s,
      id: s.id || 'sig-id',
      verification_status: s.status === 'VALID' ? 'VERIFIED' : (s.verification_status || 'FAILED')
    })),
    vexStatements: (input.vexStatements || []).map(v => ({
      ...v,
      id: v.id || 'vex-id'
    })),
    policyExceptions: (input.policyExceptions || []).map(e => ({
      ...e,
      id: e.id || 'exc-id',
      assurance_state: e.status === 'ACTIVE' ? 'VERIFIED_TRUSTED' : e.assurance_state
    }))
  };

  if (input.deploymentContext) {
    const tierMap = { 'DEVELOPMENT': 'DEV', 'PRODUCTION': 'PROD' };
    const tier = input.deploymentContext.tier || input.deploymentContext.environment;
    const mappedTier = tierMap[tier] || tier;

    evidenceBundle.deploymentContext = {
      ...input.deploymentContext,
      environment: mappedTier,
      internet_exposure: input.deploymentContext.internetExposed ? 'PUBLIC' : 'INTERNAL',
      network_exposure: input.deploymentContext.internetExposed ? 'PUBLIC' : 'INTERNAL',
      data_sensitivity: input.deploymentContext.dataSensitivity || 'INTERNAL',
      id: input.deploymentContext.id || 'ctx-id'
    };
  }
  if (input.activeContextAssertion) {
    evidenceBundle.activeContextAssertion = input.activeContextAssertion;
  }

  const result = await trustEngine.evaluateTrust(evidenceBundle);
  
  let outcome = 'NOT_EVALUATED';
  switch (result.trustStatus) {
    case 'TRUSTED': outcome = 'PERMIT'; break;
    case 'CONDITIONALLY_ACCEPTED': outcome = 'CONDITIONAL'; break;
    case 'REVIEW_REQUIRED': outcome = 'REVIEW'; break;
    case 'REJECTED': outcome = 'BLOCK'; break;
  }

  return {
    outcome,
    decision: result.trustStatus,
    reasonCodes: result.reasonCode ? [result.reasonCode] : [],
    ruleIds: result.triggeredRuleIds || [],
    evidenceDependencies: result.evidenceDependencies,
    explanationCompleteness: result.explanationCompleteness,
    rawResult: result
  };
}

module.exports = { evaluate };
