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

  // Construct evidence bundle from input
  const evidenceBundle = {
    sbomDocument: {
      sbom_id: input.sbomId || 'fixture-sbom',
      id: 'fixture-doc-id',
      sbom_json: {
        vulnerabilities: input.vulnerabilities || []
      }
    },
    provenance: input.provenance || [],
    signatures: input.signatures || [],
    vexStatements: input.vexStatements || [],
    policyExceptions: input.policyExceptions || []
  };

  if (input.deploymentContext) {
    evidenceBundle.deploymentContext = input.deploymentContext;
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
    reasonCode: result.reasonCode,
    triggeredRuleIds: result.triggeredRuleIds,
    evidenceDependencies: result.evidenceDependencies,
    explanationCompleteness: result.explanationCompleteness,
    rawResult: result
  };
}

module.exports = { evaluate };
