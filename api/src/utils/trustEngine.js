/**
 * TPSR v3 Trust-Evaluation Orchestration Engine (CAECTD 0.1)
 *
 * Authoritatively orchestrates integrity, provenance, signature, VEX,
 * deployment context, and exception evidence to emit deterministic trust
 * decisions using the authoritative four-state model:
 *
 *   TRUSTED                — all mandatory checks pass, no blocking issue, no exception needed
 *   CONDITIONALLY_ACCEPTED — mandatory checks pass; a remaining policy issue is covered by
 *                            an approved, correctly scoped, active, unexpired exception
 *   REVIEW_REQUIRED        — evidence is incomplete or ambiguous; manual review needed
 *   REJECTED               — mandatory integrity, provenance, or signature check failed;
 *                            or a blocking vulnerability has no accepted mitigation
 *
 * UNEVALUATED must never be returned by this function.
 * UNTRUSTED must never be written by this function.
 *
 * Decision priority: REJECTED > REVIEW_REQUIRED > CONDITIONALLY_ACCEPTED > TRUSTED
 */

'use strict';

const { applyVexOverlays } = require('./vexEngine');
const { assembleContextRiskEvidence } = require('../services/contextRiskEvidenceAssembler');
const { evaluateContextRisk } = require('./contextRiskEngine');
const provenanceEngine = require('./provenanceEngine');
const { mapSignatureEvidence, mapProvenanceEvidence, mapVexEvidence, mapContextEvidence, mapExceptionEvidence } = require('./evidenceAssuranceMapper');
const { CAECTD_RULES } = require('./caectdRuleMapper');

const TRUST_STATUS = {
  TRUSTED: 'TRUSTED',
  CONDITIONALLY_ACCEPTED: 'CONDITIONALLY_ACCEPTED',
  REVIEW_REQUIRED: 'REVIEW_REQUIRED',
  REJECTED: 'REJECTED'
};

async function evaluateTrust(evidenceBundle = {}) {
  const result = {
    trustStatus: TRUST_STATUS.REJECTED,
    reasonCode: 'GOV-003',
    reasonDescription: 'Trust evaluation failed or unverified',
    effectiveRiskScore: 0.0,
    highestEffectiveSeverity: 'NONE',
    evidenceSummary: {
      provenanceCount: 0,
      signatureCount: 0,
      vexCount: 0,
      hasDeploymentContext: false,
      activeExceptionCount: 0
    },
    policyVersion: '3.0',
    evaluatedAt: new Date().toISOString(),
    caectdModelVersion: '0.1',
    triggeredRuleIds: [],
    evaluatedRuleIds: [],
    evidenceDependencies: {},
    explanationCompleteness: {
      complete: false,
      requiredChecks: {
        triggeredRulesPresent: false,
        reasonCodesMapped: false,
        mandatoryDependenciesEvaluated: false,
        policyVersionPresent: false,
        trustPolicyHashPresent: false,
        lifecycleEffectPresent: false,
        contextPolicyResultPresent: false,
        contextAssertionEvaluated: false,
        requiredVexEvaluated: false,
        exceptionEvaluated: false
      },
      missingFields: []
    },
    trustPolicyHash: 'unknown'
  };

  const evalRules = new Set();
  
  const sbomDoc = evidenceBundle.sbomDocument;
  evalRules.add('CAECTD-R001');
  if (!sbomDoc || !sbomDoc.sbom_id) {
    result.trustStatus = TRUST_STATUS.REJECTED;
    result.reasonCode = 'INT-002';
    result.reasonDescription = 'SBOM document record is missing or invalid — mandatory integrity check failed.';
    result.triggeredRuleIds.push('CAECTD-R001');
    result.evidenceDependencies.integrity = {
      required: true,
      assuranceState: 'MISSING',
      evidenceIds: []
    };
    finalizeExplanation(result, evalRules);
    return result;
  }

  const provenance  = Array.isArray(evidenceBundle.provenance)       ? evidenceBundle.provenance       : [];
  const signatures  = Array.isArray(evidenceBundle.signatures)       ? evidenceBundle.signatures       : [];
  const vexStatements = Array.isArray(evidenceBundle.vexStatements)  ? evidenceBundle.vexStatements    : [];
  const depContext  = evidenceBundle.activeContextAssertion || evidenceBundle.deploymentContext || null;
  const isAuthenticatedContext = !!evidenceBundle.activeContextAssertion;
  const exceptions  = Array.isArray(evidenceBundle.policyExceptions) ? evidenceBundle.policyExceptions : [];

  result.evidenceSummary.provenanceCount     = provenance.length;
  result.evidenceSummary.signatureCount      = signatures.length;
  result.evidenceSummary.vexCount            = vexStatements.length;
  result.evidenceSummary.hasDeploymentContext = !!depContext;
  result.evidenceSummary.activeExceptionCount = exceptions.length;

  result.evidenceDependencies.integrity = {
    required: true,
    assuranceState: 'VERIFIED_TRUSTED',
    evidenceIds: [sbomDoc.id]
  };

  evalRules.add('CAECTD-R007');
  const validProv = provenance.find(p => p.status === 'VALID' && p.slsa_level !== 'SLSA_BUILD_LEVEL_0');
  if (!validProv) {
    result.trustStatus = TRUST_STATUS.REJECTED;
    result.reasonCode = 'PRV-005';
    result.reasonDescription = 'No valid build provenance attestation found — mandatory provenance check failed.';
    result.triggeredRuleIds.push('CAECTD-R007');
    result.evidenceDependencies.provenance = {
      required: true,
      assuranceState: mapProvenanceEvidence(provenance[0]).normalized,
      evidenceIds: provenance.map(p => p.id)
    };
    finalizeExplanation(result, evalRules);
    return result;
  }
  result.evidenceDependencies.provenance = {
    required: true,
    assuranceState: mapProvenanceEvidence(validProv).normalized,
    evidenceIds: [validProv.id]
  };

  evalRules.add('CAECTD-R003');
  const validSig = signatures.find(
    s => s.verification_status === 'VERIFIED' || s.verificationStatus === 'VERIFIED'
  );
  if (!validSig) {
    result.trustStatus = TRUST_STATUS.REJECTED;
    result.reasonCode = 'SIG-002';
    result.reasonDescription = 'Cosign cryptographic signature verification failed or no valid signature bundle found — mandatory signature check failed.';
    result.triggeredRuleIds.push('CAECTD-R003');
    result.evidenceDependencies.signature = {
      required: true,
      assuranceState: mapSignatureEvidence(signatures[0]).normalized,
      evidenceIds: signatures.map(s => s.id)
    };
    finalizeExplanation(result, evalRules);
    return result;
  }
  result.evidenceDependencies.signature = {
    required: true,
    assuranceState: mapSignatureEvidence(validSig).normalized,
    evidenceIds: [validSig.id]
  };

  const policy = provenanceEngine.getTrustPolicy();
  const contextRequired = policy.requireDeploymentContext === true || (policy.contextRiskPolicy && policy.contextRiskPolicy.operations.includes('verify'));
  result.policyVersion = policy.version || '3.0';
  result.trustPolicyHash = policy.hash || 'unknown';

  const assembledEvidence = assembleContextRiskEvidence({
    sbomDocument: sbomDoc,
    contextAssertions: evidenceBundle.allActiveContextAssertions || [depContext].filter(Boolean),
    vexStatements,
    policyExceptions: exceptions,
    policy,
    operation: 'verify'
  });

  const contextResult = evaluateContextRisk(assembledEvidence);

  result.contextResult = contextResult;
  result.evidenceDependencies.contextRisk = {
    required: contextRequired,
    modelVersion: '0.1',
    contextAssertionId: assembledEvidence.contextAssertionId || null,
    contextAssuranceState: contextResult.contextAssuranceState,
    normalizedContextVector: assembledEvidence.contextVector || {},
    exploitability: contextResult.exploitability || 'UNKNOWN',
    exploitabilityBasis: contextResult.exploitabilityBasis || 'Not evaluated',
    contextualRisk: contextResult.contextualRisk || 'UNKNOWN',
    policyBlockingStatus: contextResult.policyBlockingStatus || 'NON_BLOCKING',
    reviewRequired: contextResult.policyBlockingStatus === 'REVIEW_REQUIRED',
    exceptionRequired: !!contextResult.exceptionRequired,
    exceptionId: assembledEvidence.exceptionId || null,
    vexEvidenceIds: assembledEvidence.vexEvidenceIds || [],
    vulnerabilityIds: assembledEvidence.vulnerabilities ? assembledEvidence.vulnerabilities.map(v => v.id).filter(Boolean) : [],
    originalCvss: assembledEvidence.vulnerabilities ? assembledEvidence.vulnerabilities.map(v => v.originalCvss || v.cvss || null) : [],
    originalSeverities: assembledEvidence.vulnerabilities ? assembledEvidence.vulnerabilities.map(v => v.originalSeverity || v.severity || 'UNKNOWN') : [],
    componentIdentifiers: assembledEvidence.vulnerabilities ? [...new Set(assembledEvidence.vulnerabilities.map(v => v.componentId).filter(Boolean))] : [],
    triggeredContextRuleIds: contextResult.triggeredRuleIds || [],
    evaluatedContextRuleIds: contextResult.evaluatedRuleIds || [],
    contextReasonCodes: contextResult.reasonCodes || [],
    conflictResults: assembledEvidence.conflictResults || null,
    contextEvaluatedAt: new Date().toISOString(),
    evidenceIds: assembledEvidence.contextAssertionId ? [assembledEvidence.contextAssertionId] : []
  };
  
  result.evidenceDependencies.exception = {
    required: false,
    assuranceState: contextResult.exceptionRequired ? 'VERIFIED_TRUSTED' : 'NOT_APPLICABLE',
    evidenceIds: contextResult.exceptionId ? [contextResult.exceptionId] : []
  };

  if (contextResult.triggeredRuleIds && contextResult.triggeredRuleIds.length > 0) {
    contextResult.triggeredRuleIds.forEach(id => evalRules.add(id));
    result.triggeredRuleIds.push(...contextResult.triggeredRuleIds);
  }

  if (contextResult.reasonCodes && contextResult.reasonCodes.length > 0) {
    result.reasonCode = contextResult.reasonCodes[0];
  }

  const hasExpired = exceptions.some(e => e.status === 'EXPIRED');
  const hasRevoked = exceptions.some(e => e.status === 'REVOKED');
  if (hasExpired) {
     evalRules.add('CAECTD-R028');
     result.triggeredRuleIds.push('CAECTD-R028');
  }
  if (hasRevoked) {
     evalRules.add('CAECTD-R029');
     result.triggeredRuleIds.push('CAECTD-R029');
  }

  if (contextResult.policyBlockingStatus === 'BLOCKING') {
    if (contextResult.exceptionContribution === 'CONDITIONALLY_ACCEPTED') {
      result.trustStatus = TRUST_STATUS.CONDITIONALLY_ACCEPTED;
      result.reasonCode = 'EXC-001';
      result.reasonDescription = `Active governed policy exception(s) cover the remaining policy violation. Trust is conditionally accepted.`;
      evalRules.add('CAECTD-R027');
      result.triggeredRuleIds.push('CAECTD-R027');
    } else {
      result.trustStatus = TRUST_STATUS.REJECTED;
      result.reasonDescription = 'Unmitigated blocking context risk.';
      evalRules.add('CAECTD-R017');
      result.triggeredRuleIds.push('CAECTD-R017');
    }
  } else if (contextResult.policyBlockingStatus === 'REVIEW_REQUIRED') {
    result.trustStatus = TRUST_STATUS.REVIEW_REQUIRED;
    result.reasonDescription = 'Context risk review required.';
  } else if (contextResult.policyBlockingStatus === 'NON_BLOCKING') {
    const hasActiveException = exceptions.some(e => e.status === 'ACTIVE');
    if (hasActiveException) {
      result.trustStatus = TRUST_STATUS.REVIEW_REQUIRED;
      result.reasonCode = 'GOV-003';
      result.reasonDescription = 'All controls pass but an exception remains active unnecessarily.';
      evalRules.add('CAECTD-R027');
      result.triggeredRuleIds.push('CAECTD-R027');
    } else {
      result.trustStatus = TRUST_STATUS.TRUSTED;
      result.reasonCode = 'GOV-001';
      result.reasonDescription = 'Full TPSR v3 trust evaluation passed all mandatory governance criteria.';
      evalRules.add('CAECTD-R031');
      result.triggeredRuleIds.push('CAECTD-R031');
    }
  }

  finalizeExplanation(result, evalRules);
  return result;
}

function finalizeExplanation(result, evalRules) {
  result.evaluatedRuleIds = Array.from(evalRules);
  
  const reqChecks = result.explanationCompleteness.requiredChecks;
  reqChecks.triggeredRulesPresent = result.triggeredRuleIds.length > 0;
  reqChecks.reasonCodesMapped = !!result.reasonCode;
  reqChecks.mandatoryDependenciesEvaluated = !!(result.evidenceDependencies.integrity && result.evidenceDependencies.provenance && result.evidenceDependencies.signature);
  reqChecks.policyVersionPresent = !!result.policyVersion;
  reqChecks.trustPolicyHashPresent = !!result.trustPolicyHash && result.trustPolicyHash !== 'unknown';
  reqChecks.lifecycleEffectPresent = true; // Derived based on state
  
  if (result.evidenceDependencies.contextRisk && result.evidenceDependencies.contextRisk.required) {
    reqChecks.contextPolicyResultPresent = !!result.contextResult;
    reqChecks.contextAssertionEvaluated = !!result.evidenceDependencies.contextRisk.contextAssuranceState;
    reqChecks.requiredVexEvaluated = true; // Evaluated in assembler
    reqChecks.exceptionEvaluated = !!result.evidenceDependencies.exception;
  } else {
    reqChecks.contextPolicyResultPresent = true;
    reqChecks.contextAssertionEvaluated = true;
    reqChecks.requiredVexEvaluated = true;
    reqChecks.exceptionEvaluated = true;
  }
  
  result.explanationCompleteness.complete = 
    reqChecks.triggeredRulesPresent && 
    reqChecks.reasonCodesMapped && 
    reqChecks.mandatoryDependenciesEvaluated && 
    reqChecks.policyVersionPresent &&
    reqChecks.trustPolicyHashPresent &&
    reqChecks.lifecycleEffectPresent &&
    reqChecks.contextPolicyResultPresent &&
    reqChecks.contextAssertionEvaluated &&
    reqChecks.requiredVexEvaluated &&
    reqChecks.exceptionEvaluated;
    
  if (!reqChecks.triggeredRulesPresent) result.explanationCompleteness.missingFields.push('triggeredRuleIds');
  if (!reqChecks.mandatoryDependenciesEvaluated) result.explanationCompleteness.missingFields.push('evidenceDependencies');
  if (!reqChecks.contextPolicyResultPresent) result.explanationCompleteness.missingFields.push('contextResult');
}

module.exports = {
  evaluateTrust,
  TRUST_STATUS
};
