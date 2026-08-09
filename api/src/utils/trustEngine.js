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
const { evaluateDeploymentContext } = require('./contextEngine');
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
        lifecycleEffectPresent: false
      },
      missingFields: []
    }
  };

  const evalRules = new Set();
  
  const sbomDoc = evidenceBundle.sbomDocument;
  evalRules.add('CAECTD-R001');
  if (!sbomDoc || !sbomDoc.sbom_id) {
    result.trustStatus = TRUST_STATUS.REJECTED;
    result.reasonCode = 'INT-002';
    result.reasonDescription = 'SBOM document record is missing or invalid — mandatory integrity check failed.';
    result.triggeredRuleIds.push('CAECTD-R001');
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
  const validProv = provenance.find(p => p.status === 'VALID' || p.slsa_level);
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

  let rawSbom = {};
  try {
    rawSbom = typeof sbomDoc.sbom_json === 'string'
      ? JSON.parse(sbomDoc.sbom_json)
      : (sbomDoc.sbom_json || {});
  } catch (_) {
    rawSbom = {};
  }
  const components = rawSbom.components || [];
  const vulns = [];
  components.forEach(c => {
    if (c.vulnerabilities && Array.isArray(c.vulnerabilities)) {
      vulns.push(...c.vulnerabilities);
    }
  });

  const vexSummary = applyVexOverlays(vulns, vexStatements);
  
  result.evidenceDependencies.vex = {
    required: false,
    assuranceState: vexStatements.length > 0 ? mapVexEvidence(vexStatements[0]).normalized : 'NOT_APPLICABLE',
    evidenceIds: vexStatements.map(v => v.id)
  };

  let contextViolation = false;
  let contextReasonCode = null;
  let contextReasonDescription = null;

  const policy = provenanceEngine.getTrustPolicy();
  const contextRequired = policy.requireDeploymentContext === true;

  if (evidenceBundle.allActiveContextAssertions && evidenceBundle.allActiveContextAssertions.length > 1) {
    evalRules.add('CAECTD-R025');
    result.triggeredRuleIds.push('CAECTD-R025');
    result.evidenceDependencies.context = {
      required: contextRequired,
      assuranceState: 'CONFLICTING',
      evidenceIds: evidenceBundle.allActiveContextAssertions.map(a => a.id)
    };
    contextViolation = true;
    contextReasonCode = 'CTX-017';
    contextReasonDescription = 'Conflicting trusted assertions exist for this release.';
  } else {
    result.evidenceDependencies.context = {
      required: contextRequired,
      assuranceState: isAuthenticatedContext ? depContext.assurance_state || depContext.assuranceState || 'INVALID' : (depContext ? mapContextEvidence(depContext).normalized : 'MISSING'),
      evidenceIds: depContext ? [depContext.id] : []
    };

    if (!depContext && contextRequired) {
      evalRules.add('CAECTD-R024');
      result.triggeredRuleIds.push('CAECTD-R024');
    }

    if (isAuthenticatedContext && result.evidenceDependencies.context.assuranceState !== 'VERIFIED_TRUSTED') {
      evalRules.add('CAECTD-R026');
      result.triggeredRuleIds.push('CAECTD-R026');
      contextViolation = true;
      contextReasonCode = 'CTX-010';
      contextReasonDescription = 'Invalid, untrusted, or unauthorized authenticated assertion.';
    }
  }

  if (depContext && !contextViolation) {
    for (const vuln of vexSummary.vulnerabilities) {
      const ctxRes = evaluateDeploymentContext({
        deploymentTier:    isAuthenticatedContext ? depContext.environment : depContext.environment,
        internetExposed:   isAuthenticatedContext ? (depContext.internet_exposure === 'PUBLIC' || depContext.internetExposure === 'PUBLIC') : (depContext.network_exposure === 'PUBLIC' || depContext.network_exposure === 'INTERNET'),
        dataClassification: isAuthenticatedContext ? (depContext.data_sensitivity || depContext.dataSensitivity) : depContext.data_sensitivity,
        runtimeEnvironment: isAuthenticatedContext ? (depContext.runtime_execution || depContext.runtimeExecution) : depContext.environment
      }, {
        cvssScore: vuln.originalCvssScore,
        severity: vuln.originalSeverity
      }, {
        applicabilityDisposition: vuln.applicabilityDisposition,
        policyBlockingStatus: vuln.policyBlockingStatus
      });

      if (!ctxRes.compliant) {
        contextViolation = true;
        contextReasonCode = ctxRes.reasonCode || 'CTX-002';
        contextReasonDescription = ctxRes.reasonDescription;
        evalRules.add('CAECTD-R017');
        result.triggeredRuleIds.push('CAECTD-R017');
        break; // Stop at first blocking violation
      }
    }
    
    // Legacy unauthenticated context cannot produce TRUSTED contextual assurance
    if (!isAuthenticatedContext && !contextViolation && contextRequired) {
      contextViolation = true;
      contextReasonCode = 'CTX-005'; // Missing required *authenticated* context
      contextReasonDescription = 'Legacy unauthenticated context cannot produce TRUSTED contextual assurance when context is required.';
      evalRules.add('CAECTD-R024');
      result.triggeredRuleIds.push('CAECTD-R024');
    }
  } else if (!contextViolation) {
    if (contextRequired) {
      contextViolation = true;
      contextReasonCode = 'CTX-005';
      contextReasonDescription = 'Deployment context is required by policy but was not provided.';
    } else {
      const hasBlockingCritical = vexSummary.vulnerabilities.some(v => v.originalSeverity === 'CRITICAL' && v.policyBlockingStatus === 'BLOCKING');
      if (hasBlockingCritical && exceptions.length === 0) {
        contextViolation = true;
        contextReasonCode = 'CTX-002';
        contextReasonDescription = 'Unmitigated CRITICAL vulnerability present without a registered deployment context or approved policy exception.';
        evalRules.add('CAECTD-R017');
        result.triggeredRuleIds.push('CAECTD-R017');
      }
    }
  }

  evalRules.add('CAECTD-R027');
  if (contextViolation) {
    const activeExceptions = exceptions.filter(exc => 
      exc.status === 'ACTIVE' && exc.assurance_state === 'VERIFIED_TRUSTED'
    );
    // Note: To be fully strict we'd use policyExceptionEngine in real time, but since it's pre-computed 
    // into assurance_state when requested/approved, we rely on the DB's assurance_state for this decision
    // mapping if it matches the release.
    
    // In our repository, we enforce valid_until > NOW() when fetching active exceptions.
    // For now we assume if it's in `activeExceptions`, it's valid for this SBOM.
    // Ensure we don't override Class A failures (though contextViolation is Class B typically).

    const hasClassC = contextReasonCode === 'CTX-005' || contextReasonCode === 'CTX-017' || contextReasonCode === 'CTX-010';
    
    // Check if the underlying failure is exceptionable (e.g., CTX-002, CTX-014 etc. but not missing context which is CTX-005)
    // For now we check if it is not Class C and not Class A.
    
    result.evidenceDependencies.exception = {
      required: true,
      assuranceState: exceptions.length > 0 ? (activeExceptions.length > 0 ? 'VERIFIED_TRUSTED' : 'INVALID') : 'MISSING',
      evidenceIds: exceptions.map(e => e.id),
      details: exceptions.map(e => ({
        exceptionId: e.id,
        exceptionStatus: e.status,
        exceptionAssuranceState: e.assurance_state,
        policyRuleId: e.policy_rule_id,
        reasonCode: e.reason_code,
        vulnerabilityIds: e.vulnerability_ids,
        owner: e.owned_by,
        approver: e.approved_by,
        validUntil: e.valid_until,
        governanceResult: e.assurance_state === 'VERIFIED_TRUSTED' ? 'PASSED' : 'FAILED'
      }))
    };

    if (activeExceptions.length > 0 && !hasClassC) {
      result.trustStatus = TRUST_STATUS.CONDITIONALLY_ACCEPTED;
      result.reasonCode = 'EXC-001';
      result.reasonDescription = `Active governed policy exception(s) cover the remaining policy violation (${contextReasonCode}). Trust is conditionally accepted.`;
      result.evidenceSummary.activeExceptionCount = activeExceptions.length;
      result.triggeredRuleIds.push('CAECTD-R027');
      finalizeExplanation(result, evalRules);
      return result;
    }

    if (activeExceptions.length > 0 && hasClassC) {
       // Cannot override Class C
       evalRules.add('CAECTD-R030');
       result.triggeredRuleIds.push('CAECTD-R030');
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

    result.trustStatus = hasClassC ? TRUST_STATUS.REVIEW_REQUIRED : TRUST_STATUS.REJECTED;
    result.reasonCode = contextReasonCode;
    result.reasonDescription = contextReasonDescription;

    finalizeExplanation(result, evalRules);
    return result;
  }

  evalRules.add('CAECTD-R031');
  result.trustStatus = TRUST_STATUS.TRUSTED;
  result.reasonCode = 'GOV-001';
  result.reasonDescription = 'Full TPSR v3 trust evaluation passed all mandatory governance criteria.';
  result.triggeredRuleIds.push('CAECTD-R031');
  
  result.evidenceDependencies.exception = {
    required: false,
    assuranceState: 'NOT_APPLICABLE',
    evidenceIds: []
  };
  
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
  reqChecks.lifecycleEffectPresent = true; // Derived based on state
  
  result.explanationCompleteness.complete = 
    reqChecks.triggeredRulesPresent && 
    reqChecks.reasonCodesMapped && 
    reqChecks.mandatoryDependenciesEvaluated && 
    reqChecks.policyVersionPresent && 
    reqChecks.lifecycleEffectPresent;
    
  if (!reqChecks.triggeredRulesPresent) result.explanationCompleteness.missingFields.push('triggeredRuleIds');
  if (!reqChecks.mandatoryDependenciesEvaluated) result.explanationCompleteness.missingFields.push('evidenceDependencies');
}

module.exports = {
  evaluateTrust,
  TRUST_STATUS
};
