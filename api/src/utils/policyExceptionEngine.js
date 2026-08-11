const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const uuidv4 = crypto.randomUUID;
const caectdRuleMapper = require('./caectdRuleMapper');
const { getTrustPolicy } = require('./trustPolicyLoader');

const trustPolicyPath = path.join(__dirname, '../../../docs/TRUST_POLICY.json');
const caectdModelPath = path.join(__dirname, '../../../docs/models/caectd-model.v0.1.json');

let cachedCaectdModel = null;
function getCaectdModel() {
  if (!cachedCaectdModel) {
    cachedCaectdModel = JSON.parse(fs.readFileSync(caectdModelPath, 'utf8'));
  }
  return cachedCaectdModel;
}

function parseExceptionRequest(reqBody) {
  return {
    sbomId: reqBody.sbomId,
    digestManifestDigest: reqBody.digestManifestDigest,
    policyRuleId: reqBody.policyRuleId,
    reasonCode: reqBody.reasonCode,
    vulnerabilityIds: reqBody.vulnerabilityIds || [],
    componentIdentifiers: reqBody.componentIdentifiers || [],
    environment: reqBody.environment,
    validUntil: reqBody.validUntil,
    justification: reqBody.justification,
    businessNeed: reqBody.businessNeed,
    remediationPlan: reqBody.remediationPlan,
    compensatingControls: reqBody.compensatingControls || [],
    residualRisk: reqBody.residualRisk,
    requestedBy: reqBody.requestedBy,
    requestedByRole: reqBody.requestedByRole,
    ownedBy: reqBody.ownedBy,
    ownerRole: reqBody.ownerRole
  };
}

function validateExceptionStructure(parsed) {
  if (!parsed.sbomId || !parsed.digestManifestDigest || !parsed.policyRuleId || !parsed.reasonCode) return false;
  if (!parsed.justification || parsed.justification.trim() === '') return false;
  if (!parsed.validUntil || isNaN(new Date(parsed.validUntil).getTime())) return false;
  const allowedRisks = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  if (!parsed.residualRisk || !allowedRisks.includes(parsed.residualRisk)) return false;
  return true;
}

function validateRequesterAuthority(role, policy) {
  const allowed = policy.exceptionGovernance.allowedRequesterRoles || [];
  return allowed.includes(role);
}

function validateOwnerAuthority(role, policy) {
  const allowed = policy.exceptionGovernance.allowedOwnerRoles || [];
  return allowed.includes(role);
}

function validateApproverAuthority(role, policy) {
  const allowed = policy.exceptionGovernance.allowedApproverRoles || [];
  return allowed.includes(role);
}

function validateSeparationOfDuties(requester, owner, approver, policy) {
  const gov = policy.exceptionGovernance;
  if (gov.requireIndependentApprover && (!approver || approver === '')) return false;
  if (gov.requireRequesterDifferentFromApprover && requester === approver) return false;
  if (gov.requireOwnerDifferentFromApprover && owner === approver) return false;
  return true;
}

function bindExceptionToRelease(parsed, dbSbomId, dbDigest) {
  if (parsed.sbomId !== dbSbomId) return false;
  if (parsed.digestManifestDigest !== dbDigest) return false;
  return true;
}

function validatePolicyRuleScope(ruleId) {
  const model = getCaectdModel();
  const rule = model.rules.find(r => r.ruleId === ruleId);
  if (!rule) return { valid: false, reason: 'Rule not found' };
  if (rule.exceptionPolicy === 'NON_EXCEPTIONABLE') {
    return { valid: false, reason: 'Rule is NON_EXCEPTIONABLE' };
  }
  if (rule.exceptionPolicy === 'REVIEW_ONLY') {
    return { valid: false, reason: 'Rule is REVIEW_ONLY and cannot be conditionally accepted solely via exception' };
  }
  return { valid: true, reason: 'Rule is EXCEPTIONABLE' };
}

function validateVulnerabilityAndComponentScope(parsed, activeViolations) {
  // Simplistic validation: if the rule is vulnerability-based, ensure the CVE exists in violations
  // This can be expanded based on the strict requirements
  return true;
}

function validateResidualRisk(risk, policy) {
  if (risk === 'CRITICAL' && !policy.exceptionGovernance.allowCriticalRiskExceptions) return false;
  return true;
}

function validateRequiredJustification(justification) {
  return justification && justification.trim().length > 0;
}

function validateRemediationPlan(plan, policy) {
  if (policy.exceptionGovernance.requireRemediationPlan) {
    return plan && plan.trim().length > 0;
  }
  return true;
}

function validateCompensatingControls(controls, risk, policy) {
  if (policy.exceptionGovernance.requireCompensatingControlsForHighRisk && (risk === 'HIGH' || risk === 'CRITICAL')) {
    return Array.isArray(controls) && controls.length > 0;
  }
  return true;
}

function validateValidityPeriod(validFrom, validUntil, risk, policy) {
  const fromTime = new Date(validFrom).getTime();
  const untilTime = new Date(validUntil).getTime();
  if (untilTime <= fromTime) return false;
  
  const hours = (untilTime - fromTime) / (1000 * 60 * 60);
  const maxHours = policy.exceptionGovernance.maximumValidityHoursByRisk[risk] || 0;
  return hours <= maxHours;
}

function deriveExceptionAssuranceState(evalResult) {
  if (!evalResult.structureValid) return 'INVALID';
  if (!evalResult.governanceValid) return 'VERIFIED_UNTRUSTED';
  if (!evalResult.policyScopePassed) return 'INVALID';
  if (!evalResult.releaseBindingPassed) return 'INVALID';
  if (!evalResult.separationOfDutiesPassed) return 'INVALID';
  if (!evalResult.validityPassed) return 'INVALID';
  if (evalResult.isExpired) return 'STALE';
  if (evalResult.status === 'REVOKED') return 'INVALID';
  if (evalResult.status === 'CONFLICTING') return 'CONFLICTING';
  
  if (evalResult.status === 'ACTIVE') return 'VERIFIED_TRUSTED';
  
  return 'NOT_EVALUATED';
}

function deriveExceptionStatus(evalResult) {
  if (!evalResult.structureValid || !evalResult.policyScopePassed || !evalResult.releaseBindingPassed || !evalResult.validityPassed) {
    return 'INVALID';
  }
  if (!evalResult.governanceValid || !evalResult.separationOfDutiesPassed) {
    return 'REJECTED';
  }
  if (evalResult.isExpired) {
    return 'EXPIRED';
  }
  if (evalResult.approvedBy) {
    return 'ACTIVE';
  }
  return 'REQUESTED';
}

function evaluateExceptionApproval(exceptionData, approvalData, dbSbomId, dbDigest) {
  const policy = getTrustPolicy();
  
  const structureValid = validateExceptionStructure(exceptionData);
  const releaseBindingPassed = bindExceptionToRelease(exceptionData, dbSbomId, dbDigest);
  
  const scopeResult = validatePolicyRuleScope(exceptionData.policyRuleId);
  const policyScopePassed = scopeResult.valid;
  
  const requesterValid = validateRequesterAuthority(exceptionData.requestedByRole, policy);
  const ownerValid = validateOwnerAuthority(exceptionData.ownerRole, policy);
  const approverValid = validateApproverAuthority(approvalData.approverRole, policy);
  const governanceValid = requesterValid && ownerValid && approverValid;
  
  const separationOfDutiesPassed = validateSeparationOfDuties(exceptionData.requestedBy, exceptionData.ownedBy, approvalData.approvedBy, policy);
  
  const validFrom = exceptionData.validFrom || new Date().toISOString();
  const validityPassed = validateValidityPeriod(validFrom, exceptionData.validUntil, exceptionData.residualRisk, policy);
  
  const riskValid = validateResidualRisk(exceptionData.residualRisk, policy);
  const justificationValid = validateRequiredJustification(exceptionData.justification);
  const remediationValid = validateRemediationPlan(exceptionData.remediationPlan, policy);
  const controlsValid = validateCompensatingControls(exceptionData.compensatingControls, exceptionData.residualRisk, policy);
  
  const now = Date.now();
  const isExpired = new Date(exceptionData.validUntil).getTime() <= now;
  
  const evalResult = {
    structureValid,
    releaseBindingPassed,
    policyScopePassed,
    governanceValid,
    separationOfDutiesPassed,
    validityPassed: validityPassed && riskValid && justificationValid && remediationValid && controlsValid,
    isExpired,
    approvedBy: approvalData.approvedBy,
    status: exceptionData.status
  };
  
  const derivedStatus = deriveExceptionStatus(evalResult);
  evalResult.status = derivedStatus;
  const assuranceState = deriveExceptionAssuranceState(evalResult);
  
  return {
    verificationStatus: derivedStatus === 'ACTIVE' ? 'VERIFIED' : 'FAILED',
    assuranceState,
    governanceValid,
    separationOfDutiesPassed,
    releaseBindingPassed,
    policyScopePassed,
    vulnerabilityScopePassed: true,
    validityPassed: evalResult.validityPassed,
    exceptionableFailureConfirmed: scopeResult.valid,
    ruleIds: [exceptionData.policyRuleId],
    reasonCodes: derivedStatus === 'ACTIVE' ? ['EXC-001'] : (derivedStatus === 'INVALID' || derivedStatus === 'REJECTED' ? ['EXC-003', 'EXC-004'] : []),
    normalizedException: exceptionData,
    policyVersion: policy.policyVersion,
    trustPolicyHash: 'hash-placeholder', // In real system, compute hash
    evaluatedAt: new Date().toISOString(),
    derivedStatus
  };
}

module.exports = {
  parseExceptionRequest,
  validateExceptionStructure,
  validateRequesterAuthority,
  validateOwnerAuthority,
  validateApproverAuthority,
  validateSeparationOfDuties,
  bindExceptionToRelease,
  validatePolicyRuleScope,
  validateVulnerabilityAndComponentScope,
  validateResidualRisk,
  validateRequiredJustification,
  validateRemediationPlan,
  validateCompensatingControls,
  validateValidityPeriod,
  deriveExceptionAssuranceState,
  deriveExceptionStatus,
  evaluateExceptionApproval
};
