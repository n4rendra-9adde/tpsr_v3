const fs = require('fs');
const path = require('path');

const VALID_TIERS = ['PROD_CRITICAL', 'PROD', 'STAGING', 'DEV', 'LAB'];
const VALID_CLASSIFICATIONS = ['RESTRICTED', 'CONFIDENTIAL', 'INTERNAL', 'PUBLIC'];

function evaluateDeploymentContext(context, originalVulnerability = {}, vexResult = {}) {
  const result = {
    compliant: false,
    deploymentTier: (context?.deploymentTier || 'PROD').toUpperCase(),
    internetExposed: !!context?.internetExposed,
    dataClassification: (context?.dataClassification || 'INTERNAL').toUpperCase(),
    originalCvss: Number(originalVulnerability.cvssScore || originalVulnerability.cvss || 0),
    originalSeverity: (originalVulnerability.severity || 'UNKNOWN').toUpperCase(),
    applicabilityDisposition: vexResult.applicabilityDisposition || 'APPLICABLE',
    policyBlockingStatus: 'BLOCKING',
    reasonCode: 'CTX-004',
    reasonCodes: [],
    evaluatedAt: new Date().toISOString()
  };

  if (!context || typeof context !== 'object') {
    result.reasonCode = 'CTX-003';
    result.reasonCodes.push('CTX-003');
    result.reasonDescription = 'Missing or invalid deployment context payload';
    return result;
  }

  if (!VALID_TIERS.includes(result.deploymentTier)) {
    result.reasonCode = 'CTX-003';
    result.reasonCodes.push('CTX-003');
    result.reasonDescription = `Unsupported deployment tier: ${context.deploymentTier}`;
    return result;
  }

  // If VEX makes it non-blocking, then it's NON_BLOCKING in context too
  if (vexResult.policyBlockingStatus === 'NON_BLOCKING') {
    result.compliant = true;
    result.policyBlockingStatus = 'NON_BLOCKING';
    result.reasonCode = 'CTX-004'; // Verified applicability evidence makes finding non-blocking
    result.reasonCodes.push('CTX-004');
    result.reasonDescription = 'Verified applicability evidence makes finding non-blocking';
    return result;
  }

  if (vexResult.policyBlockingStatus === 'REVIEW_REQUIRED') {
    result.compliant = false;
    result.policyBlockingStatus = 'REVIEW_REQUIRED';
    result.reasonCode = 'CTX-005';
    result.reasonCodes.push('CTX-005');
    result.reasonDescription = 'Applicability evidence requires review';
    return result;
  }

  // Evaluate against original severity since it's APPLICABLE/BLOCKING
  const highestSeverity = result.originalSeverity;

  // Rule 1: PROD_CRITICAL zero-tolerance for unmitigated CRITICAL vulnerabilities
  if (result.deploymentTier === 'PROD_CRITICAL' && highestSeverity === 'CRITICAL') {
    result.compliant = false;
    result.policyBlockingStatus = 'BLOCKING';
    result.reasonCode = 'CTX-001';
    result.reasonCodes.push('CTX-001');
    result.reasonDescription = 'Deployment context policy violation - unmitigated CRITICAL vulnerability in PROD_CRITICAL tier';
    return result;
  }

  // Rule 2: Internet Exposed assets cannot have unmitigated HIGH or CRITICAL vulnerabilities
  if (result.internetExposed && (highestSeverity === 'CRITICAL' || highestSeverity === 'HIGH')) {
    result.compliant = false;
    result.policyBlockingStatus = 'BLOCKING';
    result.reasonCode = 'CTX-001';
    result.reasonCodes.push('CTX-001');
    result.reasonDescription = `Deployment context violation - internet exposed asset has unmitigated ${highestSeverity} vulnerability`;
    return result;
  }

  // Rule 4: STAGING/DEV/LAB or passed rules
  result.compliant = true;
  result.policyBlockingStatus = 'NON_BLOCKING';
  result.reasonCode = 'CTX-000';
  result.reasonCodes.push('CTX-000');
  result.reasonDescription = `Deployment context policy check passed for tier: ${result.deploymentTier}`;
  return result;
}

module.exports = {
  evaluateDeploymentContext,
  VALID_TIERS,
  VALID_CLASSIFICATIONS
};
