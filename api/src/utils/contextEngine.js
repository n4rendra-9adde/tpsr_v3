/**
 * TPSR v3 Deployment Context Policy Evaluation Engine
 * Implements context-aware policy evaluation mapping deployment tier and exposure to reason codes.
 */

const VALID_TIERS = ['PROD_CRITICAL', 'PROD', 'STAGING', 'DEV', 'LAB'];
const VALID_CLASSIFICATIONS = ['RESTRICTED', 'CONFIDENTIAL', 'INTERNAL', 'PUBLIC'];

/**
 * Evaluates deployment context against vulnerability overlays and trust evidence
 * @param {Object} context - Deployment context parameters
 * @param {string} context.deploymentTier - Deployment tier (e.g. PROD_CRITICAL)
 * @param {boolean} [context.internetExposed=false] - Whether asset is internet accessible
 * @param {string} [context.dataClassification='INTERNAL'] - Sensitivity of data processed
 * @param {string} [context.runtimeEnvironment] - e.g. KUBERNETES_PROD
 * @param {Object} [vexSummary] - Summary from applyVexOverlays containing highestEffectiveSeverity and effectiveRiskScore
 * @param {Object} [provenanceSummary] - Verified provenance result
 * @returns {Object} Context evaluation result with compliant status, reasonCode, and reasonDescription
 */
function evaluateDeploymentContext(context, vexSummary = {}, provenanceSummary = {}) {
  const result = {
    compliant: false,
    deploymentTier: (context?.deploymentTier || 'PROD').toUpperCase(),
    internetExposed: !!context?.internetExposed,
    dataClassification: (context?.dataClassification || 'INTERNAL').toUpperCase(),
    reasonCode: 'CTX-004',
    reasonDescription: 'Deployment context evaluation unverified or failed',
    evaluatedAt: new Date().toISOString()
  };

  if (!context || typeof context !== 'object') {
    result.reasonCode = 'CTX-004';
    result.reasonDescription = 'Missing or invalid deployment context payload';
    return result;
  }

  if (!VALID_TIERS.includes(result.deploymentTier)) {
    result.reasonCode = 'CTX-004';
    result.reasonDescription = `Unsupported deployment tier: ${context.deploymentTier}`;
    return result;
  }

  const highestSeverity = (vexSummary.highestEffectiveSeverity || 'NONE').toUpperCase();
  const effectiveRisk = Number(vexSummary.effectiveRiskScore || 0);

  // Rule 1: PROD_CRITICAL zero-tolerance for unmitigated CRITICAL vulnerabilities
  if (result.deploymentTier === 'PROD_CRITICAL') {
    if (highestSeverity === 'CRITICAL') {
      result.compliant = false;
      result.reasonCode = 'CTX-002';
      result.reasonDescription = 'Deployment context policy violation - unmitigated CRITICAL vulnerability in PROD_CRITICAL tier';
      return result;
    }
    // PROD_CRITICAL also requires verified SLSA Level 3 provenance if provenance summary provided
    if (provenanceSummary && provenanceSummary.status && provenanceSummary.slsaLevel !== 'SLSA_BUILD_LEVEL_3') {
      result.compliant = false;
      result.reasonCode = 'CTX-002';
      result.reasonDescription = `PROD_CRITICAL tier requires SLSA_BUILD_LEVEL_3 provenance, got: ${provenanceSummary.slsaLevel || 'NONE'}`;
      return result;
    }
  }

  // Rule 2: Internet Exposed assets cannot have unmitigated HIGH or CRITICAL vulnerabilities
  if (result.internetExposed) {
    if (highestSeverity === 'CRITICAL' || highestSeverity === 'HIGH') {
      result.compliant = false;
      result.reasonCode = 'CTX-003';
      result.reasonDescription = `Deployment context violation - internet exposed asset has unmitigated ${highestSeverity} vulnerability`;
      return result;
    }
  }

  // Rule 3: PROD tier cannot have effective risk score > 7.0 without formal exception
  if (result.deploymentTier === 'PROD' && effectiveRisk > 7.0) {
    result.compliant = false;
    result.reasonCode = 'CTX-002';
    result.reasonDescription = `Deployment context violation - effective risk score (${effectiveRisk}) exceeds PROD threshold (7.0)`;
    return result;
  }

  // Rule 4: STAGING/DEV/LAB allow higher thresholds, check passed
  result.compliant = true;
  result.reasonCode = 'CTX-001';
  result.reasonDescription = `Deployment context policy check passed for tier: ${result.deploymentTier}`;
  return result;
}

module.exports = {
  evaluateDeploymentContext,
  VALID_TIERS,
  VALID_CLASSIFICATIONS
};
