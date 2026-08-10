const { 
  ENUM_ENVIRONMENT, 
  ENUM_EXPLOITABILITY, 
  ENUM_ASSET_CRITICALITY, 
  ENUM_INTERNET_EXPOSURE, 
  ENUM_PRIVILEGE_LEVEL, 
  ENUM_DATA_SENSITIVITY, 
  ENUM_RUNTIME_EXECUTION, 
  ENUM_COMPONENT_PRESENCE, 
  ENUM_VEX_APPLICABILITY, 
  ENUM_EXCEPTION_STATUS 
} = require('./contextRiskConstants');

function evaluateContextRisk(input) {
  let contextAssuranceState = 'NOT_EVALUATED';
  if (input && !input.missingContext && !input.invalidContext && !input.conflict && input.contextAssertionId) {
    contextAssuranceState = 'VERIFIED_TRUSTED';
  }

  const result = {
    modelId: 'CAECTD_CONTEXT_RISK',
    modelVersion: '0.1',
    normalizedContextVector: {},
    contextAssuranceState: contextAssuranceState,
    exploitability: 'UNKNOWN',
    exploitabilityBasis: 'Default',
    contextualRisk: 'UNKNOWN',
    policyBlockingStatus: 'REVIEW_REQUIRED',
    reviewRequired: true,
    exceptionRequired: false,
    exceptionContribution: 'NONE',
    triggeredRuleIds: [],
    evaluatedRuleIds: [],
    reasonCodes: [],
    evidenceDependencies: [],
    conflictResults: []
  };

  if (!input) return result;

  const originalCvss = input.originalCvss || 0;
  const originalSeverity = input.originalSeverity || 'UNKNOWN';

  result.normalizedContextVector = { ...input.contextVector };

  let highestRisk = 'LOW';
  let isBlocking = false;
  let needsReview = false;
  let exceptionNeeded = false;
  let triggeredRules = new Set();
  let reasonCodes = new Set();
  
  let normalizedVulnerabilities = [];
  if (Array.isArray(input.vulnerabilities)) {
    normalizedVulnerabilities = input.vulnerabilities;
  } else if (Array.isArray(input.vulns)) { // temporary compatibility alias
    normalizedVulnerabilities = input.vulns;
  } else if (input.vulnerability && typeof input.vulnerability === 'object') {
    normalizedVulnerabilities = [input.vulnerability];
  } else if (input.sbomDocument && input.sbomDocument.sbom_json) {
    let sbom = {};
    try {
      sbom = typeof input.sbomDocument.sbom_json === 'string' ? JSON.parse(input.sbomDocument.sbom_json) : input.sbomDocument.sbom_json;
    } catch (_) {}
    if (sbom.components && Array.isArray(sbom.components)) {
      sbom.components.forEach(c => {
        if (c.vulnerabilities && Array.isArray(c.vulnerabilities)) {
          normalizedVulnerabilities.push(...c.vulnerabilities);
        }
      });
    }
  }

  if (normalizedVulnerabilities.length > 0) {
    for (const vuln of normalizedVulnerabilities) {
      let vexStatus = vuln.vexApplicability || 'UNKNOWN';
      let compPres = input.contextVector.componentPresence || 'UNKNOWN';
      let runExec = input.contextVector.runtimeExecution || 'UNKNOWN';

      let expl = 'UNKNOWN';
      let explBasis = 'Default';
      let risk = 'LOW';
      let blockStatus = 'NON_BLOCKING';
      
      if (vexStatus === 'AFFECTED' && (compPres === 'PRESENT' || compPres === 'PARTIAL') && runExec === 'EXECUTED') {
        expl = 'EXPLOITABLE';
        explBasis = 'Trusted AFFECTED VEX with executed component';
      } else if (vexStatus === 'NOT_AFFECTED') {
        if (input.vexTrusted && input.vexCurrent && input.vexExactScope) {
          expl = 'NOT_EXPLOITABLE';
          explBasis = 'Trusted NOT_AFFECTED VEX';
          triggeredRules.add('CAECTD-R016');
        } else {
          explBasis = 'Untrusted or invalid NOT_AFFECTED VEX';
          needsReview = true;
        }
      } else if (vexStatus === 'UNDER_INVESTIGATION') {
        expl = 'UNDER_INVESTIGATION';
        explBasis = 'UNDER_INVESTIGATION VEX';
      } else if (compPres === 'NOT_PRESENT' && input.componentPresenceTrusted) {
        expl = 'NOT_EXPLOITABLE';
        explBasis = 'Verified component NOT_PRESENT';
      } else if (compPres === 'PRESENT' && runExec === 'PRESENT_NOT_EXECUTED') {
        expl = 'UNKNOWN';
        explBasis = 'Component PRESENT_NOT_EXECUTED';
      } else if (compPres === 'PRESENT' && runExec === 'EXECUTED') {
        expl = 'EXPLOITABLE';
        explBasis = 'Component PRESENT and EXECUTED';
      }
      
      let env = input.contextVector.environment;
      let exp = input.contextVector.internetExposure;
      let crit = input.contextVector.assetCriticality;
      let priv = input.contextVector.privilegeLevel;
      let sens = input.contextVector.dataSensitivity;
      
      let sev = vuln.originalSeverity || vuln.severity || 'UNKNOWN';
      if (expl === 'UNDER_INVESTIGATION' || explBasis === 'Component PRESENT_NOT_EXECUTED') {
        blockStatus = 'REVIEW_REQUIRED';
        risk = 'UNKNOWN';
        triggeredRules.add('GOV-003');
        reasonCodes.add('GOV-003');
        if (expl === 'UNDER_INVESTIGATION') {
          triggeredRules.add('CAECTD-R019');
        }
      } else if (env === 'PRODUCTION' && (exp === 'PUBLIC' || exp === 'RESTRICTED_PUBLIC') && expl !== 'NOT_EXPLOITABLE' && sev === 'CRITICAL') {
        risk = 'CRITICAL';
        blockStatus = 'BLOCKING';
        exceptionNeeded = true;
        triggeredRules.add('CR-001');
        reasonCodes.add('CTX-001');
      } else if (env === 'PRODUCTION' && crit === 'CRITICAL' && expl !== 'NOT_EXPLOITABLE') {
        risk = 'HIGH';
        blockStatus = 'BLOCKING';
      } else if (priv === 'SYSTEM' && expl !== 'NOT_EXPLOITABLE') {
        risk = 'HIGH';
        blockStatus = 'BLOCKING';
      } else if (sens === 'RESTRICTED' && expl !== 'NOT_EXPLOITABLE') {
        risk = 'HIGH';
        blockStatus = 'BLOCKING';
      } else if (env === 'DEVELOPMENT' && (exp === 'NONE' || exp === 'INTERNAL') && expl !== 'EXPLOITABLE') {
        risk = 'LOW';
        blockStatus = 'NON_BLOCKING';
      } else if (!env && sev === 'CRITICAL' && expl !== 'NOT_EXPLOITABLE') {
        risk = 'CRITICAL';
        blockStatus = 'BLOCKING';
        exceptionNeeded = true;
        triggeredRules.add('CAECTD-R017');
        reasonCodes.add('CTX-002');
      }

      if (blockStatus === 'BLOCKING') isBlocking = true;
      if (blockStatus === 'REVIEW_REQUIRED') needsReview = true;
      
      result.exploitability = expl;
      result.exploitabilityBasis = explBasis;
      highestRisk = risk === 'CRITICAL' ? 'CRITICAL' : (risk === 'HIGH' && highestRisk !== 'CRITICAL' ? 'HIGH' : highestRisk);
    }
  } else {
    // No vulns, just check context
    if (input.contextRequired && !input.contextVector.environment) {
      needsReview = true;
      reasonCodes.add('CTX-005');
      triggeredRules.add('CAECTD-R024');
    }
  }

  if (input.contextVector.hasStaleVex) {
    reasonCodes.add('VEX-007');
  }
  if (input.contextVector.hasInvalidVex) {
    reasonCodes.add('VEX-010');
  }
  if (input.contextVector.hasExpiredException) {
    reasonCodes.add('EXC-002');
  }

  if (input.conflict) {
    result.contextAssuranceState = 'CONFLICTING';
    result.contextualRisk = 'UNKNOWN';
    result.policyBlockingStatus = 'REVIEW_REQUIRED';
    result.reasonCodes.push('CTX-017');
    result.triggeredRuleIds.push('CAECTD-R025');
    return result;
  }

  if (input.invalidContext) {
    result.contextAssuranceState = 'INVALID';
    result.contextualRisk = 'UNKNOWN';
    result.policyBlockingStatus = 'REVIEW_REQUIRED';
    result.reasonCodes.push('CTX-010');
    result.triggeredRuleIds.push('CAECTD-R026');
    return result;
  }

  if (input.missingContext) {
    result.contextAssuranceState = 'MISSING';
    result.contextualRisk = 'UNKNOWN';
    result.policyBlockingStatus = 'REVIEW_REQUIRED';
    result.reasonCodes.push('CTX-005');
    result.triggeredRuleIds.push('CAECTD-R024');
    return result;
  }

  if (isBlocking) result.policyBlockingStatus = 'BLOCKING';
  else if (needsReview) result.policyBlockingStatus = 'REVIEW_REQUIRED';
  else result.policyBlockingStatus = 'NON_BLOCKING';
  
  result.contextualRisk = highestRisk;
  result.exceptionRequired = exceptionNeeded;
  result.triggeredRuleIds = Array.from(triggeredRules);
  result.reasonCodes = Array.from(reasonCodes);

  // Exception processing
  let excStatus = input.contextVector.exceptionStatus;
  if (excStatus === 'ACTIVE' && input.exceptionTrusted && result.policyBlockingStatus === 'BLOCKING') {
    result.exceptionContribution = 'CONDITIONALLY_ACCEPTED';
    result.triggeredRuleIds.push('CR-011');
  }

  // Precedence overrides
  if (input.classAFailure) {
    result.policyBlockingStatus = 'BLOCKING';
    result.exceptionContribution = 'NONE';
  }

  if (result.policyBlockingStatus === 'REVIEW_REQUIRED') {
    result.reviewRequired = true;
  }

  return result;
}

module.exports = {
  evaluateContextRisk
};
