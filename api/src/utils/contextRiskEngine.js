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
  const result = {
    modelId: 'CAECTD_CONTEXT_RISK',
    modelVersion: '0.1',
    normalizedContextVector: {},
    contextAssuranceState: 'NOT_EVALUATED',
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

  // Track original CVSS / severity changes to prove we don't mutate
  const originalCvss = input.originalCvss;
  const originalSeverity = input.originalSeverity;

  result.normalizedContextVector = { ...input.contextVector };

  // Exploitability Derivation
  let vexStatus = input.contextVector.vexApplicability;
  let compPres = input.contextVector.componentPresence;
  let runExec = input.contextVector.runtimeExecution;

  if (vexStatus === 'AFFECTED' && (compPres === 'PRESENT' || compPres === 'PARTIAL') && runExec === 'EXECUTED') {
    result.exploitability = 'EXPLOITABLE';
    result.exploitabilityBasis = 'Trusted AFFECTED VEX with executed component';
  } else if (vexStatus === 'NOT_AFFECTED') {
    if (input.vexTrusted && input.vexCurrent && input.vexExactScope) {
      result.exploitability = 'NOT_EXPLOITABLE';
      result.exploitabilityBasis = 'Trusted NOT_AFFECTED VEX';
      result.policyBlockingStatus = 'NON_BLOCKING';
      result.reviewRequired = false;
      result.contextualRisk = 'LOW';
    } else {
      result.exploitabilityBasis = 'Untrusted or invalid NOT_AFFECTED VEX';
    }
  } else if (vexStatus === 'UNDER_INVESTIGATION') {
    result.exploitability = 'UNDER_INVESTIGATION';
    result.exploitabilityBasis = 'UNDER_INVESTIGATION VEX';
  } else if (compPres === 'NOT_PRESENT' && input.componentPresenceTrusted) {
    result.exploitability = 'NOT_EXPLOITABLE';
    result.exploitabilityBasis = 'Verified component NOT_PRESENT';
    result.policyBlockingStatus = 'NON_BLOCKING';
    result.reviewRequired = false;
    result.contextualRisk = 'LOW';
  } else if (compPres === 'PRESENT' && runExec === 'PRESENT_NOT_EXECUTED') {
    result.exploitability = 'UNKNOWN';
    result.exploitabilityBasis = 'Component PRESENT_NOT_EXECUTED';
  }

  // Conflict handling
  if (input.conflict) {
    result.contextAssuranceState = 'CONFLICTING';
    result.contextualRisk = 'UNKNOWN';
    result.policyBlockingStatus = 'REVIEW_REQUIRED';
    result.reasonCodes.push('CFL-001');
    return result;
  }

  // Invalid context
  if (input.invalidContext) {
    result.contextAssuranceState = 'INVALID';
    result.contextualRisk = 'UNKNOWN';
    result.policyBlockingStatus = 'REVIEW_REQUIRED';
    return result;
  }

  // Context Risk Rules
  let env = input.contextVector.environment;
  let exp = input.contextVector.internetExposure;
  let crit = input.contextVector.assetCriticality;
  let priv = input.contextVector.privilegeLevel;
  let sens = input.contextVector.dataSensitivity;

  if (env === 'PRODUCTION' && (exp === 'PUBLIC' || exp === 'RESTRICTED_PUBLIC') && result.exploitability === 'EXPLOITABLE') {
    result.contextualRisk = 'CRITICAL';
    result.policyBlockingStatus = 'BLOCKING';
    result.reviewRequired = false;
    result.exceptionRequired = true;
    result.triggeredRuleIds.push('CR-001');
    result.reasonCodes.push('CTX-001');
  } else if (env === 'PRODUCTION' && crit === 'CRITICAL' && result.exploitability === 'EXPLOITABLE') {
    result.contextualRisk = 'HIGH'; // or CRITICAL
    result.policyBlockingStatus = 'BLOCKING';
    result.reviewRequired = false;
  } else if (priv === 'SYSTEM' && result.exploitability === 'EXPLOITABLE') {
    result.contextualRisk = 'HIGH';
    result.policyBlockingStatus = 'BLOCKING';
    result.reviewRequired = false;
  } else if (sens === 'RESTRICTED' && result.exploitability === 'EXPLOITABLE') {
    result.contextualRisk = 'HIGH';
    result.policyBlockingStatus = 'BLOCKING';
    result.reviewRequired = false;
  } else if (env === 'DEVELOPMENT' && (exp === 'NONE' || exp === 'INTERNAL') && result.exploitability !== 'EXPLOITABLE') {
    result.contextualRisk = 'LOW';
    result.policyBlockingStatus = 'NON_BLOCKING';
    result.reviewRequired = false;
  }

  // Exception processing
  let excStatus = input.contextVector.exceptionStatus;
  if (excStatus === 'ACTIVE' && input.exceptionTrusted && result.policyBlockingStatus === 'BLOCKING') {
    // Condition met for active valid exception over exceptionable class B
    result.exceptionContribution = 'CONDITIONALLY_ACCEPTED';
    result.triggeredRuleIds.push('CR-011');
  }

  // Precedence overrides
  if (input.classAFailure) {
    result.policyBlockingStatus = 'BLOCKING';
    result.exceptionContribution = 'NONE';
  }

  // Final review fallback if no rule explicitly sets it
  if (result.policyBlockingStatus === 'REVIEW_REQUIRED') {
    result.reviewRequired = true;
  }

  return result;
}

module.exports = {
  evaluateContextRisk
};
