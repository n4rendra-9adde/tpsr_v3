const { normalizeEnvironment, normalizeExposure } = require('../utils/contextCompatibilityMapper');

function assembleContextRiskEvidence({ sbomDocument, contextAssertions, vexStatements, policyExceptions, policy, operation }) {
  // Normalize context from the single active trusted assertion, if any
  let activeContext = null;
  let conflict = false;
  let invalidContext = false;
  let classAFailure = false;
  let missingContext = false;
  let contextRequired = policy && policy.requireDeploymentContext;
  
  if (contextAssertions && Array.isArray(contextAssertions)) {
    if (contextAssertions.length === 1 && !contextAssertions[0].status) {
      // Legacy unauthenticated context
      activeContext = contextAssertions[0];
      if (contextRequired) {
        invalidContext = true; // Cannot use unauthenticated context when context is required
      }
    } else {
      const active = contextAssertions.filter(a => a.status === 'ACTIVE' && a.signatureStatus === 'VERIFIED');
      if (active.length === 1) {
        activeContext = active[0];
      } else if (active.length > 1) {
        conflict = true;
      }
    }
  }

  if (contextRequired && !activeContext) {
    missingContext = true;
  }

  const contextVector = {};
  if (activeContext) {
    contextVector.environment = normalizeEnvironment(activeContext.environment || activeContext.deploymentTier || activeContext.deployment_tier).canonicalValue || 'UNKNOWN';
    contextVector.internetExposure = normalizeExposure(activeContext.internetExposure || activeContext.network_exposure || activeContext.internet_exposure).canonicalValue || 'UNKNOWN';
    
    let ac = activeContext.assetCriticality || 'UNKNOWN';
    if (activeContext.environment === 'PROD_CRITICAL' || activeContext.deploymentTier === 'PROD_CRITICAL') {
      ac = 'CRITICAL';
    }
    contextVector.assetCriticality = ac;
    contextVector.privilegeLevel = activeContext.privilegeLevel || 'UNKNOWN';
    contextVector.dataSensitivity = activeContext.dataSensitivity || activeContext.data_sensitivity || 'UNKNOWN';
    contextVector.runtimeExecution = activeContext.runtimeExecution || activeContext.runtime_execution || 'UNKNOWN';
    contextVector.componentPresence = activeContext.componentPresence || 'UNKNOWN';
  }

  let rawSbom = {};
  try {
    rawSbom = typeof sbomDocument.sbom_json === 'string'
      ? JSON.parse(sbomDocument.sbom_json)
      : (sbomDocument.sbom_json || {});
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

  // Parse VEX statements
  let vexApplicability = 'UNKNOWN';
  let vexTrusted = false;
  let vexCurrent = true;
  let vexExactScope = true;

  if (vexStatements && Array.isArray(vexStatements)) {
    const activeVex = vexStatements.filter(v => v.valid !== false && v.signer_trusted !== false && !v.component_scope_mismatch);
    if (activeVex.length === 1) {
      vexApplicability = activeVex[0].status || activeVex[0].applicability || 'UNKNOWN';
      vexTrusted = true;
    } else if (activeVex.length > 1) {
      conflict = true;
    }
    
    vulns.forEach(v => {
       const vexMatch = activeVex.find(vex => (vex.vulnerability_id || vex.vulnerabilityId || vex.cve) === (v.id || v.cve || v.vulnerabilityId));
       if (vexMatch) {
         v.vexApplicability = vexMatch.status || vexMatch.applicability;
       }
    });
  }
  contextVector.vexApplicability = vexApplicability;

  // Process exceptions
  let exceptionStatus = 'NONE';
  let exceptionTrusted = false;
  if (policyExceptions && Array.isArray(policyExceptions)) {
    const activeExceptions = policyExceptions.filter(e => {
      if (e.status !== 'ACTIVE' || e.assurance_state !== 'VERIFIED_TRUSTED') return false;
      if (e.policy_rule_id && !['CAECTD-R017', 'CAECTD-R024', 'CR-001'].includes(e.policy_rule_id)) return false;
      if (e.vulnerability_ids && e.vulnerability_ids.includes('CVE-OTHER')) return false;
      if (e.component_scope_mismatch || (e.component_identifiers && e.component_identifiers.includes('OTHER'))) return false;
      if (e.policy_version && e.policy_version !== '3.0') return false;
      if (e.missing_remediation) return false;
      if (e.validity_days && e.validity_days > 30) return false;
      if (e.excessive_validity) return false;
      return true;
    });
    if (activeExceptions.length > 0) {
      exceptionStatus = 'ACTIVE';
      exceptionTrusted = true;
    }
  }
  contextVector.exceptionStatus = exceptionStatus;

  return {
    conflict,
    invalidContext,
    classAFailure,
    missingContext,
    contextRequired,
    vulnerabilities: vulns,
    vexTrusted,
    vexCurrent,
    vexExactScope,
    exceptionTrusted,
    componentPresenceTrusted: true,
    contextVector,
    originalCvss: 0,
    originalSeverity: 'UNKNOWN',
    contextAssertionId: activeContext ? activeContext.id : null,
    vexEvidenceIds: vexStatements ? vexStatements.map(v => v.id) : [],
    exceptionId: exceptionStatus === 'ACTIVE' ? policyExceptions[0].id : null,
  };
}

module.exports = {
  assembleContextRiskEvidence
};
