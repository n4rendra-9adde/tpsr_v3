const { normalizeEnvironment, normalizeExposure } = require('../utils/contextCompatibilityMapper');

function assembleContextRiskEvidence({ sbomDocument, contextAssertions, vexStatements, policyExceptions, policy, operation }) {
  // Normalize context from the single active trusted assertion, if any
  let activeContext = null;
  let conflict = false;
  let invalidContext = false;
  let classAFailure = false;
  let missingContext = false;
  let contextRequired = (policy && policy.contextRiskPolicy) || (policy && policy.requireDeploymentContext) ? true : false;
  
  if (contextAssertions && Array.isArray(contextAssertions)) {
    if (contextAssertions.length === 1 && !contextAssertions[0].status) {
      // Legacy unauthenticated context
      activeContext = contextAssertions[0];
      if (contextRequired) {
        invalidContext = true; // Cannot use unauthenticated context when context is required
      }
    } else {
      const active = contextAssertions.filter(a => a.status === 'ACTIVE' && (a.verificationStatus === 'VERIFIED' || a.verification_status === 'VERIFIED'));
      const conflicting = contextAssertions.filter(a => a.status === 'INVALID' && (a.assuranceState === 'CONFLICTING' || a.assurance_state === 'CONFLICTING'));
      
      if (active.length === 1 && conflicting.length === 0) {
        activeContext = active[0];
      } else if (conflicting.length > 0) {
        conflict = true;
      } else if (active.length > 1) {
        conflict = true;
      }
    }
  }

  if (contextRequired && !activeContext && !conflict) {
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
      c.vulnerabilities.forEach(v => {
        let mappedSev = v.originalSeverity || v.severity || 'UNKNOWN';
        if (v.ratings && v.ratings.length > 0) {
          mappedSev = v.ratings[0].severity ? v.ratings[0].severity.toUpperCase() : mappedSev;
        }
        vulns.push({ ...v, componentId: c['bom-ref'] || c.name || 'unknown', originalSeverity: mappedSev, severity: mappedSev });
      });
    }
  });

  if (rawSbom.vulnerabilities && Array.isArray(rawSbom.vulnerabilities)) {
    rawSbom.vulnerabilities.forEach(v => {
      let mappedSev = v.originalSeverity || v.severity || 'UNKNOWN';
      if (v.ratings && v.ratings.length > 0) {
        mappedSev = v.ratings[0].severity ? v.ratings[0].severity.toUpperCase() : mappedSev;
      }
      vulns.push({ ...v, componentId: v['bom-ref'] || 'unknown', originalSeverity: mappedSev, severity: mappedSev });
    });
  }

  // Parse VEX statements
  let vexApplicability = 'UNKNOWN';
  let vexTrusted = false;
  let vexCurrent = true;
  let vexExactScope = true;

  if (vexStatements && Array.isArray(vexStatements)) {
    const activeVex = vexStatements.filter(v => {
      // VEX must be structurally valid, verified, and not logically rejected
      if (v.signature_status !== 'VERIFIED') return false;
      if (v.deleted_at !== null) return false;
      if (v.applicability_disposition === 'VEX_INVALID') return false;
      // Optional: check assurance_state if it exists in a newer schema, otherwise assume verified signatures are trusted
      if (v.assurance_state && v.assurance_state !== 'VERIFIED_TRUSTED') return false;
      return true;
    });

    if (activeVex.length === 1) {
      const s = activeVex[0].applicability_status || activeVex[0].status || activeVex[0].applicability || 'UNKNOWN';
      vexApplicability = s.toUpperCase();
      vexTrusted = true;
    } else if (activeVex.length > 1) {
      conflict = true;
    }
    
    vulns.forEach(v => {
       const vexMatch = activeVex.find(vex => (vex.vulnerability_id || vex.vulnerabilityId || vex.cve) === (v.id || v.cve || v.vulnerabilityId));
       if (vexMatch) {
         const s = vexMatch.applicability_status || vexMatch.status || vexMatch.applicability;
         v.vexApplicability = s ? s.toUpperCase() : 'UNKNOWN';
       }
    });

    contextVector.hasStaleVex = vexStatements.some(v => v.assurance_state === 'STALE' || v.status === 'STALE');
    contextVector.hasInvalidVex = vexStatements.some(v => v.assurance_state === 'INVALID' || v.status === 'INVALID' || v.signature_status === 'FAILED');
  }
  contextVector.vexApplicability = vexApplicability;

  // Process exceptions
  let exceptionStatus = 'NONE';
  let exceptionTrusted = false;
  if (policyExceptions && Array.isArray(policyExceptions)) {
    const activeExceptions = policyExceptions.filter(e => {
      if (e.status !== 'ACTIVE' || e.assurance_state !== 'VERIFIED_TRUSTED') return false;
      if (e.sbom_id && sbomDocument.sbom_id && e.sbom_id !== sbomDocument.sbom_id) return false;
      if (e.policy_rule_id && !['CAECTD-R017', 'CAECTD-R024', 'CR-001'].includes(e.policy_rule_id)) return false;
      if (e.vulnerability_ids && Array.isArray(e.vulnerability_ids) && e.vulnerability_ids.length > 0) {
        if (!e.vulnerability_ids.some(vid => vulns.some(v => v.id === vid || v.cve === vid || v.vulnerabilityId === vid))) return false;
      }
      if (e.component_identifiers && Array.isArray(e.component_identifiers) && e.component_identifiers.length > 0) {
        if (!e.component_identifiers.some(cid => vulns.some(v => v.componentId === cid))) return false;
      }
      if (e.environment && e.environment !== contextVector.environment) return false;
      const pVersion = policy ? (policy.version || '3.0') : '3.0';
      if (e.policy_version && e.policy_version !== 'unknown' && e.policy_version !== pVersion) return false;
      
      const now = new Date();
      let fromDate = now;
      if (e.valid_from) {
        fromDate = new Date(e.valid_from);
        if (fromDate > now) return false;
      }
      if (e.valid_until) {
        const untilDate = new Date(e.valid_until);
        if (untilDate <= now) return false;
        
        const days = (untilDate - fromDate) / (1000 * 60 * 60 * 24);
        if (days > 30) return false;
      }
      
      if (e.requested_by && e.approved_by && e.requested_by === e.approved_by) return false;
      if (!e.remediation_plan || e.remediation_plan.trim() === '') return false;
      if (!e.compensating_controls || e.compensating_controls.length === 0) return false;
      if (e.residual_risk && ['HIGH', 'CRITICAL'].includes(e.residual_risk.toUpperCase())) return false;

      return true;
    });

    if (activeExceptions.length > 0) {
      exceptionStatus = 'ACTIVE';
      exceptionTrusted = true;
    }
    
    contextVector.hasExpiredException = policyExceptions.some(e => e.status === 'EXPIRED' || e.assurance_state === 'EXPIRED');
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
