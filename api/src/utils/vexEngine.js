/**
 * TPSR v3 VEX Applicability Overlay Engine
 * Implements OpenVEX / CycloneDX VEX applicability analysis while preserving raw CVSS scores.
 */

const VALID_STATUSES = ['affected', 'not_affected', 'under_investigation', 'fixed'];
const VALID_JUSTIFICATIONS = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist'
];

/**
 * Evaluates a single VEX statement against a vulnerability
 * @param {Object} vex - The VEX statement object
 * @returns {Object} Evaluation result with status, reasonCode, reasonDescription, and effectiveSeverity
 */
function evaluateVexStatement(vex) {
  const result = {
    isValid: false,
    status: 'under_investigation',
    reasonCode: 'VEX-004',
    reasonDescription: 'VEX statement under investigation or unverified',
    justification: null,
    impactStatement: null,
    evaluatedAt: new Date().toISOString()
  };

  if (!vex || typeof vex !== 'object') {
    result.reasonCode = 'VEX-002';
    result.reasonDescription = 'VEX statement payload is missing or invalid';
    return result;
  }

  const status = (vex.status || '').toLowerCase().trim();
  if (!VALID_STATUSES.includes(status)) {
    result.reasonCode = 'VEX-002';
    result.reasonDescription = `Invalid VEX status: ${vex.status}`;
    return result;
  }
  result.status = status;

  if (status === 'not_affected') {
    const justification = (vex.justification || '').toLowerCase().trim();
    const impactStatement = (vex.impactStatement || vex.impact_statement || '').trim();

    if (!VALID_JUSTIFICATIONS.includes(justification)) {
      result.reasonCode = 'VEX-002';
      result.reasonDescription = `Missing or invalid justification for not_affected VEX status: ${vex.justification || 'none'}`;
      return result;
    }

    result.isValid = true;
    result.justification = justification;
    result.impactStatement = impactStatement || `Mitigated by ${justification}`;
    result.reasonCode = 'VEX-001';
    result.reasonDescription = `VEX justification approved - vulnerability not applicable (${justification})`;
    return result;
  }

  if (status === 'fixed') {
    result.isValid = true;
    result.reasonCode = 'VEX-001';
    result.reasonDescription = 'VEX statement verified - vulnerability has been remediated in this version';
    return result;
  }

  if (status === 'affected') {
    result.isValid = true;
    result.reasonCode = 'VEX-003';
    result.reasonDescription = 'VEX confirms component is affected; active remediation or exception required';
    return result;
  }

  result.isValid = true;
  return result;
}

/**
 * Applies VEX overlays onto an array of component vulnerabilities while preserving raw CVSS scores
 * @param {Array<Object>} vulnerabilities - Array of vulnerability objects (e.g. from SBOM or scanner)
 * @param {Array<Object>} vexStatements - Array of active VEX statement records
 * @returns {Object} Overlay summary with updated vulnerabilities, effectiveRiskScore, and activeVexIds
 */
function applyVexOverlays(vulnerabilities = [], vexStatements = []) {
  const activeVexIds = [];
  let totalRawCvss = 0;
  let totalEffectiveScore = 0;
  let highestEffectiveSeverity = 'NONE';

  const severityMap = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };
  const revSeverityMap = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

  const updatedVulnerabilities = vulnerabilities.map(vuln => {
    const vulnCopy = { ...vuln };
    const vulnId = vulnCopy.id || vulnCopy.cve || vulnCopy.vulnerabilityId;
    const rawCvss = Number(vulnCopy.cvssScore || vulnCopy.cvss || 0);
    totalRawCvss += rawCvss;

    // Find matching VEX statement
    const matchingVex = vexStatements.find(v => {
      const targetId = v.vulnerability_id || v.vulnerabilityId || v.cve || v.sub;
      return targetId && targetId.toLowerCase() === (vulnId || '').toLowerCase();
    });

    vulnCopy.rawCvssScore = rawCvss;
    vulnCopy.rawSeverity = vulnCopy.severity || 'UNKNOWN';

    if (matchingVex) {
      if (matchingVex.id || matchingVex.vex_id) {
        activeVexIds.push(matchingVex.id || matchingVex.vex_id);
      }
      const evalResult = evaluateVexStatement(matchingVex);
      vulnCopy.vexStatus = evalResult.status;
      vulnCopy.vexReasonCode = evalResult.reasonCode;
      vulnCopy.vexReasonDescription = evalResult.reasonDescription;
      vulnCopy.vexJustification = evalResult.justification;

      if (evalResult.status === 'not_affected' || evalResult.status === 'fixed') {
        // PRESERVE rawCvssScore, but reduce effective risk to 0 for policy evaluation
        vulnCopy.effectiveCvssScore = 0;
        vulnCopy.effectiveSeverity = 'NONE';
        vulnCopy.suppressedByVex = true;
      } else {
        vulnCopy.effectiveCvssScore = rawCvss;
        vulnCopy.effectiveSeverity = vulnCopy.rawSeverity;
        vulnCopy.suppressedByVex = false;
      }
    } else {
      vulnCopy.vexStatus = 'unevaluated';
      vulnCopy.effectiveCvssScore = rawCvss;
      vulnCopy.effectiveSeverity = vulnCopy.rawSeverity;
      vulnCopy.suppressedByVex = false;
    }

    totalEffectiveScore += vulnCopy.effectiveCvssScore;
    const effSevNum = severityMap[(vulnCopy.effectiveSeverity || '').toUpperCase()] || 0;
    if (effSevNum > severityMap[highestEffectiveSeverity]) {
      highestEffectiveSeverity = revSeverityMap[effSevNum];
    }

    return vulnCopy;
  });

  const effectiveRiskScore = updatedVulnerabilities.length > 0 ? Math.round((totalEffectiveScore / updatedVulnerabilities.length) * 100) / 100 : 0;

  return {
    vulnerabilities: updatedVulnerabilities,
    totalRawCvssScore: Math.round(totalRawCvss * 100) / 100,
    totalEffectiveCvssScore: Math.round(totalEffectiveScore * 100) / 100,
    effectiveRiskScore: effectiveRiskScore,
    highestEffectiveSeverity: highestEffectiveSeverity,
    activeVexIds: Array.from(new Set(activeVexIds)),
    appliedAt: new Date().toISOString()
  };
}

module.exports = {
  evaluateVexStatement,
  applyVexOverlays,
  VALID_STATUSES,
  VALID_JUSTIFICATIONS
};
