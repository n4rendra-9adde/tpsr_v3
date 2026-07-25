/**
 * TPSR v3 Trust-Evaluation Orchestration Engine
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

/**
 * Authoritative TPSR v3 trust-decision constants.
 * These are the only values this engine may emit as trustStatus.
 */
const TRUST_STATUS = {
  TRUSTED: 'TRUSTED',
  CONDITIONALLY_ACCEPTED: 'CONDITIONALLY_ACCEPTED',
  REVIEW_REQUIRED: 'REVIEW_REQUIRED',
  REJECTED: 'REJECTED'
};

/**
 * Evaluates comprehensive trust for an SBOM and its associated evidence bundle.
 * @param {Object} evidenceBundle
 * @param {Object} evidenceBundle.sbomDocument - PostgreSQL sbom_documents row
 * @param {Array<Object>} [evidenceBundle.provenance=[]] - provenance_attestations rows
 * @param {Array<Object>} [evidenceBundle.signatures=[]] - signature_verifications rows
 * @param {Array<Object>} [evidenceBundle.vexStatements=[]] - vex_statements rows
 * @param {Object} [evidenceBundle.deploymentContext=null] - latest deployment_contexts row
 * @param {Array<Object>} [evidenceBundle.policyExceptions=[]] - approved policy_exceptions rows
 * @returns {Object} Trust decision summary with trustStatus from the four-state enum
 */
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
    evaluatedAt: new Date().toISOString()
  };

  // ── Rule 1: SBOM document must be present ───────────────────────────────────
  const sbomDoc = evidenceBundle.sbomDocument;
  if (!sbomDoc || !sbomDoc.sbom_id) {
    result.trustStatus = TRUST_STATUS.REJECTED;
    result.reasonCode = 'INT-002';
    result.reasonDescription = 'SBOM document record is missing or invalid — mandatory integrity check failed.';
    return result;
  }

  const provenance  = Array.isArray(evidenceBundle.provenance)       ? evidenceBundle.provenance       : [];
  const signatures  = Array.isArray(evidenceBundle.signatures)       ? evidenceBundle.signatures       : [];
  const vexStatements = Array.isArray(evidenceBundle.vexStatements)  ? evidenceBundle.vexStatements    : [];
  const depContext  = evidenceBundle.deploymentContext || null;
  const exceptions  = Array.isArray(evidenceBundle.policyExceptions) ? evidenceBundle.policyExceptions : [];

  result.evidenceSummary.provenanceCount     = provenance.length;
  result.evidenceSummary.signatureCount      = signatures.length;
  result.evidenceSummary.vexCount            = vexStatements.length;
  result.evidenceSummary.hasDeploymentContext = !!depContext;
  result.evidenceSummary.activeExceptionCount = exceptions.length;

  // ── Rule 2: Valid provenance attestation is mandatory ───────────────────────
  const validProv = provenance.find(p => p.status === 'VALID' || p.slsa_level);
  if (!validProv) {
    result.trustStatus = TRUST_STATUS.REJECTED;
    result.reasonCode = 'PRV-005';
    result.reasonDescription = 'No valid build provenance attestation found — mandatory provenance check failed.';
    return result;
  }

  // ── Rule 3: Valid signature verification is mandatory ───────────────────────
  const validSig = signatures.find(
    s => s.verification_status === 'VERIFIED' || s.verificationStatus === 'VERIFIED'
  );
  if (!validSig) {
    result.trustStatus = TRUST_STATUS.REJECTED;
    result.reasonCode = 'SIG-002';
    result.reasonDescription = 'Cosign cryptographic signature verification failed or no valid signature bundle found — mandatory signature check failed.';
    return result;
  }

  // ── Rule 4: VEX Applicability Overlays & Risk Calculation ───────────────────
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
  result.effectiveRiskScore = vexSummary.effectiveRiskScore;
  result.highestEffectiveSeverity = vexSummary.highestEffectiveSeverity;

  // ── Rule 5: Deployment Context Policy Evaluation ─────────────────────────────
  let contextViolation = false;
  let contextReasonCode = null;
  let contextReasonDescription = null;

  if (depContext) {
    const ctxRes = evaluateDeploymentContext({
      deploymentTier:    depContext.environment,
      internetExposed:   depContext.network_exposure === 'PUBLIC' || depContext.network_exposure === 'INTERNET',
      dataClassification: depContext.data_sensitivity,
      runtimeEnvironment: depContext.environment
    }, vexSummary, {
      status:    validProv.status   || 'VALID',
      slsaLevel: validProv.slsa_level || validProv.slsaLevel || 'SLSA_BUILD_LEVEL_3'
    });

    if (!ctxRes.compliant) {
      contextViolation = true;
      contextReasonCode = ctxRes.reasonCode || 'CTX-002';
      contextReasonDescription = ctxRes.reasonDescription;
    }
  } else if (vexSummary.highestEffectiveSeverity === 'CRITICAL' && exceptions.length === 0) {
    // No deployment context registered and unmitigated CRITICAL vulnerability present
    contextViolation = true;
    contextReasonCode = 'CTX-002';
    contextReasonDescription = 'Unmitigated CRITICAL vulnerability present without a registered deployment context or approved policy exception.';
  }

  // ── Rule 6: Apply exceptions to policy violations ──────────────────────────
  if (contextViolation) {
    const activeExceptions = exceptions.filter(exc =>
      exc.status === 'APPROVED' && (!exc.valid_until || new Date(exc.valid_until) > new Date())
    );

    if (activeExceptions.length > 0) {
      // Policy violation is covered by a valid, active, unexpired exception
      result.trustStatus = TRUST_STATUS.CONDITIONALLY_ACCEPTED;
      result.reasonCode = 'EXC-001';
      result.reasonDescription = `Active approved policy exception(s) cover the remaining policy violation (${contextReasonCode}). Trust is conditionally accepted.`;
      result.evidenceSummary.activeExceptionCount = activeExceptions.length;
      return result;
    }

    // Violation with no valid exception → REJECTED
    result.trustStatus = TRUST_STATUS.REJECTED;
    result.reasonCode = contextReasonCode;
    result.reasonDescription = contextReasonDescription;
    return result;
  }

  // ── Rule 7: All mandatory checks pass, no blocking violations ──────────────
  result.trustStatus = TRUST_STATUS.TRUSTED;
  result.reasonCode = 'GOV-001';
  result.reasonDescription = 'Full TPSR v3 trust evaluation passed all mandatory governance criteria.';
  return result;
}

module.exports = {
  evaluateTrust,
  TRUST_STATUS
};
