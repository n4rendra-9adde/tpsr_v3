'use strict';

const sbomRepository = require('../repositories/sbomRepository');
const trustRepository = require('../repositories/trustRepository');
const contextAssertionRepository = require('../repositories/contextAssertionRepository');
const { evaluateTrust } = require('../utils/trustEngine');
const snapshotService = require('../services/snapshotService');
const crypto = require('crypto');

function mapRecommendation(trustStatus, reasonCode) {
  if (trustStatus === 'TRUSTED') return 'APPROVE';
  if (trustStatus === 'CONDITIONALLY_ACCEPTED') return 'APPROVE_WITH_CONDITIONS';
  if (trustStatus === 'REVIEW_REQUIRED' || reasonCode === 'CTX-017') return 'MANUAL_REVIEW_REQUIRED';
  if (trustStatus === 'REJECTED') return 'REJECT';
  return 'ANALYSIS_INCOMPLETE';
}

async function evaluateSubmittedSbom({ sbomId, correlationId, principal, triggerType = 'SBOM_SUBMITTED' }) {
  try {
    const sbomDoc = await sbomRepository.getSBOMDocumentBySBOMID(sbomId);
    if (!sbomDoc) {
      throw new Error(`SBOM document not found for ID: ${sbomId}`);
    }

    const [provenance, signatures, vexStatements, depContexts, exceptions, activeAssertions] = await Promise.all([
      sbomRepository.getProvenanceBySBOMID(sbomId),
      sbomRepository.getSignaturesBySBOMID(sbomId),
      sbomRepository.getVexStatementsBySBOMID(sbomId),
      sbomRepository.getDeploymentContextBySBOMID(sbomId),
      sbomRepository.getPolicyExceptionsBySBOMID(sbomId),
      contextAssertionRepository.listContextAssertionsBySbomId(sbomId)
    ]);

    const activeAssertion = activeAssertions.find(a => a.status === 'ACTIVE') || null;
    const latestLegacyContext = depContexts.length > 0 ? depContexts[0] : null;

    const evalResult = await evaluateTrust({
      sbomDocument: sbomDoc,
      provenance,
      signatures,
      vexStatements,
      deploymentContext: latestLegacyContext,
      activeContextAssertion: activeAssertion,
      allActiveContextAssertions: activeAssertions.filter(a => a.status === 'ACTIVE' || (a.status === 'INVALID' && a.assurance_state === 'CONFLICTING')),
      policyExceptions: exceptions
    });

    const history = await trustRepository.getTrustDecisionHistoryBySBOMID(sbomId);
    const previousDecision = history.length > 0 ? history[0] : null;

    let actualLifecycleEffect = "UNKNOWN";
    if (evalResult.trustStatus === 'TRUSTED') actualLifecycleEffect = "ALLOW_ALL";
    if (evalResult.trustStatus === 'CONDITIONALLY_ACCEPTED') actualLifecycleEffect = "ALLOW_WITH_RESTRICTIONS";
    if (evalResult.trustStatus === 'REVIEW_REQUIRED') actualLifecycleEffect = "HOLD_FOR_REVIEW";
    if (evalResult.trustStatus === 'REJECTED') actualLifecycleEffect = "BLOCK_ALL";

    evalResult.evidenceSummary = evalResult.evidenceSummary || {};
    evalResult.evidenceSummary.transitionMetadata = {
      previousDecision: previousDecision ? previousDecision.trust_status : null,
      previousDecisionId: previousDecision ? previousDecision.id : null,
      currentDecision: evalResult.trustStatus,
      transitionId: `TR-${crypto.randomUUID()}`,
      transitionReason: `Transitioned from ${previousDecision ? previousDecision.trust_status : 'ANY'} to ${evalResult.trustStatus}`,
      reevaluationTrigger: triggerType,
      lifecycleEffect: actualLifecycleEffect
    };

    const dbDecision = await trustRepository.insertTrustDecision({
      sbomId: sbomId,
      trustStatus: evalResult.trustStatus,
      reasonCode: evalResult.reasonCode,
      reasonDescription: evalResult.reasonDescription,
      evidenceSummary: evalResult.evidenceSummary,
      policyVersion: evalResult.policyVersion,
      evaluatedBy: principal || 'system-automatic-evaluator',
      idempotencyKey: null,
      caectdModelVersion: evalResult.caectdModelVersion,
      triggeredRuleIds: evalResult.triggeredRuleIds,
      evaluatedRuleIds: evalResult.evaluatedRuleIds,
      evidenceDependencies: evalResult.evidenceDependencies,
      explanationCompleteness: evalResult.explanationCompleteness
    });

    await trustRepository.insertOutboxRecord({
      sbomId: sbomId,
      decisionId: dbDecision.id,
      action: 'RECORD_TRUST_DECISION',
      payload: {
        version: "3.0",
        sbomID: sbomId,
        decisionId: dbDecision.id,
        trustStatus: evalResult.trustStatus,
        reasonCode: evalResult.reasonCode,
        reasonDescription: evalResult.reasonDescription,
        policyVersion: evalResult.policyVersion || '3.0',
        idempotencyKey: null,
        evidenceSummary: evalResult.evidenceSummary
      }
    });

    const snapshot = await snapshotService.captureAndPersistSnapshot(
        sbomId,
        evalResult,
        {
          provenance, signatures, vexStatements, deploymentContext: latestLegacyContext,
          activeContextAssertion: activeAssertion, allActiveContextAssertions: activeAssertions.filter(a => a.status === 'ACTIVE' || (a.status === 'INVALID' && a.assurance_state === 'CONFLICTING')),
          policyExceptions: exceptions
        },
        dbDecision
    );

    const recommendation = mapRecommendation(evalResult.trustStatus, evalResult.reasonCode);
    const primaryRuleId = (evalResult.triggeredRuleIds && evalResult.triggeredRuleIds.length > 0) ? evalResult.triggeredRuleIds[0] : null;

    return {
      recommendation: recommendation,
      internalTrustState: evalResult.trustStatus,
      decisionId: dbDecision.id,
      snapshotId: snapshot.snapshotId,
      primaryRuleId: primaryRuleId,
      primaryReasonCode: evalResult.reasonCode,
      ruleIds: evalResult.triggeredRuleIds || [],
      reasonCodes: evalResult.reasonCode ? [evalResult.reasonCode] : [],
      blockingFindings: evalResult.trustStatus === 'REJECTED' ? [evalResult.reasonDescription] : [],
      reviewFindings: evalResult.trustStatus === 'REVIEW_REQUIRED' ? [evalResult.reasonDescription] : [],
      evidenceCompleteness: evalResult.explanationCompleteness,
      policyId: evalResult.policyVersion,
      policyVersion: evalResult.policyVersion,
      policyGeneration: evalResult.policyVersion,
      evaluatedAt: dbDecision.evaluated_at,
      correlationId: correlationId || crypto.randomUUID(),
      humanReviewRequired: evalResult.trustStatus === 'REVIEW_REQUIRED',
      exceptionPermitted: evalResult.trustStatus !== 'REJECTED'
    };

  } catch (err) {
    console.error('[TPSR] evaluateSubmittedSbom error:', err);
    return {
      recommendation: 'ANALYSIS_INCOMPLETE',
      internalTrustState: 'UNKNOWN',
      decisionId: null,
      snapshotId: null,
      primaryRuleId: null,
      primaryReasonCode: null,
      ruleIds: [],
      reasonCodes: [],
      blockingFindings: [],
      reviewFindings: [],
      evidenceCompleteness: {},
      policyId: null,
      policyVersion: null,
      policyGeneration: null,
      evaluatedAt: new Date().toISOString(),
      correlationId: correlationId || crypto.randomUUID(),
      humanReviewRequired: false,
      exceptionPermitted: false
    };
  }
}

module.exports = {
  evaluateSubmittedSbom,
  mapRecommendation
};
