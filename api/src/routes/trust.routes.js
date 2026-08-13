'use strict';

const express = require('express');
const router = express.Router();
const sbomRepository = require('../repositories/sbomRepository');
const trustRepository = require('../repositories/trustRepository');
const { evaluateTrust } = require('../utils/trustEngine');
const snapshotService = require('../services/snapshotService');

/**
 * Handle full trust evaluation execution with Idempotency-Key support
 */
async function handleEvaluateTrust(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  const idempotencyKey = req.headers['idempotency-key'] || req.headers['x-idempotency-key'] || null;
  try {
    if (idempotencyKey) {
      const cached = await trustRepository.getTrustDecisionByIdempotencyKey(idempotencyKey.trim());
      if (cached) {
        if (cached.sbom_id !== sbomId.trim()) {
          return res.status(409).json({ error: 'Idempotency key reused with a different request context (sbomId mismatch)' });
        }
        return res.status(200).json({
          message: 'Trust evaluation retrieved from cache (idempotent request)',
          decisionId: cached.id,
          sbomId: cached.sbom_id,
          trustStatus: cached.trust_status,
          reasonCode: cached.reason_code,
          reasonDescription: cached.reason_description,
          evidenceSummary: typeof cached.evidence_summary === 'string' ? JSON.parse(cached.evidence_summary) : cached.evidence_summary,
          idempotent: true,
          evaluatedAt: cached.evaluated_at
        });
      }
    }

    const sbomDoc = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!sbomDoc) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const contextAssertionRepository = require('../repositories/contextAssertionRepository');
    const [provenance, signatures, vexStatements, depContexts, exceptions, activeAssertions] = await Promise.all([
      sbomRepository.getProvenanceBySBOMID(sbomId.trim()),
      sbomRepository.getSignaturesBySBOMID(sbomId.trim()),
      sbomRepository.getVexStatementsBySBOMID(sbomId.trim()),
      sbomRepository.getDeploymentContextBySBOMID(sbomId.trim()),
      sbomRepository.getPolicyExceptionsBySBOMID(sbomId.trim()),
      contextAssertionRepository.listContextAssertionsBySbomId(sbomId.trim())
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
    
    // Add State Transition Metadata for Point 6
    const history = await trustRepository.getTrustDecisionHistoryBySBOMID(sbomId.trim());
    const previousDecision = history.length > 0 ? history[0] : null;
    
    let reevaluationTrigger = 'NEW_EVIDENCE';
    if (req.body && req.body.trigger) {
      reevaluationTrigger = req.body.trigger;
    } else if (req.headers['x-reevaluation-trigger']) {
      reevaluationTrigger = req.headers['x-reevaluation-trigger'];
    }

    let actualLifecycleEffect = "UNKNOWN";
    if (evalResult.trustStatus === 'TRUSTED') actualLifecycleEffect = "ALLOW_ALL";
    if (evalResult.trustStatus === 'CONDITIONALLY_ACCEPTED') actualLifecycleEffect = "ALLOW_WITH_RESTRICTIONS";
    if (evalResult.trustStatus === 'REVIEW_REQUIRED') actualLifecycleEffect = "HOLD_FOR_REVIEW";
    if (evalResult.trustStatus === 'REJECTED') actualLifecycleEffect = "BLOCK_ALL";
    
    const crypto = require('crypto');
    evalResult.evidenceSummary = evalResult.evidenceSummary || {};
    evalResult.evidenceSummary.transitionMetadata = {
      previousDecision: previousDecision ? previousDecision.trust_status : null,
      previousDecisionId: previousDecision ? previousDecision.id : null,
      currentDecision: evalResult.trustStatus,
      transitionId: `TR-${crypto.randomUUID()}`,
      transitionReason: `Transitioned from ${previousDecision ? previousDecision.trust_status : 'ANY'} to ${evalResult.trustStatus}`,
      reevaluationTrigger: reevaluationTrigger,
      lifecycleEffect: actualLifecycleEffect
    };

    const dbDecision = await trustRepository.insertTrustDecision({
      sbomId: sbomId.trim(),
      trustStatus: evalResult.trustStatus,
      reasonCode: evalResult.reasonCode,
      reasonDescription: evalResult.reasonDescription,
      evidenceSummary: evalResult.evidenceSummary,
      policyVersion: evalResult.policyVersion,
      evaluatedBy: req.headers['x-user-id'] || 'security-officer',
      idempotencyKey: idempotencyKey ? idempotencyKey.trim() : null,
      caectdModelVersion: evalResult.caectdModelVersion,
      triggeredRuleIds: evalResult.triggeredRuleIds,
      evaluatedRuleIds: evalResult.evaluatedRuleIds,
      evidenceDependencies: evalResult.evidenceDependencies,
      explanationCompleteness: evalResult.explanationCompleteness
    });

    // Queue into ledger outbox for transactional background anchoring
    const outboxRecord = await trustRepository.insertOutboxRecord({
      sbomId: sbomId.trim(),
      decisionId: dbDecision.id,
      action: 'RECORD_TRUST_DECISION',
      payload: {
        version: "3.0",
        sbomID: sbomId.trim(),
        decisionId: dbDecision.id,
        trustStatus: evalResult.trustStatus,
        reasonCode: evalResult.reasonCode,
        reasonDescription: evalResult.reasonDescription,
        policyVersion: evalResult.policyVersion || '3.0',
        idempotencyKey: idempotencyKey ? idempotencyKey.trim() : null,
        evidenceSummary: evalResult.evidenceSummary
      }
    });

    const snapshot = await snapshotService.captureAndPersistSnapshot(
        sbomId.trim(),
        evalResult,
        {
          provenance, signatures, vexStatements, deploymentContext: latestLegacyContext,
          activeContextAssertion: activeAssertion, allActiveContextAssertions: activeAssertions.filter(a => a.status === 'ACTIVE' || (a.status === 'INVALID' && a.assurance_state === 'CONFLICTING')),
          policyExceptions: exceptions
        },
        dbDecision
    );

    // HTTP status code: 201 Created for all new authoritative evaluation records.
    // The trust decision (TRUSTED, CONDITIONALLY_ACCEPTED, REVIEW_REQUIRED, REJECTED)
    // is communicated via the response body `trustStatus` field — not the HTTP status code.
    // Using different 2xx codes to encode business trust outcomes would violate REST
    // resource-creation semantics and break standard API clients and monitoring tools.
    // 201: a new trust_decision_history record was successfully created.
    return res.status(201).json({
      message: evalResult.trustStatus === 'TRUSTED'
        ? 'Trust evaluation passed — all mandatory governance criteria satisfied.'
        : evalResult.trustStatus === 'CONDITIONALLY_ACCEPTED'
          ? 'Trust evaluation conditionally accepted — valid policy exception covers remaining violation.'
          : evalResult.trustStatus === 'REVIEW_REQUIRED'
            ? 'Trust evaluation requires manual review — evidence is incomplete or ambiguous.'
            : 'Trust evaluation completed — mandatory governance check failed (decision: REJECTED).',
      decisionId: dbDecision.id,
      outboxId: outboxRecord.id,
      sbomId: sbomId.trim(),
      trustStatus: evalResult.trustStatus,
      reasonCode: evalResult.reasonCode,
      reasonDescription: evalResult.reasonDescription,
      effectiveRiskScore: evalResult.effectiveRiskScore,
      highestEffectiveSeverity: evalResult.highestEffectiveSeverity,
      evidenceSummary: evalResult.evidenceSummary,
      idempotent: false,
      ledgerStatus: outboxRecord.status,
      evaluatedAt: dbDecision.evaluated_at,
      snapshotId: snapshot.snapshotId
    });
  } catch (err) {
    console.error('[TPSR] Error evaluating trust:', err);
    return res.status(500).json({ error: 'Failed to execute trust evaluation', details: err.message });
  }
}

function sanitizeDecisionRecord(record) {
  if (!record) return null;
  const result = { ...record };
  
  if (typeof result.evidence_summary === 'string') {
    try { result.evidence_summary = JSON.parse(result.evidence_summary); } catch (e) {}
  }
  if (typeof result.evidence_dependencies === 'string') {
    try { result.evidence_dependencies = JSON.parse(result.evidence_dependencies); } catch (e) {}
  }
  if (typeof result.triggered_rule_ids === 'string') {
    try { result.triggered_rule_ids = JSON.parse(result.triggered_rule_ids); } catch (e) {}
  }
  if (typeof result.evaluated_rule_ids === 'string') {
    try { result.evaluated_rule_ids = JSON.parse(result.evaluated_rule_ids); } catch (e) {}
  }
  if (typeof result.explanation_completeness === 'string') {
    try { result.explanation_completeness = JSON.parse(result.explanation_completeness); } catch (e) {}
  }

  // Remove forbidden fields from evidenceSummary
  if (result.evidence_summary && result.evidence_summary.vulnerabilities) {
    result.evidence_summary.vulnerabilities = result.evidence_summary.vulnerabilities.map(v => {
      const { 
        effectiveCvssScore, effectiveSeverity, suppressedByVex, 
        raw_signature, private_key, public_key, access_token, certificate, compensating_control,
        ...allowed 
      } = v;
      return allowed;
    });
  }

  // Extract Context Risk Result
  if (result.evidence_dependencies && result.evidence_dependencies.contextRisk) {
    const cr = result.evidence_dependencies.contextRisk;
    result.contextRisk = {
      contextModelVersion: cr.modelVersion || 'NOT_AVAILABLE',
      contextAssertionId: cr.contextAssertionId || 'NOT_AVAILABLE',
      contextAssuranceState: cr.contextAssuranceState || 'NOT_AVAILABLE',
      environment: cr.normalizedContextVector?.environment || 'NOT_AVAILABLE',
      internetExposure: cr.normalizedContextVector?.internetExposure || 'NOT_AVAILABLE',
      assetCriticality: cr.normalizedContextVector?.assetCriticality || 'NOT_AVAILABLE',
      privilegeLevel: cr.normalizedContextVector?.privilegeLevel || 'NOT_AVAILABLE',
      dataSensitivity: cr.normalizedContextVector?.dataSensitivity || 'NOT_AVAILABLE',
      runtimeExecution: cr.normalizedContextVector?.runtimeExecution || 'NOT_AVAILABLE',
      componentPresence: cr.normalizedContextVector?.componentPresence || 'NOT_AVAILABLE',
      exploitability: cr.exploitability || 'NOT_AVAILABLE',
      exploitabilityBasis: cr.exploitabilityBasis || 'NOT_AVAILABLE',
      vexApplicability: cr.normalizedContextVector?.vexApplicability || 'NOT_AVAILABLE',
      exceptionStatus: cr.normalizedContextVector?.exceptionStatus || 'NOT_AVAILABLE',
      exceptionId: cr.exceptionId || 'NOT_AVAILABLE',
      contextualRisk: cr.contextualRisk || 'NOT_AVAILABLE',
      policyBlockingStatus: cr.policyBlockingStatus || 'NOT_AVAILABLE',
      triggeredContextRuleIds: cr.triggeredContextRuleIds || [],
      evaluatedContextRuleIds: cr.evaluatedContextRuleIds || [],
      contextReasonCodes: cr.contextReasonCodes || [],
      conflictResults: cr.conflictResults || null,
      contextEvaluatedAt: cr.contextEvaluatedAt || 'NOT_AVAILABLE'
    };
    
    // Original vulnerability info
    if (cr.vulnerabilityIds && cr.vulnerabilityIds.length > 0) {
      result.originalVulnerabilities = cr.vulnerabilityIds.map((id, index) => {
        return {
          vulnerabilityId: id,
          originalCvss: cr.originalCvss?.[index] || null,
          originalSeverity: cr.originalSeverities?.[index] || 'UNKNOWN'
        };
      });
    } else {
      result.originalVulnerabilities = [];
    }
  } else {
    result.contextRisk = null;
    result.originalVulnerabilities = [];
  }

  // Never return raw evidence_dependencies directly to avoid leaking internal keys
  delete result.evidence_dependencies;

  // Extract Transition Metadata for Point 6
  if (result.evidence_summary && result.evidence_summary.transitionMetadata) {
    const tm = result.evidence_summary.transitionMetadata;
    result.previousDecision = tm.previousDecision || 'NOT_AVAILABLE';
    result.currentDecision = tm.currentDecision || 'NOT_AVAILABLE';
    result.transitionId = tm.transitionId || 'NOT_AVAILABLE';
    result.transitionReason = tm.transitionReason || 'NOT_AVAILABLE';
    result.reevaluationTrigger = tm.reevaluationTrigger || 'NOT_AVAILABLE';
    result.lifecycleEffect = tm.lifecycleEffect || 'NOT_AVAILABLE';
  } else {
    result.previousDecision = 'NOT_AVAILABLE';
    result.currentDecision = result.trust_status || 'NOT_AVAILABLE';
    result.transitionId = 'NOT_AVAILABLE';
    result.transitionReason = 'NOT_AVAILABLE';
    result.reevaluationTrigger = 'NOT_AVAILABLE';
    result.lifecycleEffect = 'NOT_AVAILABLE';
  }

  return result;
}

/**
 * Handle retrieving latest trust decision or history
 */
async function handleGetTrustDecision(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  try {
    const sbomDoc = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!sbomDoc) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const history = await trustRepository.getTrustDecisionHistoryBySBOMID(sbomId.trim());
    const sanitizedHistory = history.map(sanitizeDecisionRecord);
    const latest = sanitizedHistory.length > 0 ? sanitizedHistory[0] : null;

    return res.status(200).json({
      sbomId: sbomId.trim(),
      latestDecision: latest,
      historyCount: sanitizedHistory.length,
      history: sanitizedHistory
    });
  } catch (err) {
    console.error('[TPSR] Error fetching trust decision:', err);
    return res.status(500).json({ error: 'Failed to retrieve trust decision', details: err.message });
  }
}

/**
 * Handle retrieving full evidence bundle
 */
async function handleGetTrustEvidence(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  try {
    const sbomDoc = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!sbomDoc) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const [provenance, signatures, vexStatements, depContexts, exceptions] = await Promise.all([
      sbomRepository.getProvenanceBySBOMID(sbomId.trim()),
      sbomRepository.getSignaturesBySBOMID(sbomId.trim()),
      sbomRepository.getVexStatementsBySBOMID(sbomId.trim()),
      sbomRepository.getDeploymentContextBySBOMID(sbomId.trim()),
      sbomRepository.getPolicyExceptionsBySBOMID(sbomId.trim())
    ]);

    return res.status(200).json({
      sbomId: sbomId.trim(),
      sbomHash: sbomDoc.sbom_hash,
      evidenceBundle: {
        provenanceCount: provenance.length,
        provenance: provenance,
        signatureCount: signatures.length,
        signatures: signatures,
        vexCount: vexStatements.length,
        vexStatements: vexStatements,
        deploymentContextCount: depContexts.length,
        deploymentContexts: depContexts,
        exceptionCount: exceptions.length,
        policyExceptions: exceptions
      },
      retrievedAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('[TPSR] Error fetching trust evidence:', err);
    return res.status(500).json({ error: 'Failed to retrieve trust evidence', details: err.message });
  }
}

router.post('/v1/sbom/:sbomId/trust-evaluation', handleEvaluateTrust);
router.post('/sbom/:sbomId/trust-evaluation', handleEvaluateTrust);
router.get('/v1/sbom/:sbomId/trust-decision', handleGetTrustDecision);
router.get('/sbom/:sbomId/trust-decision', handleGetTrustDecision);
router.get('/v1/sbom/:sbomId/trust-evidence', handleGetTrustEvidence);
router.get('/sbom/:sbomId/trust-evidence', handleGetTrustEvidence);

module.exports = router;
