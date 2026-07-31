'use strict';

const express = require('express');
const router = express.Router();
const sbomRepository = require('../repositories/sbomRepository');
const trustRepository = require('../repositories/trustRepository');
const { evaluateTrust } = require('../utils/trustEngine');

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

    const [provenance, signatures, vexStatements, depContexts, exceptions] = await Promise.all([
      sbomRepository.getProvenanceBySBOMID(sbomId.trim()),
      sbomRepository.getSignaturesBySBOMID(sbomId.trim()),
      sbomRepository.getVexStatementsBySBOMID(sbomId.trim()),
      sbomRepository.getDeploymentContextBySBOMID(sbomId.trim()),
      sbomRepository.getPolicyExceptionsBySBOMID(sbomId.trim())
    ]);

    const latestContext = depContexts.length > 0 ? depContexts[0] : null;

    const evalResult = await evaluateTrust({
      sbomDocument: sbomDoc,
      provenance,
      signatures,
      vexStatements,
      deploymentContext: latestContext,
      policyExceptions: exceptions
    });

    const dbDecision = await trustRepository.insertTrustDecision({
      sbomId: sbomId.trim(),
      trustStatus: evalResult.trustStatus,
      reasonCode: evalResult.reasonCode,
      reasonDescription: evalResult.reasonDescription,
      evidenceSummary: evalResult.evidenceSummary,
      policyVersion: evalResult.policyVersion,
      evaluatedBy: req.headers['x-user-id'] || 'security-officer',
      idempotencyKey: idempotencyKey ? idempotencyKey.trim() : null
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
      evaluatedAt: dbDecision.evaluated_at
    });
  } catch (err) {
    console.error('[TPSR] Error evaluating trust:', err);
    return res.status(500).json({ error: 'Failed to execute trust evaluation', details: err.message });
  }
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
    const latest = history.length > 0 ? history[0] : null;

    return res.status(200).json({
      sbomId: sbomId.trim(),
      latestDecision: latest,
      historyCount: history.length,
      history: history
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
