'use strict';

const express = require('express');
const router = express.Router();
const sbomRepository = require('../repositories/sbomRepository');
const policyExceptionRepository = require('../repositories/policyExceptionRepository');
const policyExceptionEngine = require('../utils/policyExceptionEngine');

async function ensureSbomExists(sbomId) {
  const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId);
  return pgDocument;
}

// Request Exception
async function requestException(req, res) {
  const sbomId = req.params.sbomId.trim();
  const pgDocument = await ensureSbomExists(sbomId);
  if (!pgDocument) return res.status(404).json({ error: `SBOM not found: ${sbomId}` });

  if (!req.auth || !req.auth.userId) {
    return res.status(401).json({ error: 'Unauthenticated principal' });
  }
  const role = req.auth.role;
  const actor = req.auth.userId;

  const provenanceEngine = require('../utils/provenanceEngine');
  const policy = provenanceEngine.getTrustPolicy();
  const requestAuth = policy.contextAuthorizationRules && policy.contextAuthorizationRules.request_exception;
  if (!requestAuth || !requestAuth.allowedRoles || !requestAuth.allowedRoles.includes(role)) {
    return res.status(403).json({ error: 'Unauthorized role to request exception' });
  }

  const parsed = policyExceptionEngine.parseExceptionRequest({ ...req.body, sbomId });
  parsed.requestedByRole = role;
  parsed.requestedBy = actor;
  parsed.ownedBy = actor;
  parsed.ownerRole = role;
  parsed.digestManifestDigest = pgDocument.sbom_hash;

  if (!policyExceptionEngine.validateExceptionStructure(parsed)) {
    return res.status(400).json({ error: 'Invalid exception structure' });
  }

  try {
    const record = await policyExceptionRepository.createExceptionRequest(parsed);
    await policyExceptionRepository.recordExceptionEvent({
      exceptionId: record.id,
      sbomId: record.sbom_id,
      eventType: 'REQUESTED',
      previousStatus: null,
      newStatus: 'REQUESTED',
      actorId: parsed.requestedBy,
      actorRole: parsed.requestedByRole,
      policyVersion: record.policy_version,
      trustPolicyHash: record.trust_policy_hash
    });
    return res.status(201).json(record);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to create exception request', details: err.message });
  }
}

// Approve Exception
async function approveException(req, res) {
  const sbomId = req.params.sbomId.trim();
  const exceptionId = req.params.exceptionId.trim();
  if (!req.auth || !req.auth.userId) {
    return res.status(401).json({ error: 'Unauthenticated principal' });
  }
  const role = req.auth.role;
  const actor = req.auth.userId;

  const provenanceEngine = require('../utils/provenanceEngine');
  const policy = provenanceEngine.getTrustPolicy();
  const approveAuth = policy.contextAuthorizationRules && policy.contextAuthorizationRules.approve_exception;
  if (!approveAuth || !approveAuth.allowedRoles || !approveAuth.allowedRoles.includes(role)) {
    return res.status(403).json({ error: 'Unauthorized role to approve exception' });
  }

  const pgDocument = await ensureSbomExists(sbomId);
  if (!pgDocument) return res.status(404).json({ error: `SBOM not found: ${sbomId}` });

  const exception = await policyExceptionRepository.getExceptionById(exceptionId);
  if (!exception) return res.status(404).json({ error: 'Exception not found' });
  if (exception.status !== 'REQUESTED') return res.status(400).json({ error: 'Exception not in REQUESTED state' });

  // Convert db row to camelCase object for engine
  const exceptionData = {
    ...exception,
    sbomId: exception.sbom_id,
    digestManifestDigest: exception.digest_manifest_digest,
    policyRuleId: exception.policy_rule_id,
    requestedBy: exception.requested_by,
    requestedByRole: exception.requested_by_role,
    ownedBy: exception.owned_by,
    ownerRole: exception.owner_role,
    validFrom: exception.valid_from,
    validUntil: exception.valid_until,
    residualRisk: exception.residual_risk,
    compensatingControls: exception.compensating_controls,
    remediationPlan: exception.remediation_plan,
    reasonCode: exception.reason_code,
    justification: exception.justification,
    businessNeed: exception.business_need
  };

  const evalResult = policyExceptionEngine.evaluateExceptionApproval(
    exceptionData,
    { approverRole: role, approvedBy: actor },
    pgDocument.sbom_id,
    pgDocument.sbom_hash
  );

  if (!evalResult.separationOfDutiesPassed) {
    return res.status(403).json({ error: 'Separation of duties check failed' });
  }

  if (evalResult.derivedStatus !== 'ACTIVE') {
    return res.status(400).json({ error: 'Approval checks failed', details: evalResult });
  }

  try {
    const record = await policyExceptionRepository.approveException(exceptionId, {
      approvedBy: actor,
      approverRole: role,
      approvalComment: req.body.approvalComment || 'Approved',
      assuranceState: evalResult.assuranceState
    });

    await policyExceptionRepository.recordExceptionEvent({
      exceptionId,
      sbomId: exception.sbom_id,
      eventType: 'APPROVED',
      previousStatus: 'REQUESTED',
      newStatus: 'ACTIVE',
      actorId: actor,
      actorRole: role,
      reason: req.body.approvalComment || 'Approved',
      policyVersion: exception.policy_version,
      trustPolicyHash: exception.trust_policy_hash
    });

    // TODO: Trigger reevaluation (which is part of outbox pattern or worker later)
    return res.status(200).json(record);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to approve exception', details: err.message });
  }
}

// Reject Exception
async function rejectException(req, res) {
  const sbomId = req.params.sbomId.trim();
  const exceptionId = req.params.exceptionId.trim();
  if (!req.auth || !req.auth.userId) {
    return res.status(401).json({ error: 'Unauthenticated principal' });
  }
  const role = req.auth.role;
  const actor = req.auth.userId;

  const provenanceEngine = require('../utils/provenanceEngine');
  const policy = provenanceEngine.getTrustPolicy();
  const rejectAuth = policy.contextAuthorizationRules && policy.contextAuthorizationRules.reject_exception;
  if (!rejectAuth || !rejectAuth.allowedRoles || !rejectAuth.allowedRoles.includes(role)) {
    return res.status(403).json({ error: 'Unauthorized role to reject exception' });
  }

  if (!req.body.rejectionReason) return res.status(400).json({ error: 'Mandatory rejectionReason missing' });

  const exception = await policyExceptionRepository.getExceptionById(exceptionId);
  if (!exception) return res.status(404).json({ error: 'Exception not found' });
  if (exception.status !== 'REQUESTED') return res.status(400).json({ error: 'Exception not in REQUESTED state' });

  try {
    const record = await policyExceptionRepository.rejectException(exceptionId, {
      approvedBy: actor,
      approverRole: role,
      approvalComment: req.body.rejectionReason,
      assuranceState: 'INVALID'
    });

    await policyExceptionRepository.recordExceptionEvent({
      exceptionId,
      sbomId: exception.sbom_id,
      eventType: 'REJECTED',
      previousStatus: 'REQUESTED',
      newStatus: 'REJECTED',
      actorId: actor,
      actorRole: role,
      reason: req.body.rejectionReason,
      policyVersion: exception.policy_version,
      trustPolicyHash: exception.trust_policy_hash
    });

    return res.status(200).json(record);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to reject exception', details: err.message });
  }
}

// Revoke Exception
async function revokeException(req, res) {
  const exceptionId = req.params.exceptionId.trim();
  if (!req.auth || !req.auth.userId) {
    return res.status(401).json({ error: 'Unauthenticated principal' });
  }
  const role = req.auth.role;
  const actor = req.auth.userId;

  const provenanceEngine = require('../utils/provenanceEngine');
  const policy = provenanceEngine.getTrustPolicy();
  const revokeAuth = policy.contextAuthorizationRules && policy.contextAuthorizationRules.revoke_exception;
  if (!revokeAuth || !revokeAuth.allowedRoles || !revokeAuth.allowedRoles.includes(role)) {
    return res.status(403).json({ error: 'Unauthorized role to revoke exception' });
  }

  if (!req.body.revocationReason) return res.status(400).json({ error: 'Mandatory revocationReason missing' });

  const exception = await policyExceptionRepository.getExceptionById(exceptionId);
  if (!exception) return res.status(404).json({ error: 'Exception not found' });
  if (exception.status !== 'ACTIVE') return res.status(400).json({ error: 'Exception not in ACTIVE state' });

  try {
    const record = await policyExceptionRepository.revokeException(exceptionId, {
      revokedBy: actor,
      revocationReason: req.body.revocationReason
    });

    await policyExceptionRepository.recordExceptionEvent({
      exceptionId,
      sbomId: exception.sbom_id,
      eventType: 'REVOKED',
      previousStatus: 'ACTIVE',
      newStatus: 'REVOKED',
      actorId: actor,
      actorRole: role,
      reason: req.body.revocationReason,
      policyVersion: exception.policy_version,
      trustPolicyHash: exception.trust_policy_hash
    });

    // TODO: Trigger Reevaluation Worker or API call directly here for reevaluation
    const reevaluateWorker = require('../workers/exceptionExpiryWorker');
    if (reevaluateWorker.triggerReevaluationForSbom) {
      // Async reevaluation
      reevaluateWorker.triggerReevaluationForSbom(exception.sbom_id).catch(console.error);
    }

    return res.status(200).json(record);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to revoke exception', details: err.message });
  }
}

// Lists
async function listExceptions(req, res) {
  const sbomId = req.params.sbomId.trim();
  const records = await policyExceptionRepository.listExceptionsBySbomId(sbomId);
  res.json({ sbomId, count: records.length, policyExceptions: records });
}

async function listActiveExceptions(req, res) {
  const sbomId = req.params.sbomId.trim();
  const records = await policyExceptionRepository.getActiveExceptionsForDecision(sbomId);
  res.json({ sbomId, count: records.length, policyExceptions: records });
}

async function getExceptionHistory(req, res) {
  const sbomId = req.params.sbomId.trim();
  const exceptionId = req.params.exceptionId.trim();
  
  if (!req.auth || !req.auth.userId) {
    return res.status(401).json({ error: 'Unauthenticated principal' });
  }
  const role = req.auth.role;
  const policy = require('../utils/provenanceEngine').getTrustPolicy();
  const viewAuth = policy.contextAuthorizationRules && policy.contextAuthorizationRules.view_exception_history;
  if (!viewAuth || !viewAuth.allowedRoles || !viewAuth.allowedRoles.includes(role)) {
    return res.status(403).json({ error: 'Unauthorized role to view exception history' });
  }

  const db = require('../config/database');
  const query = 'SELECT * FROM policy_exception_events WHERE exception_id = $1 ORDER BY event_timestamp ASC';
  try {
    const result = await db.pool.query(query, [exceptionId]);
    return res.json({ exceptionId, history: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve exception history', details: err.message });
  }
}

async function supersedeException(req, res) {
  const sbomId = req.params.sbomId.trim();
  const exceptionId = req.params.exceptionId.trim();
  if (!req.auth || !req.auth.userId) {
    return res.status(401).json({ error: 'Unauthenticated principal' });
  }
  const role = req.auth.role;
  const actor = req.auth.userId;

  const provenanceEngine = require('../utils/provenanceEngine');
  const policy = provenanceEngine.getTrustPolicy();
  const supersedeAuth = policy.contextAuthorizationRules && policy.contextAuthorizationRules.supersede_exception;
  if (!supersedeAuth || !supersedeAuth.allowedRoles || !supersedeAuth.allowedRoles.includes(role)) {
    return res.status(403).json({ error: 'Unauthorized role to supersede exception' });
  }

  if (!req.body.supersedingExceptionId) return res.status(400).json({ error: 'Mandatory supersedingExceptionId missing' });

  const exception = await policyExceptionRepository.getExceptionById(exceptionId);
  if (!exception) return res.status(404).json({ error: 'Exception not found' });
  if (exception.status !== 'ACTIVE' && exception.status !== 'REQUESTED') return res.status(400).json({ error: 'Exception must be ACTIVE or REQUESTED to be superseded' });

  try {
    const record = await policyExceptionRepository.supersedeException(exceptionId, req.body.supersedingExceptionId);

    await policyExceptionRepository.recordExceptionEvent({
      exceptionId,
      sbomId: exception.sbom_id,
      eventType: 'SUPERSEDED',
      previousStatus: exception.status,
      newStatus: 'SUPERSEDED',
      actorId: actor,
      actorRole: role,
      reason: req.body.supersessionReason || 'Superseded',
      policyVersion: exception.policy_version,
      trustPolicyHash: exception.trust_policy_hash
    });

    return res.status(200).json(record);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to supersede exception', details: err.message });
  }
}

async function getException(req, res) {
  const exception = await policyExceptionRepository.getExceptionById(req.params.exceptionId);
  if (!exception) return res.status(404).json({ error: 'Exception not found' });
  res.json(exception);
}

router.post('/v1/sbom/:sbomId/exceptions', requestException);
router.post('/v1/sbom/:sbomId/exceptions/:exceptionId/approve', approveException);
router.post('/v1/sbom/:sbomId/exceptions/:exceptionId/reject', rejectException);
router.post('/v1/sbom/:sbomId/exceptions/:exceptionId/revoke', revokeException);
router.post('/v1/sbom/:sbomId/exceptions/:exceptionId/supersede', supersedeException);
router.get('/v1/sbom/:sbomId/exceptions', listExceptions);
router.get('/v1/sbom/:sbomId/exceptions/active', listActiveExceptions);
router.get('/v1/sbom/:sbomId/exceptions/:exceptionId', getException);
router.get('/v1/sbom/:sbomId/exceptions/:exceptionId/history', getExceptionHistory);

// Old routes support for tests if needed
router.post('/sbom/:sbomId/exceptions', requestException);
router.get('/sbom/:sbomId/exceptions', listExceptions);

module.exports = router;
