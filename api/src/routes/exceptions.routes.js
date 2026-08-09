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

  const role = req.headers['x-user-role'] || 'developer';
  if (!['developer', 'security'].includes(role)) {
    return res.status(403).json({ error: 'Unauthorized role' });
  }

  const parsed = policyExceptionEngine.parseExceptionRequest({ ...req.body, sbomId });
  parsed.requestedByRole = role;
  parsed.requestedBy = req.headers['x-user-id'] || 'test-user';
  parsed.ownedBy = parsed.ownedBy || parsed.requestedBy;
  parsed.ownerRole = parsed.ownerRole || role;
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
  const role = req.headers['x-user-role'] || 'security';
  const actor = req.headers['x-user-id'] || 'test-approver';

  if (!['security', 'admin'].includes(role)) {
    return res.status(403).json({ error: 'Unauthorized role' });
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
    policyRuleId: exception.policy_rule_id,
    requestedBy: exception.requested_by,
    requestedByRole: exception.requested_by_role,
    ownedBy: exception.owned_by,
    ownerRole: exception.owner_role,
    validFrom: exception.valid_from,
    validUntil: exception.valid_until,
    residualRisk: exception.residual_risk,
    compensatingControls: exception.compensating_controls,
    remediationPlan: exception.remediation_plan
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
  const role = req.headers['x-user-role'] || 'security';
  const actor = req.headers['x-user-id'] || 'test-approver';

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
  const role = req.headers['x-user-role'] || 'security';
  const actor = req.headers['x-user-id'] || 'test-approver';

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

async function getException(req, res) {
  const exception = await policyExceptionRepository.getExceptionById(req.params.exceptionId);
  if (!exception) return res.status(404).json({ error: 'Exception not found' });
  res.json(exception);
}

router.post('/v1/sbom/:sbomId/exceptions', requestException);
router.post('/v1/sbom/:sbomId/exceptions/:exceptionId/approve', approveException);
router.post('/v1/sbom/:sbomId/exceptions/:exceptionId/reject', rejectException);
router.post('/v1/sbom/:sbomId/exceptions/:exceptionId/revoke', revokeException);
router.get('/v1/sbom/:sbomId/exceptions', listExceptions);
router.get('/v1/sbom/:sbomId/exceptions/active', listActiveExceptions);
router.get('/v1/sbom/:sbomId/exceptions/:exceptionId', getException);

// Old routes support for tests if needed
router.post('/sbom/:sbomId/exceptions', requestException);
router.get('/sbom/:sbomId/exceptions', listExceptions);

module.exports = router;
