const db = require('../config/database');
const crypto = require('crypto');
const uuidv4 = crypto.randomUUID;

async function createExceptionRequest(data, client = null) {
  const query = `
    INSERT INTO policy_exceptions (
      id, exception_version, sbom_id, digest_manifest_digest, policy_rule_id,
      reason_code, vulnerability_ids, component_identifiers, environment,
      requested_by, requested_by_role, owned_by, owner_role, requested_at,
      valid_from, valid_until, justification, business_need, remediation_plan,
      compensating_controls, residual_risk, status, policy_version, trust_policy_hash
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(),
      $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
    ) RETURNING *;
  `;
  
  const id = data.id || uuidv4();
  const values = [
    id, data.exceptionVersion || 'v1', data.sbomId, data.digestManifestDigest, data.policyRuleId,
    data.reasonCode, JSON.stringify(data.vulnerabilityIds || []), JSON.stringify(data.componentIdentifiers || []), data.environment,
    data.requestedBy, data.requestedByRole, data.ownedBy, data.ownerRole,
    data.validFrom, data.validUntil, data.justification, data.businessNeed, data.remediationPlan,
    JSON.stringify(data.compensatingControls || []), data.residualRisk || 'MEDIUM', data.status || 'REQUESTED',
    data.policyVersion || 'unknown', data.trustPolicyHash || 'unknown'
  ];

  const executor = client || db.pool;
  const result = await executor.query(query, values);
  return result.rows[0];
}

async function getExceptionById(id, client = null) {
  const query = 'SELECT * FROM policy_exceptions WHERE id = $1';
  const executor = client || db.pool;
  const result = await executor.query(query, [id]);
  return result.rows[0] || null;
}

async function listExceptionsBySbomId(sbomId, client = null) {
  const query = 'SELECT * FROM policy_exceptions WHERE sbom_id = $1 ORDER BY created_at DESC';
  const executor = client || db.pool;
  const result = await executor.query(query, [sbomId]);
  return result.rows;
}

async function getActiveExceptionsForDecision(sbomId, client = null) {
  const query = 'SELECT * FROM policy_exceptions WHERE sbom_id = $1 AND status = $2 AND valid_until > NOW()';
  const executor = client || db.pool;
  const result = await executor.query(query, [sbomId, 'ACTIVE']);
  return result.rows;
}

async function approveException(id, approvalData, client = null) {
  const query = `
    UPDATE policy_exceptions
    SET status = 'ACTIVE', approved_by = $1, approver_role = $2, approved_at = NOW(),
        approval_comment = $3, assurance_state = $4, updated_at = NOW()
    WHERE id = $5 AND status = 'REQUESTED'
    RETURNING *;
  `;
  const executor = client || db.pool;
  const result = await executor.query(query, [
    approvalData.approvedBy, approvalData.approverRole, approvalData.approvalComment,
    approvalData.assuranceState, id
  ]);
  return result.rows[0] || null;
}

async function rejectException(id, rejectionData, client = null) {
  const query = `
    UPDATE policy_exceptions
    SET status = 'REJECTED', approved_by = $1, approver_role = $2, approved_at = NOW(),
        approval_comment = $3, assurance_state = $4, updated_at = NOW()
    WHERE id = $5 AND status = 'REQUESTED'
    RETURNING *;
  `;
  const executor = client || db.pool;
  const result = await executor.query(query, [
    rejectionData.approvedBy, rejectionData.approverRole, rejectionData.approvalComment,
    rejectionData.assuranceState, id
  ]);
  return result.rows[0] || null;
}

async function revokeException(id, revocationData, client = null) {
  const query = `
    UPDATE policy_exceptions
    SET status = 'REVOKED', revoked_by = $1, revoked_at = NOW(),
        revocation_reason = $2, updated_at = NOW()
    WHERE id = $3 AND status = 'ACTIVE'
    RETURNING *;
  `;
  const executor = client || db.pool;
  const result = await executor.query(query, [
    revocationData.revokedBy, revocationData.revocationReason, id
  ]);
  return result.rows[0] || null;
}

async function supersedeException(id, newExceptionId, client = null) {
  const query = `
    UPDATE policy_exceptions
    SET status = 'SUPERSEDED', supersedes_exception_id = $1, updated_at = NOW()
    WHERE id = $2 AND status = 'ACTIVE'
    RETURNING *;
  `;
  const executor = client || db.pool;
  const result = await executor.query(query, [newExceptionId, id]);
  return result.rows[0] || null;
}

async function findExceptionsExpiringBefore(date, client = null) {
  const query = 'SELECT * FROM policy_exceptions WHERE status = $1 AND valid_until <= $2 FOR UPDATE SKIP LOCKED';
  const executor = client || db.pool;
  const result = await executor.query(query, ['ACTIVE', date]);
  return result.rows;
}

async function markExpiredExceptions(ids, client = null) {
  if (!ids || ids.length === 0) return [];
  const query = `
    UPDATE policy_exceptions
    SET status = 'EXPIRED', updated_at = NOW(), assurance_state = 'STALE'
    WHERE id = ANY($1) AND status = 'ACTIVE'
    RETURNING *;
  `;
  const executor = client || db.pool;
  const result = await executor.query(query, [ids]);
  return result.rows;
}

async function getAffectedSbomIdsForExpiredExceptions(ids, client = null) {
  if (!ids || ids.length === 0) return [];
  const query = 'SELECT DISTINCT sbom_id FROM policy_exceptions WHERE id = ANY($1)';
  const executor = client || db.pool;
  const result = await executor.query(query, [ids]);
  return result.rows.map(r => r.sbom_id);
}

async function recordExceptionEvent(data, client = null) {
  const query = `
    INSERT INTO policy_exception_events (
      event_id, exception_id, sbom_id, event_type, previous_status, new_status,
      actor_id, actor_role, reason, event_timestamp, policy_version, trust_policy_hash, related_decision_id
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11, $12
    ) RETURNING *;
  `;
  const executor = client || db.pool;
  const result = await executor.query(query, [
    uuidv4(), data.exceptionId, data.sbomId, data.eventType, data.previousStatus, data.newStatus,
    data.actorId, data.actorRole, data.reason, data.policyVersion, data.trustPolicyHash, data.relatedDecisionId || null
  ]);
  return result.rows[0];
}

module.exports = {
  createExceptionRequest,
  getExceptionById,
  listExceptionsBySbomId,
  getActiveExceptionsForDecision,
  approveException,
  rejectException,
  revokeException,
  supersedeException,
  findExceptionsExpiringBefore,
  markExpiredExceptions,
  getAffectedSbomIdsForExpiredExceptions,
  recordExceptionEvent
};
