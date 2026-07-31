'use strict';

const db = require('../config/database');

/**
 * TPSR v3 Trust-Decision Compatibility Mapper
 *
 * Normalizes historical trust status values read from PostgreSQL or the Fabric
 * ledger to the authoritative four-state TPSR v3 enum at read time.
 *
 * Compatibility contract:
 *   - 'UNTRUSTED' (pre-v3 enum, stored before the four-state migration) → 'REJECTED'
 *   - All other values pass through unchanged.
 *
 * This function MUST NOT be used when writing new authoritative decisions.
 * New evaluations must always use trustEngine.TRUST_STATUS constants directly.
 *
 * Historical records are preserved as-is in the database; this mapper applies
 * only in memory during the current read operation.
 *
 * @param {string|null|undefined} status - Trust status string from DB or ledger
 * @returns {string} Normalized trust status
 */
function normalizeTrustStatus(status) {
  if (!status) {
    return { trustDecision: 'UNEVALUATED', legacyNormalized: false };
  }
  var upperTs = status.toUpperCase();
  if (upperTs === 'UNTRUSTED') {
    return {
      trustDecision: 'REJECTED',
      legacyDecision: 'UNTRUSTED',
      legacyNormalized: true
    };
  }
  // If it's a known authoritative state, return it directly
  if (['TRUSTED', 'CONDITIONALLY_ACCEPTED', 'REVIEW_REQUIRED', 'REJECTED', 'UNEVALUATED'].includes(upperTs)) {
    return { trustDecision: upperTs, legacyNormalized: false };
  }
  return { trustDecision: 'UNEVALUATED', legacyNormalized: false };
}


async function insertTrustDecision(record) {
  // Validate the authoritative trust-decision enum before any DB write.
  const AUTHORITATIVE_DECISIONS = ['TRUSTED', 'CONDITIONALLY_ACCEPTED', 'REVIEW_REQUIRED', 'REJECTED'];
  if (!AUTHORITATIVE_DECISIONS.includes(record.trustStatus)) {
    throw new Error(
      `insertTrustDecision: invalid trustStatus '${record.trustStatus}'. ` +
      `Only TRUSTED, CONDITIONALLY_ACCEPTED, REVIEW_REQUIRED, or REJECTED are permitted. ` +
      `UNTRUSTED is not an authoritative v3 decision. Use REJECTED instead.`
    );
  }

  const query = `
    INSERT INTO trust_decision_history (
      sbom_id, trust_status, reason_code, reason_description,
      evidence_summary, policy_version, evaluated_by, idempotency_key
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING *;
  `;
  const values = [
    record.sbomId,
    record.trustStatus,
    record.reasonCode || 'TRST-000',
    record.reasonDescription || 'Trust evaluation recorded',
    JSON.stringify(record.evidenceSummary || {}),
    record.policyVersion || '3.0',
    record.evaluatedBy || 'system',
    record.idempotencyKey || null
  ];

  const client = await db.pool.connect();
  try {
    const result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

async function getLatestTrustDecisionBySBOMID(sbomID) {
  const query = `
    SELECT * FROM trust_decision_history
    WHERE sbom_id = $1 AND deleted_at IS NULL
    ORDER BY evaluated_at DESC LIMIT 1;
  `;
  const client = await db.pool.connect();
  try {
    const result = await client.query(query, [sbomID]);
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function getTrustDecisionHistoryBySBOMID(sbomID) {
  const query = `
    SELECT * FROM trust_decision_history
    WHERE sbom_id = $1 AND deleted_at IS NULL
    ORDER BY evaluated_at DESC;
  `;
  const client = await db.pool.connect();
  try {
    const result = await client.query(query, [sbomID]);
    return result.rows;
  } finally {
    client.release();
  }
}

async function getTrustDecisionByIdempotencyKey(key) {
  if (!key) return null;
  const query = `
    SELECT * FROM trust_decision_history
    WHERE idempotency_key = $1 AND deleted_at IS NULL LIMIT 1;
  `;
  const client = await db.pool.connect();
  try {
    const result = await client.query(query, [key]);
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function insertContextEvaluation(record) {
  const query = `
    INSERT INTO context_evaluations (
      sbom_id, vulnerability_id, raw_cvss, adjusted_cvss,
      risk_multiplier, context_factors
    ) VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING *;
  `;
  const values = [
    record.sbomId,
    record.vulnerabilityId || 'UNKNOWN-CVE',
    record.rawCvss || 0,
    record.adjustedCvss || 0,
    record.riskMultiplier || 1.0,
    JSON.stringify(record.contextFactors || {})
  ];
  const client = await db.pool.connect();
  try {
    const result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

async function getContextEvaluationsBySBOMID(sbomID) {
  const query = `
    SELECT * FROM context_evaluations
    WHERE sbom_id = $1 AND deleted_at IS NULL
    ORDER BY evaluated_at DESC;
  `;
  const client = await db.pool.connect();
  try {
    const result = await client.query(query, [sbomID]);
    return result.rows;
  } finally {
    client.release();
  }
}

/**
 * Ledger outbox methods
 */
async function insertOutboxRecord(record) {
  if (record.action !== 'RECORD_TRUST_DECISION' && record.action !== 'RECORD_TRUST_EVIDENCE') {
    throw new Error(`Unsupported outbox action: ${record.action}`);
  }

  const query = `
    INSERT INTO ledger_outbox (
      sbom_id, decision_id, action, payload, status, next_attempt_at
    ) VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING *;
  `;
  const values = [
    record.sbomId,
    record.decisionId,
    record.action,
    JSON.stringify(record.payload || {}),
    record.status || 'PENDING',
    record.nextAttemptAt || new Date().toISOString()
  ];
  const client = await db.pool.connect();
  try {
    const result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

/**
 * Claim pending outbox records atomically using FOR UPDATE SKIP LOCKED
 */
async function claimPendingOutboxRecords(batchSize = 10, workerId = 'worker-1') {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');

    const selectQuery = `
      SELECT id, action, payload FROM ledger_outbox
      WHERE status IN ('PENDING', 'RETRY_PENDING')
        AND next_attempt_at <= CURRENT_TIMESTAMP
        AND deleted_at IS NULL
      ORDER BY created_at ASC
      LIMIT $1
      FOR UPDATE SKIP LOCKED;
    `;
    const selectRes = await client.query(selectQuery, [batchSize]);
    const ids = selectRes.rows.map(r => r.id);

    if (ids.length === 0) {
      await client.query('COMMIT');
      return [];
    }

    const updateQuery = `
      UPDATE ledger_outbox
      SET status = 'PROCESSING',
          locked_at = CURRENT_TIMESTAMP,
          locked_by = $1,
          last_attempt_at = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP,
          retry_count = retry_count + 1
      WHERE id = ANY($2::uuid[])
      RETURNING *;
    `;
    const updateRes = await client.query(updateQuery, [workerId, ids]);
    await client.query('COMMIT');
    return updateRes.rows;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function updateOutboxRecordStatus(id, status, errorMsg = null, txId = null, nextAttemptAt = null) {
  const query = `
    UPDATE ledger_outbox
    SET status = $1,
        error_message = $2,
        fabric_tx_id = COALESCE($3, fabric_tx_id),
        next_attempt_at = COALESCE($4, next_attempt_at),
        locked_at = NULL,
        locked_by = NULL,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = $5
    RETURNING *;
  `;
  const values = [status, errorMsg, txId, nextAttemptAt, id];
  const client = await db.pool.connect();
  try {
    const result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

async function getOutboxRecordsBySBOMID(sbomID) {
  const query = `
    SELECT * FROM ledger_outbox
    WHERE sbom_id = $1 AND deleted_at IS NULL
    ORDER BY created_at DESC;
  `;
  const client = await db.pool.connect();
  try {
    const result = await client.query(query, [sbomID]);
    return result.rows;
  } finally {
    client.release();
  }
}

async function getOutboxRecordByID(id) {
  const query = `
    SELECT * FROM ledger_outbox
    WHERE id = $1 AND deleted_at IS NULL LIMIT 1;
  `;
  const client = await db.pool.connect();
  try {
    const result = await client.query(query, [id]);
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

module.exports = {
  normalizeTrustStatus,
  insertTrustDecision,
  getLatestTrustDecisionBySBOMID,
  getTrustDecisionHistoryBySBOMID,
  getTrustDecisionByIdempotencyKey,
  insertContextEvaluation,
  getContextEvaluationsBySBOMID,
  insertOutboxRecord,
  claimPendingOutboxRecords,
  updateOutboxRecordStatus,
  getOutboxRecordsBySBOMID,
  getOutboxRecordByID
};
