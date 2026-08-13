const db = require('../config/database');

async function getLatestPolicyGeneration(policyId) {
  const res = await db.pool.query(
    'SELECT * FROM trust_policy_generations WHERE policy_id = $1 ORDER BY generation DESC LIMIT 1',
    [policyId]
  );
  return res.rows[0] || null;
}

async function insertPolicyGeneration(gen) {
  const res = await db.pool.query(
    `INSERT INTO trust_policy_generations 
     (policy_id, generation, schema_version, policy_hash, maximum_age_hours, loaded_by, loaded_at) 
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
    [gen.policyId, gen.generation, gen.schemaVersion, gen.policyHash, gen.maximumAgeHours, gen.loadedBy, gen.loadedAt]
  );
  return res.rows[0];
}

async function getActiveRevocations() {
  const res = await db.pool.query(
    'SELECT * FROM trust_policy_revocations WHERE revocation_time <= NOW()'
  );
  return res.rows;
}

async function insertRevocation(rev) {
  const res = await db.pool.query(
    `INSERT INTO trust_policy_revocations 
     (subject_type, subject_identifier, revocation_time, revocation_reason, revoked_by) 
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [rev.subjectType, rev.subjectIdentifier, rev.revocationTime, rev.revocationReason, rev.revokedBy]
  );
  return res.rows[0];
}

async function insertObservabilityEvent(evt) {
  await db.pool.query(
    `INSERT INTO security_observability_events 
     (event_type, correlation_id, policy_id, policy_generation, rule_id, reason_code, subject_fingerprint) 
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [evt.eventType, evt.correlationId, evt.policyId, evt.policyGeneration, evt.ruleId, evt.reasonCode, evt.subjectFingerprint]
  );
}

module.exports = {
  getLatestPolicyGeneration,
  insertPolicyGeneration,
  getActiveRevocations,
  insertRevocation,
  insertObservabilityEvent
};
