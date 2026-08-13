'use strict';

const db = require('../config/database');

async function createContextAssertion(client, assertion) {
  const query = `
    INSERT INTO deployment_context_assertions (
      id, assertion_version, sbom_id, digest_manifest_digest, canonical_assertion,
      assertion_payload_hash, environment, internet_exposure, asset_criticality,
      privilege_level, data_sensitivity, runtime_execution, component_presence,
      compensating_controls, asserted_by, assertor_role, asserted_at, valid_until,
      justification, previous_assertion_id, supersedes_assertion_id, signature_type,
      verification_mode, signer_identity, public_key_fingerprint, signature_verified,
      transparency_log_verified, verification_status, assurance_state, status,
      reason_codes, policy_version, trust_policy_hash, verified_at, created_at,
      evidence_source, matched_authorization_rule, correlation_id, authority_trusted, provenance_mode,
      authentication_mode, authentication_assurance
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
      $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35,
      $36, $37, $38, $39, $40, $41, $42
    ) RETURNING *;
  `;
  const values = [
    assertion.id, assertion.assertionVersion, assertion.sbomId, assertion.digestManifestDigest,
    JSON.stringify(assertion.canonicalAssertion), assertion.assertionPayloadHash, assertion.environment,
    assertion.internetExposure, assertion.assetCriticality, assertion.privilegeLevel,
    assertion.dataSensitivity, assertion.runtimeExecution, assertion.componentPresence,
    JSON.stringify(assertion.compensatingControls || []), assertion.assertedBy, assertion.assertorRole,
    assertion.assertedAt, assertion.validUntil, assertion.justification, assertion.previousAssertionId || null,
    assertion.supersedesAssertionId || null, assertion.signatureType, assertion.verificationMode,
    assertion.signerIdentity, assertion.publicKeyFingerprint, assertion.signatureVerified,
    assertion.transparencyLogVerified, assertion.verificationStatus, assertion.assuranceState,
    assertion.status, JSON.stringify(assertion.reasonCodes || []), assertion.policyVersion,
    assertion.trustPolicyHash || null, assertion.verifiedAt || new Date(), assertion.createdAt || new Date(),
    assertion.evidenceSource || null, assertion.matchedAuthorizationRule || null, assertion.correlationId || null,
    assertion.authorityTrusted || false, assertion.provenanceMode || 'CRYPTOGRAPHIC',
    assertion.authenticationMode || null, assertion.authenticationAssurance || null
  ];

  const result = await client.query(query, values);
  return result.rows[0];
}

async function getContextAssertionById(id) {
  const query = `SELECT * FROM deployment_context_assertions WHERE id = $1`;
  const result = await db.pool.query(query, [id]);
  return result.rows[0] || null;
}

async function listContextAssertionsBySbomId(sbomId) {
  const query = `SELECT * FROM deployment_context_assertions WHERE sbom_id = $1 ORDER BY created_at DESC`;
  const result = await db.pool.query(query, [sbomId]);
  return result.rows;
}

async function getActiveContextAssertion(sbomId, client = db.pool) {
  const query = `
    SELECT * FROM deployment_context_assertions
    WHERE sbom_id = $1 AND status = 'ACTIVE'
    ORDER BY created_at DESC LIMIT 1
  `;
  const result = await client.query(query, [sbomId]);
  return result.rows[0] || null;
}

async function revokeContextAssertion(client, assertionId, justification, revokedBy) {
  const query = `
    UPDATE deployment_context_assertions
    SET status = 'REVOKED', justification = COALESCE(justification || '; ', '') || 'Revoked: ' || $2,
        revoked_by = $3, revoked_at = CURRENT_TIMESTAMP
    WHERE id = $1 AND status = 'ACTIVE'
    RETURNING *;
  `;
  const result = await client.query(query, [assertionId, justification, revokedBy || 'unknown']);
  return result.rows[0] || null;
}

async function supersedeContextAssertion(client, oldAssertionId, newAssertionId) {
  const query = `
    UPDATE deployment_context_assertions
    SET status = 'SUPERSEDED', supersedes_assertion_id = $2
    WHERE id = $1 AND status = 'ACTIVE'
    RETURNING *;
  `;
  const result = await client.query(query, [oldAssertionId, newAssertionId]);
  return result.rows[0] || null;
}

async function findConflictingActiveAssertions(client, sbomId, newEnvironment) {
  const query = `
    SELECT * FROM deployment_context_assertions
    WHERE sbom_id = $1 AND status = 'ACTIVE' AND environment != $2
    FOR UPDATE SKIP LOCKED;
  `;
  const result = await client.query(query, [sbomId, newEnvironment]);
  return result.rows;
}

module.exports = {
  createContextAssertion,
  getContextAssertionById,
  listContextAssertionsBySbomId,
  getActiveContextAssertion,
  revokeContextAssertion,
  supersedeContextAssertion,
  findConflictingActiveAssertions
};
