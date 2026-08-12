'use strict';

var db = require('../config/database');

/**
 * Insert a new SBOM document record into PostgreSQL.
 * @param {Object} record
 * @returns {Promise<Object>} The inserted row.
 */
async function insertSBOMDocument(record) {
  var fabricChannel = record.fabricChannel || 'tpsrchannel';
  var fabricChaincode = record.fabricChaincode || 'sbom';
  var canonicalizationVersion = record.canonicalizationVersion || 'v1';

  var query = `
    INSERT INTO sbom_documents (
      sbom_id, build_id, software_name, software_version, format,
      status, sbom_hash, sbom_json, submitter_id, requested_by,
      job_name, build_number, git_commit, git_branch, repository_url,
      off_chain_ref, fabric_tx_id, fabric_channel, fabric_chaincode,
      signatures, canonicalization_version,
      policy_status, policy_reason, policy_violations, policy_evaluation_mode
    ) VALUES (
      $1, $2, $3, $4, $5,
      $6, $7, $8, $9, $10,
      $11, $12, $13, $14, $15,
      $16, $17, $18, $19,
      $20, $21,
      $22, $23, $24, $25
    ) RETURNING *;
  `;

  var values = [
    record.sbomID,
    record.buildID,
    record.softwareName,
    record.softwareVersion,
    record.format,
    record.status || 'PENDING',
    record.sbomHash,
    record.sbomJSON,
    record.submitterID,
    record.requestedBy,
    record.jobName,
    record.buildNumber,
    record.gitCommit,
    record.gitBranch,
    record.repositoryURL,
    record.offChainRef,
    record.fabricTxID,
    fabricChannel,
    fabricChaincode,
    record.signatures ? JSON.stringify(record.signatures) : '[]',
    canonicalizationVersion,
    record.policyStatus || null,
    record.policyReason || null,
    record.policyViolations ? JSON.stringify(record.policyViolations) : '[]',
    record.policyEvaluationMode || null
  ];

  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

/**
 * Insert a new artifact record linked to an SBOM document in PostgreSQL.
 * @param {Object} record
 * @returns {Promise<Object>} The inserted row.
 */
async function insertArtifactRecord(record) {
  var query = `
    INSERT INTO artifact_records (
      sbom_document_id, artifact_type, artifact_name,
      artifact_hash, artifact_uri, size_bytes
    ) VALUES (
      $1, $2, $3,
      $4, $5, $6
    ) RETURNING *;
  `;

  var values = [
    record.sbomDocumentID,
    record.artifactType,
    record.artifactName,
    record.artifactHash,
    record.artifactURI,
    record.sizeBytes
  ];

  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

/**
 * Fetch an SBOM document by its sbom_id.
 * @param {string} sbomID
 * @returns {Promise<Object|null>} The row, or null if not found.
 */
async function getSBOMDocumentBySBOMID(sbomID) {
  var query = 'SELECT * FROM sbom_documents WHERE sbom_id = $1;';
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, [sbomID]);
    if (result.rows.length === 0) {
      return null;
    }
    return result.rows[0];
  } finally {
    client.release();
  }
}

/**
 * Fetch all artifact records for a given SBOM document.
 * @param {string} sbomDocumentID
 * @returns {Promise<Array>} Array of rows, ordered by created_at ascending.
 */
async function getArtifactRecordsBySBOMDocumentID(sbomDocumentID) {
  var query = 'SELECT * FROM artifact_records WHERE sbom_document_id = $1 ORDER BY created_at ASC;';
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, [sbomDocumentID]);
    return result.rows;
  } finally {
    client.release();
  }
}

/**
 * Fetch an SBOM document along with its associated artifacts by sbom_id.
 * @param {string} sbomID
 * @returns {Promise<Object|null>} Object containing document and artifacts, or null if document not found.
 */
async function getSBOMDocumentWithArtifactsBySBOMID(sbomID) {
  var document = await getSBOMDocumentBySBOMID(sbomID);
  if (!document) {
    return null;
  }
  
  var artifacts = await getArtifactRecordsBySBOMDocumentID(document.id);
  
  return {
    document: document,
    artifacts: artifacts
  };
}

/**
 * Update the status, optionally fabric_tx_id, and optionally submitter_id of an SBOM document.
 * @param {string} sbomID
 * @param {string} status
 * @param {string} [fabricTxID]
 * @param {string} [submitterID]
 * @returns {Promise<Object|null>} The updated row.
 */
async function updateSBOMStatus(sbomID, status, fabricTxID, submitterID) {
  var setClauses = ['status = $2'];
  var values = [sbomID, status];
  var paramIndex = 3;

  if (fabricTxID) {
    setClauses.push('fabric_tx_id = $' + paramIndex);
    values.push(fabricTxID);
    paramIndex++;
  }

  if (submitterID) {
    setClauses.push('submitter_id = $' + paramIndex);
    values.push(submitterID);
    paramIndex++;
  }

  var query = 'UPDATE sbom_documents SET ' + setClauses.join(', ') + ' WHERE sbom_id = $1 RETURNING *;';

  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    if (result.rows.length === 0) {
      return null;
    }
    return result.rows[0];
  } finally {
    client.release();
  }
}

/**
 * Update an existing SBOM document record after Fabric submission.
 * @param {Object} record
 * @returns {Promise<Object>} The updated row.
 */
async function finalizeSBOMDocument(record) {
  var query = `
    UPDATE sbom_documents
    SET fabric_tx_id = $2,
        off_chain_ref = $3,
        submitter_id = $4,
        status = $5
    WHERE id = $1
    RETURNING *;
  `;

  var values = [
    record.id,
    record.fabricTxID,
    record.offChainRef,
    record.submitterID,
    record.status
  ];

  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

/**
 * Delete an SBOM document by its ID for rollback.
 * @param {string} id
 * @returns {Promise<Object|null>} The deleted row, or null if not found.
 */
async function deleteSBOMDocumentByID(id) {
  var query = 'DELETE FROM sbom_documents WHERE id = $1 RETURNING *;';
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, [id]);
    if (result.rows.length === 0) {
      return null;
    }
    return result.rows[0];
  } finally {
    client.release();
  }
}

/**
 * Return the newest SBOM documents from PostgreSQL.
 * @param {number} [limit]
 * @returns {Promise<Array>} Array of rows, ordered by created_at descending.
 */
async function listSBOMDocuments(limit) {
  var limitVal = 100;
  if (limit !== undefined && limit !== null) {
    var parsed = parseInt(limit, 10);
    if (!isNaN(parsed) && parsed > 0) {
      limitVal = parsed;
    }
  }

  var query = 'SELECT * FROM sbom_documents ORDER BY created_at DESC LIMIT $1;';
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, [limitVal]);
    return result.rows;
  } finally {
    client.release();
  }
}

/**
 * Insert a new verification event record into PostgreSQL.
 * @param {Object} record
 * @returns {Promise<Object>} The inserted row.
 */
async function insertVerificationEvent(record) {
  var query = `
    INSERT INTO verification_events (
      sbom_document_id, submitted_hash, stored_hash,
      match, verified_by, verifier_role,
      verification_mode, fabric_tx_id,
      tamper_detected, tamper_type, affected_components, tamper_report
    ) VALUES (
      $1, $2, $3,
      $4, $5, $6,
      $7, $8,
      $9, $10, $11, $12
    ) RETURNING *;
  `;

  var values = [
    record.sbomDocumentID,
    record.submittedHash,
    record.storedHash,
    record.match,
    record.verifiedBy,
    record.verifierRole,
    record.verificationMode,
    record.fabricTxID || null,
    record.tamperDetected || false,
    record.tamperType || null,
    record.affectedComponents ? JSON.stringify(record.affectedComponents) : '[]',
    record.tamperReport ? JSON.stringify(record.tamperReport) : null
  ];

  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

/**
 * Insert a new compliance report record into PostgreSQL.
 * @param {Object} record
 * @returns {Promise<Object>} The inserted row.
 */
async function insertComplianceReport(record) {
  var query = `
    INSERT INTO compliance_reports (
      sbom_document_id, integrity_match, ledger_status,
      history_count, latest_tx_id, latest_timestamp,
      latest_is_delete, compliant, generated_by
    ) VALUES (
      $1, $2, $3,
      $4, $5, $6,
      $7, $8, $9
    ) RETURNING *;
  `;

  var values = [
    record.sbomDocumentID,
    record.integrityMatch,
    record.ledgerStatus,
    record.historyCount,
    record.latestTxID,
    record.latestTimestamp,
    record.latestIsDelete,
    record.compliant,
    record.generatedBy
  ];

  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

async function insertProvenanceAttestation(record) {
  var query = `
    INSERT INTO provenance_attestations (
      sbom_id, artifact_hash, attestation_type, builder_id,
      slsa_level, payload, attestation_hash, status,
      envelope_hash, predicate_type, predicate_version,
      source_repository, source_commit, build_type,
      external_parameters, build_started_on, build_finished_on,
      signature_status, verification_status, public_key_fingerprint,
      signer_identity, policy_version, trust_policy_hash, reason_codes, verified_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)
    RETURNING *;
  `;
  var values = [
    record.sbomId,
    record.artifactHash,
    record.attestationType,
    record.builderId,
    record.slsaLevel,
    JSON.stringify(record.payload),
    record.attestationHash,
    record.status || 'VALID',
    record.envelopeHash || null,
    record.predicateType || null,
    record.predicateVersion || null,
    record.sourceRepository || null,
    record.sourceCommit || null,
    record.buildType || null,
    record.externalParameters ? JSON.stringify(record.externalParameters) : null,
    record.buildStartedOn || null,
    record.buildFinishedOn || null,
    record.signatureStatus || 'UNVERIFIED',
    record.verificationStatus || 'FAILED',
    record.publicKeyFingerprint || null,
    record.signerIdentity || null,
    record.policyVersion || null,
    record.trustPolicyHash || null,
    record.reasonCodes ? JSON.stringify(record.reasonCodes) : null,
    record.status === 'VALID' ? new Date().toISOString() : null
  ];
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

async function getProvenanceBySBOMID(sbomID) {
  var query = `SELECT * FROM provenance_attestations WHERE sbom_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC;`;
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, [sbomID]);
    return result.rows;
  } finally {
    client.release();
  }
}

async function insertSignatureVerification(record) {
  var query = `
    INSERT INTO signature_verifications (
      sbom_id, artifact_hash, signature_type, signer_identity,
      verification_status, bundle_json, signature_hash,
      public_key_fingerprint, verification_mode, failure_reason
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    RETURNING *;
  `;
  var values = [
    record.sbomId,
    record.artifactHash,
    record.signatureType,
    record.signerIdentity,
    record.verificationStatus || 'VERIFIED',
    record.bundleJson ? JSON.stringify(record.bundleJson) : null,
    record.signatureHash,
    record.publicKeyFingerprint || null,
    record.verificationMode || 'offline-keyed',
    record.failureReason || null
  ];
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

async function getSignaturesBySBOMID(sbomID) {
  var query = `SELECT * FROM signature_verifications WHERE sbom_id = $1 AND deleted_at IS NULL ORDER BY verified_at DESC;`;
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, [sbomID]);
    return result.rows;
  } finally {
    client.release();
  }
}

async function insertVexStatement(record) {
  var query = `
    INSERT INTO vex_statements (
      sbom_id, vulnerability_id, original_severity, original_cvss,
      applicability_status, policy_impact, justification, impact_statement,
      statement_payload, issuer_identity, statement_issued_at,
      statement_last_updated_at, policy_valid_until,
      statement_hash, public_key_fingerprint, signature_status,
      format, format_version, product_identifiers, release_identifiers,
      component_identifiers, vulnerability_identifiers, applicability_disposition,
      policy_blocking_status, reason_codes, trust_policy_hash, action_statement,
      verified_at, policy_version, verification_mode, transparency_log_status,
      digest_manifest_reference, statement_id, vex_authoritative,
      canonical_payload_digest, policy_id, target_binding, verifier_version
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38)
    RETURNING *;
  `;
  var now = new Date().toISOString();
  var values = [
    record.sbomId,
    record.vulnerabilityId || 'UNKNOWN-CVE',
    record.originalSeverity || 'UNKNOWN',
    record.originalCvss || 0,
    record.status || 'not_affected',
    record.policyImpact || 'SUPPRESSED',
    record.justification || null,
    record.impactStatement || null,
    JSON.stringify(record.payload || {}),
    record.issuerIdentity || 'security-team',
    record.issuedAt || now,
    record.lastUpdatedAt || now,
    record.validUntil || new Date(Date.now() + 31536000000).toISOString(),
    record.statementHash || null,
    record.publicKeyFingerprint || null,
    record.signatureStatus || null,
    record.format || 'OpenVEX',
    record.formatVersion || 'v0.2.0',
    record.productIdentifiers ? JSON.stringify(record.productIdentifiers) : null,
    record.releaseIdentifiers ? JSON.stringify(record.releaseIdentifiers) : null,
    record.componentIdentifiers ? JSON.stringify(record.componentIdentifiers) : null,
    record.vulnerabilityIdentifiers ? JSON.stringify(record.vulnerabilityIdentifiers) : null,
    record.applicabilityDisposition || null,
    record.policyBlockingStatus || null,
    record.reasonCodes ? JSON.stringify(record.reasonCodes) : null,
    record.trustPolicyHash || null,
    record.actionStatement || null,
    record.verifiedAt || null,
    record.policyVersion || null,
    record.verificationMode || null,
    record.transparencyLogStatus || null,
    record.digestManifestReference ? JSON.stringify(record.digestManifestReference) : null,
    record.statementId || null,
    record.vexAuthoritative || false,
    record.canonicalPayloadDigest || null,
    record.policyId || null,
    record.targetBinding ? JSON.stringify(record.targetBinding) : null,
    record.verifierVersion || null
  ];
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

async function getVexStatementsBySBOMID(sbomID) {
  var query = `SELECT * FROM vex_statements WHERE sbom_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC;`;
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, [sbomID]);
    return result.rows;
  } finally {
    client.release();
  }
}

async function insertDeploymentContext(record) {
  var query = `
    INSERT INTO deployment_contexts (
      sbom_id, environment, network_exposure, data_sensitivity,
      privilege_level, compensating_controls, risk_multiplier
    ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *;
  `;
  var values = [
    record.sbomId,
    record.environment || 'PROD',
    record.networkExposure || 'INTERNAL',
    record.dataSensitivity || 'INTERNAL',
    record.privilegeLevel || 'STANDARD',
    JSON.stringify(record.compensatingControls || []),
    record.riskMultiplier || 1.00
  ];
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

async function getDeploymentContextBySBOMID(sbomID) {
  var query = `SELECT * FROM deployment_contexts WHERE sbom_id = $1 AND deleted_at IS NULL ORDER BY registered_at DESC;`;
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, [sbomID]);
    return result.rows;
  } finally {
    client.release();
  }
}

async function insertPolicyException(record) {
  var query = `
    INSERT INTO policy_exceptions (
      sbom_id, violation_id, violation_type, justification,
      compensating_controls, requested_by, approved_by, status, valid_until
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    RETURNING *;
  `;
  var values = [
    record.sbomId,
    record.violationId || 'POL-V01',
    record.violationType || 'VULNERABILITY_THRESHOLD',
    record.justification || 'Operational necessity with compensating controls',
    record.compensatingControls || null,
    record.requestedBy || 'developer',
    record.approvedBy || 'security-officer',
    record.status || 'APPROVED',
    record.validUntil || new Date(Date.now() + 2592000000).toISOString()
  ];
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, values);
    return result.rows[0];
  } finally {
    client.release();
  }
}

async function getPolicyExceptionsBySBOMID(sbomID) {
  var query = `SELECT * FROM policy_exceptions WHERE sbom_id = $1 AND deleted_at IS NULL AND status = 'ACTIVE' AND valid_until > CURRENT_TIMESTAMP ORDER BY created_at DESC;`;
  var client = await db.pool.connect();
  try {
    var result = await client.query(query, [sbomID]);
    return result.rows;
  } finally {
    client.release();
  }
}

module.exports = {
  insertSBOMDocument: insertSBOMDocument,
  insertArtifactRecord: insertArtifactRecord,
  getSBOMDocumentBySBOMID: getSBOMDocumentBySBOMID,
  getArtifactRecordsBySBOMDocumentID: getArtifactRecordsBySBOMDocumentID,
  getSBOMDocumentWithArtifactsBySBOMID: getSBOMDocumentWithArtifactsBySBOMID,
  finalizeSBOMDocument: finalizeSBOMDocument,
  deleteSBOMDocumentByID: deleteSBOMDocumentByID,
  listSBOMDocuments: listSBOMDocuments,
  insertVerificationEvent: insertVerificationEvent,
  insertComplianceReport: insertComplianceReport,
  updateSBOMStatus: updateSBOMStatus,
  insertProvenanceAttestation: insertProvenanceAttestation,
  getProvenanceBySBOMID: getProvenanceBySBOMID,
  insertSignatureVerification: insertSignatureVerification,
  getSignaturesBySBOMID: getSignaturesBySBOMID,
  insertVexStatement: insertVexStatement,
  getVexStatementsBySBOMID: getVexStatementsBySBOMID,
  insertDeploymentContext: insertDeploymentContext,
  getDeploymentContextBySBOMID: getDeploymentContextBySBOMID,
  insertPolicyException: insertPolicyException,
  getPolicyExceptionsBySBOMID: getPolicyExceptionsBySBOMID
};
