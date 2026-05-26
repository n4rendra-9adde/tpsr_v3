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
  updateSBOMStatus: updateSBOMStatus
};
