'use strict';

const express = require('express');
const router = express.Router();
const sbomRepository = require('../repositories/sbomRepository');
const { verifyVexDocument } = require('../utils/vexEngine');

/**
 * Handle VEX statement submission and evaluation
 */
async function handleRecordVex(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  const { envelope, signatureType, publicKey, targetContext } = req.body || {};
  if (!envelope) {
    return res.status(400).json({ error: 'envelope parameter is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const evalResult = await verifyVexDocument(envelope, signatureType, publicKey, targetContext);

    // If context is given, pull its details for persistence
    const vulnerabilityId = targetContext?.vulnerabilityId || 'UNKNOWN-CVE';
    const originalSeverity = targetContext?.originalSeverity || 'UNKNOWN';
    const originalCvss = targetContext?.originalCvss || 0;

    const dbRecord = await sbomRepository.insertVexStatement({
      sbomId: sbomId.trim(),
      vulnerabilityId: vulnerabilityId,
      originalSeverity: originalSeverity,
      originalCvss: originalCvss,
      status: evalResult.vexStatus || 'not_affected',
      policyImpact: evalResult.policyBlockingStatus === 'NON_BLOCKING' ? 'SUPPRESSED' : 'ACTIVE',
      justification: evalResult.justification || null,
      impactStatement: evalResult.impactStatement || null,
      actionStatement: evalResult.actionStatement || null,
      payload: envelope,
      issuerIdentity: req.headers['x-user-id'] || 'security-team',
      issuedAt: new Date().toISOString(),
      lastUpdatedAt: new Date().toISOString(),
      validUntil: new Date(Date.now() + 31536000000).toISOString(),
      statementHash: evalResult.statementHash,
      publicKeyFingerprint: evalResult.publicKeyFingerprint,
      signatureStatus: evalResult.signatureStatus,
      format: evalResult.format,
      formatVersion: evalResult.formatVersion,
      productIdentifiers: evalResult.productIdentifiers,
      releaseIdentifiers: evalResult.releaseIdentifiers,
      componentIdentifiers: evalResult.componentIdentifiers,
      vulnerabilityIdentifiers: evalResult.vulnerabilityIdentifiers,
      applicabilityDisposition: evalResult.applicabilityDisposition,
      policyBlockingStatus: evalResult.policyBlockingStatus,
      reasonCodes: evalResult.reasonCodes,
      trustPolicyHash: evalResult.trustPolicyHash,
      verifiedAt: evalResult.verifiedAt,
      policyVersion: evalResult.policyVersion,
      verificationMode: evalResult.verificationMode,
      transparencyLogStatus: evalResult.transparencyLogStatus,
      statementId: evalResult.statementId,
      vexAuthoritative: evalResult.vexAuthoritative,
      canonicalPayloadDigest: evalResult.canonicalPayloadDigest,
      policyId: evalResult.policyId,
      targetBinding: evalResult.targetBinding,
      verifierVersion: evalResult.verifierVersion
    });

    const statusCode = evalResult.isValid ? 201 : 422;
    return res.status(statusCode).json({
      message: evalResult.isValid ? 'VEX statement recorded and evaluated successfully' : 'VEX statement evaluation failed',
      vexId: dbRecord.id,
      sbomId: sbomId.trim(),
      vulnerabilityId: dbRecord.vulnerability_id,
      status: evalResult.vexStatus,
      reasonCode: evalResult.reasonCode,
      reasonCodes: evalResult.reasonCodes,
      policyBlockingStatus: dbRecord.policy_blocking_status,
      applicabilityDisposition: dbRecord.applicability_disposition,
      createdAt: dbRecord.created_at
    });
  } catch (err) {
    console.error('[TPSR] Error recording VEX statement:', err);
    return res.status(500).json({ error: 'Failed to record VEX statement', details: err.message });
  }
}

/**
 * Handle VEX statements retrieval
 */
async function handleGetVex(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const records = await sbomRepository.getVexStatementsBySBOMID(sbomId.trim());
    return res.status(200).json({
      sbomId: sbomId.trim(),
      count: records.length,
      vexStatements: records
    });
  } catch (err) {
    console.error('[TPSR] Error fetching VEX statements:', err);
    return res.status(500).json({ error: 'Failed to retrieve VEX statements', details: err.message });
  }
}

router.post('/v1/sbom/:sbomId/vex', handleRecordVex);
router.post('/sbom/:sbomId/vex', handleRecordVex);
router.get('/v1/sbom/:sbomId/vex', handleGetVex);
router.get('/sbom/:sbomId/vex', handleGetVex);

module.exports = router;
