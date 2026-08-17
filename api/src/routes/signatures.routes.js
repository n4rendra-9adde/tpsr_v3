'use strict';

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const sbomRepository = require('../repositories/sbomRepository');
const { verifySignature } = require('../utils/cosignEngine');
const fabric = require('../config/fabric');

/**
 * Handle signature verification and recording
 */
async function handleRecordSignature(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  const body = req.body || {};
  if (!body.signatureType || (body.signatureType !== 'OFFLINE_KEYED' && body.signatureType !== 'KEYLESS')) {
    return res.status(400).json({ error: 'signatureType parameter is required and must be OFFLINE_KEYED or KEYLESS' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const trueArtifactHash = pgDocument.sbom_hash;
    const submittedHash = body.artifactHash ? body.artifactHash.toLowerCase().trim() : trueArtifactHash;

    // Artifact Digest Binding: Reject if the submitted hash does not match the registered artifact hash
    if (submittedHash !== trueArtifactHash) {
      return res.status(422).json({
        message: 'Signature verification failed',
        status: 'FAILED',
        reasonCode: 'SIG-005',
        reasonDescription: 'Signed target digest mismatch. Submitted artifact hash does not match registered artifact.',
        sbomId: sbomId.trim()
      });
    }

    // Force verifySignature to use the strictly bound registered hash
    const verificationResult = await verifySignature({ ...body, artifactHash: trueArtifactHash });

    const fallbackHash = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
    const sigHash = verificationResult.signatureHash || fallbackHash;
    const signerId = body.signerIdentity || body.expectedSubject || verificationResult.signerIdentity || 'unknown-signer';

    const dbRecord = await sbomRepository.insertSignatureVerification({
      sbomId: sbomId.trim(),
      artifactHash: trueArtifactHash,
      signatureType: body.signatureType,
      signerIdentity: signerId,
      verificationStatus: verificationResult.status,
      bundleJson: body.bundleJson || null,
      signatureHash: sigHash,
      publicKeyFingerprint: verificationResult.publicKeyFingerprint,
      verificationMode: verificationResult.verificationMode,
      failureReason: verificationResult.failureReason
    });

    // Attempt to anchor signature evidence on Fabric ledger asynchronously / best-effort
    let ledgerStatus = 'PENDING';
    let gateway = null;
    try {
      const fabricRes = await fabric.getContract();
      gateway = fabricRes.gateway;
      const contract = fabricRes.contract;

      const chaincodePayload = JSON.stringify({
        version: "3.0",
        sbomID: sbomId.trim(),
        evidenceType: body.signatureType === 'KEYLESS' ? "COSIGN_KEYLESS_V1" : "COSIGN_KEYED_V1",
        evidenceHash: sigHash,
        evidenceId: dbRecord.id,
        evidencePayload: JSON.stringify({ signerIdentity: signerId, status: verificationResult.status })
      });

      await contract.submitTransaction('RecordTrustEvidence', chaincodePayload);
      ledgerStatus = 'ANCHORED';
    } catch (fabricErr) {
      console.warn(`[TPSR][SIGNATURE] Fabric anchoring deferred/failed for signature ${dbRecord.id}: ${fabricErr.message}`);
      ledgerStatus = 'OUTBOX_QUEUED';
    } finally {
      if (gateway) {
        fabric.disconnectGateway(gateway);
      }
    }

    if (verificationResult.status === 'VERIFIED') {
      try {
        const automaticEvaluationService = require('../services/automaticEvaluationService');
        await automaticEvaluationService.evaluateSubmittedSbom({
          sbomId: sbomId.trim(),
          correlationId: null,
          principal: req.headers['x-user-id'] || 'system-signature',
          triggerType: 'SIGNATURE_ADDED'
        });
      } catch (reevalErr) {
        console.warn(`[TPSR][SIGNATURE] Automatic reevaluation failed for ${sbomId}:`, reevalErr.message);
      }
    }

    const statusCode = verificationResult.status === 'VERIFIED' ? 201 : 422;
    return res.status(statusCode).json({
      message: verificationResult.status === 'VERIFIED' ? 'Signature verified and recorded successfully' : 'Signature verification failed',
      verificationId: dbRecord.id,
      sbomId: sbomId.trim(),
      status: verificationResult.status,
      reasonCode: verificationResult.reasonCode,
      reasonDescription: verificationResult.failureReason,
      signerIdentity: signerId,
      signatureHash: sigHash,
      ledgerStatus: ledgerStatus,
      verifiedAt: dbRecord.verified_at
    });
  } catch (err) {
    console.error('[TPSR] Error verifying signature:', err);
    return res.status(500).json({ error: 'Failed to verify signature', details: err.message });
  }
}

/**
 * Handle signature records retrieval
 */
async function handleGetSignatures(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const records = await sbomRepository.getSignaturesBySBOMID(sbomId.trim());
    return res.status(200).json({
      sbomId: sbomId.trim(),
      count: records.length,
      signatures: records
    });
  } catch (err) {
    console.error('[TPSR] Error fetching signatures:', err);
    return res.status(500).json({ error: 'Failed to retrieve signature records', details: err.message });
  }
}

router.post('/v1/sbom/:sbomId/signatures', handleRecordSignature);
router.post('/sbom/:sbomId/signatures', handleRecordSignature);
router.get('/v1/sbom/:sbomId/signatures', handleGetSignatures);
router.get('/sbom/:sbomId/signatures', handleGetSignatures);

module.exports = router;
