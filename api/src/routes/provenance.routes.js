'use strict';

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const sbomRepository = require('../repositories/sbomRepository');
const { verifyProvenance } = require('../utils/provenanceEngine');
const fabric = require('../config/fabric');

/**
 * Handle provenance submission and verification
 */
async function handleRecordProvenance(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  const body = req.body || {};
  // Now expecting envelope, signatureType, publicKey, expectedArtifactHash
  const envelope = body.envelope || body.attestationPayload || body.attestation || (body._type ? body : null);
  
  if (!envelope || typeof envelope !== 'object') {
    return res.status(400).json({ error: 'envelope or attestationPayload JSON object is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const expectedArtifactHash = body.expectedArtifactHash || pgDocument.sbom_hash;
    
    // Check if the user is providing explicit offline keys, else try to use policy or fallbacks
    const signatureType = body.signatureType || 'OFFLINE_KEYED';
    const publicKey = body.publicKey || null;

    const verificationResult = await verifyProvenance(envelope, expectedArtifactHash, signatureType, publicKey);

    const attestationHash = crypto.createHash('sha256').update(JSON.stringify(envelope)).digest('hex');
    const statementType = verificationResult.normalizedOutput?._type || 'https://in-toto.io/Statement/v1';

    // Insert new enhanced record
    const dbRecord = await sbomRepository.insertProvenanceAttestation({
      sbomId: sbomId.trim(),
      artifactHash: expectedArtifactHash,
      attestationType: statementType,
      builderId: verificationResult.builderId || 'unknown-builder',
      slsaLevel: verificationResult.slsaLevel || 'SLSA_BUILD_LEVEL_0',
      payload: envelope, // Storing original envelope
      attestationHash: attestationHash,
      status: verificationResult.status,
      // Enhanced Fields
      envelopeHash: verificationResult.envelopeHash,
      predicateType: verificationResult.predicateType,
      predicateVersion: verificationResult.predicateVersion,
      sourceRepository: verificationResult.sourceRepository,
      sourceCommit: verificationResult.sourceCommit,
      buildType: verificationResult.buildType,
      externalParameters: verificationResult.externalParameters,
      buildStartedOn: verificationResult.buildStartedOn,
      buildFinishedOn: verificationResult.buildFinishedOn,
      signatureStatus: verificationResult.signatureStatus || 'UNVERIFIED',
      verificationStatus: verificationResult.status,
      publicKeyFingerprint: verificationResult.publicKeyFingerprint,
      signerIdentity: verificationResult.signerIdentity,
      policyVersion: verificationResult.policyVersion,
      trustPolicyHash: verificationResult.trustPolicyHash,
      reasonCodes: verificationResult.reasonCodes || [verificationResult.reasonCode]
    });

    // Attempt to anchor evidence on Fabric ledger asynchronously / best-effort
    let ledgerStatus = 'PENDING';
    let gateway = null;
    try {
      const fabricRes = await fabric.getContract();
      gateway = fabricRes.gateway;
      const contract = fabricRes.contract;

      const chaincodePayload = JSON.stringify({
        version: "3.0",
        sbomID: sbomId.trim(),
        evidenceType: "SLSA_PROVENANCE_V1",
        evidenceHash: attestationHash,
        evidenceId: dbRecord.id,
        evidencePayload: JSON.stringify(envelope).slice(0, 1000) // truncated for ledger brevity
      });

      await contract.submitTransaction('RecordTrustEvidence', chaincodePayload);
      ledgerStatus = 'ANCHORED';
    } catch (fabricErr) {
      console.warn(`[TPSR][PROVENANCE] Fabric anchoring deferred/failed for evidence ${dbRecord.id}: ${fabricErr.message}`);
      ledgerStatus = 'OUTBOX_QUEUED';
    } finally {
      if (gateway) {
        fabric.disconnectGateway(gateway);
      }
    }

    const statusCode = verificationResult.status === 'VALID' ? 201 : 422;
    return res.status(statusCode).json({
      message: verificationResult.status === 'VALID' ? 'Provenance attestation recorded and verified successfully' : 'Provenance verification failed',
      evidenceId: dbRecord.id,
      sbomId: sbomId.trim(),
      status: verificationResult.status,
      slsaLevel: verificationResult.slsaLevel,
      reasonCodes: verificationResult.reasonCodes || [verificationResult.reasonCode],
      builderId: verificationResult.builderId,
      attestationHash: attestationHash,
      ledgerStatus: ledgerStatus,
      createdAt: dbRecord.created_at || new Date().toISOString()
    });
  } catch (err) {
    console.error('[TPSR] Error recording provenance:', err);
    return res.status(500).json({ error: 'Failed to record provenance attestation', details: err.message });
  }
}

/**
 * Handle provenance retrieval
 */
async function handleGetProvenance(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const records = await sbomRepository.getProvenanceBySBOMID(sbomId.trim());
    return res.status(200).json({
      sbomId: sbomId.trim(),
      count: records.length,
      attestations: records
    });
  } catch (err) {
    console.error('[TPSR] Error fetching provenance:', err);
    return res.status(500).json({ error: 'Failed to retrieve provenance attestations', details: err.message });
  }
}

router.post('/v1/sbom/:sbomId/provenance', handleRecordProvenance);
router.post('/sbom/:sbomId/provenance', handleRecordProvenance);
router.get('/v1/sbom/:sbomId/provenance', handleGetProvenance);
router.get('/sbom/:sbomId/provenance', handleGetProvenance);

module.exports = router;
