'use strict';

const express = require('express');
const router = express.Router();
const sbomRepository = require('../repositories/sbomRepository');
const contextAssertionRepository = require('../repositories/contextAssertionRepository');
const { verifyContextAssertion } = require('../utils/contextAssertionEngine');
const crypto = require('crypto');
const db = require('../config/database');

async function handleRecordContextAssertion(req, res) {
  const sbomId = req.params.sbomId;
  const body = req.body;
  
  if (!sbomId) return res.status(400).json({ error: 'sbomId required' });
  if (!body.assertion || !body.signature || !body.publicKey || !body.verificationMode) {
    return res.status(400).json({ error: 'assertion, signature, publicKey, verificationMode required' });
  }

  if (body.assertion.simulated === true) {
    return res.status(422).json({ error: 'Simulated assertion not allowed in authoritative path' });
  }

  const actorRole = req.headers['x-user-role'] || 'unknown';
  const actorId = req.headers['x-user-id'] || 'unknown';

  try {
    const sbomDoc = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!sbomDoc) return res.status(404).json({ error: 'SBOM not found' });

    const activeAssertions = await contextAssertionRepository.listContextAssertionsBySbomId(sbomId.trim());

    const evalResult = await verifyContextAssertion({
      ...body.assertion,
      signatureValue: body.signature,
      publicKey: body.publicKey,
      signatureType: 'OFFLINE_KEYED',
      verificationMode: body.verificationMode,
      signerIdentity: body.assertion.signerIdentity,
      assertorRole: actorRole,
      assertedBy: actorId
    }, sbomDoc, activeAssertions);

    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');
      
      let status = 'INVALID';
      if (evalResult.verificationStatus === 'VERIFIED') status = 'ACTIVE';
      
      const newId = crypto.randomUUID();
      
      const record = {
        id: newId,
        assertionVersion: body.assertion.assertionVersion || '0.1',
        sbomId: sbomId.trim(),
        digestManifestDigest: body.assertion.digestManifestDigest,
        canonicalAssertion: evalResult.normalizedAssertion,
        assertionPayloadHash: evalResult.normalizedAssertion?.assertionPayloadHash || 'unknown',
        environment: body.assertion.environment,
        internetExposure: body.assertion.internetExposure || 'NONE',
        assetCriticality: body.assertion.assetCriticality || 'LOW',
        privilegeLevel: body.assertion.privilegeLevel || 'UNPRIVILEGED',
        dataSensitivity: body.assertion.dataSensitivity || 'PUBLIC',
        runtimeExecution: body.assertion.runtimeExecution || 'UNKNOWN',
        componentPresence: body.assertion.componentPresence || 'UNKNOWN',
        compensatingControls: body.assertion.compensatingControls || [],
        assertedBy: actorId,
        assertorRole: actorRole,
        assertedAt: body.assertion.assertedAt || new Date().toISOString(),
        validUntil: body.assertion.validUntil,
        justification: body.assertion.justification || '',
        previousAssertionId: null,
        supersedesAssertionId: null,
        signatureType: 'OFFLINE_KEYED',
        verificationMode: body.verificationMode,
        signerIdentity: body.assertion.signerIdentity,
        publicKeyFingerprint: crypto.createHash('sha256').update(body.publicKey.trim()).digest('hex'),
        signatureVerified: evalResult.signatureVerified,
        transparencyLogVerified: false,
        verificationStatus: evalResult.verificationStatus,
        assuranceState: evalResult.assuranceState,
        status: status,
        reasonCodes: evalResult.reasonCodes,
        policyVersion: evalResult.policyVersion,
        trustPolicyHash: evalResult.trustPolicyHash
      };

      const conflicting = await contextAssertionRepository.findConflictingActiveAssertions(client, sbomId.trim(), body.assertion.environment);
      if (status === 'ACTIVE' && conflicting.length > 0) {
        // According to CAECTD rules, conflicting active assertions might result in REVIEW_REQUIRED or HTTP 409
        // We will just return 409
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'Conflicting active assertion exists', reasonCodes: ['CTX-017'] });
      }
      
      // If there is an existing active assertion for the SAME environment, supersede it
      if (status === 'ACTIVE') {
        const sameEnv = activeAssertions.find(a => a.environment === body.assertion.environment && a.status === 'ACTIVE');
        if (sameEnv) {
          record.previousAssertionId = sameEnv.id;
          await contextAssertionRepository.supersedeContextAssertion(client, sameEnv.id, newId);
        }
      }

      const created = await contextAssertionRepository.createContextAssertion(client, record);
      await client.query('COMMIT');

      if (status !== 'ACTIVE') {
        return res.status(422).json({
          error: 'Context assertion verification failed',
          verificationStatus: evalResult.verificationStatus,
          assuranceState: evalResult.assuranceState,
          reasonCodes: evalResult.reasonCodes,
          ruleIds: evalResult.ruleIds
        });
      }

      return res.status(201).json({
        message: 'Context assertion recorded',
        assertionId: created.id,
        verificationStatus: evalResult.verificationStatus,
        assuranceState: evalResult.assuranceState,
        reasonCodes: evalResult.reasonCodes,
        ruleIds: evalResult.ruleIds
      });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

async function handleGetContextAssertions(req, res) {
  try {
    const records = await contextAssertionRepository.listContextAssertionsBySbomId(req.params.sbomId);
    return res.json({ assertions: records });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

async function handleGetActiveContextAssertion(req, res) {
  try {
    const record = await contextAssertionRepository.getActiveContextAssertion(req.params.sbomId);
    return res.json({ activeAssertion: record });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

async function handleRevokeContextAssertion(req, res) {
  const actorRole = req.headers['x-user-role'];
  if (actorRole !== 'security' && actorRole !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized to revoke assertions' });
  }
  
  if (!req.body.justification) {
    return res.status(400).json({ error: 'Justification required for revocation' });
  }
  
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const record = await contextAssertionRepository.revokeContextAssertion(client, req.params.assertionId, req.body.justification);
    if (!record) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Active assertion not found' });
    }
    await client.query('COMMIT');
    return res.json({ message: 'Assertion revoked', assertion: record });
  } catch (e) {
    await client.query('ROLLBACK');
    return res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
}

router.post('/v1/sbom/:sbomId/context/assertions', handleRecordContextAssertion);
router.get('/v1/sbom/:sbomId/context/assertions', handleGetContextAssertions);
router.get('/v1/sbom/:sbomId/context/assertions/active', handleGetActiveContextAssertion);
router.post('/v1/sbom/:sbomId/context/assertions/:assertionId/revoke', handleRevokeContextAssertion);

module.exports = router;
