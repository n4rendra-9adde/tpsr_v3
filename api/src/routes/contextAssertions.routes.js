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
  if (!body.assertion) {
    return res.status(400).json({ error: 'assertion required' });
  }

  if (body.assertion.simulated === true) {
    return res.status(422).json({ error: 'Simulated assertion not allowed in authoritative path' });
  }

  // Ensure principal identity is verified and used, ignoring caller payload
  if (!req.auth || !req.auth.userId) {
    return res.status(401).json({ error: 'Unauthenticated principal' });
  }

  try {
    const sbomDoc = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!sbomDoc) return res.status(404).json({ error: 'SBOM not found' });

    const activeAssertions = await contextAssertionRepository.listContextAssertionsBySbomId(sbomId.trim());

    // Generate security-sensitive metadata server-side
    const assertedAt = new Date().toISOString();
    // Default validUntil to 24h if not specified or malformed, but policy limit takes precedence
    let validUntil = body.assertion.validUntil ? new Date(body.assertion.validUntil) : new Date(Date.now() + 24*3600000);
    if (isNaN(validUntil.getTime())) {
      validUntil = new Date(Date.now() + 24*3600000);
    }

    const evalResult = await verifyContextAssertion({
      ...body.assertion,
      sbomId: sbomId.trim(),
      digestManifestDigest: body.assertion.digestManifestDigest || `sha256:${sbomDoc.sbom_hash}`,
      signatureValue: body.signature,
      publicKey: body.publicKey,
      signatureType: body.signature ? 'OFFLINE_KEYED' : 'NONE',
      verificationMode: body.verificationMode || 'STRICT',
      signerIdentity: body.assertion.signerIdentity,
      assertorRole: req.auth.role,
      assertedBy: req.auth.userId,
      assertedAt: assertedAt,
      validUntil: validUntil.toISOString()
    }, sbomDoc, activeAssertions);

    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');

      let status = 'INVALID';
      if (evalResult.verificationStatus === 'VERIFIED' || evalResult.verificationStatus === 'AUTHORIZED') status = 'ACTIVE';

      const newId = crypto.randomUUID();

      const record = {
        id: newId,
        assertionVersion: body.assertion.assertionVersion || '0.1',
        sbomId: sbomId.trim(),
        digestManifestDigest: body.assertion.digestManifestDigest || `sha256:${sbomDoc.sbom_hash}`,
        canonicalAssertion: evalResult.normalizedAssertion || {},
        assertionPayloadHash: evalResult.normalizedAssertion?.assertionPayloadHash || 'unknown',
        environment: body.assertion.environment,
        internetExposure: body.assertion.internetExposure || 'NONE',
        assetCriticality: body.assertion.assetCriticality || 'LOW',
        privilegeLevel: body.assertion.privilegeLevel || 'UNPRIVILEGED',
        dataSensitivity: body.assertion.dataSensitivity || 'PUBLIC',
        runtimeExecution: body.assertion.runtimeExecution || 'UNKNOWN',
        componentPresence: body.assertion.componentPresence || 'UNKNOWN',
        compensatingControls: body.assertion.compensatingControls || [],
        assertedBy: req.auth.userId,
        assertorRole: req.auth.role,
        assertedAt: assertedAt,
        validUntil: evalResult.finalValidUntil || validUntil.toISOString(),
        justification: body.assertion.justification || 'No justification provided',
        previousAssertionId: null,
        supersedesAssertionId: null,
        signatureType: body.signature ? 'OFFLINE_KEYED' : 'NONE',
        verificationMode: body.verificationMode || 'STRICT',
        signerIdentity: body.assertion.signerIdentity || null,
        publicKeyFingerprint: body.publicKey ? crypto.createHash('sha256').update(body.publicKey.trim()).digest('hex') : null,
        signatureVerified: evalResult.signatureVerified || false,
        transparencyLogVerified: false,
        verificationStatus: evalResult.verificationStatus,
        assuranceState: evalResult.assuranceState,
        status: status,
        reasonCodes: evalResult.reasonCodes,
        policyVersion: evalResult.policyVersion,
        trustPolicyHash: evalResult.trustPolicyHash,
        evidenceSource: body.assertion.evidenceSource || null,
        matchedAuthorizationRule: 'assert_environment',
        correlationId: body.correlationId || crypto.randomUUID(),
        authorityTrusted: evalResult.authorityTrusted || false,
        provenanceMode: body.signature ? 'CRYPTOGRAPHIC' : 'AUTHENTICATED_API',
        authenticationMode: req.auth.authenticationMode || 'UNKNOWN',
        authenticationAssurance: req.auth.authenticationAssurance || 'LOW'
      };

      const conflicting = await contextAssertionRepository.findConflictingActiveAssertions(client, sbomId.trim(), body.assertion.environment);

      if (status === 'ACTIVE') {
        const sameEnv = activeAssertions.find(a => a.environment === body.assertion.environment && a.status === 'ACTIVE');
        if (sameEnv) {
          record.previousAssertionId = sameEnv.id;
        }
      }

      const created = await contextAssertionRepository.createContextAssertion(client, record);

      // If there is an existing active assertion for the SAME environment, supersede it
      if (status === 'ACTIVE' && record.previousAssertionId) {
        await contextAssertionRepository.supersedeContextAssertion(client, record.previousAssertionId, newId);
      }

      // If conflicting, we also want to mark the old ones as INVALID but wait, schema only has INVALID.
      // Actually, if we just let it insert as INVALID, the assembler can detect it.
      await client.query('COMMIT');

      if (status !== 'ACTIVE' && evalResult.assuranceState !== 'CONFLICTING') {
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
  if (!req.auth || !req.auth.userId) {
    return res.status(401).json({ error: 'Unauthenticated principal' });
  }

  const actorRole = req.auth.role;
  const actorId = req.auth.userId;

  // Validate revoke authorization via policy
  const provenanceEngine = require('../utils/provenanceEngine');
  const policy = provenanceEngine.getTrustPolicy();
  const revokeAuth = policy.contextAuthorizationRules && policy.contextAuthorizationRules.revoke_assertion;
  if (!revokeAuth || !revokeAuth.allowedRoles || !revokeAuth.allowedRoles.includes(actorRole)) {
    return res.status(403).json({ error: 'Unauthorized to revoke assertions' });
  }

  if (!req.body.justification) {
    return res.status(400).json({ error: 'Justification required for revocation' });
  }

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const record = await contextAssertionRepository.revokeContextAssertion(client, req.params.assertionId, req.body.justification, actorId);
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
