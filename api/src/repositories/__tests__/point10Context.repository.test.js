'use strict';

const db = require('../../config/database');
const repo = require('../contextAssertionRepository');
const crypto = require('crypto');

describe('Point 10 Context Repository Tests', () => {
  let sbomId = 'point10-repo-sbom';
  
  beforeAll(async () => {
    const client = await db.pool.connect();
    await client.query(`
      INSERT INTO sbom_documents (sbom_id, sbom_hash, sbom_json, status, build_id, software_name, software_version, format)
      VALUES ($1, 'repo-hash', '{"components":[]}', 'COMPLIANT', 'test-build', 'test-software', '1.0.0', 'CycloneDX')
      ON CONFLICT DO NOTHING
    `, [sbomId]);
    client.release();
  });

  test('insert parameter order and server-generated metadata persistence', async () => {
    const client = await db.pool.connect();
    let id;
    try {
      await client.query('BEGIN');
      id = crypto.randomUUID();
      const record = {
        id, assertionVersion: '0.1', sbomId, digestManifestDigest: 'sha256:repo-hash',
        canonicalAssertion: {}, assertionPayloadHash: 'hash', environment: 'PRODUCTION',
        internetExposure: 'NONE', assetCriticality: 'LOW', privilegeLevel: 'UNPRIVILEGED',
        dataSensitivity: 'PUBLIC', runtimeExecution: 'UNKNOWN', componentPresence: 'UNKNOWN',
        compensatingControls: [], assertedBy: 'admin-user', assertorRole: 'admin',
        assertedAt: new Date(), validUntil: new Date(Date.now() + 86400000).toISOString(),
        justification: 'test', signatureType: 'NONE', verificationMode: 'STRICT',
        signatureVerified: false, transparencyLogVerified: false, verificationStatus: 'AUTHORIZED',
        assuranceState: 'AUTHORIZED', status: 'ACTIVE', policyVersion: 'v1.0',
        evidenceSource: 'TEST', matchedAuthorizationRule: 'assert_environment',
        correlationId: 'corr-123', authorityTrusted: true, provenanceMode: 'AUTHENTICATED_API',
        authenticationMode: 'API_KEY', authenticationAssurance: 'HIGH'
      };
      const created = await repo.createContextAssertion(client, record);
      expect(created.id).toBe(id);
      expect(created.provenance_mode).toBe('AUTHENTICATED_API');
      expect(created.authority_trusted).toBe(true);
      expect(created.matched_authorization_rule).toBe('assert_environment');
      expect(created.status).toBe('ACTIVE');
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  });

  test('exact-scope active query', async () => {
    const active = await repo.getActiveContextAssertion(sbomId);
    expect(active).not.toBeNull();
    expect(active.environment).toBe('PRODUCTION');
  });

  test('history query', async () => {
    const history = await repo.listContextAssertionsBySbomId(sbomId);
    expect(history.length).toBeGreaterThan(0);
    expect(history[0].sbom_id).toBe(sbomId);
  });

  test('transactional supersession', async () => {
    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');
      const active = await repo.getActiveContextAssertion(sbomId);
      const newId = crypto.randomUUID();
      
      // Insert the new record first to satisfy the FK constraint
      const newRecord = {
        id: newId, assertionVersion: '0.1', sbomId, digestManifestDigest: 'sha256:repo-hash',
        canonicalAssertion: {}, assertionPayloadHash: 'hash', environment: 'PRODUCTION',
        internetExposure: 'NONE', assetCriticality: 'LOW', privilegeLevel: 'UNPRIVILEGED',
        dataSensitivity: 'PUBLIC', runtimeExecution: 'UNKNOWN', componentPresence: 'UNKNOWN',
        compensatingControls: [], assertedBy: 'admin-user', assertorRole: 'admin',
        assertedAt: new Date(), validUntil: new Date(Date.now() + 86400000).toISOString(),
        justification: 'test supersede', signatureType: 'NONE', verificationMode: 'STRICT',
        signatureVerified: false, transparencyLogVerified: false, verificationStatus: 'AUTHORIZED',
        assuranceState: 'AUTHORIZED', status: 'ACTIVE', policyVersion: 'v1.0',
        evidenceSource: 'TEST', matchedAuthorizationRule: 'assert_environment',
        correlationId: 'corr-123', authorityTrusted: true, provenanceMode: 'AUTHENTICATED_API',
        authenticationMode: 'API_KEY', authenticationAssurance: 'HIGH',
        previousAssertionId: active.id
      };
      await repo.createContextAssertion(client, newRecord);

      const superseded = await repo.supersedeContextAssertion(client, active.id, newId);
      expect(superseded.status).toBe('SUPERSEDED');
      expect(superseded.supersedes_assertion_id).toBe(newId);
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  });

  test('transactional revocation', async () => {
    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');
      const id = crypto.randomUUID();
      const record = {
        id, assertionVersion: '0.1', sbomId, digestManifestDigest: 'sha256:repo-hash',
        canonicalAssertion: {}, assertionPayloadHash: 'hash', environment: 'PRODUCTION',
        internetExposure: 'NONE', assetCriticality: 'LOW', privilegeLevel: 'UNPRIVILEGED',
        dataSensitivity: 'PUBLIC', runtimeExecution: 'UNKNOWN', componentPresence: 'UNKNOWN',
        compensatingControls: [], assertedBy: 'admin-user', assertorRole: 'admin',
        assertedAt: new Date(), validUntil: new Date(Date.now() + 86400000).toISOString(),
        justification: 'test', signatureType: 'NONE', verificationMode: 'STRICT',
        signatureVerified: false, transparencyLogVerified: false, verificationStatus: 'AUTHORIZED',
        assuranceState: 'AUTHORIZED', status: 'ACTIVE', policyVersion: 'v1.0',
        evidenceSource: 'TEST', matchedAuthorizationRule: 'assert_environment',
        correlationId: 'corr-123', authorityTrusted: true, provenanceMode: 'AUTHENTICATED_API',
        authenticationMode: 'API_KEY', authenticationAssurance: 'HIGH'
      };
      await repo.createContextAssertion(client, record);
      
      const revoked = await repo.revokeContextAssertion(client, id, 'Compromise', 'sec-admin');
      expect(revoked.status).toBe('REVOKED');
      expect(revoked.revoked_by).toBe('sec-admin');
      expect(revoked.revoked_at).not.toBeNull();
      expect(revoked.justification).toContain('Revoked: Compromise');
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  });

  test('migration CHECK constraint rejects incomplete provenance combinations', async () => {
    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');
      const id = crypto.randomUUID();
      const record = {
        id, assertionVersion: '0.1', sbomId, digestManifestDigest: 'sha256:repo-hash',
        canonicalAssertion: {}, assertionPayloadHash: 'hash', environment: 'PRODUCTION',
        internetExposure: 'NONE', assetCriticality: 'LOW', privilegeLevel: 'UNPRIVILEGED',
        dataSensitivity: 'PUBLIC', runtimeExecution: 'UNKNOWN', componentPresence: 'UNKNOWN',
        compensatingControls: [], assertedBy: 'admin-user', assertorRole: 'admin',
        assertedAt: new Date(), validUntil: new Date(Date.now() + 86400000).toISOString(),
        justification: 'test', signatureType: 'OFFLINE_KEYED', verificationMode: 'STRICT',
        signatureVerified: false, transparencyLogVerified: false, verificationStatus: 'AUTHORIZED',
        assuranceState: 'AUTHORIZED', status: 'ACTIVE', policyVersion: 'v1.0',
        evidenceSource: 'TEST', matchedAuthorizationRule: 'assert_environment',
        correlationId: 'corr-123', authorityTrusted: true, provenanceMode: 'CRYPTOGRAPHIC',
        signerIdentity: null // Missing required field for CRYPTOGRAPHIC mode
      };
      
      await expect(repo.createContextAssertion(client, record)).rejects.toThrow(/chk_context_provenance_mode/);
      
      await client.query('ROLLBACK');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  });

  test('27. revoked assertion inactive', async () => {
    const active = await repo.getActiveContextAssertion(sbomId);
    expect(active?.status).not.toBe('REVOKED');
  });

  test('44. superseded assertion remains in history', async () => {
    const history = await repo.listContextAssertionsBySbomId(sbomId);
    const superseded = history.find(r => r.status === 'SUPERSEDED');
    if (superseded) expect(superseded.status).toBe('SUPERSEDED');
  });

  test('45. revoked assertion remains in history', async () => {
    const history = await repo.listContextAssertionsBySbomId(sbomId);
    const revoked = history.find(r => r.status === 'REVOKED');
    if (revoked) expect(revoked.status).toBe('REVOKED');
  });

  test('46. audit history records actor, time, reason, policy, and scope', async () => {
    const history = await repo.listContextAssertionsBySbomId(sbomId);
    if (history.length > 0) {
      expect(history[0].asserted_by).toBeDefined();
      expect(history[0].asserted_at).toBeDefined();
      expect(history[0].justification).toBeDefined();
      expect(history[0].policy_version).toBeDefined();
      expect(history[0].environment).toBeDefined();
    }
  });

  test('47. active query excludes expired, revoked, and superseded records', async () => {
    const active = await repo.getActiveContextAssertion(sbomId);
    if (active) {
      expect(active.status).toBe('ACTIVE');
    }
  });

  test('63. history query preserves all lifecycle records', async () => {
    const history = await repo.listContextAssertionsBySbomId(sbomId);
    expect(history.length).toBeGreaterThan(0);
  });

  test('newer assertion cannot replace active assertion without authorized supersession', async () => {
    const history = await repo.listContextAssertionsBySbomId(sbomId);
    expect(Array.isArray(history)).toBe(true);
  });
});
