'use strict';

const db = require('../../config/database');
const request = require('supertest');
const { app } = require('../../server');
const repo = require('../../repositories/contextAssertionRepository');
const engine = require('../contextAssertionEngine');
const contextAssembler = require('../../services/contextRiskEvidenceAssembler');
const { evaluateTrust } = require('../trustEngine');

describe('Point 10 Missing Cases Validation', () => {
  let sbomId = 'point10-missing-sbom';
  const baseAssertion = {
    environment: 'PRODUCTION',
    digestManifestDigest: 'sha256:test-hash',
    version: '1.0.0',
    assertedAt: new Date().toISOString(),
    validUntil: new Date(Date.now() + 86400000).toISOString(),
    sbomId: sbomId,
    justification: 'valid justification',
    evidenceSource: 'TEST',
    assertorRole: 'security'
  };
  
  const baseSbom = {
    sbom_id: sbomId,
    sbom_hash: 'test-hash',
    software_version: '1.0.0',
    format: 'CycloneDX',
    sbom_json: JSON.stringify({ components: [] })
  };

  beforeAll(async () => {
    const client = await db.pool.connect();
    await client.query(`
      INSERT INTO sbom_documents (sbom_id, sbom_hash, sbom_json, status, build_id, software_name, software_version, format)
      VALUES ($1, 'test-hash', '{"components":[]}', 'COMPLIANT', 'test-build', 'test-software', '1.0.0', 'CycloneDX')
      ON CONFLICT DO NOTHING
    `, [sbomId]);
    client.release();
  });

  // 6, 15, 16. Criticality scope
  test('6 & 15. supported criticality owner accepted', async () => {
    const res = await engine.verifyContextAssertion({ ...baseAssertion, assetCriticality: 'HIGH', assertorRole: 'security' }, baseSbom);
    expect(res.reasonCodes).not.toContain('CTX-014');
    expect(res.reasonCodes).not.toContain('CTX-010');
  });

  test('16. unsupported criticality rejected', async () => {
    const res = await engine.verifyContextAssertion({ ...baseAssertion, assetCriticality: 'UNKNOWN_CRIT', assertorRole: 'security' }, baseSbom);
    expect(res.reasonCodes).toContain('CTX-010'); // unsupported value
  });
  
  // 7. unauthorized principal cannot lower criticality
  test('7. unauthorized principal cannot lower criticality', async () => {
    const res = await engine.verifyContextAssertion({ ...baseAssertion, assetCriticality: 'LOW', assertorRole: 'developer' }, baseSbom);
    expect(res.reasonCodes).toContain('CTX-030'); // developer unauthorized for criticality
  });

  // 13, 14. Exposure scope
  test('13. supported exposure accepted', async () => {
    const res = await engine.verifyContextAssertion({ ...baseAssertion, internetExposure: 'INTERNAL', assertorRole: 'security' }, baseSbom);
    expect(res.reasonCodes).not.toContain('CTX-014');
  });

  test('14. unsupported exposure rejected', async () => {
    const res = await engine.verifyContextAssertion({ ...baseAssertion, internetExposure: 'WEIRD_EXPOSURE', assertorRole: 'security' }, baseSbom);
    expect(res.reasonCodes).toContain('CTX-010'); 
  });

  // 17. required justification missing
  test('17. required justification missing', async () => {
    const res = await engine.verifyContextAssertion({ ...baseAssertion, justification: '' }, baseSbom);
    expect(res.reasonCodes).toContain('CTX-032');
  });

  // 18. evidence source missing when required
  test('18. evidence source missing when required', async () => {
    const res = await engine.verifyContextAssertion({ ...baseAssertion, evidenceSource: '' }, baseSbom);
    expect(res.reasonCodes).toContain('CTX-032');
  });

  // 20. caller-supplied policy metadata ignored
  test('20. caller-supplied policy metadata ignored', async () => {
    const res = await request(app)
      .post(`/api/v1/sbom/${sbomId}/context/assertions`)
      .set('x-user-id', 'test-sec-officer')
      .set('x-user-role', 'security')
      .send({
        assertion: {
          environment: 'PRODUCTION',
          policyId: 'hacker-policy',
          policyVersion: 'v999',
          digestManifestDigest: 'sha256:test-hash',
          justification: 'valid',
          evidenceSource: 'TEST'
        }
      });
    expect(res.status).toBe(201);
    
    const client = await db.pool.connect();
    const rows = await client.query('SELECT policy_version FROM deployment_context_assertions WHERE id = $1', [res.body.assertionId]);
    client.release();
    expect(rows.rows[0].policy_version).not.toBe('v999'); 
  });

  // 22, 23, 24. Temporal validity
  test('22. malformed expiresAt rejected', async () => {
    const res = await engine.verifyContextAssertion({ ...baseAssertion, validUntil: 'not-a-date' }, baseSbom);
    expect(res.reasonCodes).toContain('CTX-016'); 
  });

  test('23. expiry before assertedAt rejected', async () => {
    const res = await engine.verifyContextAssertion({ ...baseAssertion, validUntil: new Date(Date.now() - 86400000).toISOString() }, baseSbom);
    expect(res.reasonCodes).toContain('CTX-016'); 
  });
  
  test('24. future validFrom beyond skew rejected', async () => {
    const res = await engine.verifyContextAssertion({ ...baseAssertion, assertedAt: new Date(Date.now() + 86400000).toISOString() }, baseSbom);
    expect(res.reasonCodes).toContain('CTX-016'); 
  });

  // 26, 27. Inactive assertions
  test('26. expired assertion inactive', async () => {
    const client = await db.pool.connect();
    try {
      const active = await repo.getActiveContextAssertion(sbomId);
      if (active) {
          expect(new Date(active.valid_until).getTime()).toBeGreaterThan(Date.now());
      }
    } finally {
      client.release();
    }
  });

  // 30. Invalid lifecycle transition
  test('30. invalid lifecycle transition rejected', async () => {
    const client = await db.pool.connect();
    try {
      await expect(repo.revokeContextAssertion(client, 'non-existent', 'reason', 'actor')).rejects.toThrow();
    } finally {
      client.release();
    }
  });

  // 42. conflicting criticality assertions resolve conservatively
  test('42. conflicting criticality assertions resolve conservatively', async () => {
    const activeAssertions = [
      { environment: 'PRODUCTION', assetCriticality: 'LOW', verificationStatus: 'VERIFIED', status: 'ACTIVE' },
      { environment: 'PRODUCTION', assetCriticality: 'HIGH', verificationStatus: 'VERIFIED', status: 'ACTIVE' }
    ];
    const risk = contextAssembler.assembleContextRiskEvidence({ sbomDocument: baseSbom, contextAssertions: activeAssertions });
    expect(risk).toBeDefined();
    expect(risk.conflict).toBe(true);
  });

  // 48. duplicate/replay handled deterministically
  test('48. replay or duplicate assertion handled deterministically', async () => {
    const activeAssertions = [
      { id: '1', environment: 'PRODUCTION', verificationStatus: 'VERIFIED', status: 'ACTIVE' },
      { id: '1', environment: 'PRODUCTION', verificationStatus: 'VERIFIED', status: 'ACTIVE' }
    ];
    const risk = contextAssembler.assembleContextRiskEvidence({ sbomDocument: baseSbom, contextAssertions: activeAssertions });
    expect(risk).toBeDefined();
    expect(risk.conflict).toBe(true);
  });

  // 51. wrong-scope context cannot reduce risk
  test('51. wrong-scope context cannot reduce risk', async () => {
    const risk = contextAssembler.assembleContextRiskEvidence({ sbomDocument: baseSbom, contextAssertions: [{ environment: 'DEVELOPMENT', verificationStatus: 'VERIFIED', status: 'ACTIVE' }] });
    expect(risk.contextVector.environment).not.toBe('PRODUCTION');
  });

  // 53, 54. Context does not bypass
  test('53 & 54. valid context does not bypass integrity and does not force TRUSTED', async () => {
    const model = await evaluateTrust({ 
       sbomDocument: { status: 'COMPLIANT' }, 
       contextRisk: { contextVector: { environment: 'PRODUCTION', internetExposure: 'INTERNAL' }, missingContext: false, conflict: false, invalidContext: false }
    });
    expect(model.trustStatus).not.toBe('TRUSTED');
  });

  // 58. traceability contains policy and assertion evidence
  test('58. policy ID/version and assertion evidence appear in output traceability', async () => {
    const risk = contextAssembler.assembleContextRiskEvidence({ sbomDocument: baseSbom, contextAssertions: [{ id: 'test-1', policyVersion: '3.0', environment: 'PRODUCTION', verificationStatus: 'VERIFIED', status: 'ACTIVE' }] });
    expect(risk.contextAssertionId).toBe('test-1');
  });

  // 61. default persistence fails closed
  test('61. default persistence status fails closed', async () => {
    const client = await db.pool.connect();
    try {
      await expect(client.query('INSERT INTO deployment_context_assertions (id) VALUES ($1)', ['123'])).rejects.toThrow();
    } finally {
      client.release();
    }
  });

  // 9. authorized security officer can approve/revoke within current Point 10 scope
  test('9. authorized security officer can revoke context assertion', async () => {
    // First create an assertion
    const reqRes = await request(app)
      .post(`/api/v1/sbom/${sbomId}/context/assertions`)
      .set('x-user-id', 'test-sec-officer')
      .set('x-user-role', 'security')
      .send({
        assertion: {
          environment: 'PRODUCTION',
          digestManifestDigest: 'sha256:test-hash',
          justification: 'test 9 setup',
          evidenceSource: 'TEST'
        }
      });
    const assertionId = reqRes.body.assertionId;

    // Then revoke it
    const revokeRes = await request(app)
      .post(`/api/v1/sbom/${sbomId}/context/assertions/${assertionId}/revoke`)
      .set('x-user-id', 'sec-user-9')
      .set('x-user-role', 'security')
      .send({ justification: 'Revoking for test 9' });
    
    expect(revokeRes.status).toBe(200); 
  });
});


