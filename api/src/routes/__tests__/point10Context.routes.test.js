'use strict';

const request = require('supertest');
const { app } = require('../../server');
const db = require('../../config/database');

describe('Point 10 Context Route Security', () => {
  let sbomId = 'point10-test-sbom';

  beforeAll(async () => {
    // Setup test sbom
    const client = await db.pool.connect();
    try {
      await client.query(`
        INSERT INTO sbom_documents (sbom_id, sbom_hash, sbom_json, status, build_id, software_name, software_version, format)
        VALUES ($1, 'test-hash', '{"components":[]}', 'COMPLIANT', 'test-build-1', 'test-software', '1.0.0', 'CycloneDX')
        ON CONFLICT DO NOTHING
      `, [sbomId]);
    } finally {
      client.release();
    }
  });

  afterAll(async () => {
    const client = await db.pool.connect();
    try {
      await client.query('DELETE FROM deployment_context_assertions WHERE sbom_id = $1', [sbomId]);
      await client.query('DELETE FROM sbom_documents WHERE sbom_id = $1', [sbomId]);
    } finally {
      client.release();
    }
  });

  test('1. missing authenticated principal rejected', async () => {
    const res = await request(app)
      .post(`/api/v1/sbom/${sbomId}/context/assertions`)
      .send({
        assertion: { environment: 'PRODUCTION', justification: 'test' },
        signature: 'fake', publicKey: 'fake', verificationMode: 'STRICT'
      });
    expect(res.status).toBe(403);
  });

  test('2 & 3. request-body assertedBy and assertedByRole ignored (generates server-side metadata)', async () => {
    const res = await request(app)
      .post(`/api/v1/sbom/${sbomId}/context/assertions`)
      .set('x-user-id', 'test-sec-officer')
      .set('x-user-role', 'security')
      .send({
        assertion: {
          environment: 'PRODUCTION',
          justification: 'valid test',
          assertedBy: 'hacker',
          assertedByRole: 'admin',
          digestManifestDigest: 'sha256:test-hash'
        }
      });
    
    // Without signature, we added AUTHORIZED if it passes authorization.
    // Let's check status
    if (res.status !== 201) console.log('DEBUG 422 (test 2):', res.body);
    expect(res.status).toBe(201);
    
    // Let's check DB
    const client = await db.pool.connect();
    const rows = await client.query('SELECT asserted_by, assertor_role FROM deployment_context_assertions WHERE id = $1', [res.body.assertionId]);
    client.release();
    expect(rows.rows[0].asserted_by).toBe('test-sec-officer');
    expect(rows.rows[0].assertor_role).toBe('security');
  });

  test('4. authorized environment asserter accepted', async () => {
    const res = await request(app)
      .post(`/api/v1/sbom/${sbomId}/context/assertions`)
      .set('x-user-id', 'dev-1')
      .set('x-user-role', 'developer')
      .send({
        assertion: {
          environment: 'DEVELOPMENT',
          justification: 'valid test',
          digestManifestDigest: 'sha256:test-hash'
        }
      });
    expect(res.status).toBe(201);
  });

  test('5. unauthorized role cannot assert environment', async () => {
    const res = await request(app)
      .post(`/api/v1/sbom/${sbomId}/context/assertions`)
      .set('x-user-id', 'dev-1')
      .set('x-user-role', 'developer')
      .send({
        assertion: {
          environment: 'PRODUCTION',
          justification: 'valid test',
          justification: 'valid test', // Developer not allowed
          digestManifestDigest: 'sha256:test-hash'
        }
      });
    expect(res.status).toBe(422);
    expect(res.body.reasonCodes).toContain('CTX-030'); // Unauthorized role
  });

  test('19. caller-supplied authorizationStatus ignored', async () => {
    const client = await db.pool.connect();
    await client.query(`
      INSERT INTO sbom_documents (sbom_id, sbom_hash, sbom_json, status, build_id, software_name, software_version, format)
      VALUES ($1, 'test-hash', '{"components":[]}', 'COMPLIANT', 'test-build-1', 'test-software', '1.0.0', 'CycloneDX')
      ON CONFLICT DO NOTHING
    `, [sbomId + '-19']);
    client.release();

    const res = await request(app)
      .post(`/api/v1/sbom/${sbomId}-19/context/assertions`)
      .set('x-user-id', 'test-sec-officer')
      .set('x-user-role', 'security')
      .send({
        assertion: {
          environment: 'PRODUCTION',
          justification: 'valid test',
          justification: 'valid test',
          authorizationStatus: 'AUTHORIZED',
          digestManifestDigest: 'sha256:test-hash'
        }
      });
    expect(res.status).toBe(201);
    expect(res.body.verificationStatus).toBe('AUTHORIZED');
  });
  
  test('29. unauthorized revoke rejected', async () => {
    const res = await request(app)
      .post(`/api/v1/sbom/${sbomId}/context/assertions/dummy/revoke`)
      .set('x-user-id', 'dev')
      .set('x-user-role', 'developer') // Not allowed to revoke
      .send({ justification: 'test' });
    expect(res.status).toBe(403);
  });

  test('59. route ignores caller actor/provenance fields', async () => {
    const res = await request(app)
      .post(`/api/v1/sbom/${sbomId}/context/assertions`)
      .set('x-user-id', 'test-sec-officer')
      .set('x-user-role', 'security')
      .send({
        assertion: {
          environment: 'PRODUCTION',
          justification: 'valid test',
          justification: 'valid test',
          assertedBy: 'hacker',
          assertorRole: 'admin',
          provenanceMode: 'HACKED',
          digestManifestDigest: 'sha256:test-hash'
        }
      });
    
    expect(res.status).toBe(201);
    
    // Check DB
    const client = await db.pool.connect();
    const rows = await client.query('SELECT asserted_by, assertor_role, provenance_mode FROM deployment_context_assertions WHERE id = $1', [res.body.assertionId]);
    client.release();
    expect(rows.rows[0].asserted_by).toBe('test-sec-officer');
    expect(rows.rows[0].assertor_role).toBe('security');
    expect(rows.rows[0].provenance_mode).toBe('AUTHENTICATED_API');
  });
});
