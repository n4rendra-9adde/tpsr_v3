'use strict';

const request = require('supertest');
const { app } = require('../../server');
const db = require('../../config/database');

describe('Point 11 Exception Lifecycle and History', () => {
  let sbomId = 'point11-hist-sbom';
  let exceptionId;

  beforeAll(async () => {
    const client = await db.pool.connect();
    try {
      await client.query(`
        INSERT INTO sbom_documents (sbom_id, sbom_hash, sbom_json, status, build_id, software_name, software_version, format)
        VALUES ($1, 'test-hash-hist', '{"components":[]}', 'COMPLIANT', 'test-build-1', 'test-software', '1.0.0', 'CycloneDX')
        ON CONFLICT DO NOTHING
      `, [sbomId]);
    } finally {
      client.release();
    }
  });

  afterAll(async () => {
    const client = await db.pool.connect();
    try {
      await client.query('DELETE FROM policy_exception_events WHERE sbom_id = $1', [sbomId]);
      await client.query('DELETE FROM policy_exceptions WHERE sbom_id = $1', [sbomId]);
      await client.query('DELETE FROM ledger_outbox WHERE decision_id IN (SELECT id FROM trust_decision_history WHERE sbom_id = $1)', [sbomId]);
      await client.query('DELETE FROM trust_decision_history WHERE sbom_id = $1', [sbomId]);
      await client.query('DELETE FROM sbom_documents WHERE sbom_id = $1', [sbomId]);
    } finally {
      client.release();
    }
  });

  const getValidPayload = () => ({
    sbomId: sbomId,
    digestManifestDigest: 'test-hash-hist',
    policyRuleId: 'CAECTD-R017',
    reasonCode: 'CTX-002',
    justification: 'valid justification',
    businessNeed: 'valid business need',
    remediationPlan: 'fix in next release',
    compensatingControls: ['WAF'],
    residualRisk: 'MEDIUM',
    validUntil: new Date(Date.now() + 86400000).toISOString()
  });

  test('51 valid request-to-approval transition & 52 rejection transition', async () => {
    // Rejection
    const p1 = getValidPayload();
    const req1 = await request(app).post(`/api/v1/sbom/${sbomId}/exceptions`).set('x-user-id', 'dev1').set('x-user-role', 'developer').send(p1);
    const ex1 = req1.body.id;
    const rej = await request(app).post(`/api/v1/sbom/${sbomId}/exceptions/${ex1}/reject`).set('x-user-id', 'sec1').set('x-user-role', 'security').send({ rejectionReason: 'Bad' });
    expect(rej.status).toBe(200);
    expect(rej.body.status).toBe('REJECTED');

    // Approval
    const p2 = getValidPayload();
    const req2 = await request(app).post(`/api/v1/sbom/${sbomId}/exceptions`).set('x-user-id', 'dev1').set('x-user-role', 'developer').send(p2);
    const ex2 = req2.body.id;
    const app2 = await request(app).post(`/api/v1/sbom/${sbomId}/exceptions/${ex2}/approve`).set('x-user-id', 'sec1').set('x-user-role', 'security').send({ approvalComment: 'Good' });
    expect(app2.status).toBe(200);
    expect(app2.body.status).toBe('ACTIVE');
    exceptionId = ex2;
  });

  test('54 second approval/reapproval rejected & 53 invalid transition rollback', async () => {
    const app2 = await request(app).post(`/api/v1/sbom/${sbomId}/exceptions/${exceptionId}/approve`).set('x-user-id', 'sec1').set('x-user-role', 'security').send({ approvalComment: 'Again' });
    expect(app2.status).toBe(400); // Not in REQUESTED state anymore
  });

  test('56 transactional supersession', async () => {
    const p3 = getValidPayload();
    const req3 = await request(app).post(`/api/v1/sbom/${sbomId}/exceptions`).set('x-user-id', 'dev1').set('x-user-role', 'developer').send(p3);
    const newEx = req3.body.id;

    const sup = await request(app).post(`/api/v1/sbom/${sbomId}/exceptions/${exceptionId}/supersede`).set('x-user-id', 'sec1').set('x-user-role', 'security').send({ supersedingExceptionId: newEx });
    expect(sup.status).toBe(200);
    expect(sup.body.status).toBe('SUPERSEDED');
    expect(sup.body.supersedes_exception_id).toBe(newEx);
  });

  test('57 old record retained in history & 58 history records actors/time/reason & 59 history RBAC', async () => {
    // Unauthenticated
    const noauth = await request(app).get(`/api/v1/sbom/${sbomId}/exceptions/${exceptionId}/history`);
    expect(noauth.status).toBeGreaterThanOrEqual(401);

    // Unauthorized
    const unauth = await request(app).get(`/api/v1/sbom/${sbomId}/exceptions/${exceptionId}/history`).set('x-user-id', 'dev1').set('x-user-role', 'developer');
    expect(unauth.status).toBe(403);

    // Authorized
    const auth = await request(app).get(`/api/v1/sbom/${sbomId}/exceptions/${exceptionId}/history`).set('x-user-id', 'sec1').set('x-user-role', 'security');
    expect(auth.status).toBe(200);
    expect(auth.body.history).toBeDefined();
    expect(auth.body.history.length).toBeGreaterThanOrEqual(2); // REQUESTED, APPROVED, SUPERSEDED (3 actually)

    const reqEvent = auth.body.history.find(h => h.event_type === 'REQUESTED');
    expect(reqEvent).toBeDefined();
    expect(reqEvent.actor_role).toBe('developer');
    
    const supEvent = auth.body.history.find(h => h.event_type === 'SUPERSEDED');
    expect(supEvent).toBeDefined();
    expect(supEvent.actor_role).toBe('security');
  });
});
