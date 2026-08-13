'use strict';

const request = require('supertest');
const express = require('express');
const crypto = require('crypto');
const db = require('../../config/database');
const repo = require('../../repositories/policyExceptionRepository');
const { authenticateHeaders } = require('../../middleware/auth');
const exceptionRoutes = require('../exceptions.routes');

const app = express();
app.use(express.json());
app.use('/api', authenticateHeaders, exceptionRoutes);

describe('Point 10 Exception Authority Boundary', () => {
  const sbomId = 'point10-exc-sbom';
  
  beforeAll(async () => {
    const client = await db.pool.connect();
    await client.query(`
      INSERT INTO sbom_documents (sbom_id, sbom_hash, sbom_json, status, build_id, software_name, software_version, format)
      VALUES ($1, 'exc-hash', '{"components":[]}', 'COMPLIANT', 'test-build', 'test-software', '1.0.0', 'CycloneDX')
      ON CONFLICT DO NOTHING
    `, [sbomId]);
    client.release();
  });

  test('request body cannot select requester/approver and requester cannot self-approve when policy prohibits it', async () => {
    // 1. Request exception
    const reqRes = await request(app)
      .post(`/api/v1/sbom/${sbomId}/exceptions`)
      .set('x-user-id', 'dev-user')
      .set('x-user-role', 'developer')
      .send({
        policyRuleId: 'CAECTD-R017',
        reasonCode: 'EXC-101',
        justification: 'test justification',
        businessNeed: 'business test',
        remediationPlan: 'plan',
        compensatingControls: ['control1'],
        residualRisk: 'MEDIUM',
        validUntil: new Date(Date.now() + 86400000).toISOString(),
        // Maliciously try to set requester/owner to admin to bypass separation
        requestedBy: 'admin',
        requestedByRole: 'admin',
        ownedBy: 'admin'
      });
    
    if (reqRes.status !== 201) {
      console.log(reqRes.body);
    }
    expect(reqRes.status).toBe(201);
    const exceptionId = reqRes.body.id;

    // Check that it ignored the body fields
    const record = await repo.getExceptionById(exceptionId);
    expect(record.requested_by).toBe('dev-user');
    expect(record.requested_by_role).toBe('developer');
    expect(record.owned_by).toBe('dev-user'); // Defaulted to requester
    
    // 2. Try to self approve
    const appRes = await request(app)
      .post(`/api/v1/sbom/${sbomId}/exceptions/${exceptionId}/approve`)
      .set('x-user-id', 'dev-user')
      .set('x-user-role', 'security') // Even if role was changed, it's the same user
      .send({
        approvalComment: 'I approve my own request'
      });
    
    // Policy prohibits self-approval (requireRequesterDifferentFromApprover: true)
    expect(appRes.status).toBe(403);
    expect(appRes.body.error).toContain('Separation of duties');
  });

  test('unauthorized role cannot approve', async () => {
    // Create an exception by dev-user
    const reqRes = await request(app)
      .post(`/api/v1/sbom/${sbomId}/exceptions`)
      .set('x-user-id', 'dev-user-2')
      .set('x-user-role', 'developer')
      .send({
        policyRuleId: 'CAECTD-R017',
        reasonCode: 'EXC-101',
        justification: 'test',
        residualRisk: 'LOW',
        validUntil: new Date(Date.now() + 86400000).toISOString()
      });
    const exceptionId = reqRes.body.id;

    // Try to approve with developer role
    const appRes = await request(app)
      .post(`/api/v1/sbom/${sbomId}/exceptions/${exceptionId}/approve`)
      .set('x-user-id', 'other-user')
      .set('x-user-role', 'developer') // Developer is not allowed to approve
      .send({
        approvalComment: 'Approve'
      });
    
    expect(appRes.status).toBe(403);
    expect(appRes.body.error).toContain('Unauthorized role');
  });

  test('8. authorized security officer can approve/revoke according to current scope', async () => {
    // Create an exception by dev-user
    const reqRes = await request(app)
      .post(`/api/v1/sbom/${sbomId}/exceptions`)
      .set('x-user-id', 'dev-user-3')
      .set('x-user-role', 'developer')
      .send({
        policyRuleId: 'CAECTD-R017',
        reasonCode: 'EXC-101',
        justification: 'test',
        residualRisk: 'LOW',
        businessNeed: 'need',
        remediationPlan: 'plan',
        compensatingControls: ['ctrl'],
        vulnerabilityIds: ['CVE-2023-1234'],
        validUntil: new Date(Date.now() + 86400000).toISOString()
      });
    const exceptionId = reqRes.body.id;

    // Approve with security officer
    const appRes = await request(app)
      .post(`/api/v1/sbom/${sbomId}/exceptions/${exceptionId}/approve`)
      .set('x-user-id', 'sec-officer-1')
      .set('x-user-role', 'security') 
      .send({
        approvalComment: 'Approved by sec officer'
      });
    
    if (appRes.status !== 200) console.log('appRes', appRes.body);
    expect(appRes.status).toBe(200);
    expect(appRes.body.status).toBe('ACTIVE');
    
    // Revoke with security officer
    const revRes = await request(app)
      .post(`/api/v1/sbom/${sbomId}/exceptions/${exceptionId}/revoke`)
      .set('x-user-id', 'sec-officer-2')
      .set('x-user-role', 'security') 
      .send({
        revocationReason: 'No longer needed'
      });
      
    expect(revRes.status).toBe(200);
    expect(revRes.body.status).toBe('REVOKED');
  });
});
