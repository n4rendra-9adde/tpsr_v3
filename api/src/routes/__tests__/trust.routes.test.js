const request = require('supertest');
const express = require('express');
const auth = require('../../middleware/auth');
const trustRoute = require('../trust.routes');
const outboxRoute = require('../outbox.routes');
const sbomRepository = require('../../repositories/sbomRepository');
const trustRepository = require('../../repositories/trustRepository');

jest.mock('../../repositories/sbomRepository');
jest.mock('../../repositories/trustRepository');
jest.mock('../../repositories/contextAssertionRepository', () => ({
  listContextAssertionsBySbomId: jest.fn()
}));
const contextAssertionRepository = require('../../repositories/contextAssertionRepository');

const app = express();
app.use(express.json());

app.use('/api', (req, res, next) => {
  auth.authenticateHeaders(req, res, () => {
    next();
  });
});

app.use('/api', trustRoute);
app.use('/api', outboxRoute);

describe('TPSR v3 Trust Evaluation & Outbox Routes Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('POST /api/v1/sbom/:sbomId/trust-evaluation: Returns cached result when Idempotency-Key matches', async () => {
    trustRepository.getTrustDecisionByIdempotencyKey.mockResolvedValue({
      id: 'dec-100',
      sbom_id: 'test-sbom-idemp',
      trust_status: 'TRUSTED',
      reason_code: 'GOV-001',
      reason_description: 'Cached decision',
      evidence_summary: '{"provenanceCount":1}',
      evaluated_at: new Date().toISOString()
    });

    const res = await request(app)
      .post('/api/v1/sbom/test-sbom-idemp/trust-evaluation')
      .set('x-user-id', 'sec-officer')
      .set('x-user-role', 'security')
      .set('idempotency-key', 'idemp-key-uuid-1234');

    expect(res.status).toBe(200);
    expect(res.body.idempotent).toBe(true);
    expect(res.body.decisionId).toBe('dec-100');
  });

  test('POST /api/v1/sbom/:sbomId/trust-evaluation: Evaluates evidence bundle, stores decision, and queues to outbox', async () => {
    trustRepository.getTrustDecisionByIdempotencyKey.mockResolvedValue(null);
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({ id: 301, sbom_id: 'test-sbom-301' });
    sbomRepository.getProvenanceBySBOMID.mockResolvedValue([{ status: 'VALID', slsa_level: 'SLSA_BUILD_LEVEL_3' }]);
    sbomRepository.getSignaturesBySBOMID.mockResolvedValue([{ verification_status: 'VERIFIED' }]);
    sbomRepository.getVexStatementsBySBOMID.mockResolvedValue([]);
    sbomRepository.getDeploymentContextBySBOMID.mockResolvedValue([]);
    sbomRepository.getPolicyExceptionsBySBOMID.mockResolvedValue([]);
    contextAssertionRepository.listContextAssertionsBySbomId.mockResolvedValue([{ status: 'ACTIVE', verification_status: 'VERIFIED', environment: 'PROD', internetExposure: 'INTERNAL', componentPresence: 'PRESENT', runtimeExecution: 'EXECUTED' }]);

    trustRepository.insertTrustDecision.mockResolvedValue({
      id: 'dec-301',
      sbom_id: 'test-sbom-301',
      trust_status: 'TRUSTED',
      evaluated_at: new Date().toISOString()
    });
    trustRepository.insertOutboxRecord.mockResolvedValue({
      id: 'outbox-301',
      status: 'PENDING'
    });

    const res = await request(app)
      .post('/api/v1/sbom/test-sbom-301/trust-evaluation')
      .set('x-user-id', 'sec-officer')
      .set('x-user-role', 'security');

    expect(res.status).toBe(201);
    expect(res.body.trustStatus).toBe('TRUSTED');
    expect(res.body.reasonCode).toBe('GOV-001');
    expect(res.body.decisionId).toBe('dec-301');
    expect(res.body.outboxId).toBe('outbox-301');
    expect(res.body.ledgerStatus).toBe('PENDING');
  });

  test('POST /api/v1/admin/outbox/:id/requeue: Requeues FAILED_REQUIRES_REVIEW outbox record', async () => {
    trustRepository.getOutboxRecordByID.mockResolvedValue({
      id: 'outbox-401',
      sbom_id: 'test-sbom-401',
      status: 'FAILED_REQUIRES_REVIEW'
    });
    trustRepository.updateOutboxRecordStatus.mockResolvedValue({
      id: 'outbox-401',
      sbom_id: 'test-sbom-401',
      status: 'PENDING',
      next_attempt_at: new Date().toISOString()
    });

    const res = await request(app)
      .post('/api/v1/admin/outbox/outbox-401/requeue')
      .set('x-user-id', 'admin-user')
      .set('x-user-role', 'admin');

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('PENDING');
    expect(res.body.outboxId).toBe('outbox-401');
  });

  test('POST /api/v1/admin/outbox/:id/requeue: Rejects requeue of COMPLETED record', async () => {
    trustRepository.getOutboxRecordByID.mockResolvedValue({
      id: 'outbox-402',
      status: 'COMPLETED'
    });

    const res = await request(app)
      .post('/api/v1/admin/outbox/outbox-402/requeue')
      .set('x-user-id', 'admin-user')
      .set('x-user-role', 'admin');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Cannot requeue outbox record in state');
  });
});
