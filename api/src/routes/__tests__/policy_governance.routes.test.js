const request = require('supertest');
const express = require('express');
const auth = require('../../middleware/auth');
const vexRoute = require('../vex.routes');
const contextRoute = require('../context.routes');
const exceptionsRoute = require('../exceptions.routes');
const sbomRepository = require('../../repositories/sbomRepository');
const vexEngine = require('../../utils/vexEngine');
const policyExceptionRepository = require('../../repositories/policyExceptionRepository');
const policyExceptionEngine = require('../../utils/policyExceptionEngine');

jest.mock('../../repositories/sbomRepository');
jest.mock('../../utils/vexEngine');
jest.mock('../../repositories/policyExceptionRepository');

const app = express();
app.use(express.json());

app.use('/api', (req, res, next) => {
  auth.authenticateHeaders(req, res, () => {
    next();
  });
});

app.use('/api', vexRoute);
app.use('/api', contextRoute);
app.use('/api', exceptionsRoute);

describe('TPSR v3 VEX, Deployment Context, and Exception Routes Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('POST /api/v1/sbom/:sbomId/vex: Records valid VEX statement and returns 201', async () => {
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({ id: 201, sbom_id: 'test-sbom-201' });
    
    vexEngine.verifyVexDocument.mockResolvedValue({
      isValid: true,
      vexStatus: 'not_affected',
      policyBlockingStatus: 'NON_BLOCKING',
      justification: 'vulnerable_code_not_present',
      impactStatement: 'Vulnerable code path removed',
      reasonCode: 'VEX-001'
    });

    sbomRepository.insertVexStatement.mockResolvedValue({
      id: 701,
      vulnerability_id: 'CVE-2026-9999',
      policy_blocking_status: 'NON_BLOCKING',
      created_at: new Date().toISOString()
    });

    const body = {
      envelope: {
        vulnerabilityId: 'CVE-2026-9999',
        originalSeverity: 'CRITICAL',
        originalCvss: 9.8,
        status: 'not_affected',
        justification: 'vulnerable_code_not_present',
        impactStatement: 'Vulnerable code path removed'
      },
      signatureType: 'NONE'
    };

    const res = await request(app)
      .post('/api/v1/sbom/test-sbom-201/vex')
      .set('x-user-id', 'sec-user')
      .set('x-user-role', 'security')
      .send(body);

    expect(res.status).toBe(201);
    expect(res.body.reasonCode).toBe('VEX-001');
    expect(res.body.policyBlockingStatus).toBe('NON_BLOCKING');
    expect(res.body.vexId).toBe(701);
  });

  test('POST /api/v1/sbom/:sbomId/context: Evaluates PROD_CRITICAL deployment context against VEX overlays', async () => {
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({
      id: 202,
      sbom_id: 'test-sbom-202',
      sbom_json: JSON.stringify({
        components: [
          { name: 'lib-a', vulnerabilities: [{ id: 'CVE-2026-8888', cvssScore: 9.8, severity: 'CRITICAL' }] }
        ]
      })
    });
    // With VEX suppressing the critical vulnerability:
    sbomRepository.getVexStatementsBySBOMID.mockResolvedValue([
      { id: 'vex-1', vulnerability_id: 'CVE-2026-8888', status: 'fixed' }
    ]);
    
    vexEngine.applyVexOverlays.mockReturnValue({
      vulnerabilities: [
        {
          originalCvssScore: 9.8,
          originalSeverity: 'CRITICAL',
          applicabilityDisposition: 'NOT_AFFECTED',
          policyBlockingStatus: 'NON_BLOCKING'
        }
      ],
      activeVexIds: ['vex-1'],
      appliedAt: new Date().toISOString()
    });

    sbomRepository.insertDeploymentContext.mockResolvedValue({
      id: 801,
      registered_at: new Date().toISOString()
    });

    const res = await request(app)
      .post('/api/v1/sbom/test-sbom-202/context')
      .set('x-user-id', 'dev-user')
      .set('x-user-role', 'developer')
      .send({ deploymentTier: 'PROD_CRITICAL', internetExposed: false });

    expect(res.status).toBe(201);
    expect(res.body.compliant).toBe(true);
    expect(res.body.reasonCode).toBe('CTX-000');
  });

  test('POST /api/v1/sbom/:sbomId/exceptions: Records formal policy exception request and returns 201', async () => {
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({ id: 203, sbom_id: 'test-sbom-203', sbom_hash: 'hash123' });
    
    policyExceptionRepository.createExceptionRequest.mockResolvedValue({
      id: 901,
      policy_rule_id: 'CAECTD-R010',
      status: 'REQUESTED',
      created_at: new Date().toISOString()
    });
    
    policyExceptionRepository.recordExceptionEvent.mockResolvedValue({});

    const body = {
      policyRuleId: 'CAECTD-R010',
      reasonCode: 'TEST',
      justification: 'Legacy system migrating in Q4; isolated network segment.',
      validUntil: '2026-12-31T23:59:59Z',
      residualRisk: 'MEDIUM'
    };

    const res = await request(app)
      .post('/api/v1/sbom/test-sbom-203/exceptions')
      .set('x-user-id', 'sec-lead')
      .set('x-user-role', 'security')
      .send(body);

    expect(res.status).toBe(201);
    expect(res.body.id).toBe(901);
    expect(res.body.status).toBe('REQUESTED');
  });

  test('GET /api/v1/sbom/:sbomId/exceptions: Retrieves active policy exceptions', async () => {
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({ id: 204, sbom_id: 'test-sbom-204' });
    policyExceptionRepository.listExceptionsBySbomId.mockResolvedValue([
      { id: 901, sbom_id: 'test-sbom-204', policy_rule_id: 'CAECTD-R010', status: 'ACTIVE' }
    ]);

    const res = await request(app)
      .get('/api/v1/sbom/test-sbom-204/exceptions')
      .set('x-user-id', 'auditor')
      .set('x-user-role', 'auditor');

    expect(res.status).toBe(200);
    expect(res.body.count).toBe(1);
    expect(res.body.policyExceptions[0].policy_rule_id).toBe('CAECTD-R010');
  });
});
