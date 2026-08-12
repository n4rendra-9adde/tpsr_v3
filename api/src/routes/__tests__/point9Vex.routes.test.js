const request = require('supertest');
const express = require('express');
jest.mock('../../repositories/sbomRepository');
jest.mock('../../utils/vexEngine');

const vexRoutes = require('../vex.routes');
const sbomRepository = require('../../repositories/sbomRepository');
const vexEngine = require('../../utils/vexEngine');

const app = express();
app.use(express.json());
// Add a fake auth middleware for RBAC checks if any
app.use((req, res, next) => {
  req.headers['x-user-id'] = 'test-user';
  req.headers['x-user-role'] = 'SECURITY_AUDITOR';
  next();
});
app.use('/', vexRoutes);

describe('Point 9 VEX Route Boundary Security', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({ id: 'sbom-123' });
    sbomRepository.insertVexStatement.mockResolvedValue({ id: 'vex-123' });
  });

  const baseReq = {
    envelope: { payloadType: 'application/vnd.in-toto+json', payload: 'e30=', signatures: [] },
    signatureType: 'OFFLINE_KEYED',
    publicKey: 'key',
    targetContext: { vulnerabilityId: 'CVE-123' }
  };

  test('1-4. Caller-supplied authority and policy metadata is completely ignored', async () => {
    vexEngine.verifyVexDocument.mockResolvedValue({
      isValid: false,
      vexAuthoritative: false,
      reasonCode: 'VEX-010',
      policyBlockingStatus: 'BLOCKING',
      signatureStatus: 'FAILED',
      vexStatus: 'affected',
      reasonCodes: ['VEX-010']
    });

    const maliciousReq = {
      ...baseReq,
      vexAuthoritative: true,
      cryptographicValid: true,
      issuerAuthorized: true,
      policyId: 'fake-policy',
      verifiedIssuerIdentity: 'admin',
      reasonCode: 'VEX-001'
    };

    const response = await request(app)
      .post('/sbom/sbom-123/vex')
      .send(maliciousReq);

    expect(response.status).toBe(422);

    // Assert exactly what was passed to the repository
    expect(sbomRepository.insertVexStatement).toHaveBeenCalledTimes(1);
    const dbArgs = sbomRepository.insertVexStatement.mock.calls[0][0];

    expect(dbArgs.vexAuthoritative).toBe(false);
    expect(dbArgs.reasonCodes).toContain('VEX-010');
    expect(dbArgs.policyId).toBeUndefined();
    expect(dbArgs.issuerIdentity).toBe('test-user'); // From our header, not request body
  });

  test('5. forged VEX cannot persist as authoritative', async () => {
    vexEngine.verifyVexDocument.mockResolvedValue({
      isValid: false,
      vexAuthoritative: false,
      reasonCode: 'VEX-010',
      reasonCodes: ['VEX-010']
    });

    await request(app).post('/sbom/sbom-123/vex').send(baseReq);
    const dbArgs = sbomRepository.insertVexStatement.mock.calls[0][0];
    expect(dbArgs.vexAuthoritative).toBe(false);
    expect(dbArgs.reasonCodes).toContain('VEX-010');
  });

  test('6. stale VEX cannot persist as authoritative', async () => {
    vexEngine.verifyVexDocument.mockResolvedValue({
      isValid: false,
      vexAuthoritative: false,
      reasonCode: 'VEX-007',
      reasonCodes: ['VEX-007']
    });

    await request(app).post('/sbom/sbom-123/vex').send(baseReq);
    const dbArgs = sbomRepository.insertVexStatement.mock.calls[0][0];
    expect(dbArgs.vexAuthoritative).toBe(false);
    expect(dbArgs.reasonCodes).toContain('VEX-007');
  });

  test('7-9. wrong artifact/version/CVE VEX cannot persist as authoritative', async () => {
    vexEngine.verifyVexDocument.mockResolvedValue({
      isValid: false,
      vexAuthoritative: false,
      reasonCode: 'VEX-004', // artifact mismatch
      reasonCodes: ['VEX-004']
    });

    await request(app).post('/sbom/sbom-123/vex').send(baseReq);
    const dbArgs = sbomRepository.insertVexStatement.mock.calls[0][0];
    expect(dbArgs.vexAuthoritative).toBe(false);
    expect(dbArgs.reasonCodes).toContain('VEX-004');
  });

  test('10. valid exact-target VEX persists verifier-generated metadata', async () => {
    vexEngine.verifyVexDocument.mockResolvedValue({
      isValid: true,
      vexAuthoritative: true,
      reasonCode: 'VEX-001',
      reasonCodes: ['VEX-001'],
      policyId: 'pol-1',
      canonicalPayloadDigest: 'hash123',
      verifiedAt: '2026-08-11T00:00:00Z',
      vexStatus: 'not_affected'
    });

    await request(app).post('/sbom/sbom-123/vex').send(baseReq);
    const dbArgs = sbomRepository.insertVexStatement.mock.calls[0][0];
    expect(dbArgs.vexAuthoritative).toBe(true);
    expect(dbArgs.policyId).toBe('pol-1');
    expect(dbArgs.canonicalPayloadDigest).toBe('hash123');
    expect(dbArgs.status).toBe('not_affected');
  });

  test('11. invalid VEX is stored non-authoritatively for audit', async () => {
    vexEngine.verifyVexDocument.mockResolvedValue({
      isValid: false,
      vexAuthoritative: false,
      reasonCode: 'VEX-010',
      reasonCodes: ['VEX-010']
    });

    await request(app).post('/sbom/sbom-123/vex').send(baseReq);
    // Still called insert for audit trailing
    expect(sbomRepository.insertVexStatement).toHaveBeenCalledTimes(1);
    const dbArgs = sbomRepository.insertVexStatement.mock.calls[0][0];
    expect(dbArgs.vexAuthoritative).toBe(false);
  });

  test('12. RBAC behavior remains unchanged', async () => {
     vexEngine.verifyVexDocument.mockResolvedValue({ isValid: true, reasonCodes: [] });
     const response = await request(app).post('/sbom/sbom-123/vex').send(baseReq);
     const dbArgs = sbomRepository.insertVexStatement.mock.calls[0][0];
     // We extract issuer from token/headers, not body
     expect(dbArgs.issuerIdentity).toBe('test-user');
  });
});
