const request = require('supertest');
const express = require('express');
const auth = require('../../middleware/auth');
const provenanceRoute = require('../provenance.routes');
const signaturesRoute = require('../signatures.routes');
const sbomRepository = require('../../repositories/sbomRepository');
const fabric = require('../../config/fabric');

jest.mock('../../repositories/sbomRepository');
jest.mock('../../config/fabric');

const app = express();
app.use(express.json());

// Add auth headers middleware matching server setup
app.use('/api', (req, res, next) => {
  auth.authenticateHeaders(req, res, () => {
    next();
  });
});

app.use('/api', provenanceRoute);
app.use('/api', signaturesRoute);

describe('TPSR v3 Evidence Governance Routes Unit Tests', () => {
  const validHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  beforeEach(() => {
    jest.clearAllMocks();
    fabric.getContract.mockRejectedValue(new Error('Fabric offline in test'));
    fabric.disconnectGateway.mockImplementation(() => {});
  });

  test('POST /api/v1/sbom/:sbomId/provenance: Returns 404 if SBOM document not found', async () => {
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue(null);

    const res = await request(app)
      .post('/api/v1/sbom/non-existent-id/provenance')
      .set('x-user-id', 'dev-user')
      .set('x-user-role', 'developer')
      .send({ attestationPayload: { _type: 'https://in-toto.io/Statement/v1', subject: [] } });

    expect(res.status).toBe(404);
    expect(res.body.error).toContain('SBOM document not found');
  });

  test('POST /api/v1/sbom/:sbomId/provenance: Records valid provenance attestation and returns 201', async () => {
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({
      id: 101,
      sbom_id: 'test-sbom-101',
      sbom_hash: validHash
    });
    sbomRepository.insertProvenanceAttestation.mockResolvedValue({
      id: 501,
      sbom_id: 'test-sbom-101',
      created_at: new Date().toISOString()
    });

    const validAttestation = {
      _type: 'https://in-toto.io/Statement/v1',
      subject: [{ name: 'app.jar', digest: { sha256: validHash } }],
      predicateType: 'https://slsa.dev/provenance/v1',
      predicate: {
        buildDefinition: { buildType: 'https://actions.github.io/buildtypes/workflow/v1' },
        runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } }
      }
    };

    const res = await request(app)
      .post('/api/v1/sbom/test-sbom-101/provenance')
      .set('x-user-id', 'dev-user')
      .set('x-user-role', 'developer')
      .send({ attestationPayload: validAttestation });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('VALID');
    expect(res.body.slsaLevel).toBe('SLSA_BUILD_LEVEL_3');
    expect(res.body.evidenceId).toBe(501);
  });

  test('POST /api/v1/sbom/:sbomId/signatures: Rejects synthetic/simulated signature and returns 422', async () => {
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({
      id: 102,
      sbom_id: 'test-sbom-102',
      sbom_hash: validHash
    });
    sbomRepository.insertSignatureVerification.mockResolvedValue({
      id: 601,
      sbom_id: 'test-sbom-102',
      verified_at: new Date().toISOString()
    });

    const body = {
      signatureType: 'KEYLESS',
      expectedIssuer: 'https://token.actions.githubusercontent.com',
      expectedSubject: 'https://github.com/org/repo/.github/workflows/build.yml',
      bundleJson: {
        simulated: true,
        verificationMaterial: { certificate: { rawBytes: 'test' } },
        messageSignature: {
          messageDigest: {
            algorithm: 'SHA256',
            digest: validHash
          }
        }
      }
    };

    const res = await request(app)
      .post('/api/v1/sbom/test-sbom-102/signatures')
      .set('x-user-id', 'sec-user')
      .set('x-user-role', 'security')
      .send(body);

    expect(res.status).toBe(422);
    expect(res.status).toBe(422);
    expect(res.body.status).toBe('INVALID');
    expect(res.body.reasonCode).toBe('SIG-010');
  });

  test('GET /api/v1/sbom/:sbomId/provenance: Retrieves provenance list for an SBOM', async () => {
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({ id: 103, sbom_id: 'test-sbom-103' });
    sbomRepository.getProvenanceBySBOMID.mockResolvedValue([
      { id: 1, sbom_id: 'test-sbom-103', slsa_level: 'SLSA_BUILD_LEVEL_3' }
    ]);

    const res = await request(app)
      .get('/api/v1/sbom/test-sbom-103/provenance')
      .set('x-user-id', 'auditor')
      .set('x-user-role', 'auditor');

    expect(res.status).toBe(200);
    expect(res.body.count).toBe(1);
    expect(res.body.attestations[0].slsa_level).toBe('SLSA_BUILD_LEVEL_3');
  });
});
