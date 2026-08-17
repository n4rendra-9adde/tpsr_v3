'use strict';

const request = require('supertest');
const { app } = require('../server');
const sbomRepository = require('../repositories/sbomRepository');
const trustRepository = require('../repositories/trustRepository');
const automaticEvaluationService = require('../services/automaticEvaluationService');
const { verifyProvenance } = require('../utils/provenanceEngine');

jest.mock('../repositories/sbomRepository');
jest.mock('../repositories/trustRepository');
jest.mock('../services/automaticEvaluationService');
jest.mock('../utils/provenanceEngine');
jest.mock('../config/fabric', () => ({
  getContract: jest.fn().mockResolvedValue({
    gateway: { disconnect: jest.fn() },
    contract: { submitTransaction: jest.fn().mockResolvedValue(true) }
  }),
  disconnectGateway: jest.fn()
}));

describe('Provenance-Triggered Reevaluation Workflow (Step 2)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('valid provenance persistence -> authenticated reevaluation request -> same SBOM evaluated -> new decision ID -> new snapshot ID -> previous decision retained', async () => {
    const mockSbomId = 'SBOM-REEVAL-01';
    
    // 1. Valid provenance persistence
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({ sbom_id: mockSbomId, sbom_hash: 'hash123' });
    verifyProvenance.mockResolvedValue({
      status: 'VALID',
      builderId: 'authorized-builder',
      slsaLevel: 'SLSA_BUILD_LEVEL_3',
      reasonCodes: ['PROV-000']
    });
    sbomRepository.insertProvenanceAttestation.mockResolvedValue({ id: 'prov-1', created_at: new Date().toISOString() });
    
    const provResponse = await request(app)
      .post(`/api/v1/sbom/${mockSbomId}/provenance`)
      .set('x-user-role', 'developer')
      .set('x-user-id', 'dev-1')
      .send({ envelope: { payloadType: 'application/vnd.in-toto+json' } });
    
    expect(provResponse.status).toBe(201);
    expect(provResponse.body.sbomId).toBe(mockSbomId);
    
    // 2. Authenticated reevaluation request
    automaticEvaluationService.evaluateSubmittedSbom.mockResolvedValue({
      recommendation: 'APPROVE',
      decisionId: 'new-dec-01',
      snapshotId: 'new-snap-01',
      correlationId: 'corr-01'
    });
    
    trustRepository.getTrustDecisionHistoryBySBOMID.mockResolvedValue([
      { id: 'new-dec-01' },
      { id: 'old-dec-01' }
    ]);
    
    const reevalResponse = await request(app)
      .post(`/api/v1/sbom/${provResponse.body.sbomId}/reevaluate`)
      .set('x-user-role', 'security')
      .set('x-user-id', 'sec-1')
      .send({ triggerType: 'PROVENANCE_CHANGED' });
    
    expect(reevalResponse.status).toBe(200);
    
    // 3. Same SBOM evaluated
    expect(automaticEvaluationService.evaluateSubmittedSbom).toHaveBeenCalledWith(
      expect.objectContaining({
        sbomId: mockSbomId,
        triggerType: 'PROVENANCE_CHANGED',
        principal: 'sec-1'
      })
    );
    
    // 4. New decision ID and New snapshot ID
    expect(reevalResponse.body.recommendation.decisionId).toBe('new-dec-01');
    expect(reevalResponse.body.recommendation.snapshotId).toBe('new-snap-01');
    
    // 5. Previous decision retained
    const history = await trustRepository.getTrustDecisionHistoryBySBOMID(mockSbomId);
    expect(history).toHaveLength(2);
    expect(history[1].id).toBe('old-dec-01');
  });
});
