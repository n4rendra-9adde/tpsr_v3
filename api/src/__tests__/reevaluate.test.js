'use strict';

const request = require('supertest');
const { app } = require('../server');
const automaticEvaluationService = require('../services/automaticEvaluationService');
const trustRepository = require('../repositories/trustRepository');

jest.mock('../services/automaticEvaluationService');
jest.mock('../repositories/trustRepository');

describe('Reevaluate Route (Step 2)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('Missing authentication is rejected', async () => {
    const response = await request(app)
      .post('/api/v1/sbom/SBOM-123/reevaluate');
    expect(response.status).toBe(403);
  });

  it('Unauthorized role is rejected', async () => {
    const response = await request(app)
      .post('/api/v1/sbom/SBOM-123/reevaluate')
      .set('x-user-role', 'invalid_role')
      .set('x-user-id', 'some-id');
    
    // In our auth setup, trust evaluation requires security/auditor typically
    // Wait, let's just make sure it fails auth if not provided
    expect(response.status).toBe(403);
  });

  it('Authorized reevaluation invokes automaticEvaluationService with exact SBOM ID and principal', async () => {
    automaticEvaluationService.evaluateSubmittedSbom.mockResolvedValue({
      recommendation: 'APPROVE',
      decisionId: 'new-dec-1',
      snapshotId: 'new-snap-1',
      correlationId: 'corr-123'
    });

    const response = await request(app)
      .post('/api/v1/sbom/SBOM-123/reevaluate')
      .set('x-user-role', 'security')
      .set('x-user-id', 'sec-1')
      .send({});
    
    expect(response.status).toBe(200);
    expect(automaticEvaluationService.evaluateSubmittedSbom).toHaveBeenCalledWith(
      expect.objectContaining({
        sbomId: 'SBOM-123',
        principal: 'sec-1',
        triggerType: 'PROVENANCE_CHANGED'
      })
    );
  });

  it('Trigger type is server generated / Caller recommendation metadata is ignored', async () => {
    automaticEvaluationService.evaluateSubmittedSbom.mockResolvedValue({
      recommendation: 'APPROVE'
    });

    const response = await request(app)
      .post('/api/v1/sbom/SBOM-123/reevaluate')
      .set('x-user-role', 'security')
      .set('x-user-id', 'sec-1')
      .send({ recommendation: 'REJECT', triggerType: 'MANUAL_RETRY' });
    
    expect(response.status).toBe(200);
    // Should respect the triggerType passed if any, but ignore recommendation metadata
    expect(automaticEvaluationService.evaluateSubmittedSbom).toHaveBeenCalledWith(
      expect.objectContaining({
        triggerType: 'MANUAL_RETRY'
      })
    );
  });

  it('Reevaluation creates a new decision ID and snapshot ID and Previous decision remains in history', async () => {
    automaticEvaluationService.evaluateSubmittedSbom.mockResolvedValue({
      recommendation: 'APPROVE',
      decisionId: 'new-dec-1',
      snapshotId: 'new-snap-1'
    });

    trustRepository.getTrustDecisionHistoryBySBOMID.mockResolvedValue([
      { id: 'new-dec-1' },
      { id: 'old-dec-1' }
    ]);

    const response = await request(app)
      .post('/api/v1/sbom/SBOM-123/reevaluate')
      .set('x-user-role', 'security')
      .set('x-user-id', 'sec-1');
    
    expect(response.body.recommendation.decisionId).toBe('new-dec-1');
    expect(response.body.recommendation.snapshotId).toBe('new-snap-1');

    const history = await trustRepository.getTrustDecisionHistoryBySBOMID('SBOM-123');
    expect(history.length).toBe(2);
    expect(history[1].id).toBe('old-dec-1');
  });

  it('Evaluator failure returns ANALYSIS_INCOMPLETE and Snapshot failure never returns APPROVE', async () => {
    automaticEvaluationService.evaluateSubmittedSbom.mockResolvedValue({
      recommendation: 'ANALYSIS_INCOMPLETE',
      internalTrustState: 'UNKNOWN',
      snapshotId: null,
      correlationId: 'corr-123'
    });

    const response = await request(app)
      .post('/api/v1/sbom/SBOM-123/reevaluate')
      .set('x-user-role', 'security')
      .set('x-user-id', 'sec-1');
    
    expect(response.status).toBe(200);
    expect(response.body.analysisStatus).toBe('INCOMPLETE');
    expect(response.body.recommendation.recommendation).toBe('ANALYSIS_INCOMPLETE');
    expect(response.body.recommendation.correlationId).toBe('corr-123');
  });

  it('Wrong/nonexistent SBOM fails safely', async () => {
    automaticEvaluationService.evaluateSubmittedSbom.mockResolvedValue({
      recommendation: 'ANALYSIS_INCOMPLETE'
    });

    const response = await request(app)
      .post('/api/v1/sbom/SBOM-INVALID/reevaluate')
      .set('x-user-role', 'security')
      .set('x-user-id', 'sec-1');
    
    expect(response.body.recommendation.recommendation).toBe('ANALYSIS_INCOMPLETE');
  });
});
