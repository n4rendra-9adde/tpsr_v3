'use strict';

const request = require('supertest');
const express = require('express');
const submitRoute = require('../routes/submit');
const automaticEvaluationService = require('../services/automaticEvaluationService');
const sbomRepository = require('../repositories/sbomRepository');
const fabric = require('../config/fabric');

jest.mock('../services/automaticEvaluationService');
jest.mock('../repositories/sbomRepository');
jest.mock('../config/fabric');

describe('SBOM Submit Route - Automatic Evaluation', () => {
  let app;

  beforeEach(() => {
    jest.clearAllMocks();
    app = express();
    app.use(express.json());
    app.use('/', submitRoute);
  });

  it('successful SBOM submission invokes the production evaluator automatically and returns recommendation', async () => {
    sbomRepository.insertSBOMDocument.mockResolvedValue({ id: 'doc-1' });
    sbomRepository.finalizeSBOMDocument.mockResolvedValue({});
    
    const mockContract = {
      createTransaction: jest.fn().mockReturnValue({
        getTransactionId: jest.fn().mockReturnValue('tx-123'),
        submit: jest.fn().mockResolvedValue()
      }),
      evaluateTransaction: jest.fn().mockResolvedValue(Buffer.from('[]'))
    };
    
    fabric.getContract.mockResolvedValue({
      gateway: {},
      contract: mockContract
    });

    automaticEvaluationService.evaluateSubmittedSbom.mockResolvedValue({
      recommendation: 'APPROVE',
      decisionId: 'dec-1',
      snapshotId: 'snap-1',
      primaryRuleId: 'RULE-1',
      primaryReasonCode: 'OK'
    });

    const response = await request(app)
      .post('/submit')
      .send({
        sbomID: 'test-sbom',
        buildID: 'build-1',
        softwareName: 'test-soft',
        softwareVersion: '1.0',
        format: 'SPDX',
        offChainRef: 'ipfs://test',
        signatures: ['sig1'],
        sbom: '{"components":[]}'
      });

    expect(response.status).toBe(201);
    expect(response.body.submissionStatus).toBe('ACCEPTED');
    expect(response.body.analysisStatus).toBe('COMPLETED');
    expect(response.body.recommendation).toMatchObject({
      recommendation: 'APPROVE',
      decisionId: 'dec-1',
      snapshotId: 'snap-1'
    });

    expect(automaticEvaluationService.evaluateSubmittedSbom).toHaveBeenCalledTimes(1);
    expect(automaticEvaluationService.evaluateSubmittedSbom).toHaveBeenCalledWith(
      expect.objectContaining({
        sbomId: 'test-sbom',
        triggerType: 'SBOM_SUBMITTED'
      })
    );
  });
});
