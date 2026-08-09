'use strict';

const trustEngine = require('../../utils/trustEngine');
const trustRepository = require('../../repositories/trustRepository');
const sbomRepository = require('../../repositories/sbomRepository');
const policyExceptionRepository = require('../../repositories/policyExceptionRepository');
const { getContract } = require('../../config/fabric');
const caectdEvaluator = require('../evaluators/caectdEvaluator');

jest.mock('../../repositories/trustRepository', () => ({
  insertTrustDecision: jest.fn().mockResolvedValue('fake-decision-id'),
  insertLedgerOutboxEvent: jest.fn().mockResolvedValue('fake-outbox-id')
}));

jest.mock('../../repositories/sbomRepository', () => ({
  insertSBOM: jest.fn().mockResolvedValue('fake-sbom-id')
}));

jest.mock('../../repositories/policyExceptionRepository', () => ({
  insertException: jest.fn().mockResolvedValue('fake-ex-id')
}));

jest.mock('../../config/fabric', () => ({
  getContract: jest.fn().mockReturnValue({
    submitTransaction: jest.fn().mockResolvedValue(Buffer.from('tx-id'))
  })
}));

describe('caectdEvaluator fixture mode', () => {
  it('must not call database or fabric', async () => {
    const input = {
      sbomId: 'fixture-sbom',
      sbomPresent: true,
      canonicalSbomHash: 'hash',
      ledgerAnchorHash: 'hash'
    };

    const res = await caectdEvaluator.evaluate(input);
    expect(res.outcome).toBeDefined();

    expect(trustRepository.insertTrustDecision).not.toHaveBeenCalled();
    expect(trustRepository.insertLedgerOutboxEvent).not.toHaveBeenCalled();
    expect(sbomRepository.insertSBOM).not.toHaveBeenCalled();
    expect(policyExceptionRepository.insertException).not.toHaveBeenCalled();
    expect(getContract).not.toHaveBeenCalled();
  });
});
