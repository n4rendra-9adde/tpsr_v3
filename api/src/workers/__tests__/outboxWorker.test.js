const { processOutboxBatch, startWorker, stopWorker, isRunning } = require('../outboxWorker');
const trustRepository = require('../../repositories/trustRepository');
const fabric = require('../../config/fabric');

jest.mock('../../repositories/trustRepository');
jest.mock('../../config/fabric');

describe('TPSR v3 Transactional Ledger Outbox Worker Concurrency & Retry Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    stopWorker();
  });

  test('processOutboxBatch: Claims empty records and returns 0 counts without error', async () => {
    trustRepository.claimPendingOutboxRecords.mockResolvedValue([]);

    const stats = await processOutboxBatch(10, 'test-worker-1');
    expect(stats.claimed).toBe(0);
    expect(stats.completed).toBe(0);
  });

  test('processOutboxBatch: Anchors record to Fabric and updates status to COMPLETED when contract succeeds', async () => {
    const mockRecord = {
      id: 'outbox-101',
      action: 'RECORD_TRUST_DECISION',
      payload: { version: '3.0', sbomID: 'sb-1', decisionId: 'd-1', trustStatus: 'TRUSTED', reasonCode: 'TR-1', reasonDescription: 'ok', policyVersion: '1.0' },
      retry_count: 0
    };
    trustRepository.claimPendingOutboxRecords.mockResolvedValue([mockRecord]);

    const mockContract = { submitTransaction: jest.fn().mockResolvedValue(Buffer.from('tx-999')) };
    fabric.getVendorContract.mockResolvedValue({ gateway: { disconnect: jest.fn() }, contract: mockContract });
    fabric.getSecurityGovernanceContract.mockResolvedValue({ gateway: { disconnect: jest.fn() }, contract: mockContract });
    fabric.disconnectGateway.mockImplementation(() => {});

    trustRepository.updateOutboxRecordStatus.mockResolvedValue({ ...mockRecord, status: 'COMPLETED' });

    const stats = await processOutboxBatch(5, 'test-worker-2');

    expect(stats.claimed).toBe(1);
    expect(stats.completed).toBe(1);
    expect(mockContract.submitTransaction).toHaveBeenCalledWith('RecordTrustDecision', expect.any(String));
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith('outbox-101', 'COMPLETED', null, 'tx-999', null);
  });

  test('processOutboxBatch: Schedules retry with exponential backoff when Fabric transaction fails', async () => {
    const mockRecord = {
      id: 'outbox-102',
      action: 'RECORD_TRUST_DECISION',
      payload: { version: '3.0', sbomID: 'sb-1', decisionId: 'd-1', trustStatus: 'TRUSTED', reasonCode: 'TR-1', reasonDescription: 'ok', policyVersion: '1.0' },
      retry_count: 1,
    };
    trustRepository.claimPendingOutboxRecords.mockResolvedValue([mockRecord]);

    const mockContract = { submitTransaction: jest.fn().mockRejectedValue(new Error('Peer connection timeout')) };
    fabric.getVendorContract.mockResolvedValue({ gateway: { disconnect: jest.fn() }, contract: mockContract });
    fabric.getSecurityGovernanceContract.mockResolvedValue({ gateway: { disconnect: jest.fn() }, contract: mockContract });
    fabric.disconnectGateway.mockImplementation(() => {});

    trustRepository.updateOutboxRecordStatus.mockResolvedValue({ ...mockRecord, status: 'RETRY_PENDING' });

    const stats = await processOutboxBatch(5, 'test-worker-3', 5);

    expect(stats.claimed).toBe(1);
    expect(stats.retryPending).toBe(1);
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith(
      'outbox-102',
      'RETRY_PENDING',
      'Transaction error: Peer connection timeout',
      null,
      expect.any(String)
    );
  });

  test('processOutboxBatch: Promotes record to FAILED_REQUIRES_REVIEW after exhausting max retries', async () => {
    const mockRecord = {
      id: 'outbox-103',
      action: 'RECORD_TRUST_DECISION',
      payload: { version: '3.0', sbomID: 'sb-1', decisionId: 'd-1', trustStatus: 'TRUSTED', reasonCode: 'TR-1', reasonDescription: 'ok', policyVersion: '1.0' },
      retry_count: 4
    };
    trustRepository.claimPendingOutboxRecords.mockResolvedValue([mockRecord]);

    const mockContract = { submitTransaction: jest.fn().mockRejectedValue(new Error('Persistent MVCC read conflict')) };
    fabric.getVendorContract.mockResolvedValue({ gateway: { disconnect: jest.fn() }, contract: mockContract });
    fabric.getSecurityGovernanceContract.mockResolvedValue({ gateway: { disconnect: jest.fn() }, contract: mockContract });
    fabric.disconnectGateway.mockImplementation(() => {});

    trustRepository.updateOutboxRecordStatus.mockResolvedValue({ ...mockRecord, status: 'FAILED_REQUIRES_REVIEW' });

    const stats = await processOutboxBatch(5, 'test-worker-4', 5);

    expect(stats.claimed).toBe(1);
    expect(stats.failedRequiresReview).toBe(1);
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith(
      'outbox-103',
      'FAILED_REQUIRES_REVIEW',
      'Transaction error: Persistent MVCC read conflict',
      null,
      null
    );
  });

  test('Worker lifecycle control: startWorker and stopWorker toggle isRunning state', () => {
    expect(isRunning()).toBe(false);
    startWorker(60000, 5, 'test-worker-5');
    expect(isRunning()).toBe(true);
    stopWorker();
    expect(isRunning()).toBe(false);
  });
});
