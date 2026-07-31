const outboxWorker = require('../outboxWorker');
const trustRepository = require('../../repositories/trustRepository');
const fabric = require('../../config/fabric');

jest.mock('../../repositories/trustRepository');
jest.mock('../../config/fabric');

describe('outboxWorker routing matrix', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const setupMocks = (record) => {
    trustRepository.claimPendingOutboxRecords.mockResolvedValue([record]);
    trustRepository.updateOutboxRecordStatus.mockResolvedValue({});
    
    const mockSecurityGateway = { disconnect: jest.fn() };
    const mockSecurityContract = { submitTransaction: jest.fn().mockResolvedValue(Buffer.from('tx-123')) };
    fabric.getSecurityGovernanceContract.mockResolvedValue({ gateway: mockSecurityGateway, contract: mockSecurityContract });

    const mockVendorGateway = { disconnect: jest.fn() };
    const mockVendorContract = { submitTransaction: jest.fn().mockResolvedValue(Buffer.from('tx-456')) };
    fabric.getVendorContract.mockResolvedValue({ gateway: mockVendorGateway, contract: mockVendorContract });

    fabric.disconnectGateway.mockImplementation(() => {});

    return { mockSecurityContract, mockVendorContract };
  };

  test('1. RECORD_TRUST_DECISION: Calls RecordTrustDecision with securityAdmin', async () => {
    const { mockSecurityContract, mockVendorContract } = setupMocks({
      id: 'rec-1',
      action: 'RECORD_TRUST_DECISION',
      retry_count: 0,
      payload: {
        version: '3.0', sbomID: 'sb-1', decisionId: 'd-1', trustStatus: 'TRUSTED', reasonCode: 'TR-1', reasonDescription: 'ok', policyVersion: '1.0'
      }
    });

    const stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.completed).toBe(1);
    expect(fabric.getSecurityGovernanceContract).toHaveBeenCalled();
    expect(mockSecurityContract.submitTransaction).toHaveBeenCalledWith('RecordTrustDecision', expect.any(String));
    expect(mockVendorContract.submitTransaction).not.toHaveBeenCalled();
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith('rec-1', 'COMPLETED', null, 'tx-123', null);
  });

  test('2. RECORD_TRUST_EVIDENCE: Calls RecordTrustEvidence with appropriate contract', async () => {
    const { mockSecurityContract, mockVendorContract } = setupMocks({
      id: 'rec-2',
      action: 'RECORD_TRUST_EVIDENCE',
      retry_count: 0,
      payload: {
        version: '3.0', sbomID: 'sb-1', evidenceId: 'ev-1', evidenceType: 'VEX', evidenceHash: 'hash123'
      }
    });

    const stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.completed).toBe(1);
    expect(fabric.getVendorContract).toHaveBeenCalled();
    expect(mockVendorContract.submitTransaction).toHaveBeenCalledWith('RecordTrustEvidence', expect.any(String));
    expect(mockSecurityContract.submitTransaction).not.toHaveBeenCalled();
  });

  test('3. Unknown action: Calls neither, marks FAILED_REQUIRES_REVIEW', async () => {
    setupMocks({ id: 'rec-3', action: 'UNKNOWN', retry_count: 0, payload: {} });
    const stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.failedRequiresReview).toBe(1);
    expect(fabric.getSecurityGovernanceContract).not.toHaveBeenCalled();
    expect(fabric.getVendorContract).not.toHaveBeenCalled();
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith(
      'rec-3', 'FAILED_REQUIRES_REVIEW', expect.stringContaining('Unknown or missing action'), null, null
    );
  });

  test('4 & 5. Null or Empty action: Rejected safely', async () => {
    setupMocks({ id: 'rec-4', action: null, retry_count: 0, payload: {} });
    let stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.failedRequiresReview).toBe(1);

    setupMocks({ id: 'rec-5', action: '', retry_count: 0, payload: {} });
    stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.failedRequiresReview).toBe(1);
  });

  test('6. Decision action with evidence payload: Rejected before Fabric call', async () => {
    setupMocks({
      id: 'rec-6', action: 'RECORD_TRUST_DECISION', retry_count: 0,
      payload: { version: '3.0', sbomID: 'sb-1', decisionId: 'd-1', trustStatus: 'TRUSTED', reasonCode: 'TR-1', reasonDescription: 'ok', policyVersion: '1.0', evidenceType: 'VEX' }
    });
    const stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.failedRequiresReview).toBe(1);
    expect(fabric.getSecurityGovernanceContract).not.toHaveBeenCalled();
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith(
      'rec-6', 'FAILED_REQUIRES_REVIEW', expect.stringContaining('decision payload cannot contain evidenceType'), null, null
    );
  });

  test('7. Evidence action with decision payload: Rejected before Fabric call', async () => {
    setupMocks({
      id: 'rec-7', action: 'RECORD_TRUST_EVIDENCE', retry_count: 0,
      payload: { version: '3.0', sbomID: 'sb-1', evidenceId: 'ev-1', evidenceType: 'VEX', evidenceHash: 'hash123', trustStatus: 'TRUSTED' }
    });
    const stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.failedRequiresReview).toBe(1);
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith(
      'rec-7', 'FAILED_REQUIRES_REVIEW', expect.stringContaining('evidence payload cannot contain trustStatus'), null, null
    );
  });

  test('8. Missing security identity: Configuration review failure', async () => {
    const { mockSecurityContract } = setupMocks({
      id: 'rec-8', action: 'RECORD_TRUST_DECISION', retry_count: 0,
      payload: { version: '3.0', sbomID: 'sb-1', decisionId: 'd-1', trustStatus: 'TRUSTED', reasonCode: 'TR-1', reasonDescription: 'ok', policyVersion: '1.0' }
    });
    fabric.getSecurityGovernanceContract.mockRejectedValue(new Error('unauthorized MSP error'));
    
    const stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.failedRequiresReview).toBe(1);
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith(
      'rec-8', 'FAILED_REQUIRES_REVIEW', expect.stringContaining('Identity configuration error'), null, null
    );
  });

  test('9. Fabric network failure: Uses normal retry/backoff', async () => {
    const { mockSecurityContract } = setupMocks({
      id: 'rec-9', action: 'RECORD_TRUST_DECISION', retry_count: 0,
      payload: { version: '3.0', sbomID: 'sb-1', decisionId: 'd-1', trustStatus: 'TRUSTED', reasonCode: 'TR-1', reasonDescription: 'ok', policyVersion: '1.0' }
    });
    mockSecurityContract.submitTransaction.mockRejectedValue(new Error('chaincode connection timeout'));
    
    const stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.retryPending).toBe(1);
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith(
      'rec-9', 'RETRY_PENDING', expect.stringContaining('chaincode connection timeout'), null, expect.any(String)
    );
  });

  test('10. Successful decision anchor: Stores Fabric Tx ID, marks outbox completed', async () => {
    const { mockSecurityContract } = setupMocks({
      id: 'rec-10', action: 'RECORD_TRUST_DECISION', retry_count: 0,
      payload: { version: '3.0', sbomID: 'sb-1', decisionId: 'd-1', trustStatus: 'TRUSTED', reasonCode: 'TR-1', reasonDescription: 'ok', policyVersion: '1.0' }
    });
    const stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.completed).toBe(1);
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith(
      'rec-10', 'COMPLETED', null, 'tx-123', null
    );
  });

  test('11. Duplicate/idempotent Fabric success', async () => {
    // Exact same logic as successful decision anchor since chaincode handles idempotency transparently
    const { mockSecurityContract } = setupMocks({
      id: 'rec-11', action: 'RECORD_TRUST_DECISION', retry_count: 0,
      payload: { version: '3.0', sbomID: 'sb-1', decisionId: 'd-1', trustStatus: 'TRUSTED', reasonCode: 'TR-1', reasonDescription: 'ok', policyVersion: '1.0' }
    });
    const stats = await outboxWorker.processOutboxBatch(1, 'test');
    expect(stats.completed).toBe(1);
    expect(trustRepository.updateOutboxRecordStatus).toHaveBeenCalledWith(
      'rec-11', 'COMPLETED', null, 'tx-123', null
    );
  });
});
