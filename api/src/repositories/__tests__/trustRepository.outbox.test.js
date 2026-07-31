const trustRepository = require('../trustRepository');
const db = require('../../config/database');

jest.mock('../../config/database');

describe('trustRepository outbox methods', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('insertOutboxRecord rejects unsupported actions', async () => {
    await expect(trustRepository.insertOutboxRecord({
      sbomId: 'sb-1', decisionId: 'd-1', action: 'INVALID_ACTION', payload: {}
    })).rejects.toThrow('Unsupported outbox action: INVALID_ACTION');
  });

  test('insertOutboxRecord strictly inserts RECORD_TRUST_DECISION', async () => {
    const mockClient = { query: jest.fn().mockResolvedValue({ rows: [{ id: '123' }] }), release: jest.fn() };
    db.pool.connect.mockResolvedValue(mockClient);

    const res = await trustRepository.insertOutboxRecord({
      sbomId: 'sb-1', decisionId: 'd-1', action: 'RECORD_TRUST_DECISION', payload: { foo: 'bar' }
    });

    expect(res.id).toBe('123');
    expect(mockClient.query).toHaveBeenCalledWith(
      expect.stringContaining('INSERT INTO ledger_outbox'),
      expect.arrayContaining(['sb-1', 'd-1', 'RECORD_TRUST_DECISION', JSON.stringify({ foo: 'bar' })])
    );
  });
  
  test('insertOutboxRecord strictly inserts RECORD_TRUST_EVIDENCE', async () => {
    const mockClient = { query: jest.fn().mockResolvedValue({ rows: [{ id: '456' }] }), release: jest.fn() };
    db.pool.connect.mockResolvedValue(mockClient);

    const res = await trustRepository.insertOutboxRecord({
      sbomId: 'sb-1', decisionId: 'd-1', action: 'RECORD_TRUST_EVIDENCE', payload: { bar: 'baz' }
    });

    expect(res.id).toBe('456');
    expect(mockClient.query).toHaveBeenCalledWith(
      expect.stringContaining('INSERT INTO ledger_outbox'),
      expect.arrayContaining(['sb-1', 'd-1', 'RECORD_TRUST_EVIDENCE', JSON.stringify({ bar: 'baz' })])
    );
  });
});
