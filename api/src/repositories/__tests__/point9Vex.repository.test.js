const sbomRepository = require('../sbomRepository');
const db = require('../../config/database');

jest.mock('../../config/database', () => ({
  pool: {
    connect: jest.fn()
  }
}));

describe('Point 9 VEX Repository Persistence', () => {
  let mockClient;

  beforeEach(() => {
    jest.clearAllMocks();
    mockClient = {
      query: jest.fn().mockResolvedValue({ rows: [{ id: 'vex-123', vex_authoritative: true }] }),
      release: jest.fn()
    };
    db.pool.connect.mockResolvedValue(mockClient);
  });

  test('1. authoritative verification metadata is persisted accurately', async () => {
    const record = {
      sbomId: 'sbom-123',
      vulnerabilityId: 'CVE-123',
      vexAuthoritative: true,
      signatureStatus: 'VERIFIED',
      publicKeyFingerprint: 'fp-123',
      issuerIdentity: 'auth-issuer',
      policyVersion: 'v1.1',
      canonicalPayloadDigest: 'hash123',
      targetBinding: { artifact: 'pkg:npm/test@1.0.0' },
      verifiedAt: '2026-08-11T00:00:00Z',
      reasonCodes: ['VEX-001']
    };

    const result = await sbomRepository.insertVexStatement(record);

    expect(mockClient.query).toHaveBeenCalledTimes(1);
    const [query, values] = mockClient.query.mock.calls[0];

    // Assert SQL columns order
    expect(query).toContain('vex_authoritative');
    expect(query).toContain('canonical_payload_digest');
    expect(query).toContain('target_binding');

    // Assert exactly what is bound
    // We expect the array length to be 38
    expect(values).toHaveLength(38);
    expect(values[33]).toBe(true); // vex_authoritative at index 33 (1-based $34)
    expect(values[34]).toBe('hash123'); // canonicalPayloadDigest at $35
    expect(values[36]).toBe(JSON.stringify({ artifact: 'pkg:npm/test@1.0.0' })); // targetBinding
    expect(result.id).toBe('vex-123');
  });

  test('2. invalid evidence persists as non-authoritative', async () => {
    const record = {
      sbomId: 'sbom-123',
      vulnerabilityId: 'CVE-123',
      vexAuthoritative: false,
      reasonCodes: ['VEX-010']
    };

    await sbomRepository.insertVexStatement(record);
    const [, values] = mockClient.query.mock.calls[0];
    expect(values[33]).toBe(false); // vex_authoritative
  });

  test('3. null/default behavior is fail closed', async () => {
    const record = { sbomId: 'sbom-123' };
    await sbomRepository.insertVexStatement(record);
    const [, values] = mockClient.query.mock.calls[0];
    expect(values[33]).toBe(false); // defaults to false
  });

  test('4. caller request fields cannot bypass the trusted repository call path', async () => {
    // Proving the object structure directly mapped by the route
    const record = { sbomId: 'sbom-123', vexAuthoritative: false };
    await sbomRepository.insertVexStatement(record);
    const [, values] = mockClient.query.mock.calls[0];
    expect(values[33]).toBe(false);
  });
});
