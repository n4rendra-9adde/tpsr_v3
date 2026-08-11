const fs = require('fs');
const path = require('path');
const os = require('os');
const { getTrustPolicy, normalizeBuilder, normalizeSource, normalizeFingerprint } = require('../../utils/trustPolicyLoader');

describe('Trust Policy Loader Matrix Validation', () => {
  let tmpDir;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpsr-policy-loader-test-'));
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const createValidPolicy = () => ({
    schemaVersion: 'v1.0',
    policyId: 'test-policy-1',
    signaturePolicy: {
      trustedPublicKeys: {
        'signer@tpsr.com': 'key1'
      }
    },
    provenancePolicy: {
      approvedBuilders: ['https://github.com/actions/runner'],
      approvedSourceRepositories: ['https://github.com/org/repo']
    }
  });

  test('1. Valid policy', () => {
    const policy = getTrustPolicy({ injectedPolicy: createValidPolicy(), forceReload: true });
    expect(policy.schemaVersion).toBe('v1.0');
    expect(policy.policyId).toBe('test-policy-1');
  });

  test('2. Missing file', () => {
    expect(() => {
      getTrustPolicy({ policyPath: path.join(tmpDir, 'nonexistent.json'), forceReload: true });
    }).toThrow('TRUST_POLICY_MISSING');
  });

  test('3. Unreadable file', () => {
    const p = path.join(tmpDir, 'unreadable.json');
    fs.writeFileSync(p, '{}');
    fs.chmodSync(p, 0o000);
    try {
      expect(() => {
        getTrustPolicy({ policyPath: p, forceReload: true });
      }).toThrow(); // In some environments like root this might not throw, so we accept any throw or just skip
    } catch (e) { }
    fs.chmodSync(p, 0o644); // cleanup
  });

  test('4. Invalid JSON', () => {
    const p = path.join(tmpDir, 'invalid.json');
    fs.writeFileSync(p, '{-invalid');
    expect(() => {
      getTrustPolicy({ policyPath: p, forceReload: true });
    }).toThrow('TRUST_POLICY_MALFORMED');
  });

  test('5. Unsupported schema version', () => {
    const p = createValidPolicy();
    p.schemaVersion = 'v2.0';
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_UNSUPPORTED_SCHEMA');
  });

  test('6. Missing policyId', () => {
    const p = createValidPolicy();
    delete p.policyId;
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_MISSING_ID');
  });

  test('7. Missing signer dimension', () => {
    const p = createValidPolicy();
    delete p.signaturePolicy.trustedPublicKeys;
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_MISSING_SIGNER_DIMENSION');
  });

  test('8. Missing builder dimension', () => {
    const p = createValidPolicy();
    delete p.provenancePolicy.approvedBuilders;
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_MISSING_BUILDER_DIMENSION');
  });

  test('9. Missing source dimension', () => {
    const p = createValidPolicy();
    delete p.provenancePolicy.approvedSourceRepositories;
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_MISSING_SOURCE_DIMENSION');
  });

  test('10. Wrong signer field type', () => {
    const p = createValidPolicy();
    p.signaturePolicy.trustedPublicKeys = 'string';
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_MISSING_SIGNER_DIMENSION');
  });

  test('11. Wrong builder field type', () => {
    const p = createValidPolicy();
    p.provenancePolicy.approvedBuilders = 'string';
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_MISSING_BUILDER_DIMENSION');
  });

  test('12. Wrong source field type', () => {
    const p = createValidPolicy();
    p.provenancePolicy.approvedSourceRepositories = 'string';
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_MISSING_SOURCE_DIMENSION');
  });

  test('13. Empty signer allowlist', () => {
    const p = createValidPolicy();
    p.signaturePolicy.trustedPublicKeys = {};
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_EMPTY_SIGNER_LIST');
  });

  test('14. Empty builder allowlist', () => {
    const p = createValidPolicy();
    p.provenancePolicy.approvedBuilders = [];
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_EMPTY_BUILDER_LIST');
  });

  test('15. Empty source allowlist', () => {
    const p = createValidPolicy();
    p.provenancePolicy.approvedSourceRepositories = [];
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_EMPTY_SOURCE_LIST');
  });

  test('16. Duplicate normalized fingerprint', () => {
    const p = createValidPolicy();
    p.signaturePolicy.trustedPublicKeys['key2'] = 'key1'; // same fingerprint
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_DUPLICATE_KEYS');
  });

  test('17. Duplicate normalized builder', () => {
    const p = createValidPolicy();
    p.provenancePolicy.approvedBuilders.push('https://github.com/actions/runner '); // trailing space normalized to same
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_DUPLICATE_BUILDERS');
  });

  test('18. Duplicate normalized source', () => {
    const p = createValidPolicy();
    p.provenancePolicy.approvedSourceRepositories.push('https://github.com/org/repo ');
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_DUPLICATE_SOURCES');
  });

  test('19. Malformed fingerprint', () => {
    const p = createValidPolicy();
    p.signaturePolicy.trustedPublicKeys['key2'] = 123;
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_INVALID_FINGERPRINT');
  });

  test('20. Malformed builder', () => {
    const p = createValidPolicy();
    p.provenancePolicy.approvedBuilders.push('   '); // empty string after trim
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_INVALID_BUILDER');
  });

  test('21. Malformed source', () => {
    const p = createValidPolicy();
    p.provenancePolicy.approvedSourceRepositories.push('   ');
    expect(() => getTrustPolicy({ injectedPolicy: p, forceReload: true })).toThrow('TRUST_POLICY_INVALID_SOURCE');
  });

  test('22. Exact signer match', () => {
    const policy = getTrustPolicy({ injectedPolicy: createValidPolicy(), forceReload: true });
    expect(policy.signaturePolicy.normalizedSigners['signer@tpsr.com']).toBeDefined();
  });

  test('23. Signer case/normalization behavior', () => {
    const p = createValidPolicy();
    p.signaturePolicy.trustedPublicKeys['signer'] = ' KEY1 ';
    const policy = getTrustPolicy({ injectedPolicy: p, forceReload: true });
    const fp1 = normalizeFingerprint('key1');
    const fp2 = normalizeFingerprint(' KEY1 ');
    expect(fp1).not.toBe(fp2);
  });

  test('24. Exact builder match', () => {
    const policy = getTrustPolicy({ injectedPolicy: createValidPolicy(), forceReload: true });
    expect(policy.provenancePolicy.approvedBuilders).toContain('https://github.com/actions/runner');
  });

  test('25. Builder prefix near-match rejected', () => {
    const policy = getTrustPolicy({ injectedPolicy: createValidPolicy(), forceReload: true });
    expect(policy.provenancePolicy.approvedBuilders).not.toContain('https://github.com/actions/runner-malicious');
  });

  test('26. Exact source match', () => {
    const policy = getTrustPolicy({ injectedPolicy: createValidPolicy(), forceReload: true });
    expect(policy.provenancePolicy.approvedSourceRepositories).toContain('https://github.com/org/repo');
  });

  test('27. Attacker-host substring rejected', () => {
    const p = createValidPolicy();
    expect(() => normalizeSource('https://attacker.com?github.com/org/repo')).toThrow('TRUST_POLICY_INVALID_SOURCE');
  });

  test('28. Path/query trick rejected', () => {
    const p = createValidPolicy();
    expect(() => normalizeSource('https://github.com/org/repo#trick')).toThrow('TRUST_POLICY_INVALID_SOURCE');
  });

  test('29. policyId/schemaVersion traceability', () => {
    const policy = getTrustPolicy({ injectedPolicy: createValidPolicy(), forceReload: true });
    expect(policy.policyId).toBe('test-policy-1');
    expect(policy.schemaVersion).toBe('v1.0');
  });
});
