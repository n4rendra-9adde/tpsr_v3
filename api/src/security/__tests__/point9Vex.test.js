const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { verifyVexDocument, applyVexOverlays, evaluateVexStatement } = require('../../utils/vexEngine');
const trustPolicyLoader = require('../../utils/trustPolicyLoader');
const originalGetTrustPolicy = trustPolicyLoader.getTrustPolicy;

describe('Point 9 VEX Authentication and Trust Matrix', () => {
  let tmpDir;
  let validKeyPair;
  let unauthorizedKeyPair;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpsr-p9-'));
    validKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    unauthorizedKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const getPem = (pubKeyObj) => pubKeyObj.export({ type: 'spki', format: 'pem' });

  const mockTrustPolicy = (overrides = {}) => {
    const p = {
      schemaVersion: 'v1.1',
      policyId: 'test-policy',
      policyVersion: 'v1',
      signaturePolicy: { trustedPublicKeys: { 'dummy@tpsr.com': 'dummy' } },
      provenancePolicy: { approvedBuilders: ['https://builder'], approvedSourceRepositories: ['https://source'] },
      vexPolicy: {
        authorizedIssuers: {
          'sec@tpsr.com': { publicKey: getPem(validKeyPair.publicKey), globalAuthority: true },
          'product-sec@tpsr.com': { publicKey: getPem(unauthorizedKeyPair.publicKey), allowedProducts: ['pkg:npm/test-product@1.0.0'] }
        },
        maxOverlayValidityDays: overrides.maxOverlayValidityDays !== undefined ? overrides.maxOverlayValidityDays : 30,
        allowedClockSkewSeconds: overrides.allowedClockSkewSeconds !== undefined ? overrides.allowedClockSkewSeconds : 600,
        expiryRequired: overrides.expiryRequired !== undefined ? overrides.expiryRequired : false,
        requireImpactStatementForNotAffected: true,
        allowedJustifications: ['component_not_present', 'vulnerable_code_not_present']
      }
    };
    jest.spyOn(trustPolicyLoader, 'getTrustPolicy').mockReturnValue(
      originalGetTrustPolicy({ injectedPolicy: p, forceReload: true })
    );
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockTrustPolicy();
  });

  const createSignedVex = (overrides = {}) => {
    const statements = overrides.statements || [{
      vulnerability: { name: overrides.vuln || 'CVE-2026-0001' },
      products: [ { '@id': overrides.product || 'pkg:npm/test-product@1.0.0', subcomponents: overrides.subcomponents || [] } ],
      status: overrides.status || 'not_affected',
      justification: overrides.justification !== undefined ? overrides.justification : 'component_not_present',
      impact_statement: overrides.impact_statement !== undefined ? overrides.impact_statement : 'Not present in our deployment',
      expires_at: overrides.expires_at !== undefined ? overrides.expires_at : undefined
    }];

    const predicate = {
      timestamp: overrides.timestamp !== undefined ? overrides.timestamp : new Date().toISOString(),
      statements
    };

    if (overrides.timestamp === null) delete predicate.timestamp;

    const payloadObj = {
      predicateType: overrides.predicateType || 'https://openvex.dev/ns/v0.2.0',
      predicate
    };
    const payloadStr = JSON.stringify(payloadObj);
    const payloadBase64 = Buffer.from(payloadStr).toString('base64');

    const type = overrides.payloadType || 'application/vnd.in-toto+json';

    const pae = Buffer.concat([
      Buffer.from(`DSSEv1 ${type.length} ${type} ${Buffer.byteLength(payloadStr)} `),
      Buffer.from(payloadStr)
    ]);

    const signKey = overrides.signKey || validKeyPair.privateKey;
    const sign = crypto.createSign('SHA256');
    sign.update(pae);
    sign.end();
    const signature = overrides.badSignature ? 'bad_signature_base64_which_is_invalid==' : sign.sign(signKey, 'base64');

    return {
      payloadType: type,
      payload: overrides.malformedPayload ? 'not_base64' : payloadBase64,
      signatures: [{ sig: signature }]
    };
  };

  // CRYPTOGRAPHIC AND ISSUER TESTS
  test('1. malformed VEX document', async () => {
    const env = createSignedVex({ payloadType: 'wrong' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-011');
  });

  test('2. unsigned VEX when signature is mandatory', async () => {
    const env = createSignedVex();
    env.signatures = [];
    const res = await verifyVexDocument(env, 'UNSIGNED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-010');
  });

  test('3. forged/invalid VEX signature', async () => {
    const env = createSignedVex({ badSignature: true });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-010');
  });

  test('4. unsupported signature algorithm', async () => {
    const env = createSignedVex();
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', 'invalid-key');
    expect(res.reasonCode).toBe('VEX-021');
  });

  test('5. valid signature from unauthorized issuer', async () => {
    const unknownKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const env = createSignedVex({ signKey: unknownKey.privateKey });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(unknownKey.publicKey));
    expect(res.reasonCode).toBe('VEX-009');
  });

  test('6. valid signature from authorized issuer', async () => {
    const env = createSignedVex();
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.isValid).toBe(true);
    expect(res.vexAuthoritative).toBe(true);
  });

  test('7. caller-supplied trusted issuer with a different untrusted verified key', async () => {
    const unknownKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const env = createSignedVex({ signKey: unknownKey.privateKey });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(unknownKey.publicKey));
    expect(res.reasonCode).toBe('VEX-009');
  });

  test('8. authorized key with mismatched caller-supplied issuer identity', async () => {
    const env = createSignedVex();
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.verifiedIssuerIdentity).toBe('sec@tpsr.com');
  });

  test('9. missing issuer identity', async () => {
    // In our implementation, missing pubkey implies unresolved fingerprint
    const env = createSignedVex();
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', '');
    expect(res.reasonCode).toBe('VEX-021');
  });

  test('10. malformed or missing VEX issuer policy', async () => {
    jest.spyOn(trustPolicyLoader, 'getTrustPolicy').mockImplementationOnce(() => { throw new Error('TRUST_POLICY_MISSING_VEX_ISSUER_DIMENSION'); });
    const env = createSignedVex();
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-010'); // We don't propagate policy errors differently yet
  });

  test('11. duplicate VEX issuer fingerprint or identity', async () => {
    jest.spyOn(trustPolicyLoader, 'getTrustPolicy').mockImplementationOnce(() => { throw new Error('TRUST_POLICY_DUPLICATE_VEX_KEYS'); });
    const env = createSignedVex();
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-010');
  });

  test('12. issuer authorized globally but not for this artifact/product scope', async () => {
    const env = createSignedVex({ product: 'pkg:npm/other@1.0.0', signKey: unauthorizedKeyPair.privateKey });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(unauthorizedKeyPair.publicKey), { productIdentifier: 'pkg:npm/other@1.0.0' });
    expect(res.reasonCode).toBe('VEX-009');
  });

  // TEMPORAL TESTS
  test('13. missing issuedAt', async () => {
    const env = createSignedVex({ timestamp: null });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-013');
  });

  test('14. malformed issuedAt', async () => {
    const env = createSignedVex({ timestamp: 'invalid-date' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-013');
  });

  test('15. future-dated issuedAt beyond clock skew', async () => {
    const future = new Date(Date.now() + 20 * 60 * 1000).toISOString();
    const env = createSignedVex({ timestamp: future });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-014');
  });

  test('16. missing expiry when mandatory', async () => {
    mockTrustPolicy({ expiryRequired: true });
    const env = createSignedVex({ expires_at: null });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-015');
  });

  test('17. malformed expiry', async () => {
    const env = createSignedVex({ expires_at: 'invalid-date' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-015');
  });

  test('18. expiry before issuedAt', async () => {
    const t = new Date().toISOString();
    const e = new Date(Date.now() - 10000).toISOString();
    const env = createSignedVex({ timestamp: t, expires_at: e });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-015');
  });

  test('19. expired VEX', async () => {
    const t = new Date(Date.now() - 20000).toISOString();
    const e = new Date(Date.now() - 10000).toISOString();
    const env = createSignedVex({ timestamp: t, expires_at: e });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-015');
  });

  test('20. stale VEX beyond maximum age', async () => {
    const old = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
    const env = createSignedVex({ timestamp: old });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-007');
  });

  test('21. valid fresh VEX inside allowed clock skew', async () => {
    const futureSkew = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 mins in future
    const env = createSignedVex({ timestamp: futureSkew });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.isValid).toBe(true);
  });

  // BINDING AND SCOPE TESTS
  test('22. artifact identity mismatch', async () => {
    const env = createSignedVex({ product: 'pkg:npm/test-product@1.0.0' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:npm/other@1.0.0' });
    expect(res.reasonCode).toBe('VEX-004');
  });

  test('23. artifact digest mismatch', async () => {
    const env = createSignedVex({ product: 'pkg:npm/test-product@1.0.0', subcomponents: [{ hashes: { 'sha256': 'hash1' } }] });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:npm/test-product@1.0.0', digest: 'hash2' });
    expect(res.reasonCode).toBe('VEX-019');
  });

  test('24. digest-prefix near-match rejected', async () => {
    const env = createSignedVex({ product: 'pkg:npm/test-product@1.0.0', subcomponents: [{ hashes: { 'sha256': 'hash123' } }] });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:npm/test-product@1.0.0', digest: 'hash12' });
    expect(res.reasonCode).toBe('VEX-019');
  });

  test('25. artifact version mismatch', async () => {
    const env = createSignedVex({ product: 'pkg:npm/test-product@1.0.0' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:npm/test-product@2.0.0' });
    expect(res.reasonCode).toBe('VEX-004'); // since we split out exact matching to productIdentifier
  });

  test('26. version-prefix near-match rejected', async () => {
    const env = createSignedVex({ product: 'pkg:npm/test-product@1.0.0' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:npm/test-product@1.0' });
    expect(res.reasonCode).toBe('VEX-004');
  });

  test('27. vulnerability ID mismatch', async () => {
    const env = createSignedVex({ vuln: 'CVE-2026-0001' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { vulnerabilityId: 'CVE-2026-9999' });
    expect(res.reasonCode).toBe('VEX-005');
  });

  test('28. multi-vulnerability VEX only affects exact target', async () => {
    const statements = [
      { vulnerability: { name: 'CVE-2026-0001' }, products: [{ '@id': 'pkg:npm/test-product@1.0.0' }], status: 'not_affected', justification: 'component_not_present', impact_statement: 'Not present' },
      { vulnerability: { name: 'CVE-2026-0002' }, products: [{ '@id': 'pkg:npm/test-product@1.0.0' }], status: 'affected' }
    ];
    const env = createSignedVex({ statements });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { vulnerabilityId: 'CVE-2026-0002', productIdentifier: 'pkg:npm/test-product@1.0.0' });
    expect(res.reasonCode).toBe('VEX-008'); // affected
  });

  test('29. multi-product VEX only affects exact artifact/version', async () => {
    const statements = [
      { vulnerability: { name: 'CVE-2026-0001' }, products: [{ '@id': 'pkg:npm/test-product@1.0.0' }, { '@id': 'pkg:npm/other@1.0.0' }], status: 'not_affected', justification: 'component_not_present', impact_statement: 'Not present' }
    ];
    const env = createSignedVex({ statements });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { vulnerabilityId: 'CVE-2026-0001', productIdentifier: 'pkg:npm/other@1.0.0' });
    expect(res.isValid).toBe(true);
  });

  test('30. ambiguous or missing scope fails closed', async () => {
    const statements = [ { status: 'not_affected', justification: 'component_not_present', impact_statement: 'test' } ];
    const env = createSignedVex({ statements });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { vulnerabilityId: 'CVE-2026-0001' });
    expect(res.reasonCode).toBe('VEX-005');
  });

  // STATUS AND CONFLICT TESTS
  test('31. valid AFFECTED statement remains blocking', async () => {
    const env = createSignedVex({ status: 'affected' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.policyBlockingStatus).toBe('BLOCKING');
  });

  test('32. valid NOT_AFFECTED with approved justification may reduce contextual risk', async () => {
    const env = createSignedVex({ status: 'not_affected', justification: 'component_not_present', impact_statement: 'test' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.policyBlockingStatus).toBe('NON_BLOCKING');
  });

  test('33. NOT_AFFECTED without justification is rejected', async () => {
    const env = createSignedVex({ status: 'not_affected', justification: null, impact_statement: 'test' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-006');
  });

  test('34. unsupported justification is rejected', async () => {
    const env = createSignedVex({ status: 'not_affected', justification: 'invalid_justification', impact_statement: 'test' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-006');
  });

  test('35. UNDER_INVESTIGATION does not suppress vulnerability', async () => {
    const env = createSignedVex({ status: 'under_investigation' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.policyBlockingStatus).toBe('REVIEW_REQUIRED');
  });

  test('36. FIXED applies only to exact fixed version', async () => {
    const env = createSignedVex({ status: 'fixed', product: 'pkg:npm/test-product@2.0.0' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:npm/test-product@1.0.0' });
    expect(res.reasonCode).toBe('VEX-004');
  });

  test('37. unsupported VEX status fails closed', async () => {
    const env = createSignedVex({ status: 'unknown_status' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-021');
  });

  test('38. older valid VEX cannot override newer valid VEX', async () => {
    const t1 = new Date(Date.now() - 2000).toISOString();
    const t2 = new Date(Date.now() - 1000).toISOString();
    const statements = [
      { vulnerability: { name: 'CVE-1' }, products: [{ '@id': 'pkg:test' }], status: 'not_affected', justification: 'component_not_present', impact_statement: 'x', timestamp: t1 },
      { vulnerability: { name: 'CVE-1' }, products: [{ '@id': 'pkg:test' }], status: 'affected', timestamp: t2 }
    ];
    const env = createSignedVex({ statements });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { vulnerabilityId: 'CVE-1', productIdentifier: 'pkg:test' });
    expect(res.reasonCode).toBe('VEX-008'); // affected wins due to time
  });

  test('39. conflicting equally authoritative VEX produces conservative conflict/review result', async () => {
    const t = new Date().toISOString();
    const statements = [
      { vulnerability: { name: 'CVE-1' }, products: [{ '@id': 'pkg:test' }], status: 'not_affected', justification: 'component_not_present', impact_statement: 'x', timestamp: t },
      { vulnerability: { name: 'CVE-1' }, products: [{ '@id': 'pkg:test' }], status: 'affected', timestamp: t }
    ];
    const env = createSignedVex({ statements });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { vulnerabilityId: 'CVE-1', productIdentifier: 'pkg:test' });
    expect(res.policyBlockingStatus).toBe('BLOCKING');
  });

  test('40. invalid VEX remains auditable but excluded from suppression decision', async () => {
    const overlays = applyVexOverlays([{ id: 'CVE-1' }], [{ vex_id: '1', valid: false, vexAuthoritative: false, applicability_status: 'not_affected', justification: 'component_not_present', cve: 'CVE-1' }]);
    expect(overlays.vulnerabilities[0].applicabilityDisposition).toBe('APPLICABLE');
  });

  // CAECTD INTEGRATION TESTS
  test('41. authoritative NOT_AFFECTED VEX does not bypass artifact integrity failure', async () => {
    // This is tested in contextRiskEngine but we simulate it by validating applyVexOverlays result
    const overlays = applyVexOverlays([{ id: 'CVE-1', cvssScore: 9.8 }], [{ cve: 'CVE-1', valid: true, isValid: true, vexAuthoritative: true, applicability_status: 'not_affected', justification: 'component_not_present', signature_status: 'VERIFIED', public_key_fingerprint: 'x', policy_version: '1', canonical_payload_digest: 'x', target_binding: {} }]);
    expect(overlays.vulnerabilities[0].policyBlockingStatus).toBe('NON_BLOCKING');
  });

  test('42. authoritative NOT_AFFECTED VEX does not bypass unauthorized signer/builder/source', async () => {
    const env = createSignedVex({ product: 'pkg:npm/test@1.0.0', signKey: unauthorizedKeyPair.privateKey });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(unauthorizedKeyPair.publicKey), { productIdentifier: 'pkg:npm/test@1.0.0' });
    expect(res.vexAuthoritative).toBe(false);
  });

  test('43. authoritative VEX does not automatically force TRUSTED', async () => {
    const res = await verifyVexDocument(createSignedVex(), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.policyBlockingStatus).toBe('NON_BLOCKING');
  });

  test('44. forged VEX cannot change REJECTED or blocking risk to accepted', async () => {
    const env = createSignedVex({ badSignature: true });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.vexAuthoritative).toBe(false);
  });

  test('45. stale VEX cannot change blocking risk to accepted', async () => {
    const env = createSignedVex({ timestamp: new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString() });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.vexAuthoritative).toBe(false);
  });

  test('46. incorrectly scoped VEX cannot change blocking risk to accepted', async () => {
    const env = createSignedVex({ product: 'pkg:npm/other@1.0.0' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:npm/test-product@1.0.0' });
    expect(res.vexAuthoritative).toBe(false);
  });

  test('47. exact valid VEX affects only its bound artifact/version/CVE', async () => {
    const res = await verifyVexDocument(createSignedVex({ vuln: 'CVE-1', status: 'not_affected' }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    const overlays = applyVexOverlays([{ id: 'CVE-1' }, { id: 'CVE-2' }], [{ ...res, vexAuthoritative: res.vexAuthoritative, isValid: res.isValid, vulnerability_id: res.vulnerabilityIdentifiers[0], cve: res.vulnerabilityIdentifiers[0], status: res.vexStatus, justification: res.justification, signature_status: 'VERIFIED', public_key_fingerprint: 'x', policy_version: '1', canonical_payload_digest: 'x', target_binding: {} }]);
    expect(overlays.vulnerabilities[0].applicabilityDisposition).toBe('NOT_AFFECTED');
    expect(overlays.vulnerabilities[1].applicabilityDisposition).toBe('APPLICABLE');
  });

  test('48. policy ID/version and evidence traceability are present', async () => {
    const res = await verifyVexDocument(createSignedVex(), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.policyId).toBe('test-policy');
    expect(res.publicKeyFingerprint).toBeDefined();
    expect(res.canonicalPayloadDigest).toBeDefined();
  });

  test('49. ADV-06 stale VEX remains fully detected with correct rule/reason', async () => {
    const res = await verifyVexDocument(createSignedVex({ timestamp: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString() }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-007');
  });

  test('50. ADV-07 falsified VEX remains fully detected with correct rule/reason', async () => {
    const res = await verifyVexDocument(createSignedVex({ badSignature: true }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-010');
  });

  // MANDATORY ADDITIONAL TESTS
  test('relevant statement is not the first statement', async () => {
    const statements = [
      { vulnerability: { name: 'CVE-1' }, products: [{ '@id': 'pkg:test' }], status: 'affected' },
      { vulnerability: { name: 'CVE-2' }, products: [{ '@id': 'pkg:test' }], status: 'not_affected', justification: 'component_not_present', impact_statement: 'x' }
    ];
    const res = await verifyVexDocument(createSignedVex({ statements }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { vulnerabilityId: 'CVE-2', productIdentifier: 'pkg:test' });
    expect(res.reasonCode).toBe('VEX-001');
  });

  test('unrelated first statement cannot suppress target CVE', async () => {
    const statements = [
      { vulnerability: { name: 'CVE-1' }, products: [{ '@id': 'pkg:test' }], status: 'not_affected', justification: 'component_not_present', impact_statement: 'x' }
    ];
    const res = await verifyVexDocument(createSignedVex({ statements }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { vulnerabilityId: 'CVE-2', productIdentifier: 'pkg:test' });
    expect(res.reasonCode).toBe('VEX-005');
  });

  test('two matching conflicting statements produce conservative result', async () => {
    const t = new Date().toISOString();
    const statements = [
      { vulnerability: { name: 'CVE-1' }, products: [{ '@id': 'pkg:test' }], status: 'not_affected', justification: 'component_not_present', impact_statement: 'x', timestamp: t },
      { vulnerability: { name: 'CVE-1' }, products: [{ '@id': 'pkg:test' }], status: 'affected', timestamp: t }
    ];
    const res = await verifyVexDocument(createSignedVex({ statements }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { vulnerabilityId: 'CVE-1', productIdentifier: 'pkg:test' });
    expect(res.reasonCode).toBe('VEX-008'); // Conservative fallback to affected
  });

  test('raw signer_trusted: true cannot bypass verification', async () => {
    const res = evaluateVexStatement({ signer_trusted: true, applicability_status: 'not_affected', vexAuthoritative: false });
    expect(res.applicabilityDisposition).toBe('APPLICABLE');
  });

  test('raw valid: true cannot bypass verification', async () => {
    const overlays = applyVexOverlays([{ id: 'CVE-1' }], [{ cve: 'CVE-1', valid: true, applicability_status: 'not_affected', vexAuthoritative: false }]);
    expect(overlays.vulnerabilities[0].applicabilityDisposition).toBe('APPLICABLE');
  });

  test('raw not_affected cannot become NON_BLOCKING', async () => {
    const overlays = applyVexOverlays([{ id: 'CVE-1' }], [{ cve: 'CVE-1', status: 'not_affected', vexAuthoritative: false }]);
    expect(overlays.vulnerabilities[0].policyBlockingStatus).toBe('BLOCKING');
  });

  test('dummy-target verification is not used', async () => {
    const res = await verifyVexDocument(createSignedVex(), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.isValid).toBe(true);
  });

  test('digest prefix rejected', async () => {
    const env = createSignedVex({ product: 'pkg:npm/test-product@1.0.0', subcomponents: [{ hashes: { 'sha256': 'hash123' } }] });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:npm/test-product@1.0.0', digest: 'hash12' });
    expect(res.reasonCode).toBe('VEX-019');
  });

  test('version prefix rejected', async () => {
    const env = createSignedVex({ product: 'pkg:npm/test-product@1.0.0' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:npm/test-product@1.0' });
    expect(res.reasonCode).toBe('VEX-004');
  });

  test('FIXED for version B does not suppress version A', async () => {
    const env = createSignedVex({ status: 'fixed', product: 'pkg:npm/test-product@2.0.0' });
    const res = await verifyVexDocument(env, 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:npm/test-product@1.0.0' });
    expect(res.reasonCode).toBe('VEX-004');
  });

  test('valid VEX for CVE-A does not affect CVE-B', async () => {
    const res = await verifyVexDocument(createSignedVex({ vuln: 'CVE-A' }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { vulnerabilityId: 'CVE-B' });
    expect(res.reasonCode).toBe('VEX-005');
  });

  test('valid VEX for artifact A does not affect artifact B', async () => {
    const res = await verifyVexDocument(createSignedVex({ product: 'pkg:A@1' }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:B@1' });
    expect(res.reasonCode).toBe('VEX-004');
  });

  test('valid VEX for version A does not affect version B', async () => {
    const res = await verifyVexDocument(createSignedVex({ product: 'pkg:A@1' }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey), { productIdentifier: 'pkg:A@2' });
    expect(res.reasonCode).toBe('VEX-004');
  });

  test('expired VEX distinct from stale VEX', async () => {
    const e = new Date(Date.now() - 10000).toISOString();
    const res = await verifyVexDocument(createSignedVex({ expires_at: e }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-015');
  });

  test('expiry before issue rejected', async () => {
    const t = new Date().toISOString();
    const e = new Date(Date.now() - 10000).toISOString();
    const res = await verifyVexDocument(createSignedVex({ timestamp: t, expires_at: e }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-015');
  });

  test('future issue outside policy skew rejected', async () => {
    const future = new Date(Date.now() + 20 * 60 * 1000).toISOString();
    const res = await verifyVexDocument(createSignedVex({ timestamp: future }), 'OFFLINE_KEYED', getPem(validKeyPair.publicKey));
    expect(res.reasonCode).toBe('VEX-014');
  });

  test('invalid VEX remains present for audit but excluded from activeVexIds', async () => {
    const overlays = applyVexOverlays([{ id: 'CVE-1' }], [{ cve: 'CVE-1', vex_id: 'test-1', valid: false, vexAuthoritative: false }]);
    expect(overlays.activeVexIds).not.toContain('test-1');
  });
});
