const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execSync } = require('child_process');
const { verifySignature } = require('../cosignEngine');
const trustPolicyLoader = require('../trustPolicyLoader');

jest.mock('../trustPolicyLoader', () => {
  const original = jest.requireActual('../trustPolicyLoader');
  return {
    ...original,
    getTrustPolicy: jest.fn()
  };
});

describe('Sigstore Cosign Cryptographic Signature Verification Engine', () => {
  const validHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  let testPubKey = '';
  let testSigValue = '';
  let tmpDir = '';

  beforeAll(() => {
    // Generate a real Cosign keypair and signature for the tests
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpsr-test-'));
    const keyPath = path.join(tmpDir, 'cosign.key');
    const pubPath = path.join(tmpDir, 'cosign.pub');
    const blobPath = path.join(tmpDir, 'blob.txt');
    const sigPath = path.join(tmpDir, 'sig.bin');

    fs.writeFileSync(blobPath, validHash, 'utf8');

    const cosignBin = path.join(__dirname, '../../../../bin/cosign');
    
    // Generate keypair
    execSync(`env COSIGN_PASSWORD="" ${cosignBin} generate-key-pair`, { cwd: tmpDir });
    
    // Sign blob
    execSync(`env COSIGN_PASSWORD="" ${cosignBin} sign-blob --key cosign.key --yes --tlog-upload=false --output-signature sig.bin blob.txt`, { cwd: tmpDir });

    testPubKey = fs.readFileSync(pubPath);
    testSigValue = fs.readFileSync(sigPath, 'base64');

    const fp = trustPolicyLoader.normalizeFingerprint(testPubKey.toString('utf8'));
    trustPolicyLoader.getTrustPolicy.mockReturnValue({
      schemaVersion: 'v1.0', policyId: 'id',
      signaturePolicy: {
        normalizedSigners: {
          'test-signer@tpsr.com': fp
        }
      }
    });
  });

  afterAll(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('Rejects synthetic/simulated verification requests', async () => {
    const res = await verifySignature({ 
      signatureType: 'OFFLINE_KEYED',
      simulated: true 
    });
    expect(res.verificationStatus).toBe('FAILED');
    expect(res.reasonCode).toBe('SIG-010');
  });

  test('Rejects verification request with missing artifactHash', async () => {
    const res = await verifySignature({ signatureType: 'OFFLINE_KEYED' });
    expect(res.verificationStatus).toBe('FAILED');
    expect(res.reasonCode).toBe('SIG-005');
  });

  test('OFFLINE_KEYED: Rejects verification when signatureValue or publicKey is missing', async () => {
    const res = await verifySignature({
      signatureType: 'OFFLINE_KEYED',
      artifactHash: validHash
    });
    expect(res.verificationStatus).toBe('FAILED');
    expect(res.reasonCode).toBe('SIG-006');
  });

  test('OFFLINE_KEYED: Rejects oversized payload inputs', async () => {
    const res = await verifySignature({
      signatureType: 'OFFLINE_KEYED',
      artifactHash: validHash,
      signatureValue: Buffer.alloc(11 * 1024 * 1024).toString('base64'), // 11MB
      publicKey: testPubKey
    });
    expect(res.verificationStatus).toBe('FAILED');
    expect(res.reasonCode).toBe('SIG-011');
  });

  test('OFFLINE_KEYED: Successfully verifies valid Cosign signature', async () => {
    const res = await verifySignature({
      signatureType: 'OFFLINE_KEYED',
      artifactHash: validHash,
      signatureValue: testSigValue,
      publicKey: testPubKey,
      signerIdentity: 'test-signer@tpsr.com'
    });

    expect(res.verificationStatus).toBe('VERIFIED');
    expect(res.reasonCode).toBe('SIG-000');
    expect(res.signatureVerified).toBe(true);
    expect(res.publicKeyFingerprint).toBeDefined();
    expect(res.signatureHash).toBeDefined();
  });

  test('OFFLINE_KEYED: Rejects invalid signature', async () => {
    const invalidSig = Buffer.from('invalid-signature-data').toString('base64');
    const res = await verifySignature({
      signatureType: 'OFFLINE_KEYED',
      artifactHash: validHash,
      signatureValue: invalidSig,
      publicKey: testPubKey
    });

    expect(res.verificationStatus).toBe('FAILED');
    expect(res.reasonCode).toBe('SIG-002');
  });

  test('KEYLESS: Rejects keyless mode as unsupported', async () => {
    const res = await verifySignature({
      signatureType: 'KEYLESS',
      artifactHash: validHash
    });
    expect(res.verificationStatus).toBe('FAILED');
    expect(res.reasonCode).toBe('SIG-009');
  });
});
