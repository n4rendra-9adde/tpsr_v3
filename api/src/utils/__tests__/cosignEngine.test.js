const crypto = require('crypto');
const { verifySignature } = require('../cosignEngine');

describe('Sigstore Cosign Cryptographic Signature Verification Engine', () => {
  const validHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  test('Rejects verification request with missing artifactHash', async () => {
    const res = await verifySignature({ signatureType: 'OFFLINE_KEYED' });
    expect(res.status).toBe('INVALID');
    expect(res.reasonCode).toBe('SIG-002');
  });

  test('OFFLINE_KEYED: Rejects verification when signatureValue or publicKey is missing', async () => {
    const res = await verifySignature({
      signatureType: 'OFFLINE_KEYED',
      artifactHash: validHash
    });
    expect(res.status).toBe('INVALID');
    expect(res.reasonCode).toBe('SIG-002');
  });

  test('OFFLINE_KEYED: Successfully verifies valid RSA signature generated via native crypto', async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const signer = crypto.createSign('SHA256');
    signer.update(validHash);
    signer.end();
    const signatureValue = signer.sign(privateKey, 'base64');

    const res = await verifySignature({
      signatureType: 'OFFLINE_KEYED',
      artifactHash: validHash,
      signatureValue,
      publicKey
    });

    expect(res.status).toBe('VERIFIED');
    expect(res.reasonCode).toBe('SIG-001');
    expect(res.signatureHash).toBeDefined();
  });

  test('KEYLESS: Rejects keyless bundle verification when bundleJson is missing', async () => {
    const res = await verifySignature({
      signatureType: 'KEYLESS',
      artifactHash: validHash
    });
    expect(res.status).toBe('INVALID');
    expect(res.reasonCode).toBe('SIG-002');
  });

  test('KEYLESS: Rejects keyless verification with unauthorized OIDC issuer', async () => {
    const res = await verifySignature({
      signatureType: 'KEYLESS',
      artifactHash: validHash,
      bundleJson: {},
      expectedIssuer: 'https://unauthorized-issuer.example.com',
      expectedSubject: 'build-officer@example.com'
    });
    expect(res.status).toBe('INVALID');
    expect(res.reasonCode).toBe('SIG-003');
  });

  test('KEYLESS: Validates simulated keyless bundle structure when digest matches', async () => {
    const bundleJson = {
      simulated: true,
      verificationMaterial: { certificate: { rawBytes: 'test' } },
      messageSignature: {
        messageDigest: {
          algorithm: 'SHA256',
          digest: validHash
        }
      }
    };

    const res = await verifySignature({
      signatureType: 'KEYLESS',
      artifactHash: validHash,
      bundleJson,
      expectedIssuer: 'https://token.actions.githubusercontent.com',
      expectedSubject: 'https://github.com/org/repo/.github/workflows/build.yml'
    });

    expect(res.status).toBe('VERIFIED');
    expect(res.reasonCode).toBe('SIG-001');
    expect(res.signatureHash).toBeDefined();
  });
});
