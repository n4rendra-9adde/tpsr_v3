/**
 * TPSR v3 Sigstore Cosign Cryptographic Signature Verification Engine
 * Implements real offline-keyed verification using Sigstore Cosign CLI.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { getTrustPolicy, normalizeFingerprint } = require('./trustPolicyLoader');

const COSIGN_BIN = process.env.COSIGN_PATH || path.join(__dirname, '../../../bin/cosign');
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB limit

/**
 * Helper to run execFile as a Promise without shell vulnerability
 */
function runExecFile(bin, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(bin, args, { timeout: 15000, ...options }, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        return reject(error);
      }
      resolve({ stdout, stderr });
    });
  });
}


/**
 * Verifies an offline-keyed signature against an artifact
 */
async function verifySignature(params) {
  const result = {
    verificationMode: params?.signatureType === 'OFFLINE_KEYED' ? 'offline-keyed' : 'keyless',
    targetType: 'sbom',
    targetDigest: params?.artifactHash || null,
    signatureType: 'COSIGN',
    verificationStatus: 'FAILED',
    signatureVerified: false,
    cryptographicValid: false,
    signerIdentityResolved: false,
    verifiedSignerIdentity: null,
    verifiedKeyFingerprint: null,
    signerAuthorized: false,
    policyId: null,
    policyVersion: null,
    matchedPolicyEntry: null,
    signerIdentity: params?.signerIdentity || 'unknown',
    publicKeyFingerprint: null,
    certificateSubject: null,
    certificateIssuer: null,
    transparencyLogVerified: false,
    verifiedAt: new Date().toISOString(),
    failureReason: 'Signature verification failed',
    reasonCode: 'SIG-002',
    status: 'INVALID',
    signatureHash: null
  };

  // Prevent synthetic success in authoritative paths
  if (params.simulated || params.bundleJson?.simulated) {
    result.reasonCode = 'SIG-010';
    result.failureReason = 'Synthetic verification prohibited in authoritative path';
    result.status = 'INVALID';
    return result;
  }

  if (!params || !params.artifactHash) {
    result.reasonCode = 'SIG-005';
    result.failureReason = 'Missing required artifactHash for signature verification';
    return result;
  }

  const policy = getTrustPolicy();
  const normalizedHash = params.artifactHash.toLowerCase().trim();

  if (params.signatureType === 'KEYLESS') {
    result.reasonCode = 'SIG-009';
    result.failureReason = 'KEYLESS_NOT_IMPLEMENTED';
    return result;
  }

  if (params.signatureType === 'OFFLINE_KEYED') {
    if (!params.signatureValue || !params.publicKey) {
      result.reasonCode = 'SIG-006';
      result.failureReason = 'Missing signatureValue or publicKey for OFFLINE_KEYED verification';
      return result;
    }

    const pubKeyString = params.publicKey.toString('utf8');
    result.publicKeyFingerprint = normalizeFingerprint(pubKeyString);

    if (Buffer.byteLength(params.signatureValue, 'base64') > MAX_FILE_SIZE ||
        Buffer.byteLength(pubKeyString, 'utf8') > MAX_FILE_SIZE) {
      result.reasonCode = 'SIG-011';
      result.failureReason = 'Input payload exceeds maximum allowed size limit';
      return result;
    }

    if (!fs.existsSync(COSIGN_BIN)) {
      result.reasonCode = 'SIG-007';
      result.failureReason = 'Cosign binary unavailable';
      return result;
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpsr-cosign-'));
    const blobPath = path.join(tmpDir, 'artifact.sha256');
    const sigPath = path.join(tmpDir, 'sig.bin');
    const pubPath = path.join(tmpDir, 'pub.pem');

    let cryptoPassed = false;
    try {
      fs.writeFileSync(blobPath, normalizedHash, 'utf8');
      fs.writeFileSync(sigPath, Buffer.from(params.signatureValue, 'base64'));
      fs.writeFileSync(pubPath, pubKeyString, 'utf8');

      fs.chmodSync(tmpDir, 0o700);
      fs.chmodSync(blobPath, 0o600);
      fs.chmodSync(sigPath, 0o600);
      fs.chmodSync(pubPath, 0o600);

      const args = [
        'verify-blob',
        '--key', pubPath,
        '--signature', sigPath,
        '--insecure-ignore-tlog=true',
        blobPath
      ];

      await runExecFile(COSIGN_BIN, args);
      cryptoPassed = true;
    } catch (cliErr) {
      if (cliErr.code === 'ETIMEDOUT' || cliErr.killed) {
        result.reasonCode = 'SIG-008';
        result.failureReason = 'Cosign process timeout exceeded';
      } else {
        result.reasonCode = 'SIG-002'; // Cryptographic failure
        let stderrMsg = (cliErr.stderr || cliErr.message).split('\n')[0];
        result.failureReason = `Cryptographic signature invalid: ${stderrMsg}`;
      }
      return result;
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }

    // Cryptography passed. Now perform Identity Authorization
    if (cryptoPassed) {
      result.cryptographicValid = true;
      result.verifiedKeyFingerprint = result.publicKeyFingerprint;

      let matchedIdentity = null;
      if (policy.signaturePolicy && policy.signaturePolicy.normalizedSigners) {
        for (const [identity, fp] of Object.entries(policy.signaturePolicy.normalizedSigners)) {
          if (fp === result.publicKeyFingerprint) {
            matchedIdentity = identity;
            break;
          }
        }
      }

      if (!matchedIdentity && params.signerIdentity && policy.signaturePolicy && policy.signaturePolicy.trustedPublicKeys && policy.signaturePolicy.trustedPublicKeys[params.signerIdentity]) {
        matchedIdentity = params.signerIdentity;
      }

      if (!matchedIdentity) {
        result.signerIdentityResolved = false;
        result.reasonCode = 'SIG-003';
        result.failureReason = 'Signer identity unauthorized (not found in policy)';
        return result;
      }

      // Check caller mismatch if provided
      if (params.signerIdentity && params.signerIdentity !== matchedIdentity) {
         // Fails caller mismatch
         result.reasonCode = 'SIG-003';
         result.failureReason = 'Caller provided signerIdentity does not match cryptographically bound identity';
         return result;
      }

      // Check revocation
      if (policy.isRevoked && policy.isRevoked('SIGNER', matchedIdentity, params.signedAt || new Date())) {
         result.signerAuthorized = false;
         result.reasonCode = 'SIG-004';
         result.failureReason = 'Signer identity is revoked';
         return result;
      }

      result.signerIdentityResolved = true;
      result.verifiedSignerIdentity = matchedIdentity;
      result.signerIdentity = matchedIdentity; // backwards compat
      result.signerAuthorized = true;
      result.policyId = policy.policyId;
      result.policyVersion = policy.schemaVersion;
      result.matchedPolicyEntry = matchedIdentity;

      result.verificationStatus = 'VERIFIED';
      result.status = 'VERIFIED';
      result.signatureVerified = true;
      result.reasonCode = 'SIG-000';
      result.failureReason = 'Real Cosign signature verified and trusted';
      result.signatureHash = crypto.createHash('sha256').update(Buffer.from(params.signatureValue, 'base64')).digest('hex');

      return result;
    }
  }

  result.reasonCode = 'SIG-009';
  result.failureReason = `Unsupported signature type: ${params.signatureType}`;
  return result;
}

module.exports = {
  verifySignature
};
