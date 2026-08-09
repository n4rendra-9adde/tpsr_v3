'use strict';

const crypto = require('crypto');
const { verifySignature } = require('./cosignEngine');
const provenanceEngine = require('./provenanceEngine');

/**
 * Stage 3: Canonicalize Context Assertion
 * - UTF-8 JSON
 * - Lexicographically sorted object keys
 * - Array order preserved unless explicitly set-like
 * - No insignificant whitespace
 */
function canonicalizeContextAssertion(assertionData) {
  // Simple recursive sort function for JSON objects
  const sortKeys = (obj) => {
    if (typeof obj !== 'object' || obj === null) return obj;
    if (Array.isArray(obj)) return obj.map(sortKeys);
    
    const sortedObj = {};
    Object.keys(obj).sort().forEach(key => {
      sortedObj[key] = sortKeys(obj[key]);
    });
    return sortedObj;
  };
  
  // Make a clone without signature related fields to form the canonical payload
  const payload = { ...assertionData };
  delete payload.signatureValue;
  delete payload.publicKey;
  delete payload.signatureType;
  delete payload.verificationMode;
  delete payload.signerIdentity;

  const sortedPayload = sortKeys(payload);
  const canonicalBytes = JSON.stringify(sortedPayload);
  const payloadHash = crypto.createHash('sha256').update(canonicalBytes, 'utf8').digest('hex');
  
  return { canonicalBytes, payloadHash, sortedPayload };
}

/**
 * Map context assertions to assurance state
 */
function deriveContextAssuranceState(ctx) {
  if (ctx.verificationStatus === 'INVALID' || !ctx.signatureVerified || !ctx.releaseBindingPassed) {
    return 'INVALID';
  }
  
  if (ctx.conflictDetected) {
    return 'CONFLICTING';
  }
  
  if (!ctx.freshnessPassed) {
    return 'STALE';
  }

  if (ctx.signatureVerified && !ctx.authorityTrusted) {
    return 'VERIFIED_UNTRUSTED';
  }

  if (ctx.signatureVerified && ctx.authorityTrusted && ctx.releaseBindingPassed && ctx.freshnessPassed) {
    return 'VERIFIED_TRUSTED';
  }

  return 'INVALID';
}

/**
 * Full engine verification
 */
async function verifyContextAssertion(payload, sbomDoc, activeAssertions = []) {
  const result = {
    verificationStatus: 'FAILED',
    assuranceState: 'INVALID',
    signatureVerified: false,
    authorityTrusted: false,
    releaseBindingPassed: false,
    freshnessPassed: false,
    conflictDetected: false,
    ruleIds: [],
    reasonCodes: [],
    normalizedAssertion: null,
    policyVersion: '3.0',
    trustPolicyHash: null,
    verifiedAt: new Date().toISOString()
  };

  if (!payload || payload.simulated === true) {
    result.reasonCodes.push('CTX-010');
    result.ruleIds.push('CAECTD-R026');
    result.verificationStatus = 'INVALID';
    return result;
  }

  // Stage 1 & 2: Parse and validate structure (Simplified for this exercise)
  if (!payload.environment || !payload.sbomId || !payload.digestManifestDigest) {
    result.reasonCodes.push('CTX-011');
    result.ruleIds.push('CAECTD-R026');
    result.verificationStatus = 'INVALID';
    return result;
  }

  // Stage 3: Canonicalize
  const { payloadHash, sortedPayload } = canonicalizeContextAssertion(payload);

  // Stage 4: Verify Signature
  if (payload.signatureType === 'OFFLINE_KEYED') {
    const sigParams = {
      signatureType: payload.signatureType,
      signatureValue: payload.signatureValue,
      publicKey: Buffer.from(payload.publicKey || '', 'utf8'),
      signerIdentity: payload.signerIdentity,
      artifactHash: payloadHash // The target digest is the hash of the canonical assertion!
    };
    const sigRes = await verifySignature(sigParams);
    result.signatureVerified = sigRes.signatureVerified;
    if (!result.signatureVerified) {
      result.reasonCodes.push(sigRes.reasonCode || 'CTX-012');
      result.ruleIds.push('CAECTD-R026');
    }
  } else {
    result.reasonCodes.push('CTX-013');
    result.ruleIds.push('CAECTD-R026');
  }

  // Stage 5: Validate Authority
  const policy = provenanceEngine.getTrustPolicy();
  const envAuth = policy.contextAuthorities ? policy.contextAuthorities[payload.environment] : null;
  
  if (envAuth) {
    // Check role
    if (envAuth.allowedRoles && envAuth.allowedRoles.includes(payload.assertorRole)) {
      // Check fingerprint
      const pubKeyString = Buffer.from(payload.publicKey || '', 'utf8').toString('utf8');
      const fingerprint = crypto.createHash('sha256').update(pubKeyString.trim()).digest('hex');
      
      if (envAuth.approvedPublicKeyFingerprints && envAuth.approvedPublicKeyFingerprints.includes(fingerprint)) {
        result.authorityTrusted = true;
      }
    }
  }
  
  if (!result.authorityTrusted && result.signatureVerified) {
    result.reasonCodes.push('CTX-014');
    result.ruleIds.push('CAECTD-R026');
  }

  // Stage 6: Bind to Release
  if (sbomDoc && payload.sbomId === sbomDoc.sbom_id && payload.digestManifestDigest === `sha256:${sbomDoc.sbom_hash}`) {
    result.releaseBindingPassed = true;
  } else {
    result.reasonCodes.push('CTX-015');
    result.ruleIds.push('CAECTD-R026'); // Valid signature over another release or wrong release binding must fail binding
  }

  // Stage 7: Validate Freshness
  const now = new Date();
  const validUntil = new Date(payload.validUntil);
  const maxHours = envAuth && envAuth.maximumValidityHours ? envAuth.maximumValidityHours : 24;
  const assertedAt = new Date(payload.assertedAt);
  
  if (validUntil > now && (validUntil.getTime() - assertedAt.getTime()) <= maxHours * 3600000) {
    result.freshnessPassed = true;
  } else {
    result.reasonCodes.push('CTX-016');
    result.ruleIds.push('CAECTD-R026');
  }

  // Stage 8: Detect Conflict
  const conflicting = activeAssertions.filter(a => a.environment !== payload.environment);
  if (conflicting.length > 0) {
    result.conflictDetected = true;
    result.reasonCodes.push('CTX-017');
    result.ruleIds.push('CAECTD-R025');
  }

  // Stage 9: Derive Assurance State
  result.assuranceState = deriveContextAssuranceState(result);
  
  if (result.assuranceState === 'VERIFIED_TRUSTED') {
    result.verificationStatus = 'VERIFIED';
    result.reasonCodes.push('CTX-000');
  } else if (result.assuranceState === 'VERIFIED_UNTRUSTED') {
    result.verificationStatus = 'UNTRUSTED';
  }

  // Remove duplicates
  result.reasonCodes = [...new Set(result.reasonCodes)];
  result.ruleIds = [...new Set(result.ruleIds)];

  result.normalizedAssertion = {
    ...sortedPayload,
    assertionPayloadHash: payloadHash
  };

  return result;
}

module.exports = {
  verifyContextAssertion,
  canonicalizeContextAssertion,
  deriveContextAssuranceState
};
