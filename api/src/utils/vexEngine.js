const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const trustPolicyLoader = require('./trustPolicyLoader');

function verifyDSSE(envelope, publicKey) {
  if (!envelope || envelope.payloadType !== 'application/vnd.in-toto+json' || !envelope.payload || !envelope.signatures || envelope.signatures.length === 0) {
    throw { reasonCode: 'VEX-011', message: 'Malformed DSSE envelope' };
  }
  let pubKeyObj;
  try {
    pubKeyObj = crypto.createPublicKey(publicKey);
  } catch (err) {
    throw { reasonCode: 'VEX-021', message: 'Invalid or unsupported public key format/algorithm' };
  }

  const decodedPayload = Buffer.from(envelope.payload, 'base64');
  const type = envelope.payloadType;
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} ${type} ${decodedPayload.length} `),
    decodedPayload
  ]);

  let verified = false;
  for (const sig of envelope.signatures) {
    try {
      const sigBuffer = Buffer.from(sig.sig, 'base64');
      const verify = crypto.createVerify('SHA256');
      verify.update(pae);
      verify.end();
      if (verify.verify(pubKeyObj, sigBuffer)) {
        verified = true;
        break;
      }
    } catch (e) {
      // Ignore individual signature parsing failures
    }
  }

  if (!verified) {
    throw { reasonCode: 'VEX-010', message: 'DSSE signature verification failed' };
  }
  return crypto.createHash('sha256').update(pubKeyObj.export({ type: 'spki', format: 'der' })).digest('hex');
}

function resolveConflict(matchingStmts) {
  if (!matchingStmts || matchingStmts.length === 0) return null;
  // Sort by newest timestamp first. If no timestamp, treat as 0.
  matchingStmts.sort((a, b) => {
    const tA = a.timestamp ? new Date(a.timestamp).getTime() : 0;
    const tB = b.timestamp ? new Date(b.timestamp).getTime() : 0;
    if (tB !== tA) return tB - tA;

    // Conservative fallback for same timestamp
    const rank = { 'affected': 4, 'under_investigation': 3, 'fixed': 2, 'not_affected': 1 };
    return rank[b.status || 'not_affected'] - rank[a.status || 'not_affected'];
  });
  return matchingStmts[0];
}

async function verifyVexDocument(envelope, signatureType, publicKey, targetContext) {
  const result = {
    isValid: false,
    applicabilityDisposition: 'VEX_INVALID',
    policyBlockingStatus: 'BLOCKING',
    reasonCode: 'VEX-012',
    reasonCodes: [],
    verifiedAt: new Date().toISOString(),
    statementHash: crypto.createHash('sha256').update(JSON.stringify(envelope)).digest('hex'),
    format: 'OpenVEX',
    formatVersion: 'v0.2.0',
    policyVersion: null,
    trustPolicyHash: null,
    transparencyLogStatus: 'false',
    vexAuthoritative: false
  };

  let trustPolicy;
  try {
      trustPolicy = trustPolicyLoader.getTrustPolicy();
      result.policyVersion = trustPolicy.policyVersion;
      result.trustPolicyHash = crypto.createHash('sha256').update(JSON.stringify(trustPolicy)).digest('hex');
  } catch (err) {
      result.reasonCode = 'VEX-010';
      result.reasonCodes.push('VEX-010');
      return result;
  }
  const vexPolicy = trustPolicy.vexPolicy || {};
  const allowedJustifications = vexPolicy.allowedJustifications || [];

  if (signatureType !== 'OFFLINE_KEYED') {
    result.reasonCode = 'VEX-010';
    result.reasonCodes.push('VEX-010');
    return result;
  }

  let pubFingerprint;
  try {
    pubFingerprint = verifyDSSE(envelope, publicKey);
    result.signatureStatus = 'VERIFIED';
    result.publicKeyFingerprint = pubFingerprint;
    result.verificationMode = 'offline-keyed';
  } catch (err) {
    result.reasonCode = err.reasonCode || 'VEX-010';
    result.reasonCodes.push(result.reasonCode);
    return result;
  }

  // Issuer matching
  let issuerConfig = null;
  let verifiedIssuerIdentity = null;
  const authorizedIssuers = vexPolicy.authorizedIssuers || {};
  for (const [identity, cfg] of Object.entries(authorizedIssuers)) {
    const cfgDer = crypto.createPublicKey(cfg.publicKey).export({ type: 'spki', format: 'der' });
    const cfgFp = crypto.createHash('sha256').update(cfgDer).digest('hex');
    if (cfgFp === pubFingerprint) {
      issuerConfig = cfg;
      verifiedIssuerIdentity = identity;
      break;
    }
  }

  if (!issuerConfig) {
    result.reasonCode = 'VEX-009';
    result.reasonCodes.push('VEX-009');
    return result;
  }

  // Revocation Check
  // We use Date.now() here as the default check time. Detailed stmt timestamps are evaluated below if needed.
  if (trustPolicy.isRevoked && trustPolicy.isRevoked('VEX_ISSUER', verifiedIssuerIdentity, new Date())) {
    result.reasonCode = 'VEX-022';
    result.reasonCodes.push('VEX-022');
    return result;
  }

  // Check product authorization if not globally authorized
  if (!issuerConfig.globalAuthority && targetContext?.productIdentifier) {
    const allowed = issuerConfig.allowedProducts || [];
    if (!allowed.includes(targetContext.productIdentifier)) {
      result.reasonCode = 'VEX-009';
      result.reasonCodes.push('VEX-009');
      return result;
    }
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8'));
    result.canonicalPayloadDigest = crypto.createHash('sha256').update(envelope.payload).digest('hex');
  } catch (err) {
    result.reasonCode = 'VEX-011';
    result.reasonCodes.push('VEX-011');
    return result;
  }

  if (payload.predicateType !== 'https://openvex.dev/ns/v0.2.0') {
    result.reasonCode = 'VEX-011';
    result.reasonCodes.push('VEX-011');
    return result;
  }

  const predicate = payload.predicate || {};
  const globalTimestamp = predicate.timestamp;
  const statements = predicate.statements || [];

  if (statements.length === 0) {
    result.reasonCode = 'VEX-012';
    result.reasonCodes.push('VEX-012');
    return result;
  }

  // Bind to TargetContext across all statements
  const matchingStmts = [];

  for (const stmt of statements) {
    const tStampStr = stmt.timestamp || globalTimestamp;

    // Temporal verification
    if (!tStampStr) {
      continue;
    }
    const issuedAt = new Date(tStampStr);
    if (isNaN(issuedAt.getTime())) {
      continue;
    }

    const skew = vexPolicy.allowedClockSkewSeconds || 600;
    if (issuedAt.getTime() > Date.now() + (skew * 1000)) {
      continue;
    }

    const maxAge = vexPolicy.maxOverlayValidityDays || 365;
    if ((Date.now() - issuedAt.getTime()) / (1000 * 60 * 60 * 24) > maxAge) {
      continue;
    }

    if (vexPolicy.expiryRequired && !stmt.expires_at) {
        continue;
    }

    if (stmt.expires_at) {
        const exp = new Date(stmt.expires_at);
        if (isNaN(exp.getTime()) || exp.getTime() <= issuedAt.getTime() || exp.getTime() < Date.now()) {
            continue;
        }
    }

    // Scope matching
    if (targetContext) {
      const vulnIds = [stmt.vulnerability?.name, stmt.vulnerability?.['@id']].filter(Boolean);
      if (targetContext.vulnerabilityId && !vulnIds.includes(targetContext.vulnerabilityId)) {
        continue;
      }

      const prods = (stmt.products || []).map(p => p['@id']).filter(Boolean);
      if (targetContext.productIdentifier) {
        // EXACT match for version. No prefix/suffix shortcuts.
        const pidParts = targetContext.productIdentifier.split('@');
        const hasVersion = targetContext.version || pidParts[1];
        let matchedProd = false;

        for (const p of prods) {
            // Must equal exact product identifier
            if (p === targetContext.productIdentifier) {
                matchedProd = true;
                break;
            }
        }
        if (!matchedProd) continue;
      }

      // Exact digest matching if requested
      if (targetContext.digest) {
        let digestMatched = false;
        for (const p of (stmt.products || [])) {
            const subs = p.subcomponents || [];
            for (const sub of subs) {
                const hashes = sub.hashes || {};
                for (const h of Object.values(hashes)) {
                    if (h === targetContext.digest) digestMatched = true;
                }
            }
        }
        if (!digestMatched) continue;
      }
    }

    matchingStmts.push({
        ...stmt,
        timestamp: tStampStr
    });
  }

  // Reason codes for complete rejection (no statements left)
  if (matchingStmts.length === 0) {
    let hasTimestampError = false;
    let hasExpiryError = false;
    let hasScopeError = false;
    let hasDigestError = false;

    // Diagnose why statements were rejected
    for (const stmt of statements) {
      const tStampStr = stmt.timestamp || globalTimestamp;
      if (!tStampStr || isNaN(new Date(tStampStr).getTime())) hasTimestampError = true;
      else {
          const issuedAt = new Date(tStampStr);
          const skew = vexPolicy.allowedClockSkewSeconds || 600;
          if (issuedAt.getTime() > Date.now() + (skew * 1000)) hasTimestampError = true;
          const maxAge = vexPolicy.maxOverlayValidityDays || 365;
          if ((Date.now() - issuedAt.getTime()) / (1000 * 60 * 60 * 24) > maxAge) hasTimestampError = true; // stale
      }

      if (vexPolicy.expiryRequired && !stmt.expires_at) {
          hasExpiryError = true;
      } else if (stmt.expires_at) {
          const exp = new Date(stmt.expires_at);
          const issuedAt = tStampStr ? new Date(tStampStr) : new Date(0);
          if (isNaN(exp.getTime()) || exp.getTime() <= issuedAt.getTime() || exp.getTime() < Date.now()) {
              hasExpiryError = true;
          }
      }

      if (targetContext) {
          const vulnIds = [stmt.vulnerability?.name, stmt.vulnerability?.['@id']].filter(Boolean);
          let matchedVuln = false;
          if (targetContext.vulnerabilityId && !vulnIds.includes(targetContext.vulnerabilityId)) {
              hasScopeError = true;
          } else {
              matchedVuln = true;
          }

          const prods = (stmt.products || []).map(p => p['@id']).filter(Boolean);
          let matchedProd = true;
          if (targetContext.productIdentifier) {
            matchedProd = false;
            for (const p of prods) {
                if (p === targetContext.productIdentifier) matchedProd = true;
            }
            if (!matchedProd) hasScopeError = true;
          }

          if (hasScopeError) {
              if (matchedProd && !matchedVuln) {
                  result.reasonCode = 'VEX-005';
              } else {
                  result.reasonCode = 'VEX-004';
              }
          }

          if (targetContext.digest) {
            let digestMatched = false;
            for (const p of (stmt.products || [])) {
                const subs = p.subcomponents || [];
                for (const sub of subs) {
                    const hashes = sub.hashes || {};
                    for (const h of Object.values(hashes)) {
                        if (h === targetContext.digest) digestMatched = true;
                    }
                }
            }
            if (!digestMatched) hasDigestError = true;
          }
      }
    }

    if (hasTimestampError) {
        result.reasonCode = 'VEX-013'; // Timestamp error or future
        // wait, we distinguish VEX-013 (missing/malformed) and VEX-014 (future) and VEX-007 (stale)
        // for simplicity, let's just do an approximate assignment for the rejection code since it's just diagnosing
        for (const stmt of statements) {
            const ts = stmt.timestamp || globalTimestamp;
            if (!ts || isNaN(new Date(ts).getTime())) {
                result.reasonCode = 'VEX-013';
                break;
            }
            const iTime = new Date(ts).getTime();
            if (iTime > Date.now() + 600 * 1000) {
                result.reasonCode = 'VEX-014';
                break;
            }
            const maxAge = vexPolicy.maxOverlayValidityDays || 365;
            if ((Date.now() - iTime) / (1000 * 60 * 60 * 24) > maxAge) {
                result.reasonCode = 'VEX-007';
                break;
            }
        }
    } else if (hasExpiryError) {
        result.reasonCode = 'VEX-015'; // Expiry error
    } else if (hasDigestError) {
        result.reasonCode = 'VEX-019';
    } else if (hasScopeError) {
        // reasonCode was already assigned above
    } else {
        result.reasonCode = 'VEX-020'; // Ambiguous or missing scope
    }

    result.reasonCodes.push(result.reasonCode);
    return result;
  }

  const finalStmt = resolveConflict(matchingStmts);

  result.vexStatus = finalStmt.status;
  result.justification = finalStmt.justification;
  result.impactStatement = finalStmt.impact_statement;
  result.actionStatement = finalStmt.action_statement;

  result.vulnerabilityIdentifiers = [finalStmt.vulnerability?.name, finalStmt.vulnerability?.['@id']].filter(Boolean);
  result.productIdentifiers = (finalStmt.products || []).map(p => p['@id']).filter(Boolean);
  result.verifiedIssuerIdentity = verifiedIssuerIdentity;
  result.policyId = trustPolicy.policyId;

  // Strict semantic validation
  if (finalStmt.status === 'not_affected') {
    if (!allowedJustifications.includes(finalStmt.justification)) {
      result.reasonCode = 'VEX-006';
      result.reasonCodes.push('VEX-006');
      return result;
    }
    if (vexPolicy.requireImpactStatementForNotAffected && !finalStmt.impact_statement) {
      result.reasonCode = 'VEX-006';
      result.reasonCodes.push('VEX-006');
      return result;
    }
    result.isValid = true;
    result.applicabilityDisposition = 'NOT_AFFECTED';
    result.policyBlockingStatus = 'NON_BLOCKING';
    result.reasonCode = 'VEX-001';
    result.vexAuthoritative = true;
  } else if (finalStmt.status === 'under_investigation') {
    result.isValid = true;
    result.applicabilityDisposition = 'UNDER_INVESTIGATION';
    result.policyBlockingStatus = 'REVIEW_REQUIRED';
    result.reasonCode = 'VEX-002';
    result.vexAuthoritative = true;
  } else if (finalStmt.status === 'affected') {
    result.isValid = true;
    result.applicabilityDisposition = 'APPLICABLE';
    result.policyBlockingStatus = 'BLOCKING';
    result.reasonCode = 'VEX-008';
    result.vexAuthoritative = true;
  } else if (finalStmt.status === 'fixed') {
    result.isValid = true;
    result.applicabilityDisposition = 'FIXED_FOR_RELEASE';
    result.policyBlockingStatus = 'NON_BLOCKING';
    result.reasonCode = 'VEX-001';
    result.vexAuthoritative = true;
  } else {
    result.reasonCode = 'VEX-021'; // Unsupported status
    result.reasonCodes.push('VEX-021');
    return result;
  }

  result.targetBinding = {
      productIdentifier: targetContext?.productIdentifier || null,
      vulnerabilityId: targetContext?.vulnerabilityId || null,
      digest: targetContext?.digest || null
  };

  result.reasonCodes.push(result.reasonCode);
  return result;
}

function evaluateVexStatement(vexRecord) {
  // Require complete authoritative metadata, not just a single boolean
  const isAuthoritative = vexRecord.vexAuthoritative === true || vexRecord.vex_authoritative === true;
  const hasCrypto = (vexRecord.signatureStatus || vexRecord.signature_status) === 'VERIFIED';
  const hasIssuer = !!(vexRecord.publicKeyFingerprint || vexRecord.public_key_fingerprint);
  const hasPolicy = !!(vexRecord.policyVersion || vexRecord.policy_version);
  const hasBinding = !!(vexRecord.targetBinding || vexRecord.target_binding);
  const hasDigest = !!(vexRecord.canonicalPayloadDigest || vexRecord.canonical_payload_digest);

  if (!isAuthoritative || !hasCrypto || !hasIssuer || !hasPolicy || !hasBinding || !hasDigest) {
      return { status: 'unevaluated', reasonCode: 'VEX-012', reasonDescription: 'Non-authoritative VEX', applicabilityDisposition: 'APPLICABLE', policyBlockingStatus: 'BLOCKING' };
  }

  const status = vexRecord.applicability_status || vexRecord.status;
  const justification = vexRecord.justification;

  if (status === 'not_affected' || status === 'fixed') {
    return { status, reasonCode: 'VEX-001', reasonDescription: 'VEX policy applied: Risk mitigated.', justification, applicabilityDisposition: 'NOT_AFFECTED', policyBlockingStatus: 'NON_BLOCKING' };
  } else if (status === 'under_investigation') {
    return { status, reasonCode: 'VEX-002', reasonDescription: 'VEX policy applied: Under investigation.', justification, applicabilityDisposition: 'UNDER_INVESTIGATION', policyBlockingStatus: 'REVIEW_REQUIRED' };
  } else {
    return { status: 'affected', reasonCode: 'VEX-003', reasonDescription: 'VEX policy applied: Vulnerability applicable.', justification, applicabilityDisposition: 'APPLICABLE', policyBlockingStatus: 'BLOCKING' };
  }
}

function applyVexOverlays(vulnerabilities = [], vexStatements = []) {
  const activeVexIds = [];

  const updatedVulnerabilities = vulnerabilities.map(vuln => {
    const vulnCopy = { ...vuln };
    const vulnId = vulnCopy.id || vulnCopy.cve || vulnCopy.vulnerabilityId;

    const matchingVex = vexStatements.find(v => {
      // REQUIRE full verification metadata
      const isAuthoritative = v.vexAuthoritative === true || v.vex_authoritative === true;
      const hasCrypto = (v.signatureStatus || v.signature_status) === 'VERIFIED';
      const hasIssuer = !!(v.publicKeyFingerprint || v.public_key_fingerprint);
      const hasPolicy = !!(v.policyVersion || v.policy_version);
      const hasBinding = !!(v.targetBinding || v.target_binding);
      const hasDigest = !!(v.canonicalPayloadDigest || v.canonical_payload_digest);

      if (!isAuthoritative || !hasCrypto || !hasIssuer || !hasPolicy || !hasBinding || !hasDigest || v.valid === false || v.isValid === false) return false;
      const targetId = v.vulnerability_id || v.vulnerabilityId || v.cve || v.sub;
      return targetId && targetId.toLowerCase() === (vulnId || '').toLowerCase();
    });

    vulnCopy.originalCvssScore = Number(vulnCopy.cvssScore || vulnCopy.cvss || 0);
    vulnCopy.originalSeverity = (vulnCopy.severity || 'UNKNOWN').toUpperCase();

    if (matchingVex) {
      if (matchingVex.id || matchingVex.vex_id || matchingVex.statementId) {
        activeVexIds.push(matchingVex.id || matchingVex.vex_id || matchingVex.statementId);
      }
      const evalResult = evaluateVexStatement(matchingVex);
      vulnCopy.vexStatus = evalResult.status;
      vulnCopy.vexReasonCode = evalResult.reasonCode;
      vulnCopy.vexReasonDescription = evalResult.reasonDescription;
      vulnCopy.vexJustification = evalResult.justification;
      vulnCopy.applicabilityDisposition = evalResult.applicabilityDisposition;
      vulnCopy.policyBlockingStatus = evalResult.policyBlockingStatus;
    } else {
      vulnCopy.vexStatus = 'unevaluated';
      vulnCopy.applicabilityDisposition = 'APPLICABLE';
      vulnCopy.policyBlockingStatus = 'BLOCKING';
    }

    return vulnCopy;
  });

  return {
    vulnerabilities: updatedVulnerabilities,
    activeVexIds: Array.from(new Set(activeVexIds)),
    appliedAt: new Date().toISOString()
  };
}

module.exports = {
  verifyVexDocument,
  evaluateVexStatement,
  applyVexOverlays
};
