const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile } = require('child_process');
const util = require('util');
const execFileAsync = util.promisify(execFile);

// Read Trust Policy
const trustPolicyPath = path.join(__dirname, '../../../docs/TRUST_POLICY.json');
let trustPolicy = {};
let trustPolicyHash = '';
try {
  const tpContent = fs.readFileSync(trustPolicyPath, 'utf8');
  trustPolicy = JSON.parse(tpContent);
  trustPolicyHash = crypto.createHash('sha256').update(tpContent).digest('hex');
} catch (err) {
  console.warn('Failed to load TRUST_POLICY.json', err);
}

const vexPolicy = trustPolicy.vexPolicy || {};
const VALID_JUSTIFICATIONS = vexPolicy.allowedJustifications || [];

async function verifyVexSignature(envelope, publicKey) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpsr-vex-'));
  try {
    const envPath = path.join(tmpDir, 'envelope.json');
    const pubPath = path.join(tmpDir, 'cosign.pub');
    // Using a dummy target since we use verify-blob-attestation
    const dummyPath = path.join(tmpDir, 'dummy.txt');
    fs.writeFileSync(dummyPath, 'vex-target-placeholder');

    fs.writeFileSync(envPath, JSON.stringify(envelope));
    fs.writeFileSync(pubPath, publicKey);

    const cosignBin = path.resolve(__dirname, '../../../bin/cosign');
    if (!fs.existsSync(cosignBin)) {
      throw new Error('Cosign binary not found at ' + cosignBin);
    }

    const args = [
      'verify-blob-attestation',
      '--key', pubPath,
      '--signature', envPath,
      '--insecure-ignore-tlog=true',
      '--check-claims=false', // Custom claims checked by our engine
      '--type', 'https://openvex.dev/ns/v0.2.0',
      dummyPath
    ];

    await execFileAsync(cosignBin, args, {
      env: { ...process.env, COSIGN_PASSWORD: '' }
    });

    const pubDer = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
    const pubFingerprint = crypto.createHash('sha256').update(pubDer).digest('hex');

    return { signatureStatus: 'VERIFIED', publicKeyFingerprint: pubFingerprint };
  } catch (err) {
    throw { reasonCode: 'VEX-010', message: 'VEX signature invalid' };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function verifyVexDocument(envelope, signatureType, publicKey, targetContext) {
  const result = {
    isValid: false,
    applicabilityDisposition: 'VEX_INVALID',
    policyBlockingStatus: 'BLOCKING',
    reasonCode: 'VEX-012',
    reasonCodes: [],
    verifiedAt: new Date().toISOString()
  };

  if (envelope?.payloadType !== 'application/vnd.in-toto+json') {
    result.reasonCode = 'VEX-011';
    result.reasonCodes.push('VEX-011');
    return result;
  }

  let payloadStr = envelope.payload;
  if (!payloadStr) {
    result.reasonCodes.push('VEX-012');
    return result;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadStr, 'base64').toString('utf8'));
  } catch (err) {
    result.reasonCodes.push('VEX-012');
    return result;
  }

  if (payload.predicateType !== 'https://openvex.dev/ns/v0.2.0') {
    result.reasonCode = 'VEX-011';
    result.reasonCodes.push('VEX-011');
    return result;
  }

  result.statementHash = crypto.createHash('sha256').update(JSON.stringify(envelope)).digest('hex');
  result.format = 'OpenVEX';
  result.formatVersion = 'v0.2.0';
  result.policyVersion = trustPolicy.policyVersion;
  result.trustPolicyHash = trustPolicyHash;

  // Verify Signature
  if (signatureType === 'OFFLINE_KEYED') {
    try {
      const sigResult = await verifyVexSignature(envelope, publicKey);
      result.signatureStatus = sigResult.signatureStatus;
      result.publicKeyFingerprint = sigResult.publicKeyFingerprint;
      result.verificationMode = 'offline-keyed';
      result.transparencyLogStatus = 'false';
    } catch (err) {
      result.reasonCode = err.reasonCode || 'VEX-010';
      result.reasonCodes.push(result.reasonCode);
      return result;
    }
  } else {
    result.reasonCode = 'VEX-010';
    result.reasonCodes.push('VEX-010');
    return result;
  }

  const predicate = payload.predicate || {};
  const statements = predicate.statements || [];
  
  if (statements.length === 0) {
    result.reasonCode = 'VEX-012';
    result.reasonCodes.push('VEX-012');
    return result;
  }
  
  // Use first statement for simplicity in this normalized model, ideally loop/conflict resolution
  const stmt = statements[0];
  
  result.vulnerabilityIdentifiers = [stmt.vulnerability?.name || stmt.vulnerability?.['@id']].filter(Boolean);
  result.productIdentifiers = (stmt.products || []).map(p => p['@id'] || p).filter(Boolean);
  
  // Strict matching
  if (targetContext) {
    // Vuln match
    if (targetContext.vulnerabilityId && !result.vulnerabilityIdentifiers.includes(targetContext.vulnerabilityId)) {
      result.reasonCode = 'VEX-005';
      result.reasonCodes.push('VEX-005');
      return result;
    }
    // Product match (if provided in targetContext)
    if (targetContext.productIdentifier && !result.productIdentifiers.includes(targetContext.productIdentifier)) {
      result.reasonCode = 'VEX-004';
      result.reasonCodes.push('VEX-004');
      return result;
    }
  }

  // Freshness
  const issued = predicate.timestamp ? new Date(predicate.timestamp) : null;
  if (issued) {
    const ageDays = (Date.now() - issued.getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays > (vexPolicy.maxOverlayValidityDays || 365)) {
      result.reasonCode = 'VEX-007';
      result.reasonCodes.push('VEX-007');
      return result;
    }
    // future clock skew checking
    if (issued.getTime() > Date.now() + 10 * 60 * 1000) {
      result.reasonCode = 'VEX-007';
      result.reasonCodes.push('VEX-007');
      return result;
    }
  }

  result.vexStatus = stmt.status;
  result.justification = stmt.justification;
  result.impactStatement = stmt.impact_statement;
  result.actionStatement = stmt.action_statement;

  if (stmt.status === 'not_affected') {
    if (!VALID_JUSTIFICATIONS.includes(stmt.justification)) {
      result.reasonCode = 'VEX-006';
      result.reasonCodes.push('VEX-006');
      return result;
    }
    if (vexPolicy.requireImpactStatementForNotAffected && !stmt.impact_statement) {
      result.reasonCode = 'VEX-006';
      result.reasonCodes.push('VEX-006');
      return result;
    }
    result.isValid = true;
    result.applicabilityDisposition = 'NOT_AFFECTED';
    result.policyBlockingStatus = 'NON_BLOCKING';
    result.reasonCode = 'VEX-001';
    result.reasonCodes.push('VEX-001');
  } else if (stmt.status === 'under_investigation') {
    result.isValid = true;
    result.applicabilityDisposition = 'UNDER_INVESTIGATION';
    result.policyBlockingStatus = 'REVIEW_REQUIRED';
    result.reasonCode = 'VEX-002';
    result.reasonCodes.push('VEX-002');
  } else if (stmt.status === 'affected') {
    result.isValid = true;
    result.applicabilityDisposition = 'APPLICABLE';
    result.policyBlockingStatus = 'BLOCKING';
    result.reasonCode = 'VEX-008';
    result.reasonCodes.push('VEX-008');
  } else if (stmt.status === 'fixed') {
    // For fixed we should strictly match release, assuming matched above via productIdentifier
    result.isValid = true;
    result.applicabilityDisposition = 'FIXED_FOR_RELEASE';
    result.policyBlockingStatus = 'NON_BLOCKING';
    result.reasonCode = 'VEX-001';
    result.reasonCodes.push('VEX-001');
  } else {
    result.reasonCode = 'VEX-012';
    result.reasonCodes.push('VEX-012');
  }

  return result;
}

function evaluateVexStatement(vexRecord) {
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

    // Find matching VEX statement
    const matchingVex = vexStatements.find(v => {
      if (v.valid === false || v.signer_trusted === false || v.component_scope_mismatch) return false;
      const targetId = v.vulnerability_id || v.vulnerabilityId || v.cve || v.sub;
      return targetId && targetId.toLowerCase() === (vulnId || '').toLowerCase();
    });

    vulnCopy.originalCvssScore = Number(vulnCopy.cvssScore || vulnCopy.cvss || 0);
    vulnCopy.originalSeverity = (vulnCopy.severity || 'UNKNOWN').toUpperCase();

    if (matchingVex) {
      if (matchingVex.id || matchingVex.vex_id) {
        activeVexIds.push(matchingVex.id || matchingVex.vex_id);
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
