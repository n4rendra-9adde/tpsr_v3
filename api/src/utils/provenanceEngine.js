'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const child_process = require('child_process');
const util = require('util');
const execFile = util.promisify(child_process.execFile);
const sbomRepository = require('../repositories/sbomRepository');
const { getTrustPolicy } = require('./trustPolicyLoader');



// Stage 1
function parseAttestation(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    throw { reasonCode: 'PRV-001', message: 'Envelope is missing or not a valid JSON object' };
  }
  if (!envelope.payloadType || !envelope.payload) {
    throw { reasonCode: 'PRV-015', message: 'Unsigned provenance prohibited. Envelope missing payload/payloadType.' };
  }

  try {
    const decodedPayload = Buffer.from(envelope.payload, 'base64').toString('utf8');
    const statement = JSON.parse(decodedPayload);
    return statement;
  } catch (err) {
    throw { reasonCode: 'PRV-001', message: 'Failed to decode or parse DSSE payload as JSON' };
  }
}

// Stage 2
function validateStatementStructure(statement) {
  const statementType = statement._type || statement.type;
  if (statementType !== 'https://in-toto.io/Statement/v0.1' && statementType !== 'https://in-toto.io/Statement/v1') {
    throw { reasonCode: 'PRV-001', message: `Unsupported statement type: ${statementType}` };
  }
  const predicateType = statement.predicateType;
  if (predicateType !== 'https://slsa.dev/provenance/v1' && predicateType !== 'https://slsa.dev/provenance/v0.2') {
    throw { reasonCode: 'PRV-002', message: `Unsupported predicateType: ${predicateType}` };
  }
  const subjects = statement.subject;
  if (!Array.isArray(subjects) || subjects.length === 0) {
    throw { reasonCode: 'PRV-001', message: 'Attestation subject must be a non-empty array' };
  }
  return { statementType, predicateType, subjects };
}

// Stage 3
function adaptLegacyProvenance(statement, predicateType) {
  if (predicateType === 'https://slsa.dev/provenance/v1') {
    return statement;
  }
  // V0.2 to V1 Adapter
  const adapted = JSON.parse(JSON.stringify(statement));
  adapted.predicateType = 'https://slsa.dev/provenance/v1';
  adapted.predicate = adapted.predicate || {};
  adapted.predicate.buildDefinition = {
    buildType: statement.predicate?.buildType,
    externalParameters: statement.predicate?.invocation?.parameters || {}
  };
  adapted.predicate.runDetails = {
    builder: { id: statement.predicate?.builder?.id },
    metadata: {
      startedOn: statement.predicate?.metadata?.buildStartedOn,
      finishedOn: statement.predicate?.metadata?.buildFinishedOn
    }
  };
  return adapted;
}

// Stage 4
function validateProvenanceClaims(adaptedStatement) {
  const predicate = adaptedStatement.predicate || {};
  const builderId = predicate.runDetails?.builder?.id;
  const buildType = predicate.buildDefinition?.buildType;
  const startedOn = predicate.runDetails?.metadata?.startedOn;
  const finishedOn = predicate.runDetails?.metadata?.finishedOn;

  if (!builderId || typeof builderId !== 'string') {
    throw { reasonCode: 'PRV-003', message: 'Builder runner identity is missing' };
  }

  if (startedOn && finishedOn) {
    if (new Date(startedOn) > new Date(finishedOn)) {
      throw { reasonCode: 'PRV-011', message: 'startedOn is after finishedOn' };
    }
  }

  let sourceRepository = null;
  let sourceCommit = null;
  const extParams = predicate.buildDefinition?.externalParameters || {};
  if (extParams.source) {
    sourceRepository = extParams.source.uri;
    sourceCommit = extParams.source.digest?.sha1 || extParams.source.digest?.sha256;
  }

  return { builderId, buildType, startedOn, finishedOn, sourceRepository, sourceCommit, externalParameters: extParams };
}

// Stage 5
async function verifyAttestationEnvelope(envelope, publicKey, predicateType) {
  const cosignBin = path.join(__dirname, '../../../bin/cosign');
  if (!fs.existsSync(cosignBin)) {
    throw { reasonCode: 'PRV-006', message: 'Cosign binary not found' };
  }

  const tmpDir = fs.mkdtempSync(path.join('/tmp', 'tpsr-cosign-'));
  const envPath = path.join(tmpDir, 'envelope.json');
  fs.writeFileSync(envPath, JSON.stringify(envelope));

  let keyPath = null;
  let pubFingerprint = null;
  if (publicKey) {
    keyPath = path.join(tmpDir, 'cosign.pub');
    fs.writeFileSync(keyPath, publicKey);
    pubFingerprint = crypto.createHash('sha256').update(publicKey).digest('hex');
  } else {
    const policy = getTrustPolicy();
    const trustedKeys = policy.signaturePolicy?.trustedPublicKeys || {};
    const keys = Object.values(trustedKeys);
    if (keys.length > 0) {
      keyPath = path.join(tmpDir, 'cosign.pub');
      fs.writeFileSync(keyPath, keys[0]);
      pubFingerprint = crypto.createHash('sha256').update(keys[0]).digest('hex');
    }
  }

  if (!keyPath) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    throw { reasonCode: 'PRV-013', message: 'No public key available for offline-keyed verification' };
  }

  const dummyBlob = path.join(tmpDir, 'dummy.txt');
  fs.writeFileSync(dummyBlob, 'dummy');

  try {
    const args = [
      'verify-blob-attestation',
      '--key', keyPath,
      '--signature', envPath,
      '--insecure-ignore-tlog=true',
      '--check-claims=false',
      '--type', predicateType || 'custom',
      dummyBlob
    ];
    await execFile(cosignBin, args, { env: Object.assign({}, process.env, { COSIGN_PASSWORD: '' }), timeout: 10000 });
    return { signatureStatus: 'VERIFIED', signerIdentity: pubFingerprint, publicKeyFingerprint: pubFingerprint };
  } catch (err) {
    console.error('Cosign verification failed:', err.message, err.stderr);
    throw { reasonCode: 'PRV-006', message: 'Envelope signature invalid' };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// Stage 6
function evaluateProvenanceTrustPolicy(claims) {
  const policy = getTrustPolicy();
  const provPolicy = policy.provenancePolicy || {};

  const isApprovedBuilder = (provPolicy.approvedBuilders || []).some(b => b === claims.builderId);
  if (!isApprovedBuilder) {
    throw { reasonCode: 'PRV-003', message: `Builder identity ${claims.builderId} unauthorized` };
  }

  if (claims.buildType && provPolicy.approvedBuildTypes) {
    const isApprovedBuildType = provPolicy.approvedBuildTypes.includes(claims.buildType);
    if (!isApprovedBuildType) {
      throw { reasonCode: 'PRV-009', message: `Build type ${claims.buildType} unauthorized` };
    }
  }

  if (claims.sourceRepository && provPolicy.approvedSourceRepositories) {
    const isApprovedRepo = provPolicy.approvedSourceRepositories.includes(claims.sourceRepository);
    if (!isApprovedRepo) {
      throw { reasonCode: 'PRV-004', message: `Source repository ${claims.sourceRepository} mismatch` };
    }
  }

  let slsaLevel = 'SLSA_BUILD_LEVEL_2';
  if (claims.builderId.includes('github-hosted') || claims.builderId.includes('tekton')) {
    slsaLevel = 'SLSA_BUILD_LEVEL_3';
  }
  const requiredLevel = provPolicy.requiredSlsaLevel || 'SLSA_BUILD_LEVEL_3';
  if (requiredLevel === 'SLSA_BUILD_LEVEL_3' && slsaLevel !== 'SLSA_BUILD_LEVEL_3') {
    throw { reasonCode: 'PRV-003', message: `Policy requires ${requiredLevel} but achieved ${slsaLevel}` };
  }

  return {
    slsaLevel,
    policyId: policy.policyId,
    policyVersion: policy.schemaVersion,
    trustPolicyHash: crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex')
  };
}

// Stage 7
async function checkFreshnessAndReplay(claims) {
  const policy = getTrustPolicy();
  const freshness = policy.provenancePolicy?.freshness;
  const now = new Date();

  if (claims.finishedOn && freshness) {
    const finished = new Date(claims.finishedOn);
    const ageMs = now - finished;
    const maxAgeMs = freshness.maxAgeDays * 24 * 60 * 60 * 1000;
    if (ageMs > maxAgeMs) {
      throw { reasonCode: 'PRV-007', message: 'Provenance stale' };
    }
    const futureSkewMs = freshness.maxFutureSkewMinutes * 60 * 1000;
    if (finished - now > futureSkewMs) {
      throw { reasonCode: 'PRV-011', message: 'Future timestamp beyond allowed skew' };
    }
  }
}

// Stage 8
function bindProvenanceToTarget(subjects, expectedArtifactHash) {
  const normalizedExpectedHash = (expectedArtifactHash || '').toLowerCase().trim();
  let matchedSubject = null;

  for (const sub of subjects) {
    if (sub && sub.digest) {
      const sha256 = (sub.digest.sha256 || sub.digest.SHA256 || '').toLowerCase().trim();
      if (sha256 === normalizedExpectedHash) {
        matchedSubject = sub;
        break;
      }
    }
  }

  if (!matchedSubject) {
    throw { reasonCode: 'BND-002', message: `Attestation subject digest does not match registered artifact hash: ${normalizedExpectedHash}` };
  }
}

async function verifyProvenance(envelope, expectedArtifactHash, signatureType = 'OFFLINE_KEYED', publicKey = null) {
  const result = {
    status: 'INVALID',
    slsaLevel: 'SLSA_BUILD_LEVEL_0',
    reasonCode: 'PRV-001',
    reasonDescription: 'Unknown verification failure',
    builderId: null,
    envelopeHash: crypto.createHash('sha256').update(JSON.stringify(envelope || {})).digest('hex'),
    verifiedAt: new Date().toISOString(),
    reasonCodes: [],
    provenanceCryptographicallyValid: false,
    provenanceSignerIdentityResolved: false,
    provenanceSignerAuthorized: false,
    builderIdentityResolved: false,
    builderAuthorized: false,
    sourceIdentityResolved: false,
    sourceAuthorized: false,
    artifactBindingValid: false,
    policyId: null,
    policyVersion: null,
    matchedPolicyDimension: null
  };

  try {
    const statement = parseAttestation(envelope);
    const { statementType, predicateType, subjects } = validateStatementStructure(statement);

    result.predicateType = predicateType;
    result.predicateVersion = predicateType === 'https://slsa.dev/provenance/v1' ? 'v1' : 'v0.2';

    const adaptedStatement = adaptLegacyProvenance(statement, predicateType);
    result.normalizedOutput = adaptedStatement;

    const claims = validateProvenanceClaims(adaptedStatement);
    result.builderId = claims.builderId;
    if (claims.builderId) result.builderIdentityResolved = true;
    result.buildType = claims.buildType;
    result.sourceRepository = claims.sourceRepository;
    if (claims.sourceRepository) result.sourceIdentityResolved = true;
    result.sourceCommit = claims.sourceCommit;
    result.externalParameters = claims.externalParameters;
    result.buildStartedOn = claims.startedOn;
    result.buildFinishedOn = claims.finishedOn;

    const cryptoResult = await verifyAttestationEnvelope(envelope, publicKey, predicateType);
    result.provenanceCryptographicallyValid = true;
    if (cryptoResult.signerIdentity) {
      result.provenanceSignerIdentityResolved = true;
      result.provenanceSignerAuthorized = true; // In current TPSR v3 logic, verified offline key is mapped this way
    }
    result.signatureStatus = cryptoResult.signatureStatus;
    result.signerIdentity = cryptoResult.signerIdentity;
    result.publicKeyFingerprint = cryptoResult.publicKeyFingerprint;

    const policyEval = evaluateProvenanceTrustPolicy(claims);
    result.builderAuthorized = true;
    result.sourceAuthorized = true;
    result.slsaLevel = policyEval.slsaLevel;
    result.policyId = policyEval.policyId;
    result.policyVersion = policyEval.policyVersion;
    result.trustPolicyHash = policyEval.trustPolicyHash;
    result.matchedPolicyDimension = 'provenancePolicy';

    bindProvenanceToTarget(subjects, expectedArtifactHash);
    result.artifactBindingValid = true;

    await checkFreshnessAndReplay(claims);

    result.status = 'VALID';
    result.reasonCode = 'PRV-000';
    result.reasonCodes.push('PRV-000');
    result.reasonDescription = 'Provenance verified and trusted';

  } catch (err) {
    result.status = 'INVALID';
    result.reasonCode = err.reasonCode || 'PRV-001';
    result.reasonCodes.push(result.reasonCode);
    result.reasonDescription = err.message || 'Unknown failure';
    if (result.reasonCode.startsWith('BND')) {
      result.status = 'INVALID';
    }
  }

  return result;
}

module.exports = {
  verifyProvenance,
  getTrustPolicy,
  parseAttestation,
  validateStatementStructure,
  adaptLegacyProvenance,
  validateProvenanceClaims,
  verifyAttestationEnvelope,
  evaluateProvenanceTrustPolicy,
  checkFreshnessAndReplay,
  bindProvenanceToTarget
};
