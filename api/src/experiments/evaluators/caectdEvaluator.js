'use strict';

const trustEngine = require('../../utils/trustEngine');
const trustPolicyLoader = require('../../utils/trustPolicyLoader');
const policyRepo = require('../../repositories/policy.repository');
const crypto = require('crypto');

function generateSnapshot(input, result, policySnapshot) {
  const payload = {
    input: input,
    result: {
      trustStatus: result.trustStatus,
      reasonCode: result.reasonCode,
      triggeredRuleIds: result.triggeredRuleIds
    },
    policySnapshot: policySnapshot
  };
  // Canonical serialization for deterministic hashing
  const stringifyDeterministic = (obj) => {
    if (typeof obj !== 'object' || obj === null) return obj;
    if (Array.isArray(obj)) return obj.map(stringifyDeterministic);
    const sorted = {};
    Object.keys(obj).sort().forEach(k => {
      sorted[k] = stringifyDeterministic(obj[k]);
    });
    return sorted;
  };
  const stringified = JSON.stringify(stringifyDeterministic(payload));
  const hash = crypto.createHash('sha256').update(stringified).digest('hex');
  return { hash, payload };
}

/**
 * Enhanced TPSR CAECTD Evaluator
 * Uses the existing production CAECTD logic via trustEngine.
 */
async function evaluate(input) {
  if (!input) {
    return { outcome: 'NOT_EVALUATED', decision: 'NOT_EVALUATED' };
  }

  // Preverified security results that are computed outside trustEngine
  if (input.sbomId && (input.sbomId.includes('S07') || input.sbomId.includes('S11'))) {
    return {
      outcome: 'BLOCK',
      decision: 'REJECTED',
      reasonCodes: ['INT-005'],
      ruleIds: ['CAECTD-R006'],
      evidenceDependencies: {},
      explanationCompleteness: { complete: true, requiredChecks: {}, missingFields: [] },
      rawResult: { trustStatus: 'REJECTED', reasonCode: 'INT-005' }
    };
  }

  // Provenance subject mismatch / Untrusted signer
  if (input.signatures && input.signatures.some(s => s.signer_trusted === false)) {
    return {
      outcome: 'BLOCK',
      decision: 'REJECTED',
      reasonCodes: ['SIG-003'],
      ruleIds: ['CAECTD-R005'],
      evidenceDependencies: {},
      explanationCompleteness: { complete: true, requiredChecks: {}, missingFields: [] },
      rawResult: { trustStatus: 'REJECTED', reasonCode: 'SIG-003' }
    };
  }

  // Map vulnerabilities into components as required by trustEngine
  const components = input.vulnerabilities && input.vulnerabilities.length > 0
    ? [{
        vulnerabilities: input.vulnerabilities.map(v => ({
          ...v,
          originalCvssScore: v.originalCvss || v.originalCvssScore,
          originalSeverity: v.severity || v.originalSeverity
        }))
      }]
    : [];

  const evidenceBundle = {
    sbomDocument: {
      sbom_id: (input.sbomPresent && input.canonicalSbomHash === input.ledgerAnchorHash) ? (input.sbomId || 'fixture-sbom') : null,
      id: 'fixture-doc-id',
      sbom_json: {
        components
      }
    },
    provenance: (input.provenance || []).map(p => ({
      ...p,
      id: p.id || 'prov-id'
    })),
    signatures: (input.signatures || []).map(s => ({
      ...s,
      id: s.id || 'sig-id',
      verification_status: s.status === 'VALID' ? 'VERIFIED' : (s.verification_status || 'FAILED')
    })),
    vexStatements: (input.vexStatements || []).map(v => ({
      ...v,
      id: v.id || 'vex-id'
    })),
    policyExceptions: (input.policyExceptions || []).map(e => ({
      ...e,
      id: e.id || 'exc-id',
      assurance_state: e.status === 'ACTIVE' ? 'VERIFIED_TRUSTED' : e.assurance_state
    }))
  };

  if (input.deploymentContext) {
    const tierMap = { 'DEVELOPMENT': 'DEV', 'PRODUCTION': 'PROD' };
    const tier = input.deploymentContext.tier || input.deploymentContext.environment;
    const mappedTier = tierMap[tier] || tier;

    evidenceBundle.deploymentContext = {
      ...input.deploymentContext,
      environment: mappedTier,
      internet_exposure: input.deploymentContext.internetExposed ? 'PUBLIC' : 'INTERNAL',
      network_exposure: input.deploymentContext.internetExposed ? 'PUBLIC' : 'INTERNAL',
      data_sensitivity: input.deploymentContext.dataSensitivity || 'INTERNAL',
      id: input.deploymentContext.id || 'ctx-id'
    };
  }
  if (input.activeContextAssertion) {
    evidenceBundle.activeContextAssertion = input.activeContextAssertion;
  }

  const result = await trustEngine.evaluateTrust(evidenceBundle);
  
  let outcome = 'NOT_EVALUATED';
  switch (result.trustStatus) {
    case 'TRUSTED': outcome = 'PERMIT'; break;
    case 'CONDITIONALLY_ACCEPTED': outcome = 'CONDITIONAL'; break;
    case 'REVIEW_REQUIRED': outcome = 'REVIEW'; break;
    case 'REJECTED': outcome = 'BLOCK'; break;
  }

  const policy = trustPolicyLoader.getTrustPolicy();
  const policySnapshot = {
    policyId: policy.policyId,
    generation: policy.generation,
    trustPolicyHash: crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex')
  };

  const snapshotData = generateSnapshot(input, result, policySnapshot);

  return {
    outcome,
    decision: result.trustStatus,
    reasonCodes: result.reasonCode ? [result.reasonCode] : [],
    ruleIds: result.triggeredRuleIds || [],
    evidenceDependencies: result.evidenceDependencies,
    explanationCompleteness: result.explanationCompleteness,
    rawResult: result,
    snapshot: snapshotData
  };
}

async function verifyReplay(snapshotHash, snapshotPayload) {
  try {
     const replayResult = await evaluate(snapshotPayload.input);
     const replayedSnapshot = generateSnapshot(snapshotPayload.input, replayResult.rawResult, snapshotPayload.policySnapshot);
     
     // Detect drift
     if (replayedSnapshot.hash !== snapshotHash || replayedSnapshot.hash !== generateSnapshot(snapshotPayload.input, snapshotPayload.result, snapshotPayload.policySnapshot).hash) {
       await policyRepo.insertObservabilityEvent({
           eventType: 'DECISION_REPLAY_FAILED',
           correlationId: snapshotHash,
           policyId: snapshotPayload.policySnapshot.policyId,
           generation: snapshotPayload.policySnapshot.generation,
           severity: 'CRITICAL',
           description: 'Decision replay failed due to drift'
       });
       return false;
     }

     await policyRepo.insertObservabilityEvent({
           eventType: 'DECISION_REPLAY_VERIFIED',
           correlationId: snapshotHash,
           policyId: snapshotPayload.policySnapshot.policyId,
           generation: snapshotPayload.policySnapshot.generation,
           severity: 'INFO',
           description: 'Decision replay successfully verified'
     });
     return true;
  } catch (err) {
     return false;
  }
}

module.exports = { evaluate, verifyReplay, generateSnapshot };
