'use strict';
const crypto = require('crypto');
const snapshotRepo = require('../repositories/snapshot.repository');
const trustPolicyLoader = require('../utils/trustPolicyLoader');
const db = require('../config/database');

function stringifyDeterministic(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  if (Array.isArray(obj)) return obj.map(stringifyDeterministic);
  const sorted = {};
  Object.keys(obj).sort().forEach(k => {
    sorted[k] = stringifyDeterministic(obj[k]);
  });
  return sorted;
}

function createSnapshotPayload(sbomId, evalResult, evidenceBundle, dbDecision, policy) {
  return {
    snapshotId: `SNAP-${crypto.randomUUID()}`,
    decisionId: dbDecision.id,
    sbomId: sbomId,
    decision: evalResult.trustStatus,
    reasonCodes: evalResult.reasonCode ? [evalResult.reasonCode] : [],
    triggeredRuleIds: evalResult.triggeredRuleIds || [],
    caectdModelVersion: evalResult.caectdModelVersion,
    policySnapshot: {
      policyId: policy.policyId,
      generation: policy.generation,
      schemaVersion: policy.schemaVersion,
      trustPolicyHash: crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex')
    },
    evidenceSummaries: evalResult.evidenceSummary,
    evidenceManifest: {
      provenance: evidenceBundle.provenance ? evidenceBundle.provenance.map(p => ({ id: p.id, hash: p.payload_hash || p.hash })) : [],
      signatures: evidenceBundle.signatures ? evidenceBundle.signatures.map(s => ({ id: s.id, fingerprint: s.public_key_fingerprint })) : [],
      vexStatements: evidenceBundle.vexStatements ? evidenceBundle.vexStatements.map(v => ({ id: v.id, vulnerability_id: v.vulnerability_id })) : [],
      policyExceptions: evidenceBundle.policyExceptions ? evidenceBundle.policyExceptions.map(e => ({ id: e.id, exception_id: e.exception_id })) : [],
      contextAssertions: evidenceBundle.allActiveContextAssertions ? evidenceBundle.allActiveContextAssertions.map(a => ({ id: a.id, hash: a.payload_hash })) : []
    },
    evaluatedAt: dbDecision.evaluated_at,
    evaluatorVersion: 'TPSR_V3',
    explanationCompleteness: evalResult.explanationCompleteness
  };
}

async function captureAndPersistSnapshot(sbomId, evalResult, evidenceBundle, dbDecision) {
  const policy = trustPolicyLoader.getTrustPolicy();
  const payload = createSnapshotPayload(sbomId, evalResult, evidenceBundle, dbDecision, policy);
  
  const payloadToHash = { ...payload };
  delete payloadToHash.snapshotId;
  delete payloadToHash.decisionId;
  delete payloadToHash.evaluatedAt;
  
  if (payloadToHash.evidenceSummaries) {
    const cloned = JSON.parse(JSON.stringify(payloadToHash.evidenceSummaries));
    delete cloned.transitionMetadata;
    payloadToHash.evidenceSummaries = cloned;
  }
  
  const stringified = JSON.stringify(stringifyDeterministic(payloadToHash));
  const hash = crypto.createHash('sha256').update(stringified).digest('hex');

  const snapshotRecord = {
    snapshotId: payload.snapshotId,
    sbomId: sbomId,
    decision: evalResult.trustStatus,
    policyId: policy.policyId,
    policyGeneration: policy.generation,
    modelVersion: evalResult.caectdModelVersion || '1.0.0',
    evaluatedAt: dbDecision.evaluated_at || new Date().toISOString(),
    snapshotHash: hash,
    payload: payload
  };

  try {
    await snapshotRepo.insertSnapshot(snapshotRecord);
    return snapshotRecord;
  } catch (err) {
    throw new Error(`Failed to persist immutable decision snapshot: ${err.message}`);
  }
}

module.exports = {
  stringifyDeterministic,
  createSnapshotPayload,
  captureAndPersistSnapshot
};
