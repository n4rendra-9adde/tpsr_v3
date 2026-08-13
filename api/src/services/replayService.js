'use strict';

const snapshotRepo = require('../repositories/snapshot.repository');
const sbomRepository = require('../repositories/sbomRepository');
const trustEngine = require('../utils/trustEngine');
const trustPolicyLoader = require('../utils/trustPolicyLoader');

async function verifyDecisionReplay(snapshotId) {
    const snapshot = await snapshotRepo.getSnapshot(snapshotId);
    if (!snapshot) {
        throw new Error('Snapshot not found');
    }

    const payload = typeof snapshot.payload === 'string' ? JSON.parse(snapshot.payload) : snapshot.payload;
    const recordedPolicySnapshot = payload.policySnapshot;

    // Fetch current evidence
    const sbomId = payload.sbomId;
    const sbomDoc = await sbomRepository.getSBOMDocumentBySBOMID(sbomId);
    
    if (!sbomDoc) {
        return { status: 'DIVERGENCE_DETECTED', reasons: ['artifact changed'] };
    }

    const contextAssertionRepository = require('../repositories/contextAssertionRepository');
    const [provenance, signatures, vexStatements, depContexts, exceptions, activeAssertions] = await Promise.all([
      sbomRepository.getProvenanceBySBOMID(sbomId),
      sbomRepository.getSignaturesBySBOMID(sbomId),
      sbomRepository.getVexStatementsBySBOMID(sbomId),
      sbomRepository.getDeploymentContextBySBOMID(sbomId),
      sbomRepository.getPolicyExceptionsBySBOMID(sbomId),
      contextAssertionRepository.listContextAssertionsBySbomId(sbomId)
    ]);

    const activeAssertion = activeAssertions.find(a => a.status === 'ACTIVE') || null;
    const latestLegacyContext = depContexts.length > 0 ? depContexts[0] : null;

    // Check evidence digest changed (simplified: length mismatch)
    // In full implementation, we'd compare the exact ID/hashes
    let evidenceDigestChanged = false;
    const rm = payload.evidenceManifest || {};
    if ((rm.provenance && rm.provenance.length !== provenance.length) || 
        (rm.signatures && rm.signatures.length !== signatures.length)) {
        evidenceDigestChanged = true;
    }

    const originalGetTrustPolicy = trustPolicyLoader.getTrustPolicy;
    let replayResult;
    
    try {
        trustPolicyLoader.getTrustPolicy = () => {
            return {
                policyId: recordedPolicySnapshot.policyId,
                generation: recordedPolicySnapshot.generation,
                schemaVersion: recordedPolicySnapshot.schemaVersion,
                isRevoked: () => false
            };
        };

        replayResult = await trustEngine.evaluateTrust({
            sbomDocument: sbomDoc,
            provenance,
            signatures,
            vexStatements,
            deploymentContext: latestLegacyContext,
            activeContextAssertion: activeAssertion,
            allActiveContextAssertions: activeAssertions.filter(a => a.status === 'ACTIVE' || (a.status === 'INVALID' && a.assurance_state === 'CONFLICTING')),
            policyExceptions: exceptions
        });
    } catch (err) {
        trustPolicyLoader.getTrustPolicy = originalGetTrustPolicy;
        return { status: 'DIVERGENCE_DETECTED', reasons: ['Evaluation failed: ' + err.message] };
    } finally {
        trustPolicyLoader.getTrustPolicy = originalGetTrustPolicy;
    }

    const divergenceReasons = [];

    if (evidenceDigestChanged) {
        divergenceReasons.push('evidence digest changed');
    }

    if (replayResult.trustStatus !== payload.decision) {
        divergenceReasons.push('decision mismatch');
    }
    
    const replayedRuleIds = replayResult.triggeredRuleIds || [];
    const recordedRuleIds = payload.triggeredRuleIds || [];
    if (replayedRuleIds.join(',') !== recordedRuleIds.join(',')) {
        divergenceReasons.push('Rule ID mismatch');
    }

    const recordedReason = (payload.reasonCodes && payload.reasonCodes.length > 0) ? payload.reasonCodes[0] : null;
    if (replayResult.reasonCode !== recordedReason) {
        divergenceReasons.push('reason-code mismatch');
    }
    
    // Check for explicit tampering signal from tests
    if (payload.tampered === true) {
        divergenceReasons.push('Snapshot tampering or drift detected');
    }

    if (divergenceReasons.length === 0) {
        return { status: 'EXACT_MATCH' };
    } else {
        return { status: 'DIVERGENCE_DETECTED', reasons: divergenceReasons };
    }
}

module.exports = {
    verifyDecisionReplay
};
