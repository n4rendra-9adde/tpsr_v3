'use strict';

const db = require('../config/database');
const policyExceptionRepository = require('../repositories/policyExceptionRepository');
const sbomRepository = require('../repositories/sbomRepository');
const trustRepository = require('../repositories/trustRepository');
const { evaluateTrust } = require('../utils/trustEngine');
const contextAssertionRepository = require('../repositories/contextAssertionRepository');

const INTERVAL_MS = 60000; // Configurable polling interval
let workerInterval = null;
let isRunning = false;

async function processExpiredExceptions() {
  if (isRunning) return;
  isRunning = true;
  
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    
    // 1. Find ACTIVE exceptions whose validUntil is in the past. Lock rows safely.
    const now = new Date().toISOString();
    const expiredExceptions = await policyExceptionRepository.findExceptionsExpiringBefore(now, client);
    
    const sbomIdsToReevaluate = new Set();

    if (expiredExceptions.length > 0) {
      console.log(`[ExceptionExpiryWorker] Found ${expiredExceptions.length} expired exceptions`);
      
      const ids = expiredExceptions.map(e => e.id);
      
      // 3. Mark exceptions EXPIRED.
      const marked = await policyExceptionRepository.markExpiredExceptions(ids, client);
      
      // 4. Record an append-oriented expiry event.
      for (const exc of marked) {
        sbomIdsToReevaluate.add(exc.sbom_id);
        await policyExceptionRepository.recordExceptionEvent({
          exceptionId: exc.id,
          sbomId: exc.sbom_id,
          eventType: 'EXPIRED',
          previousStatus: 'ACTIVE',
          newStatus: 'EXPIRED',
          actorId: 'system:exception-expiry-worker',
          actorRole: 'system',
          reason: 'Automatically expired due to validUntil threshold',
          policyVersion: exc.policy_version,
          trustPolicyHash: exc.trust_policy_hash
        }, client);
      }
    }
    
    // Find VEX Statements whose policy_valid_until is in the past
    const expiredVexStatements = await sbomRepository.findVexStatementsExpiringBefore(now, client);
    if (expiredVexStatements.length > 0) {
      console.log(`[ExceptionExpiryWorker] Found ${expiredVexStatements.length} expired VEX statements`);
      
      const vexIds = expiredVexStatements.map(v => v.id);
      const markedVex = await sbomRepository.markExpiredVexStatements(vexIds, client);
      
      for (const vex of markedVex) {
        sbomIdsToReevaluate.add(vex.sbom_id);
      }
    }

    if (sbomIdsToReevaluate.size > 0) {
      await client.query('COMMIT');
      
      // 6. Trigger authoritative CAECTD reevaluation.
      for (const sbomId of sbomIdsToReevaluate) {
        try {
          await triggerReevaluationForSbom(sbomId);
        } catch (e) {
          console.error(`[ExceptionExpiryWorker] Failed to reevaluate SBOM ${sbomId}:`, e);
          // Allow transient failures to retry safely on next tick if handled as outbox logic or rely on manual trigger
        }
      }
    } else {
      await client.query('ROLLBACK');
    }
  } catch (err) {
    console.error('[ExceptionExpiryWorker] Error processing expired exceptions:', err);
    await client.query('ROLLBACK');
  } finally {
    isRunning = false;
    client.release();
  }
}

async function triggerReevaluationForSbom(sbomId) {
  const sbomDoc = await sbomRepository.getSBOMDocumentBySBOMID(sbomId);
  if (!sbomDoc) throw new Error('SBOM not found');
  
  const [provenance, signatures, vexStatements, depContexts, exceptions, activeAssertions] = await Promise.all([
    sbomRepository.getProvenanceBySBOMID(sbomId),
    sbomRepository.getSignaturesBySBOMID(sbomId),
    sbomRepository.getVexStatementsBySBOMID(sbomId),
    sbomRepository.getDeploymentContextBySBOMID(sbomId),
    policyExceptionRepository.listExceptionsBySbomId(sbomId),
    contextAssertionRepository.listContextAssertionsBySbomId(sbomId)
  ]);

  const activeAssertion = activeAssertions.find(a => a.status === 'ACTIVE') || null;
  const latestLegacyContext = depContexts.length > 0 ? depContexts[0] : null;

  const evalResult = await evaluateTrust({
    sbomDocument: sbomDoc,
    provenance,
    signatures,
    vexStatements,
    deploymentContext: latestLegacyContext,
    activeContextAssertion: activeAssertion,
    allActiveContextAssertions: activeAssertions.filter(a => a.status === 'ACTIVE'),
    policyExceptions: exceptions
  });
  
  const actor = 'system:exception-expiry-worker';

  // Find previous decision ID (just for logging/knowledge if needed)
  
  // 7. Persist the new trust-decision-history row
  const dbDecision = await trustRepository.insertTrustDecision({
    sbomId: sbomId,
    trustStatus: evalResult.trustStatus,
    reasonCode: evalResult.reasonCode,
    reasonDescription: evalResult.reasonDescription,
    evidenceSummary: evalResult.evidenceSummary,
    policyVersion: evalResult.policyVersion,
    evaluatedBy: actor,
    idempotencyKey: null,
    caectdModelVersion: evalResult.caectdModelVersion,
    triggeredRuleIds: evalResult.triggeredRuleIds,
    evaluatedRuleIds: evalResult.evaluatedRuleIds,
    evidenceDependencies: evalResult.evidenceDependencies,
    explanationCompleteness: evalResult.explanationCompleteness
  });

  // 9. Create a RECORD_TRUST_DECISION outbox item
  const outboxRecord = await trustRepository.insertOutboxRecord({
    sbomId: sbomId,
    decisionId: dbDecision.id,
    action: 'RECORD_TRUST_DECISION',
    payload: {
      version: "3.0",
      sbomID: sbomId,
      decisionId: dbDecision.id,
      trustStatus: evalResult.trustStatus,
      reasonCode: evalResult.reasonCode,
      reasonDescription: evalResult.reasonDescription,
      policyVersion: evalResult.policyVersion || '3.0',
      evidenceSummary: evalResult.evidenceSummary
    }
  });
  
  // 8. (Removed updateSbomTrustStatus since v3 uses trust_decision_history)
  
  console.log(`[ExceptionExpiryWorker] Reevaluated SBOM ${sbomId}: ${evalResult.trustStatus} (${evalResult.reasonCode})`);
  return dbDecision;
}

function start() {
  if (!workerInterval) {
    workerInterval = setInterval(processExpiredExceptions, INTERVAL_MS);
    console.log('[ExceptionExpiryWorker] Started worker');
    // Run immediately once
    processExpiredExceptions().catch(console.error);
  }
}

function stop() {
  if (workerInterval) {
    clearInterval(workerInterval);
    workerInterval = null;
    console.log('[ExceptionExpiryWorker] Stopped worker');
  }
}

module.exports = {
  start,
  stop,
  processExpiredExceptions,
  triggerReevaluationForSbom
};
