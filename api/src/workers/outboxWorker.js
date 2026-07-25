/**
 * TPSR v3 Transactional Ledger Outbox Background Worker
 * Uses SELECT FOR UPDATE SKIP LOCKED to atomically claim pending outbox records,
 * anchor them to Hyperledger Fabric, and handle retries with exponential backoff.
 */

const trustRepository = require('../repositories/trustRepository');
const fabric = require('../config/fabric');

let workerInterval = null;
let isRunning = false;

/**
 * Process a batch of outbox records
 * @param {number} batchSize
 * @param {string} workerId
 * @param {number} maxRetries
 * @returns {Promise<Object>} Batch processing statistics
 */
async function processOutboxBatch(batchSize = 10, workerId = 'outbox-worker-1', maxRetries = 5) {
  const stats = {
    claimed: 0,
    completed: 0,
    failedRequiresReview: 0,
    retryPending: 0,
    errors: []
  };

  let records = [];
  try {
    records = await trustRepository.claimPendingOutboxRecords(batchSize, workerId);
    stats.claimed = records.length;
  } catch (err) {
    console.error(`[TPSR][OUTBOX] Worker ${workerId} failed to claim records:`, err);
    stats.errors.push({ type: 'CLAIM_ERROR', message: err.message });
    return stats;
  }

  if (records.length === 0) {
    return stats;
  }

  let gateway = null;
  let contract = null;
  try {
    const fabricRes = await fabric.getContract();
    gateway = fabricRes.gateway;
    contract = fabricRes.contract;
  } catch (fabricInitErr) {
    console.warn(`[TPSR][OUTBOX] Fabric connection offline: ${fabricInitErr.message}. All claimed records will be deferred/retried.`);
  }

  for (const record of records) {
    const retryCount = (record.retry_count || 0) + 1;

    if (!contract) {
      // Defer due to offline Fabric
      if (retryCount >= maxRetries) {
        await trustRepository.updateOutboxRecordStatus(
          record.id,
          'FAILED_REQUIRES_REVIEW',
          'Fabric gateway offline after max retries',
          null,
          null
        );
        stats.failedRequiresReview++;
      } else {
        const backoffMs = Math.pow(2, retryCount) * 2000;
        const nextAttempt = new Date(Date.now() + backoffMs).toISOString();
        await trustRepository.updateOutboxRecordStatus(
          record.id,
          'RETRY_PENDING',
          'Fabric gateway offline, scheduled retry',
          null,
          nextAttempt
        );
        stats.retryPending++;
      }
      continue;
    }

    try {
      let payloadObj = record.payload;
      if (typeof payloadObj === 'string') {
        payloadObj = JSON.parse(payloadObj);
      }

      const txName = payloadObj.evidenceType ? 'RecordTrustEvidence' : 'RecordTrustDecision';
      const chaincodePayload = JSON.stringify(payloadObj);

      const resultBuffer = await contract.submitTransaction(txName, chaincodePayload);
      const txId = resultBuffer ? resultBuffer.toString('utf8').slice(0, 64) : `tx-${Date.now()}`;

      await trustRepository.updateOutboxRecordStatus(
        record.id,
        'COMPLETED',
        null,
        txId,
        null
      );
      stats.completed++;
    } catch (txErr) {
      console.warn(`[TPSR][OUTBOX] Record ${record.id} failed transaction: ${txErr.message}`);
      if (retryCount >= maxRetries) {
        await trustRepository.updateOutboxRecordStatus(
          record.id,
          'FAILED_REQUIRES_REVIEW',
          `Transaction error: ${txErr.message}`,
          null,
          null
        );
        stats.failedRequiresReview++;
      } else {
        const backoffMs = Math.pow(2, retryCount) * 2000;
        const nextAttempt = new Date(Date.now() + backoffMs).toISOString();
        await trustRepository.updateOutboxRecordStatus(
          record.id,
          'RETRY_PENDING',
          `Transaction error: ${txErr.message}`,
          null,
          nextAttempt
        );
        stats.retryPending++;
      }
    }
  }

  if (gateway) {
    fabric.disconnectGateway(gateway);
  }

  return stats;
}

/**
 * Start background worker loop
 */
function startWorker(intervalMs = 5000, batchSize = 10, workerId = 'outbox-worker-1') {
  if (isRunning) return;
  isRunning = true;
  console.log(`[TPSR][OUTBOX] Starting worker ${workerId} (interval: ${intervalMs}ms)`);

  workerInterval = setInterval(async () => {
    try {
      const res = await processOutboxBatch(batchSize, workerId);
      if (res.claimed > 0) {
        console.log(`[TPSR][OUTBOX] Batch summary: claimed=${res.claimed}, completed=${res.completed}, retrying=${res.retryPending}, failed=${res.failedRequiresReview}`);
      }
    } catch (e) {
      console.error('[TPSR][OUTBOX] Unhandled worker loop error:', e);
    }
  }, intervalMs);
}

/**
 * Stop background worker loop
 */
function stopWorker() {
  if (workerInterval) {
    clearInterval(workerInterval);
    workerInterval = null;
  }
  isRunning = false;
  console.log('[TPSR][OUTBOX] Worker stopped.');
}

module.exports = {
  processOutboxBatch,
  startWorker,
  stopWorker,
  isRunning: () => isRunning
};
