'use strict';

const express = require('express');
const router = express.Router();
const trustRepository = require('../repositories/trustRepository');

/**
 * Handle administrative requeue of failed outbox records
 */
async function handleRequeueOutbox(req, res) {
  const outboxId = req.params.outboxId || req.params.id;
  if (!outboxId || !outboxId.trim()) {
    return res.status(400).json({ error: 'outboxId parameter is required' });
  }

  try {
    const record = await trustRepository.getOutboxRecordByID(outboxId.trim());
    if (!record) {
      return res.status(404).json({ error: `Outbox record not found for ID: ${outboxId}` });
    }

    if (record.status !== 'FAILED_REQUIRES_REVIEW' && record.status !== 'RETRY_PENDING') {
      return res.status(400).json({
        error: `Cannot requeue outbox record in state: ${record.status}. Only FAILED_REQUIRES_REVIEW or RETRY_PENDING records can be requeued.`
      });
    }

    const updated = await trustRepository.updateOutboxRecordStatus(
      record.id,
      'PENDING',
      null,
      null,
      new Date().toISOString()
    );

    return res.status(200).json({
      message: 'Outbox record requeued successfully for immediate background processing',
      outboxId: updated.id,
      sbomId: updated.sbom_id,
      status: updated.status,
      nextAttemptAt: updated.next_attempt_at,
      requeuedBy: req.headers['x-user-id'] || 'admin'
    });
  } catch (err) {
    console.error('[TPSR] Error requeuing outbox record:', err);
    return res.status(500).json({ error: 'Failed to requeue outbox record', details: err.message });
  }
}

/**
 * Handle retrieving outbox records for an SBOM
 */
async function handleGetOutboxBySbom(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  try {
    const records = await trustRepository.getOutboxRecordsBySBOMID(sbomId.trim());
    return res.status(200).json({
      sbomId: sbomId.trim(),
      count: records.length,
      outboxRecords: records
    });
  } catch (err) {
    console.error('[TPSR] Error fetching outbox records:', err);
    return res.status(500).json({ error: 'Failed to retrieve outbox records', details: err.message });
  }
}

router.post('/v1/admin/outbox/:outboxId/requeue', handleRequeueOutbox);
router.post('/admin/outbox/:outboxId/requeue', handleRequeueOutbox);
router.get('/v1/admin/outbox/:sbomId', handleGetOutboxBySbom);
router.get('/admin/outbox/:sbomId', handleGetOutboxBySbom);

module.exports = router;
