'use strict';
const express = require('express');
const router = express.Router();
const snapshotRepo = require('../repositories/snapshot.repository');
const replayService = require('../services/replayService');

async function handleVerifyReplay(req, res) {
  const snapshotId = req.params.snapshotId;
  try {
    const snapshot = await snapshotRepo.getSnapshot(snapshotId);
    if (!snapshot) {
      return res.status(404).json({ error: 'Snapshot not found' });
    }

    const result = await replayService.verifyDecisionReplay(snapshotId);

    if (result.status === 'EXACT_MATCH') {
      return res.status(200).json({ status: 'EXACT_MATCH', message: 'Decision replay successfully verified' });
    } else {
      return res.status(409).json({ status: 'DIVERGENCE_DETECTED', reasons: result.reasons });
    }
  } catch (err) {
    return res.status(500).json({ error: 'Failed to verify replay', details: err.message });
  }
}

router.post('/v1/replay/:snapshotId/verify', handleVerifyReplay);

module.exports = router;
