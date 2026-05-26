'use strict';

var express = require('express');
var router = express.Router();

var fabric = require('../config/fabric');
var sbomRepository = require('../repositories/sbomRepository');

router.post('/review-pending', async function (req, res) {
  var gateway = null;

  try {
    var body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'sbomID is required' });
    }

    if (typeof body.sbomID !== 'string' || body.sbomID.trim() === '') {
      return res.status(400).json({ error: 'sbomID is required' });
    }

    var sbomID = body.sbomID.trim();

    var record = await sbomRepository.getSBOMDocumentBySBOMID(sbomID);
    if (!record) {
      return res.status(404).json({ error: 'SBOM record not found' });
    }

    if (record.status !== 'REGISTERED') {
      return res.status(409).json({
        error: `Transition denied: SBOM must be in REGISTERED state. Current state is ${record.status}`
      });
    }

    var result = await fabric.getContract();
    gateway = result.gateway;
    var contract = result.contract;

    var fabricTxID;
    try {
      var transaction = contract.createTransaction('MoveToReviewPending');
      fabricTxID = transaction.getTransactionId();
      await transaction.submit(sbomID);
    } catch (fabricErr) {
      return res.status(500).json({
        error: 'Failed to transition to REVIEW_PENDING',
        details: fabricErr.message || String(fabricErr)
      });
    }

    await sbomRepository.updateSBOMStatus(sbomID, 'REVIEW_PENDING', fabricTxID, null);

    return res.status(200).json({
      message: 'SBOM status updated to REVIEW_PENDING',
      sbomID: sbomID,
      status: 'REVIEW_PENDING',
      fabricTxID: fabricTxID
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to process request',
      details: err.message || String(err)
    });
  } finally {
    if (gateway) fabric.disconnectGateway(gateway);
  }
});

module.exports = router;
