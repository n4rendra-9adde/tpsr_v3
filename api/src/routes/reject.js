'use strict';

var express = require('express');
var router = express.Router();

var fabric = require('../config/fabric');
var sbomRepository = require('../repositories/sbomRepository');

router.post('/reject', async function (req, res) {
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
    var reason = '';
    if (typeof body.reason === 'string' && body.reason.trim() !== '') {
        reason = body.reason.trim();
    }

    var record = await sbomRepository.getSBOMDocumentBySBOMID(sbomID);
    if (!record) {
      return res.status(404).json({ error: 'SBOM record not found' });
    }

    if (record.status === 'SUPERSEDED' || record.status === 'REJECTED') {
      return res.status(409).json({
        error: `Transition denied: Cannot reject SBOM from terminal state ${record.status}`
      });
    }

    var result = await fabric.getContract();
    gateway = result.gateway;
    var contract = result.contract;

    var fabricTxID;
    try {
      var transaction = contract.createTransaction('RejectSBOM');
      fabricTxID = transaction.getTransactionId();
      await transaction.submit(sbomID, reason);
    } catch (fabricErr) {
      return res.status(500).json({
        error: 'Failed to reject SBOM',
        details: fabricErr.message || String(fabricErr)
      });
    }

    await sbomRepository.updateSBOMStatus(sbomID, 'REJECTED', fabricTxID, null);
    if (reason) {
        // Just for local reflection without full schema redesign, we append reason to policy_reason if applicable
        // Or leave it since the chaincode handled the true logic.
    }

    return res.status(200).json({
      message: 'SBOM status updated to REJECTED',
      sbomID: sbomID,
      status: 'REJECTED',
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
