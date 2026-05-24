'use strict';

var express = require('express');
var router = express.Router();

var fabric = require('../config/fabric');
var sbomRepository = require('../repositories/sbomRepository');

router.post('/supersede', async function (req, res) {
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

    var result = await fabric.getContract();
    gateway = result.gateway;
    var contract = result.contract;

    var fabricTxID;
    try {
      var transaction = contract.createTransaction('SupersedeSBOM');
      fabricTxID = transaction.getTransactionId();

      await transaction.submit(sbomID);
    } catch (fabricErr) {
      return res.status(500).json({
        error: 'Failed to supersede SBOM',
        details: fabricErr.message || String(fabricErr)
      });
    }

    var supersederSubmitterID = null;
    try {
      var historyBuffer = await contract.evaluateTransaction('GetHistory', sbomID);
      var historyArray = JSON.parse(historyBuffer.toString('utf8'));
      if (Array.isArray(historyArray) && historyArray.length > 0) {
        var latestEntry = null;
        for (var i = 0; i < historyArray.length; i++) {
          var current = historyArray[i];
          if (current) {
            if (!latestEntry) {
              latestEntry = current;
            } else {
              var currentTs = current.timestamp || 0;
              var latestTs = latestEntry.timestamp || 0;
              if (currentTs > latestTs) {
                latestEntry = current;
              }
            }
          }
        }
        if (latestEntry && latestEntry.record && latestEntry.record.submitterID) {
          supersederSubmitterID = latestEntry.record.submitterID;
        }
      }
    } catch (historyErr) {
      console.error('[TPSR] Failed to fetch history for superseder identity after superseding:', historyErr.message);
    }

    await sbomRepository.updateSBOMStatus(sbomID, 'SUPERSEDED', fabricTxID, supersederSubmitterID);

    return res.status(200).json({
      message: 'SBOM superseded successfully',
      sbomID: sbomID,
      status: 'SUPERSEDED',
      fabricTxID: fabricTxID
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to supersede SBOM',
      details: err.message || String(err)
    });
  } finally {
    fabric.disconnectGateway(gateway);
  }
});

module.exports = router;
