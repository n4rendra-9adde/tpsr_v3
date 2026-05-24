'use strict';

var express = require('express');
var router = express.Router();

var fabric = require('../config/fabric');
var sbomRepository = require('../repositories/sbomRepository');

router.post('/activate', async function (req, res) {
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
      var transaction = contract.createTransaction('ActivateSBOM');
      fabricTxID = transaction.getTransactionId();

      await transaction.submit(sbomID);
    } catch (fabricErr) {
      return res.status(500).json({
        error: 'Failed to activate SBOM',
        details: fabricErr.message || String(fabricErr)
      });
    }

    var activatorSubmitterID = null;
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
          activatorSubmitterID = latestEntry.record.submitterID;
        }
      }
    } catch (historyErr) {
      console.error('[TPSR] Failed to fetch history for activator identity after activation:', historyErr.message);
    }

    await sbomRepository.updateSBOMStatus(sbomID, 'ACTIVE', fabricTxID, activatorSubmitterID);

    return res.status(200).json({
      message: 'SBOM activated successfully',
      sbomID: sbomID,
      status: 'ACTIVE',
      fabricTxID: fabricTxID
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to activate SBOM',
      details: err.message || String(err)
    });
  } finally {
    fabric.disconnectGateway(gateway);
  }
});

module.exports = router;
