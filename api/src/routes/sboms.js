'use strict';

var express = require('express');
var router = express.Router();

var sbomRepository = require('../repositories/sbomRepository');
var trustRepository = require('../repositories/trustRepository');

router.get('/sboms', async function (req, res) {
  try {
    var limit = req.query.limit;
    
    var sboms = await sbomRepository.listSBOMDocuments(limit);
    var enriched = await Promise.all(sboms.map(async function (item) {
      var decision = await trustRepository.getLatestTrustDecisionBySBOMID(item.sbom_id);
      var normalized = trustRepository.normalizeTrustStatus(decision ? decision.trust_status : null);
      
      var outboxRecords = await trustRepository.getOutboxRecordsBySBOMID(item.sbom_id);
      var latestOutbox = outboxRecords.length > 0 ? outboxRecords[0] : null;
      var anchorStatus = 'UNANCHORED';
      if (latestOutbox) {
        if (['PENDING', 'RETRY_PENDING', 'PROCESSING'].includes(latestOutbox.status)) anchorStatus = 'PENDING_ANCHOR';
        else if (latestOutbox.status === 'COMPLETED') anchorStatus = 'ANCHORED';
        else if (latestOutbox.status === 'FAILED_REQUIRES_REVIEW') anchorStatus = 'ANCHOR_FAILED';
      }

      var result = Object.assign({}, item, {
        trustStatus: normalized.trustDecision,
        trustReasonCode: decision ? decision.reason_code : 'GOV-002',
        trustReasonDescription: decision ? decision.reason_description : 'v3 trust evaluation not yet executed',
        ledgerAnchorStatus: anchorStatus
      });
      if (normalized.legacyNormalized) {
        result.legacyNormalized = true;
      }
      return result;
    }));

    return res.status(200).json({
      message: 'SBOM list retrieved successfully',
      count: enriched.length,
      sboms: enriched
    });
  } catch (error) {
    return res.status(500).json({
      error: 'Failed to retrieve SBOM list',
      details: error.message || String(error)
    });
  }
});
router.get('/sboms/:sbomID/document', async function (req, res) {
  try {
    var sbomID = (req.params.sbomID || '').trim();
    if (!sbomID) {
      return res.status(400).json({ error: 'sbomID is required' });
    }

    var record = await sbomRepository.getSBOMDocumentBySBOMID(sbomID);
    if (!record) {
      return res.status(404).json({ error: 'SBOM record not found' });
    }

    if (req.query.download === 'true') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="' + sbomID + '.json"');
      return res.send(JSON.stringify(record.sbom_json, null, 2));
    }

    var decision = await trustRepository.getLatestTrustDecisionBySBOMID(sbomID);
    var normalized = trustRepository.normalizeTrustStatus(decision ? decision.trust_status : null);

    var outboxRecords = await trustRepository.getOutboxRecordsBySBOMID(sbomID);
    var latestOutbox = outboxRecords.length > 0 ? outboxRecords[0] : null;
    var anchorStatus = 'UNANCHORED';
    if (latestOutbox) {
      if (['PENDING', 'RETRY_PENDING', 'PROCESSING'].includes(latestOutbox.status)) anchorStatus = 'PENDING_ANCHOR';
      else if (latestOutbox.status === 'COMPLETED') anchorStatus = 'ANCHORED';
      else if (latestOutbox.status === 'FAILED_REQUIRES_REVIEW') anchorStatus = 'ANCHOR_FAILED';
    }

    var responsePayload = {
      message: 'SBOM document retrieved successfully',
      sbomID: record.sbom_id,
      format: record.format,
      sbomHash: record.sbom_hash,
      fabricTxID: record.fabric_tx_id,
      submitterID: record.submitter_id,
      recordedBy: record.requested_by || record.submitter_id || null,
      anchoredAt: record.created_at || null,
      offChainRef: record.off_chain_ref || null,
      fabricChannel: record.fabric_channel || null,
      lifecycleState: record.status || null,
      policyStatus: record.policy_status,
      policyReason: record.policy_reason,
      policyViolations: record.policy_violations,
      trustStatus: normalized.trustDecision,
      trustReasonCode: decision ? decision.reason_code : 'GOV-002',
      trustReasonDescription: decision ? decision.reason_description : 'v3 trust evaluation not yet executed',
      ledgerAnchorStatus: anchorStatus,
      sbom: record.sbom_json
    };

    if (normalized.legacyNormalized) {
      responsePayload.legacyNormalized = true;
      responsePayload.legacyDecision = normalized.legacyDecision;
    }

    return res.status(200).json(responsePayload);
  } catch (error) {
    return res.status(500).json({
      error: 'Failed to retrieve SBOM document',
      details: error.message || String(error)
    });
  }
});

module.exports = router;
