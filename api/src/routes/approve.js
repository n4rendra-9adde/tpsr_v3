'use strict';

var express = require('express');
var router = express.Router();

var fabric = require('../config/fabric');
var sbomRepository = require('../repositories/sbomRepository');
var trustRepository = require('../repositories/trustRepository');
var policy = require('../utils/policy');

router.post('/approve', async function (req, res) {
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

    var policyStatus = record.policy_status;
    var policyReason = record.policy_reason;

    // Handle legacy rows missing policy fields
    if (!policyStatus) {
      var policyResult = policy.evaluateSBOM(record.sbom_json);
      policyStatus = policyResult.policy_status;
      policyReason = policyResult.reason;
    }

    if (record.status !== 'COMPLIANT') {
      return res.status(409).json({
        error: `Approval denied: SBOM must be in COMPLIANT state. Current state is ${record.status}`
      });
    }

    if (policyStatus === 'FAIL') {
      return res.status(409).json({
        error: 'Approval denied: Automated compliance policy blocked transition.',
        details: policyReason
      });
    }

    var trustDecision = await trustRepository.getLatestTrustDecisionBySBOMID(sbomID);
    if (trustDecision) {
      // normalizeTrustStatus maps historical UNTRUSTED → REJECTED for read compatibility
      var normalizedStatus = trustRepository.normalizeTrustStatus(trustDecision.trust_status);

      if (normalizedStatus === 'REJECTED') {
        return res.status(409).json({
          error: 'Approval denied: Lifecycle transition blocked — SBOM trust decision is REJECTED. Remediate all blocking violations before approval.',
          trustStatus: 'REJECTED',
          reasonCode: trustDecision.reason_code,
          reasonDescription: trustDecision.reason_description
        });
      }

      if (normalizedStatus === 'REVIEW_REQUIRED') {
        return res.status(409).json({
          error: 'Approval denied: Lifecycle transition blocked — SBOM trust decision is REVIEW_REQUIRED. Complete the manual review workflow before approval.',
          trustStatus: 'REVIEW_REQUIRED',
          reasonCode: trustDecision.reason_code,
          reasonDescription: trustDecision.reason_description
        });
      }

      // CONDITIONALLY_ACCEPTED: blocked in Group 1.
      // Conditional approval requires anchored exception evidence verification on the Fabric
      // ledger, which is not yet implemented (pending Fabric governance remediation group).
      // Remediate the underlying policy violation to advance to TRUSTED, or await the remediation.
      if (normalizedStatus === 'CONDITIONALLY_ACCEPTED') {
        return res.status(409).json({
          error: 'Approval denied: Lifecycle transition blocked — SBOM trust decision is CONDITIONALLY_ACCEPTED. ' +
            'Conditional lifecycle advancement requires anchored exception evidence on the Fabric ledger, ' +
            'which is not yet implemented. Remediate the underlying policy violation to advance to TRUSTED.',
          trustStatus: 'CONDITIONALLY_ACCEPTED',
          reasonCode: trustDecision.reason_code,
          reasonDescription: trustDecision.reason_description,
          blockedUntil: 'Fabric governance remediation (conditional exception anchoring)'
        });
      }

      // Only TRUSTED is permitted to advance at this time.
    }

    var result = await fabric.getContract();
    gateway = result.gateway;
    var contract = result.contract;

    var fabricTxID;
    try {
      var transaction = contract.createTransaction('ApproveSBOM');
      fabricTxID = transaction.getTransactionId();

      await transaction.submit(sbomID);
    } catch (fabricErr) {
      return res.status(500).json({
        error: 'Failed to approve SBOM',
        details: fabricErr.message || String(fabricErr)
      });
    }

    var approverSubmitterID = null;
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
          approverSubmitterID = latestEntry.record.submitterID;
        }
      }
    } catch (historyErr) {
      console.error('[TPSR] Failed to fetch history for approver identity after approval:', historyErr.message);
    }

    await sbomRepository.updateSBOMStatus(sbomID, 'APPROVED', fabricTxID, approverSubmitterID);

    return res.status(200).json({
      message: 'SBOM approved successfully',
      sbomID: sbomID,
      status: 'APPROVED',
      fabricTxID: fabricTxID
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to approve SBOM',
      details: err.message || String(err)
    });
  } finally {
    fabric.disconnectGateway(gateway);
  }
});

module.exports = router;
