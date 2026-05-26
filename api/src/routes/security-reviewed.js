'use strict';

var express = require('express');
var router = express.Router();

var fabric = require('../config/fabric');
var sbomRepository = require('../repositories/sbomRepository');
var canonicalize = require('../utils/canonicalize');
var hash = require('../utils/hash');

function hrMs(start) {
  return Number(process.hrtime.bigint() - start) / 1e6;
}

router.post('/security-reviewed', async function (req, res) {
  var gateway = null;
  var totalStart = process.hrtime.bigint();

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

    if (record.status !== 'REVIEW_PENDING') {
      return res.status(409).json({
        error: `Transition denied: SBOM must be in REVIEW_PENDING state. Current state is ${record.status}`
      });
    }

    var result = await fabric.getContract();
    gateway = result.gateway;
    var contract = result.contract;

    var fabricTxID;
    var fabricMoveStart = process.hrtime.bigint();
    try {
      var transaction = contract.createTransaction('MoveToSecurityReviewed');
      fabricTxID = transaction.getTransactionId();
      await transaction.submit(sbomID);
    } catch (fabricErr) {
      return res.status(500).json({
        error: 'Failed to transition to SECURITY_REVIEWED',
        details: fabricErr.message || String(fabricErr)
      });
    }
    var fabricMoveToSecurityReviewedTimeMs = hrMs(fabricMoveStart);

    // Step 1: Update to SECURITY_REVIEWED
    await sbomRepository.updateSBOMStatus(sbomID, 'SECURITY_REVIEWED', fabricTxID, null);

    // Step 2: Automatic Compliance Evaluation
    var compliancePassed = false;
    var severeFailureReason = null;
    var computedHash;
    
    var integrityEvalStart = process.hrtime.bigint();

    try {
      var canonicalizedSBOM = canonicalize.canonicalizeSBOM(record.sbom_json);
      computedHash = hash.hashSBOM(canonicalizedSBOM);

      var resultBuffer = await contract.evaluateTransaction('VerifyIntegrity', sbomID, computedHash);
      var verificationResult = JSON.parse(resultBuffer.toString('utf8'));
      var integrityEvaluationTimeMs = hrMs(integrityEvalStart);

      var policyEvalStart = process.hrtime.bigint();
      if (verificationResult.match === false) {
        severeFailureReason = 'Integrity check failed: Computed hash does not match ledger-anchored hash';
      } else {
        var policyStatus = record.policy_status;
        if (!policyStatus) {
            var policyResult = require('../utils/policy').evaluateSBOM(record.sbom_json);
            policyStatus = policyResult.policy_status;
        }

        if (policyStatus === 'PASS') {
          compliancePassed = true;
        } else {
          // Note: The system currently treats any policy FAIL at SECURITY_REVIEWED 
          // as a rejection-worthy severe governance failure.
          severeFailureReason = 'Policy check failed: Vulnerabilities detected';
        }
      }
      var policyEvaluationTimeMs = hrMs(policyEvalStart);
    } catch (err) {
      severeFailureReason = 'Internal error during compliance check: ' + err.message;
    }

    // Step 3: Trigger appropriate system-level next transition
    var autoTransitionStart = process.hrtime.bigint();
    var finalStatus = 'SECURITY_REVIEWED';
    var finalMessage = 'SBOM status updated to SECURITY_REVIEWED';

    if (compliancePassed) {
      try {
        var compliantTx = contract.createTransaction('MarkCompliant');
        var compliantTxID = compliantTx.getTransactionId();
        await compliantTx.submit(sbomID);
        await sbomRepository.updateSBOMStatus(sbomID, 'COMPLIANT', compliantTxID, null);
        finalStatus = 'COMPLIANT';
        finalMessage = 'SBOM status updated to SECURITY_REVIEWED and automatically advanced to COMPLIANT';
      } catch (e) {
        console.error('[TPSR] Automatic MarkCompliant transition failed:', e.message);
      }
    } else if (severeFailureReason) {
      try {
        var rejectTx = contract.createTransaction('RejectSBOM');
        var rejectTxID = rejectTx.getTransactionId();
        await rejectTx.submit(sbomID, severeFailureReason);
        await sbomRepository.updateSBOMStatus(sbomID, 'REJECTED', rejectTxID, null);
        finalStatus = 'REJECTED';
        finalMessage = 'SBOM automatically REJECTED due to severe failure: ' + severeFailureReason;
      } catch (e) {
        console.error('[TPSR] Automatic RejectSBOM transition failed:', e.message);
      }
    }
    
    var autoTransitionTimeMs = hrMs(autoTransitionStart);
    var totalSecurityReviewedTimeMs = hrMs(totalStart);

    var performanceMetrics = {
      fabricMoveToSecurityReviewedTimeMs: Math.round(fabricMoveToSecurityReviewedTimeMs * 100) / 100,
      integrityEvaluationTimeMs: typeof integrityEvaluationTimeMs !== 'undefined' ? Math.round(integrityEvaluationTimeMs * 100) / 100 : null,
      policyEvaluationTimeMs: typeof policyEvaluationTimeMs !== 'undefined' ? Math.round(policyEvaluationTimeMs * 100) / 100 : null,
      autoTransitionTimeMs: Math.round(autoTransitionTimeMs * 100) / 100,
      totalSecurityReviewedTimeMs: Math.round(totalSecurityReviewedTimeMs * 100) / 100
    };

    console.log('[TPSR][PERF] security-reviewed', JSON.stringify(performanceMetrics));

    return res.status(200).json({
      message: finalMessage,
      sbomID: sbomID,
      status: finalStatus,
      initialTxID: fabricTxID,
      performanceMetrics: performanceMetrics
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
