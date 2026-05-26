'use strict';

var express = require('express');
var router = express.Router();

var fabric = require('../config/fabric');
var sbomRepository = require('../repositories/sbomRepository');
var canonicalize = require('../utils/canonicalize');
var hash = require('../utils/hash');
var sbomDiffEngine = require('../utils/sbomDiffEngine');
var policy = require('../utils/policy');

var ELIGIBLE_LIFECYCLE_STATES = ['APPROVED', 'ACTIVE'];

function hrMs(start) {
  return Number(process.hrtime.bigint() - start) / 1e6;
}

router.post('/compliance-report', async function (req, res) {
  var gateway = null;
  var totalStart = process.hrtime.bigint();

  try {
    var body = req.body;

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Request body is required' });
    }

    if (body.sbomID === undefined || body.sbomID === null || typeof body.sbomID !== 'string' || body.sbomID.trim() === '') {
      return res.status(400).json({ error: 'sbomID is required' });
    }

    if (body.sbom === undefined || body.sbom === null) {
      return res.status(400).json({ error: 'sbom is required' });
    }

    var sbomID = body.sbomID.trim();
    var sbom = body.sbom;

    var canonicalizedSBOM;
    var computedHash;

    var canonStart = process.hrtime.bigint();
    try {
      canonicalizedSBOM = canonicalize.canonicalizeSBOM(sbom);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    var canonicalizationTimeMs = hrMs(canonStart);

    var hashStart = process.hrtime.bigint();
    try {
      computedHash = hash.hashSBOM(canonicalizedSBOM);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    var hashingTimeMs = hrMs(hashStart);

    var pgDocument;
    try {
      pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomID);
    } catch (err) {
      return res.status(500).json({
        error: 'Failed to generate compliance report',
        details: err.message,
      });
    }

    if (!pgDocument) {
      return res.status(404).json({ error: 'SBOM record not found' });
    }

    var result = await fabric.getContract();
    gateway = result.gateway;
    var contract = result.contract;

    var fabricVerifyStart = process.hrtime.bigint();
    var verificationBuffer = await contract.evaluateTransaction(
      'VerifyIntegrity',
      sbomID,
      computedHash
    );
    var fabricVerifyTimeMs = hrMs(fabricVerifyStart);

    var fabricHistoryStart = process.hrtime.bigint();
    var historyBuffer = await contract.evaluateTransaction(
      'GetHistory',
      sbomID
    );
    var fabricHistoryQueryTimeMs = hrMs(fabricHistoryStart);

    var verificationResult;
    try {
      verificationResult = JSON.parse(verificationBuffer.toString('utf8'));
      if (!verificationResult || typeof verificationResult !== 'object' || Array.isArray(verificationResult)) {
        throw new Error('verification is not a valid object');
      }
    } catch (e) {
      return res.status(500).json({ error: 'Failed to parse verification response' });
    }

    var historyArray;
    try {
      historyArray = JSON.parse(historyBuffer.toString('utf8'));
      if (!Array.isArray(historyArray)) {
        throw new Error('history is not an array');
      }
    } catch (e) {
      return res.status(500).json({ error: 'Failed to parse SBOM history response' });
    }

    var historyLen = historyArray.length;
    var latestTx = null;
    if (historyLen > 0) {
      for (var i = 0; i < historyLen; i++) {
        var current = historyArray[i];
        if (current) {
          if (!latestTx) {
            latestTx = current;
          } else {
            var currentTs = current.timestamp || 0;
            var latestTs = latestTx.timestamp || 0;
            if (currentTs > latestTs) {
              latestTx = current;
            }
          }
        }
      }
    }

    var complianceEvalStart = process.hrtime.bigint();

    var policyStatus = pgDocument.policy_status;
    var policyReason = pgDocument.policy_reason;
    var policyViolations = pgDocument.policy_violations;

    if (!policyStatus) {
      var policyResult = policy.evaluateSBOM(pgDocument.sbom_json);
      policyStatus = policyResult.policy_status;
      policyReason = policyResult.reason;
      policyViolations = policyResult.violations;
    }

    // ── Diff analysis when integrity fails ────────────────────────────────────
    var integrityMatch = verificationResult.match;
    var tamperDetails = null;
    var affectedComponents = [];
    var changedFields = [];
    var integrityFailureReason = null;
    var tamperSummary = null;

    if (integrityMatch === false) {
      var parsedSubmittedSbom;
      try {
        parsedSubmittedSbom = typeof sbom === 'object' ? sbom : JSON.parse(sbom.trim());
      } catch (e) {
        parsedSubmittedSbom = {};
      }

      var diffResult = sbomDiffEngine.analyzeTampering(pgDocument.sbom_json, parsedSubmittedSbom);
      affectedComponents = diffResult.affectedComponents || [];
      changedFields = diffResult.changedFields || [];
      integrityFailureReason = diffResult.integrityFailureReason || null;
      tamperSummary = diffResult.tamperReport ? diffResult.tamperReport.summary : null;
      tamperDetails = {
        tamperType: diffResult.tamperType,
        allClassifications: diffResult.tamperReport ? diffResult.tamperReport.allClassifications : [],
        affectedComponents: affectedComponents,
        changedFields: changedFields
      };
    }

    // ── Non-compliance reasons ─────────────────────────────────────────────
    var lifecycleState = pgDocument.status;
    var lifecycleEligible = ELIGIBLE_LIFECYCLE_STATES.indexOf(verificationResult.status || lifecycleState) !== -1;

    var nonComplianceReasons = [];
    var integrityFailMsg = null;
    var policyFailureReason = null;
    var lifecycleFailureReason = null;

    if (integrityMatch === false) {
      integrityFailMsg = integrityFailureReason ||
        'Submitted SBOM hash does not match the immutable ledger-anchored hash.';
      nonComplianceReasons.push('INTEGRITY_FAILURE');
    }

    if (tamperDetails && tamperDetails.affectedComponents.length > 0) {
      nonComplianceReasons.push('TAMPERING_DETECTED');
    }

    if (policyStatus === 'FAIL') {
      policyFailureReason = policyReason || 'Policy evaluation failed.';
      nonComplianceReasons.push('POLICY_FAILURE');
    }

    if (!lifecycleEligible) {
      lifecycleFailureReason =
        'SBOM lifecycle state "' + (verificationResult.status || lifecycleState) +
        '" is not eligible for compliance. Eligible states: ' + ELIGIBLE_LIFECYCLE_STATES.join(', ') + '.';
      nonComplianceReasons.push('LIFECYCLE_NOT_ELIGIBLE');
    }

    var compliant =
      integrityMatch === true &&
      lifecycleEligible &&
      policyStatus === 'PASS';

    var complianceReport = {
      sbomID: sbomID,
      computedHash: computedHash,
      storedHash: verificationResult.storedHash || pgDocument.sbom_hash,
      integrityMatch: integrityMatch,
      ledgerStatus: verificationResult.status,
      historyCount: historyLen,
      latestTxID: latestTx ? latestTx.txID : null,
      latestTimestamp: latestTx ? latestTx.timestamp : null,
      latestIsDelete: latestTx ? latestTx.isDelete : false,
      policyStatus: policyStatus || 'UNKNOWN',
      policyReason: policyReason || null,
      policyViolations: policyViolations || [],
      lifecycleState: lifecycleState,
      compliant: compliant,
      // ── Non-compliance explanation fields ──────────────────────────────────
      nonComplianceReasons: nonComplianceReasons,
      integrityFailureReason: integrityFailMsg,
      policyFailureReason: policyFailureReason,
      lifecycleFailureReason: lifecycleFailureReason,
      tamperSummary: tamperSummary,
      tamperDetails: tamperDetails,
      affectedComponents: affectedComponents,
      changedFields: changedFields
    };
    
    var complianceEvaluationTimeMs = hrMs(complianceEvalStart);

    var dbInsertStart = process.hrtime.bigint();

    try {
      await sbomRepository.insertComplianceReport({
        sbomDocumentID: pgDocument.id,
        integrityMatch: complianceReport.integrityMatch,
        ledgerStatus: complianceReport.ledgerStatus,
        historyCount: complianceReport.historyCount || 0,
        latestTxID: complianceReport.latestTxID || null,
        latestTimestamp: complianceReport.latestTimestamp || null,
        latestIsDelete: complianceReport.latestIsDelete || false,
        compliant: complianceReport.compliant,
        generatedBy: req.headers['x-user-id'] || 'anonymous'
      });
    } catch (dbErr) {
      console.error('[TPSR] Failed to insert compliance report:', dbErr.message);
    }
    var databaseInsertTimeMs = hrMs(dbInsertStart);
    
    var totalComplianceTimeMs = hrMs(totalStart);

    var performanceMetrics = {
      canonicalizationTimeMs: Math.round(canonicalizationTimeMs * 100) / 100,
      hashingTimeMs: Math.round(hashingTimeMs * 100) / 100,
      fabricVerifyTimeMs: Math.round(fabricVerifyTimeMs * 100) / 100,
      fabricHistoryQueryTimeMs: Math.round(fabricHistoryQueryTimeMs * 100) / 100,
      complianceEvaluationTimeMs: Math.round(complianceEvaluationTimeMs * 100) / 100,
      databaseInsertTimeMs: Math.round(databaseInsertTimeMs * 100) / 100,
      totalComplianceTimeMs: Math.round(totalComplianceTimeMs * 100) / 100
    };

    console.log('[TPSR][PERF] compliance', JSON.stringify(performanceMetrics));

    return res.status(200).json({
      message: 'Compliance report generated successfully',
      report: complianceReport,
      performanceMetrics: performanceMetrics
    });

  } catch (err) {
    if (err.message && err.message.indexOf('not found') !== -1) {
      return res.status(404).json({ error: err.message });
    }
    return res.status(500).json({
      error: 'Failed to generate compliance report',
      details: err.message,
    });
  } finally {
    if (gateway) {
      fabric.disconnectGateway(gateway);
    }
  }
});

module.exports = router;
