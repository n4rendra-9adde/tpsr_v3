'use strict';

var express = require('express');
var router = express.Router();

var fabric = require('../config/fabric');
var sbomRepository = require('../repositories/sbomRepository');
var canonicalize = require('../utils/canonicalize');
var hash = require('../utils/hash');
var sbomDiffEngine = require('../utils/sbomDiffEngine');
var policy = require('../utils/policy');

function hrMs(start) {
  return Number(process.hrtime.bigint() - start) / 1e6;
}

router.post('/verify', async function (req, res) {
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

    // ── Canonicalization ──────────────────────────────────────────────────────
    var canonStart = process.hrtime.bigint();
    var canonicalizedSBOM;
    var submittedHash;
    try {
      canonicalizedSBOM = canonicalize.canonicalizeSBOM(sbom);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    var canonicalizationTimeMs = hrMs(canonStart);

    // ── Hashing ───────────────────────────────────────────────────────────────
    var hashStart = process.hrtime.bigint();
    try {
      submittedHash = hash.hashSBOM(canonicalizedSBOM);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    var hashingTimeMs = hrMs(hashStart);

    // ── DB lookup ─────────────────────────────────────────────────────────────
    var pgDocument;
    try {
      pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomID);
    } catch (err) {
      return res.status(500).json({
        error: 'Failed to verify SBOM',
        details: err.message,
      });
    }

    if (!pgDocument) {
      return res.status(404).json({ error: 'SBOM record not found' });
    }

    var result = await fabric.getContract();
    gateway = result.gateway;
    var contract = result.contract;

    // ── Fabric verify ─────────────────────────────────────────────────────────
    var fabricVerifyStart = process.hrtime.bigint();
    var resultBuffer = await contract.evaluateTransaction(
      'VerifyIntegrity',
      sbomID,
      submittedHash
    );
    var fabricVerifyTimeMs = hrMs(fabricVerifyStart);

    var resultString = resultBuffer.toString('utf8');
    var verificationResult = JSON.parse(resultString);

    var tamperDetected = false;
    var tamperType = null;
    var affectedComponents = [];
    var changedFields = [];
    var tamperReport = null;
    var integrityFailureReason = null;
    var tamperAnalysisTimeMs = 0;
    var policyEvaluationTimeMs = 0;
    var submittedPolicySnapshot = null;

    if (verificationResult.match === false) {
      var originalSbom = pgDocument.sbom_json;

      var parsedSubmittedSbom;
      try {
        parsedSubmittedSbom = typeof sbom === 'object' ? sbom : JSON.parse(sbom.trim());
      } catch (e) {
        parsedSubmittedSbom = {};
      }

      // ── Tamper analysis ───────────────────────────────────────────────────
      var tamperStart = process.hrtime.bigint();
      var diffResult = sbomDiffEngine.analyzeTampering(originalSbom, parsedSubmittedSbom);
      tamperAnalysisTimeMs = hrMs(tamperStart);

      tamperDetected = diffResult.tamperDetected;
      tamperType = diffResult.tamperType;
      affectedComponents = diffResult.affectedComponents;
      changedFields = diffResult.changedFields || [];
      integrityFailureReason = diffResult.integrityFailureReason || null;
      tamperReport = diffResult.tamperReport;

      // ── Policy on submitted SBOM ──────────────────────────────────────────
      var policyStart = process.hrtime.bigint();
      var policyResult = policy.evaluateSBOM(parsedSubmittedSbom);
      policyEvaluationTimeMs = hrMs(policyStart);

      var policyTamperNote = null;
      if (policyResult.policy_status === 'FAIL' && affectedComponents.length > 0) {
        policyTamperNote =
          'The submitted SBOM both fails integrity check and fails policy validation. ' +
          'Tampered components may include versions that violate minimum safe version requirements.';
      }

      submittedPolicySnapshot = {
        policyStatus: policyResult.policy_status,
        policyReason: policyResult.reason,
        policyViolations: policyResult.violations,
        policyEvaluationMode: policyResult.evaluation_mode,
        policyTamperNote: policyTamperNote
      };

      if (tamperReport) {
        tamperReport.submittedPolicySnapshot = submittedPolicySnapshot;
      }

      verificationResult.tamperDetected = tamperDetected;
      verificationResult.tamperType = tamperType;
      verificationResult.integrityFailureReason = integrityFailureReason;
      verificationResult.affectedComponents = affectedComponents;
      verificationResult.changedFields = changedFields;
      verificationResult.tamperReport = tamperReport;
      verificationResult.submittedPolicySnapshot = submittedPolicySnapshot;
    }

    // ── Audit DB insert ───────────────────────────────────────────────────────
    var dbAuditStart = process.hrtime.bigint();
    try {
      await sbomRepository.insertVerificationEvent({
        sbomDocumentID: pgDocument.id,
        submittedHash: submittedHash,
        storedHash: verificationResult.storedHash || pgDocument.sbom_hash,
        match: verificationResult.match,
        verifiedBy: req.headers['x-user-id'] || 'anonymous',
        verifierRole: req.headers['x-user-role'] || 'unknown',
        verificationMode: 'API',
        fabricTxID: null,
        tamperDetected: tamperDetected,
        tamperType: tamperType,
        affectedComponents: affectedComponents,
        tamperReport: tamperReport
      });
    } catch (dbErr) {
      console.error('[TPSR] Failed to insert verification event:', dbErr.message);
    }
    var databaseAuditInsertTimeMs = hrMs(dbAuditStart);

    var totalVerifyTimeMs = hrMs(totalStart);

    var performanceMetrics = {
      canonicalizationTimeMs: Math.round(canonicalizationTimeMs * 100) / 100,
      hashingTimeMs: Math.round(hashingTimeMs * 100) / 100,
      fabricVerifyTimeMs: Math.round(fabricVerifyTimeMs * 100) / 100,
      tamperAnalysisTimeMs: Math.round(tamperAnalysisTimeMs * 100) / 100,
      policyEvaluationTimeMs: Math.round(policyEvaluationTimeMs * 100) / 100,
      databaseAuditInsertTimeMs: Math.round(databaseAuditInsertTimeMs * 100) / 100,
      totalVerifyTimeMs: Math.round(totalVerifyTimeMs * 100) / 100
    };

    console.log('[TPSR][PERF] verify', JSON.stringify(performanceMetrics));

    return res.status(200).json({
      message: 'SBOM verification completed',
      verification: verificationResult,
      performanceMetrics: performanceMetrics
    });
  } catch (err) {
    if (err.message && err.message.indexOf('not found') !== -1) {
      return res.status(404).json({ error: err.message });
    }
    return res.status(500).json({
      error: 'Failed to verify SBOM',
      details: err.message,
    });
  } finally {
    fabric.disconnectGateway(gateway);
  }
});

module.exports = router;
