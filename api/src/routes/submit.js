'use strict';

var express = require('express');
var router = express.Router();

var fabric = require('../config/fabric');
var sbomRepository = require('../repositories/sbomRepository');
var canonicalize = require('../utils/canonicalize');
var hash = require('../utils/hash');
var policy = require('../utils/policy');

var STRING_FIELDS = [
  'sbomID',
  'buildID',
  'softwareName',
  'softwareVersion',
  'format',
  'offChainRef',
];

var VALID_FORMATS = ['SPDX', 'CycloneDX'];

function validateStringField(body, field) {
  var value = body[field];
  if (value === undefined || value === null) {
    return field + ' is required';
  }
  if (typeof value !== 'string' || value.trim() === '') {
    return field + ' is required';
  }
  return null;
}

function validateSignatures(signatures) {
  if (signatures === undefined || signatures === null) {
    return 'signatures is required';
  }
  if (!Array.isArray(signatures) || signatures.length === 0) {
    return 'signatures must be a non-empty array of non-empty strings';
  }
  for (var i = 0; i < signatures.length; i++) {
    if (typeof signatures[i] !== 'string' || signatures[i].trim() === '') {
      return 'signatures must be a non-empty array of non-empty strings';
    }
  }
  return null;
}

function hrMs(start) {
  return Number(process.hrtime.bigint() - start) / 1e6;
}

router.post('/submit', async function (req, res) {
  var gateway = null;
  var totalStart = process.hrtime.bigint();

  try {
    var body = req.body;

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Request body is required' });
    }

    if (body.sbom === undefined || body.sbom === null || body.sbom === '') {
      return res.status(400).json({ error: 'sbom is required' });
    }

    for (var i = 0; i < STRING_FIELDS.length; i++) {
      var fieldError = validateStringField(body, STRING_FIELDS[i]);
      if (fieldError) {
        return res.status(400).json({ error: fieldError });
      }
    }

    if (VALID_FORMATS.indexOf(body.format.trim()) === -1) {
      return res.status(400).json({ error: 'format must be SPDX or CycloneDX' });
    }

    var sigError = validateSignatures(body.signatures);
    if (sigError) {
      return res.status(400).json({ error: sigError });
    }

    var artifactHash = body.artifactHash;
    if (typeof artifactHash !== 'string' || !/^[a-f0-9]{64}$/.test(artifactHash)) {
      return res.status(400).json({ error: 'artifactHash must be a non-empty 64-character lowercase hex string' });
    }

    var artifactName = body.artifactName;
    if (typeof artifactName !== 'string' || artifactName.trim() === '') {
      return res.status(400).json({ error: 'artifactName must be a non-empty string' });
    }

    var artifactType = body.artifactType;
    var validTypes = ['JAR', 'IMAGE', 'BINARY', 'ARCHIVE', 'OTHER'];
    if (typeof artifactType !== 'string' || validTypes.indexOf(artifactType.trim()) === -1) {
      return res.status(400).json({ error: 'artifactType must be one of: JAR, IMAGE, BINARY, ARCHIVE, OTHER' });
    }

    if (body.sizeBytes !== undefined && body.sizeBytes !== null) {
      if (!Number.isInteger(body.sizeBytes) || body.sizeBytes < 0) {
        return res.status(400).json({ error: 'sizeBytes must be a non-negative integer' });
      }
    }

    var sbomID = body.sbomID.trim();
    var sbom = body.sbom;
    var buildID = body.buildID.trim();
    var softwareName = body.softwareName.trim();
    var softwareVersion = body.softwareVersion.trim();
    var format = body.format.trim();
    var offChainRef = body.offChainRef.trim();
    var signatures = body.signatures.map(function (s) { return s.trim(); });

    // ── Parse SBOM ────────────────────────────────────────────────────────────
    var parseStart = process.hrtime.bigint();
    var parsedSBOMJSON;
    try {
      parsedSBOMJSON = typeof sbom === 'object' ? sbom : JSON.parse(sbom.trim());
    } catch (e) {
      parsedSBOMJSON = { raw: sbom };
    }
    var sbomParseTimeMs = hrMs(parseStart);

    // ── Policy evaluation ─────────────────────────────────────────────────────
    var policyStart = process.hrtime.bigint();
    var policyResult = policy.evaluateSBOM(parsedSBOMJSON);
    var policyEvaluationTimeMs = hrMs(policyStart);

    // ── Canonicalization + Hashing ────────────────────────────────────────────
    var canonicalizedSBOM;
    var sbomHash;

    var canonStart = process.hrtime.bigint();
    try {
      canonicalizedSBOM = canonicalize.canonicalizeSBOM(sbom);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    var canonicalizationTimeMs = hrMs(canonStart);

    var hashStart = process.hrtime.bigint();
    try {
      sbomHash = hash.hashSBOM(canonicalizedSBOM);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    var hashingTimeMs = hrMs(hashStart);

    // ── Database insert ───────────────────────────────────────────────────────
    var dbStart = process.hrtime.bigint();
    var insertedSBOMDoc;
    try {
      insertedSBOMDoc = await sbomRepository.insertSBOMDocument({
        sbomID: sbomID,
        buildID: buildID,
        softwareName: softwareName,
        softwareVersion: softwareVersion,
        format: format,
        status: 'REGISTERED',
        sbomHash: sbomHash,
        sbomJSON: parsedSBOMJSON,
        requestedBy: req.headers['x-user-id'] || null,
        jobName: body.jobName || null,
        buildNumber: buildID,
        gitCommit: body.gitCommit || null,
        gitBranch: body.gitBranch || null,
        repositoryURL: body.repositoryURL || null,
        offChainRef: offChainRef,
        fabricTxID: null,
        signatures: signatures,
        canonicalizationVersion: 'v1',
        policyStatus: policyResult.policy_status,
        policyReason: policyResult.reason,
        policyViolations: policyResult.violations,
        policyEvaluationMode: policyResult.evaluation_mode
      });

      await sbomRepository.insertArtifactRecord({
        sbomDocumentID: insertedSBOMDoc.id,
        artifactType: artifactType.trim(),
        artifactName: artifactName.trim(),
        artifactHash: artifactHash,
        artifactURI: body.artifactURI || null,
        sizeBytes: body.sizeBytes !== undefined && body.sizeBytes !== null ? body.sizeBytes : null
      });
    } catch (dbErr) {
      if (insertedSBOMDoc && insertedSBOMDoc.id) {
        await sbomRepository.deleteSBOMDocumentByID(insertedSBOMDoc.id).catch(function(e) {
          console.error('[TPSR] Failed to rollback SBOM document after artifact insert error:', e.message);
        });
      }
      return res.status(500).json({
        error: 'Failed to persist SBOM to database',
        details: dbErr.message,
      });
    }
    var databaseInsertTimeMs = hrMs(dbStart);

    // ── Fabric submit ─────────────────────────────────────────────────────────
    var fabricStart = process.hrtime.bigint();
    var result = await fabric.getContract();
    gateway = result.gateway;
    var contract = result.contract;

    var fabricTxID;
    try {
      var transaction = contract.createTransaction('SubmitSBOM');
      fabricTxID = transaction.getTransactionId();

      await transaction.submit(
        sbomID,
        sbomHash,
        buildID,
        softwareName,
        softwareVersion,
        format,
        offChainRef,
        JSON.stringify(signatures),
        policyResult.policy_status,
        policyResult.reason,
        JSON.stringify(policyResult.violations),
        policyResult.evaluation_mode
      );
    } catch (fabricErr) {
      await sbomRepository.deleteSBOMDocumentByID(insertedSBOMDoc.id).catch(function(e) {
        console.error('[TPSR] Failed to rollback SBOM document:', e.message);
      });
      throw fabricErr;
    }
    var fabricSubmitTimeMs = hrMs(fabricStart);

    // ── Fetch submitter ID from history ───────────────────────────────────────
    var submitterID = null;
    try {
      var historyBuffer = await contract.evaluateTransaction('GetHistory', sbomID);
      var historyArray = JSON.parse(historyBuffer.toString('utf8'));
      if (Array.isArray(historyArray) && historyArray.length > 0) {
        var latestTx = historyArray[historyArray.length - 1];
        if (latestTx && latestTx.record && latestTx.record.submitterID) {
          submitterID = latestTx.record.submitterID;
        }
      }
    } catch (historyErr) {
      console.error('[TPSR] Failed to fetch or parse history for submitter ID:', historyErr.message);
    }

    await sbomRepository.finalizeSBOMDocument({
      id: insertedSBOMDoc.id,
      fabricTxID: fabricTxID,
      offChainRef: offChainRef,
      submitterID: submitterID,
      status: 'REGISTERED'
    }).catch(function(e) {
      console.error('[TPSR] Failed to finalize SBOM document:', e.message);
    });

    var totalSubmitTimeMs = hrMs(totalStart);

    var performanceMetrics = {
      sbomParseTimeMs: Math.round(sbomParseTimeMs * 100) / 100,
      canonicalizationTimeMs: Math.round(canonicalizationTimeMs * 100) / 100,
      hashingTimeMs: Math.round(hashingTimeMs * 100) / 100,
      policyEvaluationTimeMs: Math.round(policyEvaluationTimeMs * 100) / 100,
      databaseInsertTimeMs: Math.round(databaseInsertTimeMs * 100) / 100,
      fabricSubmitTimeMs: Math.round(fabricSubmitTimeMs * 100) / 100,
      totalSubmitTimeMs: Math.round(totalSubmitTimeMs * 100) / 100
    };

    console.log('[TPSR][PERF] submit', JSON.stringify(performanceMetrics));

    return res.status(201).json({
      message: 'SBOM submitted successfully',
      sbomID: sbomID,
      hash: sbomHash,
      performanceMetrics: performanceMetrics
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to submit SBOM',
      details: err.message,
    });
  } finally {
    fabric.disconnectGateway(gateway);
  }
});

module.exports = router;
