'use strict';

var express = require('express');
var router = express.Router();

var fabric = require('../config/fabric');
var sbomRepository = require('../repositories/sbomRepository');

router.get('/history/:sbomID', async function (req, res) {
  var gateway = null;

  try {
    var sbomIDParam = req.params.sbomID;

    if (sbomIDParam === undefined || sbomIDParam === null || typeof sbomIDParam !== 'string' || sbomIDParam.trim() === '') {
      return res.status(400).json({ error: 'sbomID is required' });
    }

    var sbomID = sbomIDParam.trim();

    var pgResult;
    try {
      pgResult = await sbomRepository.getSBOMDocumentWithArtifactsBySBOMID(sbomID);
    } catch (err) {
      return res.status(500).json({
        error: 'Failed to retrieve SBOM history',
        details: err.message,
      });
    }

    if (!pgResult) {
      return res.status(404).json({ error: 'SBOM record not found' });
    }

    var result = await fabric.getContract();
    gateway = result.gateway;
    var contract = result.contract;

    var resultBuffer = await contract.evaluateTransaction(
      'GetHistory',
      sbomID
    );

    var trustRepository = require('../repositories/trustRepository');
    var contextAssertionRepository = require('../repositories/contextAssertionRepository');
    var policyExceptionRepository = require('../repositories/policyExceptionRepository');

    var contextAssertions = await contextAssertionRepository.listContextAssertionsBySbomId(sbomID);
    var policyExceptions = await policyExceptionRepository.listExceptionsBySbomId(sbomID);

    // Map context assertions to include required audit fields clearly
    var mappedContextAssertions = contextAssertions.map(ca => ({
      id: ca.id,
      environment: ca.environment,
      status: ca.status,
      assertedBy: ca.asserted_by,
      assertorRole: ca.assertor_role,
      assertedAt: ca.asserted_at,
      evidenceSource: ca.evidence_source || 'UNKNOWN',
      matchedAuthorizationRule: ca.matched_authorization_rule || 'UNKNOWN',
      provenanceMode: ca.provenance_mode || 'UNKNOWN',
      revocationReason: ca.revoked_by ? ca.justification : null,
      revokedBy: ca.revoked_by,
      revokedAt: ca.revoked_at
    }));

    var resultString = resultBuffer.toString('utf8');
    var historyArray;

    try {
      historyArray = JSON.parse(resultString);
      if (!Array.isArray(historyArray)) {
        throw new Error('history is not an array');
      }

      // Apply compatibility mapper to history items
      historyArray = historyArray.map(item => {
        if (item && item.record && typeof item.record.trustStatus !== 'undefined') {
          var normalized = trustRepository.normalizeTrustStatus(item.record.trustStatus);
          item.record.trustStatus = normalized.trustDecision;
          if (normalized.legacyNormalized) {
            item.record.legacyNormalized = true;
            item.record.legacyDecision = normalized.legacyDecision;
          }
        }
        return item;
      });

    } catch (parseErr) {
      return res.status(500).json({ error: 'Failed to parse SBOM history response' });
    }

    return res.status(200).json({
      message: 'SBOM history retrieved successfully',
      sbomID: sbomID,
      sbom: pgResult.document,
      artifacts: pgResult.artifacts,
      history: historyArray,
      contextAssertions: mappedContextAssertions,
      policyExceptions: policyExceptions
    });
  } catch (err) {
    if (err.message && err.message.indexOf('not found') !== -1) {
      return res.status(404).json({ error: err.message });
    }
    return res.status(500).json({
      error: 'Failed to retrieve SBOM history',
      details: err.message,
    });
  } finally {
    if (gateway) {
      fabric.disconnectGateway(gateway);
    }
  }
});

module.exports = router;
