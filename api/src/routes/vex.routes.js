'use strict';

const express = require('express');
const router = express.Router();
const sbomRepository = require('../repositories/sbomRepository');
const { evaluateVexStatement } = require('../utils/vexEngine');

/**
 * Handle VEX statement submission and evaluation
 */
async function handleRecordVex(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  const body = req.body || {};
  if (!body.vulnerabilityId && !body.cve) {
    return res.status(400).json({ error: 'vulnerabilityId or cve parameter is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const evalResult = evaluateVexStatement(body);

    const dbRecord = await sbomRepository.insertVexStatement({
      sbomId: sbomId.trim(),
      vulnerabilityId: body.vulnerabilityId || body.cve,
      originalSeverity: body.originalSeverity || body.severity || 'UNKNOWN',
      originalCvss: body.originalCvss || body.cvss || 0,
      status: evalResult.status,
      policyImpact: evalResult.status === 'not_affected' || evalResult.status === 'fixed' ? 'SUPPRESSED' : 'ACTIVE',
      justification: evalResult.justification || body.justification || null,
      impactStatement: evalResult.impactStatement || body.impactStatement || null,
      payload: body,
      issuerIdentity: req.headers['x-user-id'] || body.issuerIdentity || 'security-team',
      issuedAt: body.issuedAt,
      lastUpdatedAt: body.lastUpdatedAt,
      validUntil: body.validUntil
    });

    const statusCode = evalResult.isValid ? 201 : 422;
    return res.status(statusCode).json({
      message: evalResult.isValid ? 'VEX statement recorded and evaluated successfully' : 'VEX statement evaluation failed',
      vexId: dbRecord.id,
      sbomId: sbomId.trim(),
      vulnerabilityId: dbRecord.vulnerability_id,
      status: evalResult.status,
      reasonCode: evalResult.reasonCode,
      reasonDescription: evalResult.reasonDescription,
      policyImpact: dbRecord.policy_impact,
      createdAt: dbRecord.created_at
    });
  } catch (err) {
    console.error('[TPSR] Error recording VEX statement:', err);
    return res.status(500).json({ error: 'Failed to record VEX statement', details: err.message });
  }
}

/**
 * Handle VEX statements retrieval
 */
async function handleGetVex(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const records = await sbomRepository.getVexStatementsBySBOMID(sbomId.trim());
    return res.status(200).json({
      sbomId: sbomId.trim(),
      count: records.length,
      vexStatements: records
    });
  } catch (err) {
    console.error('[TPSR] Error fetching VEX statements:', err);
    return res.status(500).json({ error: 'Failed to retrieve VEX statements', details: err.message });
  }
}

router.post('/v1/sbom/:sbomId/vex', handleRecordVex);
router.post('/sbom/:sbomId/vex', handleRecordVex);
router.get('/v1/sbom/:sbomId/vex', handleGetVex);
router.get('/sbom/:sbomId/vex', handleGetVex);

module.exports = router;
