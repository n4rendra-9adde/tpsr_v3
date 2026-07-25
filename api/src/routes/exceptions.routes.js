'use strict';

const express = require('express');
const router = express.Router();
const sbomRepository = require('../repositories/sbomRepository');

/**
 * Handle policy exception request submission
 */
async function handleRecordException(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  const body = req.body || {};
  if (!body.violationId && !body.violation_id && !body.cve && !body.violationType) {
    return res.status(400).json({ error: 'violationId or violationType parameter is required' });
  }

  if (!body.justification || !body.justification.trim()) {
    return res.status(400).json({ error: 'justification parameter is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const dbRecord = await sbomRepository.insertPolicyException({
      sbomId: sbomId.trim(),
      violationId: body.violationId || body.violation_id || body.cve || 'POL-V01',
      violationType: body.violationType || body.violation_type || 'VULNERABILITY_THRESHOLD',
      justification: body.justification.trim(),
      compensatingControls: body.compensatingControls || body.compensating_controls || null,
      requestedBy: req.headers['x-user-id'] || body.requestedBy || 'developer',
      approvedBy: body.approvedBy || null,
      status: body.status || 'APPROVED',
      validUntil: body.validUntil
    });

    return res.status(201).json({
      message: 'Policy exception recorded successfully',
      exceptionId: dbRecord.id,
      sbomId: sbomId.trim(),
      violationId: dbRecord.violation_id,
      violationType: dbRecord.violation_type,
      status: dbRecord.status,
      validUntil: dbRecord.valid_until,
      createdAt: dbRecord.created_at
    });
  } catch (err) {
    console.error('[TPSR] Error recording policy exception:', err);
    return res.status(500).json({ error: 'Failed to record policy exception', details: err.message });
  }
}

/**
 * Handle policy exceptions retrieval
 */
async function handleGetExceptions(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const records = await sbomRepository.getPolicyExceptionsBySBOMID(sbomId.trim());
    return res.status(200).json({
      sbomId: sbomId.trim(),
      count: records.length,
      policyExceptions: records
    });
  } catch (err) {
    console.error('[TPSR] Error fetching policy exceptions:', err);
    return res.status(500).json({ error: 'Failed to retrieve policy exceptions', details: err.message });
  }
}

router.post('/v1/sbom/:sbomId/exceptions', handleRecordException);
router.post('/sbom/:sbomId/exceptions', handleRecordException);
router.get('/v1/sbom/:sbomId/exceptions', handleGetExceptions);
router.get('/sbom/:sbomId/exceptions', handleGetExceptions);

module.exports = router;
