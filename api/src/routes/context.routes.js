'use strict';

const express = require('express');
const router = express.Router();
const sbomRepository = require('../repositories/sbomRepository');
const { evaluateDeploymentContext } = require('../utils/contextEngine');
const { applyVexOverlays } = require('../utils/vexEngine');

/**
 * Handle deployment context submission and evaluation
 */
async function handleRecordContext(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  const body = req.body || {};
  if (!body.deploymentTier && !body.environment) {
    return res.status(400).json({ error: 'deploymentTier or environment parameter is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    // Fetch existing VEX statements to determine effective risk score and highest effective severity
    const vexStatements = await sbomRepository.getVexStatementsBySBOMID(sbomId.trim());
    const rawSbom = typeof pgDocument.sbom_json === 'string' ? JSON.parse(pgDocument.sbom_json) : (pgDocument.sbom_json || {});
    const components = rawSbom.components || [];
    const vulns = [];
    components.forEach(c => {
      if (c.vulnerabilities && Array.isArray(c.vulnerabilities)) {
        vulns.push(...c.vulnerabilities);
      }
    });

    const vexSummary = applyVexOverlays(vulns, vexStatements);
    const evalResult = evaluateDeploymentContext({
      deploymentTier: body.deploymentTier || body.environment,
      internetExposed: body.internetExposed || body.networkExposure === 'PUBLIC' || body.networkExposure === 'INTERNET',
      dataClassification: body.dataClassification || body.dataSensitivity,
      runtimeEnvironment: body.runtimeEnvironment
    }, vexSummary);

    const dbRecord = await sbomRepository.insertDeploymentContext({
      sbomId: sbomId.trim(),
      environment: evalResult.deploymentTier,
      networkExposure: evalResult.internetExposed ? 'PUBLIC' : 'INTERNAL',
      dataSensitivity: evalResult.dataClassification,
      privilegeLevel: body.privilegeLevel || 'STANDARD',
      compensatingControls: body.compensatingControls || [],
      riskMultiplier: body.riskMultiplier || (evalResult.deploymentTier === 'PROD_CRITICAL' ? 1.5 : 1.0)
    });

    const statusCode = evalResult.compliant ? 201 : 422;
    return res.status(statusCode).json({
      message: evalResult.compliant ? 'Deployment context recorded and policy check passed' : 'Deployment context policy check failed',
      contextId: dbRecord.id,
      sbomId: sbomId.trim(),
      compliant: evalResult.compliant,
      deploymentTier: evalResult.deploymentTier,
      internetExposed: evalResult.internetExposed,
      reasonCode: evalResult.reasonCode,
      reasonDescription: evalResult.reasonDescription,
      effectiveRiskScore: vexSummary.effectiveRiskScore,
      highestEffectiveSeverity: vexSummary.highestEffectiveSeverity,
      registeredAt: dbRecord.registered_at
    });
  } catch (err) {
    console.error('[TPSR] Error recording deployment context:', err);
    return res.status(500).json({ error: 'Failed to record deployment context', details: err.message });
  }
}

/**
 * Handle deployment context retrieval
 */
async function handleGetContext(req, res) {
  const sbomId = req.params.sbomId;
  if (!sbomId || !sbomId.trim()) {
    return res.status(400).json({ error: 'sbomId parameter is required' });
  }

  try {
    const pgDocument = await sbomRepository.getSBOMDocumentBySBOMID(sbomId.trim());
    if (!pgDocument) {
      return res.status(404).json({ error: `SBOM document not found for ID: ${sbomId}` });
    }

    const records = await sbomRepository.getDeploymentContextBySBOMID(sbomId.trim());
    return res.status(200).json({
      sbomId: sbomId.trim(),
      count: records.length,
      deploymentContexts: records
    });
  } catch (err) {
    console.error('[TPSR] Error fetching deployment context:', err);
    return res.status(500).json({ error: 'Failed to retrieve deployment context', details: err.message });
  }
}

router.post('/v1/sbom/:sbomId/context', handleRecordContext);
router.post('/sbom/:sbomId/context', handleRecordContext);
router.get('/v1/sbom/:sbomId/context', handleGetContext);
router.get('/sbom/:sbomId/context', handleGetContext);

module.exports = router;
