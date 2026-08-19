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
    
    let isCompliant = true;
    let finalReasonCode = 'CTX-000';
    let finalReasonDescription = `Deployment context policy check passed for tier: ${body.deploymentTier || body.environment}`;

    for (const vuln of vexSummary.vulnerabilities) {
      const evalResult = evaluateDeploymentContext({
        deploymentTier: body.deploymentTier || body.environment,
        internetExposed: body.internetExposed || body.networkExposure === 'PUBLIC' || body.networkExposure === 'INTERNET',
        dataClassification: body.dataClassification || body.dataSensitivity,
        runtimeEnvironment: body.runtimeEnvironment
      }, {
        cvssScore: vuln.originalCvssScore,
        severity: vuln.originalSeverity
      }, {
        applicabilityDisposition: vuln.applicabilityDisposition,
        policyBlockingStatus: vuln.policyBlockingStatus
      });

      if (!evalResult.compliant) {
        isCompliant = false;
        finalReasonCode = evalResult.reasonCode;
        finalReasonDescription = evalResult.reasonDescription;
        break;
      }
    }

    if (vexSummary.vulnerabilities.length === 0) {
      // If there are no vulnerabilities, it is trivially compliant.
      isCompliant = true;
    }

    const dbRecord = await sbomRepository.insertDeploymentContext({
      sbomId: sbomId.trim(),
      environment: (body.deploymentTier || body.environment || 'PROD').toUpperCase(),
      networkExposure: (body.internetExposed || body.networkExposure === 'PUBLIC' || body.networkExposure === 'INTERNET') ? 'PUBLIC' : 'INTERNAL',
      dataSensitivity: body.dataClassification || body.dataSensitivity,
      privilegeLevel: body.privilegeLevel || 'STANDARD',
      compensatingControls: body.compensatingControls || [],
      riskMultiplier: body.riskMultiplier || ((body.deploymentTier || body.environment) === 'PROD_CRITICAL' ? 1.5 : 1.0)
    });

    if (isCompliant) {
      try {
        const automaticEvaluationService = require('../services/automaticEvaluationService');
        await automaticEvaluationService.evaluateSubmittedSbom({
          sbomId: sbomId.trim(),
          correlationId: null,
          principal: req.headers['x-user-id'] || 'system-context',
          triggerType: 'CONTEXT_CHANGED'
        });
      } catch (reevalErr) {
        console.warn(`[TPSR][CONTEXT] Automatic reevaluation failed for ${sbomId}:`, reevalErr.message);
      }
    }

    const statusCode = isCompliant ? 201 : 422;
    return res.status(statusCode).json({
      message: isCompliant ? 'Deployment context recorded and policy check passed' : 'Deployment context policy check failed',
      contextId: dbRecord.id,
      sbomId: sbomId.trim(),
      compliant: isCompliant,
      deploymentTier: (body.deploymentTier || body.environment || 'PROD').toUpperCase(),
      internetExposed: !!(body.internetExposed || body.networkExposure === 'PUBLIC' || body.networkExposure === 'INTERNET'),
      reasonCode: finalReasonCode,
      reasonDescription: finalReasonDescription,
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
