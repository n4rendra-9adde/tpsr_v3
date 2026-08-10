const fs = require('fs');
const path = require('path');

function validateAdversarialScenariosAndControlMap(scenariosPath, controlMapPath) {
  const errors = [];
  let model, map;

  try {
    model = JSON.parse(fs.readFileSync(scenariosPath, 'utf8'));
  } catch (e) {
    return [{ scenarioId: 'GLOBAL', field: 'modelFile', expected: 'Valid JSON', actual: 'Invalid JSON', remediation: 'Fix JSON syntax' }];
  }

  try {
    map = JSON.parse(fs.readFileSync(controlMapPath, 'utf8'));
  } catch (e) {
    return [{ scenarioId: 'GLOBAL', field: 'mapFile', expected: 'Valid JSON', actual: 'Invalid JSON', remediation: 'Fix JSON syntax' }];
  }

  const scenarios = model.scenarios;
  if (!scenarios || !Array.isArray(scenarios)) {
    return [{ scenarioId: 'GLOBAL', field: 'scenarios', expected: 'Array', actual: typeof scenarios, remediation: 'Make scenarios an array' }];
  }

  if (scenarios.length !== 10) {
    errors.push({ scenarioId: 'GLOBAL', field: 'scenarios.length', expected: 10, actual: scenarios.length, remediation: 'Include exactly ten scenarios' });
  }

  const requiredCategories = [
    'CI_COMPROMISE', 'PROVENANCE_FORGERY', 'SIGNER_ABUSE', 'ARTIFACT_SUBSTITUTION',
    'SBOM_SUBSTITUTION', 'VEX_FRESHNESS', 'VEX_FORGERY', 'CONTEXT_MANIPULATION',
    'EXCEPTION_ABUSE', 'EVIDENCE_REPLAY'
  ];

  const seenIds = new Set();
  const seenCategories = new Set();
  const authoritativeDecisions = new Set(['TRUSTED', 'CONDITIONALLY_ACCEPTED', 'REVIEW_REQUIRED', 'REJECTED']);

  const knownRules = new Set([
    'CAECTD-R001', 'CAECTD-R002', 'CAECTD-R003', 'CAECTD-R004', 'CAECTD-R005', 'CAECTD-R006', 'CAECTD-R007', 'CAECTD-R008',
    'CAECTD-R009', 'CAECTD-R010', 'CAECTD-R011', 'CAECTD-R012', 'CAECTD-R014', 'CAECTD-R016', 'CAECTD-R017', 'CAECTD-R018',
    'CAECTD-R019', 'CAECTD-R020', 'CAECTD-R021', 'CAECTD-R022', 'CAECTD-R024', 'CAECTD-R025', 'CAECTD-R026', 'CAECTD-R027',
    'CAECTD-R028', 'CAECTD-R029', 'CAECTD-R030', 'CAECTD-R031', 'CAECTD-R017_REVERT',
    'CR-001', 'CR-002', 'CR-003', 'GOV-001', 'GOV-002', 'GOV-003'
  ]);

  const validReasons = new Set([
    'INT-001', 'INT-002', 'INT-004', 'INT-005', 'SIG-002', 'SIG-003', 'PRV-002', 'PRV-003', 'PRV-004', 'PRV-005', 'PRV-006', 'BND-002', 'GOV-001',
    'CTX-001', 'CTX-002', 'CTX-005', 'CTX-017', 'EXC-001', 'EXC-002', 'EXC-003', 'EXC-004', 'EXC-005', 'VEX-001',
    'VEX-002', 'VEX-004', 'VEX-007', 'VEX-010', 'GOV-003', 'PROPOSED'
  ]);

  const classARules = ['CAECTD-R001', 'CAECTD-R002', 'CAECTD-R003', 'CAECTD-R004', 'CAECTD-R005', 'CAECTD-R006', 'CAECTD-R007', 'CAECTD-R008', 'CAECTD-R009', 'CAECTD-R010', 'CAECTD-R011', 'CAECTD-R012', 'CAECTD-R020'];

  for (const s of scenarios) {
    if (seenIds.has(s.scenarioId)) {
      errors.push({ scenarioId: s.scenarioId, field: 'scenarioId', expected: 'Unique ID', actual: 'Duplicate', remediation: 'Make scenarioId unique' });
    }
    seenIds.add(s.scenarioId);

    if (!requiredCategories.includes(s.category)) {
      errors.push({ scenarioId: s.scenarioId, field: 'category', expected: 'Valid category', actual: s.category, remediation: 'Use an allowed category' });
    }
    seenCategories.add(s.category);

    if (!authoritativeDecisions.has(s.expectedDecision)) {
      errors.push({ scenarioId: s.scenarioId, field: 'expectedDecision', expected: 'Authoritative state', actual: s.expectedDecision, remediation: 'Use an authoritative state' });
    }

    if (!s.expectedRuleIds || s.expectedRuleIds.length === 0) {
      errors.push({ scenarioId: s.scenarioId, field: 'expectedRuleIds', expected: 'At least one rule', actual: 'Empty', remediation: 'Add expectedRuleIds' });
    } else {
      for (const rule of s.expectedRuleIds) {
        if (!knownRules.has(rule)) {
          errors.push({ scenarioId: s.scenarioId, field: 'expectedRuleIds', expected: 'Valid rule ID', actual: rule, remediation: 'Use a known rule ID' });
        }
      }
    }

    if (!s.expectedReasonCodes || s.expectedReasonCodes.length === 0) {
      errors.push({ scenarioId: s.scenarioId, field: 'expectedReasonCodes', expected: 'At least one reason', actual: 'Empty', remediation: 'Add expectedReasonCodes' });
    } else {
      for (const reason of s.expectedReasonCodes) {
        if (!validReasons.has(reason)) {
          errors.push({ scenarioId: s.scenarioId, field: 'expectedReasonCodes', expected: 'Valid reason code', actual: reason, remediation: 'Use a known reason code' });
        }
      }
    }

    if (!s.securityControls || s.securityControls.length === 0) {
      errors.push({ scenarioId: s.scenarioId, field: 'securityControls', expected: 'Mapped control', actual: 'Empty', remediation: 'Map to a security control' });
    }

    if (!s.expectedEvidenceDependencies || s.expectedEvidenceDependencies.length === 0) {
      errors.push({ scenarioId: s.scenarioId, field: 'expectedEvidenceDependencies', expected: 'At least one dependency', actual: 'Empty', remediation: 'Add expectedEvidenceDependencies' });
    }

    if (!s.testReference) {
      errors.push({ scenarioId: s.scenarioId, field: 'testReference', expected: 'Test file reference', actual: 'Missing', remediation: 'Add testReference' });
    }

    if (s.expectedDecision === 'REJECTED') {
      const hasBlocking = s.expectedRuleIds.some(r => classARules.includes(r) || ['CR-001', 'CAECTD-R017'].includes(r));
      if (!hasBlocking) {
        errors.push({ scenarioId: s.scenarioId, field: 'expectedRuleIds', expected: 'Blocking policy basis', actual: s.expectedRuleIds.join(','), remediation: 'Include a Class A or blocking rule' });
      }
    }

    if (s.expectedDecision === 'REVIEW_REQUIRED') {
      const hasReviewBasis = s.expectedRuleIds.some(r => ['CAECTD-R024', 'CAECTD-R025', 'CAECTD-R026', 'GOV-003'].includes(r));
      if (!hasReviewBasis) {
        errors.push({ scenarioId: s.scenarioId, field: 'expectedRuleIds', expected: 'Uncertainty/conflict basis', actual: s.expectedRuleIds.join(','), remediation: 'Include a REVIEW_REQUIRED rule basis' });
      }
    }

    // No exception permits Class A override
    if (s.category === 'EXCEPTION_ABUSE') {
      const hasClassA = s.expectedRuleIds.some(r => classARules.includes(r));
      if (hasClassA && s.expectedDecision !== 'REJECTED') {
        errors.push({ scenarioId: s.scenarioId, field: 'expectedDecision', expected: 'REJECTED', actual: s.expectedDecision, remediation: 'Exceptions cannot override Class A failures' });
      }
    }
  }

  for (const cat of requiredCategories) {
    if (!seenCategories.has(cat)) {
      errors.push({ scenarioId: 'GLOBAL', field: 'categories', expected: cat, actual: 'Missing', remediation: 'Ensure all required categories are present' });
    }
  }

  return errors;
}

module.exports = { validateAdversarialScenariosAndControlMap };
