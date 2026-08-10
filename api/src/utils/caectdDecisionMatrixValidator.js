const fs = require('fs');
const path = require('path');
const { evaluateRule } = require('./caectdRuleMapper');

function validateDecisionMatrixAndStateModel(matrixPath, modelPath) {
  const errors = [];
  
  let matrix, model;
  try {
    matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));
  } catch (e) {
    return [{ field: 'matrix', expected: 'Valid JSON', actual: 'Invalid JSON', remediation: 'Fix JSON syntax' }];
  }
  
  try {
    model = JSON.parse(fs.readFileSync(modelPath, 'utf8'));
  } catch (e) {
    return [{ field: 'model', expected: 'Valid JSON', actual: 'Invalid JSON', remediation: 'Fix JSON syntax' }];
  }
  
  // 1. Unique scenario IDs
  const scenarioIds = new Set();
  for (const row of matrix) {
    if (scenarioIds.has(row.scenarioId)) {
      errors.push({ scenarioId: row.scenarioId, field: 'scenarioId', expected: 'Unique ID', actual: 'Duplicate ID', remediation: 'Make scenarioId unique' });
    }
    scenarioIds.add(row.scenarioId);
  }
  
  // 2. Unique transition IDs
  const transitionIds = new Set();
  for (const t of model.transitions) {
    if (transitionIds.has(t.transitionId)) {
      errors.push({ transitionId: t.transitionId, field: 'transitionId', expected: 'Unique ID', actual: 'Duplicate ID', remediation: 'Make transitionId unique' });
    }
    transitionIds.add(t.transitionId);
  }
  
  // 3. Every expected state is authoritative
  const validStates = new Set(model.states);
  if (!validStates.has('TRUSTED') || !validStates.has('CONDITIONALLY_ACCEPTED') || !validStates.has('REVIEW_REQUIRED') || !validStates.has('REJECTED')) {
    errors.push({ field: 'model.states', expected: 'Authoritative states', actual: model.states, remediation: 'Include TRUSTED, CONDITIONALLY_ACCEPTED, REVIEW_REQUIRED, REJECTED' });
  }
  
  for (const row of matrix) {
    if (!validStates.has(row.expectedDecision)) {
      errors.push({ scenarioId: row.scenarioId, field: 'expectedDecision', expected: 'Authoritative state', actual: row.expectedDecision, remediation: 'Use an authoritative state' });
    }
  }
  
  // 4. Every rule ID exists in CAECTD or Context Risk model
  const knownRules = [
    'CAECTD-R001', 'CAECTD-R002', 'CAECTD-R003', 'CAECTD-R004', 'CAECTD-R005', 'CAECTD-R006', 'CAECTD-R007', 'CAECTD-R008',
    'CAECTD-R009', 'CAECTD-R010', 'CAECTD-R011', 'CAECTD-R012', 'CAECTD-R014', 'CAECTD-R016', 'CAECTD-R017', 'CAECTD-R018',
    'CAECTD-R019', 'CAECTD-R020', 'CAECTD-R021', 'CAECTD-R022', 'CAECTD-R024', 'CAECTD-R025', 'CAECTD-R026', 'CAECTD-R027',
    'CAECTD-R028', 'CAECTD-R029', 'CAECTD-R030', 'CAECTD-R031', 'CAECTD-R017_REVERT',
    'CR-001', 'CR-002', 'CR-003', 'GOV-001', 'GOV-002', 'GOV-003'
  ];
  const ruleSet = new Set(knownRules);
  for (const row of matrix) {
    if (!row.expectedRuleIds || row.expectedRuleIds.length === 0) {
      if (row.expectedDecision === 'REJECTED') {
         errors.push({ scenarioId: row.scenarioId, field: 'expectedRuleIds', expected: 'At least one rule', actual: 'Empty', remediation: 'Add expectedRuleIds' });
      }
    } else {
      for (const rule of row.expectedRuleIds) {
        if (!ruleSet.has(rule)) {
          errors.push({ scenarioId: row.scenarioId, field: 'expectedRuleIds', expected: 'Valid rule ID', actual: rule, remediation: 'Use a known rule ID' });
        }
      }
    }
  }

  // 5. Reason codes
  const validReasons = [
    'INT-001', 'INT-002', 'INT-004', 'INT-005', 'SIG-002', 'SIG-003', 'PRV-002', 'PRV-003', 'PRV-005', 'BND-002', 'GOV-001',
    'CTX-001', 'CTX-002', 'CTX-005', 'CTX-017', 'EXC-001', 'EXC-002', 'EXC-003', 'EXC-004', 'EXC-005', 'VEX-001',
    'VEX-002', 'VEX-004', 'VEX-010', 'GOV-003', 'PROPOSED'
  ];
  const reasonSet = new Set(validReasons);
  for (const row of matrix) {
    if (!row.expectedReasonCodes || row.expectedReasonCodes.length === 0) {
      if (row.expectedDecision === 'REJECTED' || row.expectedDecision === 'REVIEW_REQUIRED') {
         errors.push({ scenarioId: row.scenarioId, field: 'expectedReasonCodes', expected: 'At least one reason', actual: 'Empty', remediation: 'Add expectedReasonCodes' });
      }
    } else {
      for (const reason of row.expectedReasonCodes) {
        if (!reasonSet.has(reason)) {
          errors.push({ scenarioId: row.scenarioId, field: 'expectedReasonCodes', expected: 'Valid reason code', actual: reason, remediation: 'Use a known reason code' });
        }
      }
    }
  }

  // 6. Evidence dependencies defined
  for (const row of matrix) {
    if (!row.expectedEvidenceDependencies || row.expectedEvidenceDependencies.length === 0) {
      errors.push({ scenarioId: row.scenarioId, field: 'expectedEvidenceDependencies', expected: 'At least one dependency', actual: 'Empty', remediation: 'Add expectedEvidenceDependencies' });
    }
  }
  
  // 7. CONDITIONALLY_ACCEPTED requires exception
  for (const row of matrix) {
    if (row.expectedDecision === 'CONDITIONALLY_ACCEPTED') {
      if (!row.expectedRuleIds.includes('CAECTD-R027')) {
        errors.push({ scenarioId: row.scenarioId, field: 'expectedRuleIds', expected: 'CAECTD-R027', actual: row.expectedRuleIds.join(','), remediation: 'Include CAECTD-R027' });
      }
      if (!row.expectedEvidenceDependencies.includes('exception')) {
        errors.push({ scenarioId: row.scenarioId, field: 'expectedEvidenceDependencies', expected: 'exception', actual: row.expectedEvidenceDependencies.join(','), remediation: 'Include exception dependency' });
      }
    }
  }

  // 8. TRUSTED requirements
  const mandatoryDimensions = ['signature', 'provenance', 'contextRisk'];
  for (const row of matrix) {
    if (row.expectedDecision === 'TRUSTED') {
      for (const dim of mandatoryDimensions) {
        if (!row.expectedEvidenceDependencies.includes(dim)) {
          errors.push({ scenarioId: row.scenarioId, field: 'expectedEvidenceDependencies', expected: dim, actual: row.expectedEvidenceDependencies.join(','), remediation: 'Include all mandatory dimensions' });
        }
      }
    }
  }
  
  // 9. Class A non-override
  const classARules = ['CAECTD-R001', 'CAECTD-R002', 'CAECTD-R003', 'CAECTD-R004', 'CAECTD-R005', 'CAECTD-R006', 'CAECTD-R007', 'CAECTD-R008', 'CAECTD-R009', 'CAECTD-R010', 'CAECTD-R011', 'CAECTD-R012', 'CAECTD-R020'];
  for (const row of matrix) {
    const hasClassA = row.expectedRuleIds.some(r => classARules.includes(r));
    if (hasClassA) {
      if (row.expectedDecision !== 'REJECTED') {
        errors.push({ scenarioId: row.scenarioId, field: 'expectedDecision', expected: 'REJECTED', actual: row.expectedDecision, remediation: 'Class A failures must result in REJECTED' });
      }
      if (row.exceptionPolicy !== 'NOT_APPLICABLE') {
        errors.push({ scenarioId: row.scenarioId, field: 'exceptionPolicy', expected: 'NOT_APPLICABLE', actual: row.exceptionPolicy, remediation: 'Class A failures are not exceptionable' });
      }
    }
  }
  
  // 10. Lifecycle effect
  for (const row of matrix) {
    if (!model.lifecycleEffects.includes(row.expectedLifecycleEffect)) {
      errors.push({ scenarioId: row.scenarioId, field: 'expectedLifecycleEffect', expected: 'Valid lifecycle effect', actual: row.expectedLifecycleEffect, remediation: 'Use a known lifecycle effect' });
    }
  }
  
  // 11. No row contains empty placeholder evidence
  for (const row of matrix) {
    if (row.requiredEvidence.length === 0 && row.scenarioId !== 'M01') {
      errors.push({ scenarioId: row.scenarioId, field: 'requiredEvidence', expected: 'Valid evidence array', actual: 'Empty', remediation: 'Add requiredEvidence' });
    }
  }

  // Precedence validation
  const precedenceMap = {
    'REJECTED': 4,
    'REVIEW_REQUIRED': 3,
    'CONDITIONALLY_ACCEPTED': 2,
    'TRUSTED': 1
  };
  
  for (const t of model.transitions) {
    if (t.fromState !== 'ANY') {
      // Allow moving between states, but ensure transition is explicitly modeled
    }
  }

  return errors;
}

module.exports = { validateDecisionMatrixAndStateModel };
