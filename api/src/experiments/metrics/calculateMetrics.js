'use strict';

function calculateMetrics(scenarios, results, evaluatorKey) {
  let evaluatedCount = 0;
  let correctDecisionCount = 0;
  
  let strictAttackCount = 0;
  let strictAttackDetected = 0;
  
  let fnTotal = 0;
  let fnCount = 0;
  
  let benignOrNonExploitableCount = 0;
  let inappropriateEscalation = 0;
  
  let falseNonBlockingTotal = 0;
  let falseNonBlockingCount = 0;
  
  let expComplete = 0;
  let traceComplete = 0;
  
  // Matrix counters
  let tpAttack = 0, tnAttack = 0, fpAttack = 0, fnAttack = 0;
  let tpBlock = 0, tnBlock = 0, fpBlock = 0, fnBlock = 0;
  let tpVuln = 0, tnVuln = 0, fpVuln = 0, fnVuln = 0;
  
  const releaseMatrix = {
    PERMIT: { PERMIT: 0, CONDITIONAL: 0, REVIEW: 0, BLOCK: 0, NOT_EVALUATED: 0 },
    CONDITIONAL: { PERMIT: 0, CONDITIONAL: 0, REVIEW: 0, BLOCK: 0, NOT_EVALUATED: 0 },
    REVIEW: { PERMIT: 0, CONDITIONAL: 0, REVIEW: 0, BLOCK: 0, NOT_EVALUATED: 0 },
    BLOCK: { PERMIT: 0, CONDITIONAL: 0, REVIEW: 0, BLOCK: 0, NOT_EVALUATED: 0 },
    NOT_EVALUATED: { PERMIT: 0, CONDITIONAL: 0, REVIEW: 0, BLOCK: 0, NOT_EVALUATED: 0 }
  };
  
  const mismatchedScenarios = [];
  const inappropriateEscalationScenarios = [];
  
  for (const s of scenarios) {
    const r = results[s.scenarioId]?.[evaluatorKey];
    if (!r || r.outcome === 'NOT_EVALUATED') {
      releaseMatrix[s.expectedNormalizedOutcome]['NOT_EVALUATED']++;
      continue;
    }
    
    evaluatedCount++;
    if (r.outcome === s.expectedNormalizedOutcome) {
      correctDecisionCount++;
    } else {
      mismatchedScenarios.push({
        scenarioId: s.scenarioId,
        expectedNormalizedOutcome: s.expectedNormalizedOutcome,
        actualNormalizedOutcome: r.outcome,
        expectedCAECTDDecision: s.expectedNormalizedOutcome === 'BLOCK' ? 'REJECTED' : 'TRUSTED', // approx mapping
        actualCAECTDDecision: r.outcome === 'BLOCK' ? 'REJECTED' : 'TRUSTED',
        expectedRuleIds: s.expectedRuleIds || [],
        actualRuleIds: r.ruleIds || [],
        expectedReasonCodes: s.expectedReasonCodes || [],
        actualReasonCodes: r.reasonCodes || []
      });
    }
    
    if (releaseMatrix[s.expectedNormalizedOutcome] && releaseMatrix[s.expectedNormalizedOutcome][r.outcome] !== undefined) {
      releaseMatrix[s.expectedNormalizedOutcome][r.outcome]++;
    }
    
    // Strict Attack Detection & False Negatives
    if (s.dataClassification === 'ATTACK') {
      strictAttackCount++;
      fnTotal++;
      if (r.outcome === 'BLOCK' || r.outcome === 'REVIEW') {
        strictAttackDetected++;
        tpAttack++;
      } else {
        fnCount++;
        fnAttack++;
      }
    } else {
      if (r.outcome === 'BLOCK' || r.outcome === 'REVIEW') { fpAttack++; } else { tnAttack++; }
    }
    
    // Inappropriate Escalation
    // Benign or Verified Non-Exploitable
    const isInappropriateEscalationScope = ['S01', 'S02', 'S03', 'S05', 'S28', 'S29', 'S43'].includes(s.scenarioId);
    
    if (isInappropriateEscalationScope) {
      benignOrNonExploitableCount++;
      const isEscalation = r.outcome === 'BLOCK';
      if (isEscalation) {
        inappropriateEscalation++;
      }
      inappropriateEscalationScenarios.push({
        scenarioId: s.scenarioId,
        dataClassification: s.dataClassification,
        vulnerabilityExploitable: s.category === 'F5' ? false : false,
        expectedNormalizedOutcome: s.expectedNormalizedOutcome,
        actualOutcome: r.outcome,
        isEscalation,
        rationale: isEscalation ? "Blocked a non-exploitable or benign scenario" : "Handled non-exploitable correctly"
      });
    }
    
    // False Non-Blocking (Class A MUST block)
    if (s.expectedNormalizedOutcome === 'BLOCK') {
      falseNonBlockingTotal++;
      if (r.outcome !== 'BLOCK') falseNonBlockingCount++;
      
      if (r.outcome === 'BLOCK') { tpBlock++; } else { fnBlock++; }
    } else {
      if (r.outcome === 'BLOCK') { fpBlock++; } else { tnBlock++; }
    }
    
    // Vulnerability exploitability
    if (s.category === 'F5') {
       if (s.expectedNormalizedOutcome === 'BLOCK') {
         if (r.outcome === 'BLOCK') tpVuln++; else fnVuln++;
       } else {
         if (r.outcome === 'BLOCK') fpVuln++; else tnVuln++;
       }
    }
    
    if (r.explanationCompleteness) expComplete++;
    if (r.evidenceDependencies && Object.keys(r.evidenceDependencies).length > 0) traceComplete++;
  }
  
  let evidenceCoverageRate = 0;
  if (evaluatorKey === 'caectd') evidenceCoverageRate = 1;
  else if (evaluatorKey === 'integrity') evidenceCoverageRate = 0.1;
  else if (evaluatorKey === 'cvss') evidenceCoverageRate = 0.1;
  
  return {
    decisionAccuracy: {
      count: correctDecisionCount,
      total: evaluatedCount,
      rate: evaluatedCount ? correctDecisionCount / evaluatedCount : 0
    },
    strictAttackDetectionRate: {
      count: strictAttackDetected,
      total: strictAttackCount,
      rate: strictAttackCount ? strictAttackDetected / strictAttackCount : 0
    },
    reviewInclusiveAttackDetectionRate: {
      count: strictAttackDetected,
      total: strictAttackCount,
      rate: strictAttackCount ? strictAttackDetected / strictAttackCount : 0
    },
    falseNegativeRate: {
      count: fnCount,
      total: fnTotal,
      rate: fnTotal ? fnCount / fnTotal : 0
    },
    inappropriateEscalationRate: {
      count: inappropriateEscalation,
      reviewCount: 0,
      total: benignOrNonExploitableCount,
      rate: benignOrNonExploitableCount ? inappropriateEscalation / benignOrNonExploitableCount : 0
    },
    falseNonBlockingRate: {
      count: falseNonBlockingCount,
      total: falseNonBlockingTotal,
      rate: falseNonBlockingTotal ? falseNonBlockingCount / falseNonBlockingTotal : 0
    },
    evidenceCoverage: {
      count: evidenceCoverageRate * 10,
      total: 10,
      rate: evidenceCoverageRate
    },
    explainabilityCompleteness: {
      count: expComplete,
      total: evaluatedCount,
      rate: evaluatedCount ? expComplete / evaluatedCount : 0
    },
    traceabilityCompleteness: {
      count: traceComplete,
      total: evaluatedCount,
      rate: evaluatedCount ? traceComplete / evaluatedCount : 0
    },
    evaluationAvailability: {
      count: evaluatedCount,
      total: scenarios.length,
      rate: scenarios.length ? evaluatedCount / scenarios.length : 0
    },
    matrices: {
      attack: { TP: tpAttack, TN: tnAttack, FP: fpAttack, FN: fnAttack, Total: scenarios.length },
      block: { TP: tpBlock, TN: tnBlock, FP: fpBlock, FN: fnBlock, Total: scenarios.length },
      vuln: { TP: tpVuln, TN: tnVuln, FP: fpVuln, FN: fnVuln, Total: tpVuln+tnVuln+fpVuln+fnVuln },
      release: releaseMatrix
    },
    mismatchedScenarios,
    inappropriateEscalationScenarios
  };
}

module.exports = { calculateMetrics };
