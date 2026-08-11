const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
process.env.POSTGRES_HOST = 'localhost';
process.env.POSTGRES_PORT = '5432';
process.env.POSTGRES_DB = 'tpsr';
process.env.POSTGRES_USER = 'user';
process.env.POSTGRES_PASSWORD = 'password';

const { validateAdversarialScenariosAndControlMap } = require('../../api/src/utils/adversarialScenarioValidator');
const { runAdversarialScenarios } = require('../../api/src/security/adversarialScenarioRunner');

const outDir = '/tmp/tpsr-mentor-feedback/point-07/adversarial-results/';
if (fs.existsSync(outDir)) {
  fs.rmSync(outDir, { recursive: true, force: true });
}
fs.mkdirSync(outDir, { recursive: true });

async function run() {
  const defaultModelPath = path.join(__dirname, '../../docs/models/tpsr-adversarial-scenarios.v0.1.json');
  const defaultMapPath = path.join(__dirname, '../../docs/models/tpsr-adversarial-control-map.v0.1.json');

  const modelPath = process.argv[2] ? path.resolve(process.argv[2]) : defaultModelPath;
  const mapPath = process.argv[3] ? path.resolve(process.argv[3]) : defaultMapPath;

  if (!fs.existsSync(modelPath) || !fs.existsSync(mapPath)) {
    console.error('Input files missing or unreadable.');
    process.exit(1);
  }

  const errors = validateAdversarialScenariosAndControlMap(modelPath, mapPath);
  fs.writeFileSync(path.join(outDir, 'model-validation.json'), JSON.stringify(errors, null, 2));
  fs.writeFileSync(path.join(outDir, 'control-map-validation.json'), JSON.stringify({ valid: errors.length === 0, errors }, null, 2));

  if (errors.length > 0) {
    console.error('Model validation failed:', errors);
    process.exit(1);
  }

  const results = await runAdversarialScenarios(modelPath);
  fs.writeFileSync(path.join(outDir, 'scenario-results.json'), JSON.stringify(results, null, 2));

  let detectedCount = 0;
  let partialCount = 0;
  let notDetectedCount = 0;
  let decisionMatches = 0;
  let ruleMatches = 0;
  let reasonMatches = 0;
  let traceMatches = 0;

  const failures = [];

  for (const r of results) {
    if (r.detected) detectedCount++;
    else if (r.partiallyDetected) partialCount++;
    else notDetectedCount++;

    if (r.decisionMatch) decisionMatches++;
    else failures.push({ scenarioId: r.scenarioId, type: 'Decision Mismatch', expected: r.expectedDecision, actual: r.actualDecision });

    if (r.ruleMatch) ruleMatches++;
    else failures.push({ scenarioId: r.scenarioId, type: 'Rule Mismatch', expected: r.expectedRuleIds, actual: r.actualRuleIds });

    if (r.reasonMatch) reasonMatches++;
    else failures.push({ scenarioId: r.scenarioId, type: 'Reason Mismatch', expected: r.expectedReasonCodes, actual: r.actualReasonCodes });

    if (r.evidenceTraceabilityMatch) traceMatches++;
    else failures.push({ scenarioId: r.scenarioId, type: 'Trace Mismatch', expected: r.expectedEvidenceDependencies, actual: r.actualEvidenceDependencies });
  }

  const summary = {
    totalScenarios: results.length,
    detectedCount,
    partiallyDetectedCount: partialCount,
    notDetectedCount,
    decisionMatches,
    ruleMatches,
    reasonCodeMatches: reasonMatches,
    evidenceTraceMatches: traceMatches,
    scenariosWithKnownLimitations: []
  };

  fs.writeFileSync(path.join(outDir, 'detection-summary.json'), JSON.stringify(summary, null, 2));
  fs.writeFileSync(path.join(outDir, 'failures.json'), JSON.stringify(failures, null, 2));

  const traceability = results.map(r => ({
    scenarioId: r.scenarioId,
    targetedEvidence: r.actualEvidenceDependencies,
    assuranceResult: r.detected ? 'DETECTED' : (r.partiallyDetected ? 'PARTIALLY_DETECTED' : 'FAILED'),
    ruleIds: r.actualRuleIds,
    reasonCodes: r.actualReasonCodes,
    finalDecision: r.actualDecision,
    lifecycleEffect: r.actualLifecycleEffect
  }));
  fs.writeFileSync(path.join(outDir, 'traceability-results.json'), JSON.stringify(traceability, null, 2));
  fs.writeFileSync(path.join(outDir, 'summary.md'), '# Adversarial Summary\nDone.');

  const filesToHash = [
    'model-validation.json',
    'control-map-validation.json',
    'scenario-results.json',
    'detection-summary.json',
    'traceability-results.json',
    'failures.json',
    'summary.md'
  ];

  let manifestStr = '';
  for (const f of filesToHash) {
    const data = fs.readFileSync(path.join(outDir, f));
    const hash = crypto.createHash('sha256').update(data).digest('hex');
    manifestStr += `${hash}  ${f}\n`;
  }
  fs.writeFileSync(path.join(outDir, 'MANIFEST.sha256'), manifestStr);

  if (failures.length > 0 || notDetectedCount > 0) {
    console.error('Validation failed with mismatches:', failures);
    process.exit(1);
  }
  if (results.length !== 10) {
    console.error('Validation failed: expected 10 scenarios.');
    process.exit(1);
  }

  console.log('Done successfully.');
  process.exit(0);
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
