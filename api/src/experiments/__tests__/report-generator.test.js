const fs = require('fs');
const { generateReport } = require('../../../../scripts/experiments/generate-caectd-report');

describe('generateReport', () => {
  it('regenerates numeric values matching source JSON', () => {
    const tmpDir = '/tmp/test-report-gen';
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir);

    const metrics = {
      caectd: {
        decisionAccuracy: { rate: 0.99 },
        strictAttackDetectionRate: { rate: 1.0 },
        falseNegativeRate: { rate: 0.0 },
        inappropriateEscalationRate: { rate: 0.0 },
        falseNonBlockingRate: { rate: 0.0 },
        evidenceCoverage: { rate: 1.0 },
        explainabilityCompleteness: { rate: 1.0 },
        traceabilityCompleteness: { rate: 1.0 }
      },
      integrity: { decisionAccuracy: { rate: 0.17 } },
      cvss: { decisionAccuracy: { rate: 0.53 } }
    };
    fs.writeFileSync(tmpDir + '/evaluator-metrics.json', JSON.stringify(metrics));
    fs.writeFileSync(tmpDir + '/confusion-matrices.json', JSON.stringify({}));

    // Generate to standard file
    generateReport(tmpDir);

    const reportContent = fs.readFileSync('../docs/experiments/CAECTD_V0.1_EXPERIMENT_REPORT.md', 'utf8');
    expect(reportContent).toContain('CAECTD Accuracy: 99%');
    expect(reportContent).toContain('Integrity-Only Accuracy: 17%');
    expect(reportContent).toContain('CVSS-Only Accuracy: 53%');
  });
});
