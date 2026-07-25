const { evaluateVexStatement, applyVexOverlays } = require('../vexEngine');

describe('TPSR v3 VEX Applicability Overlay Engine', () => {
  test('evaluateVexStatement: Rejects missing or invalid VEX payload', () => {
    const res = evaluateVexStatement(null);
    expect(res.isValid).toBe(false);
    expect(res.reasonCode).toBe('VEX-002');
  });

  test('evaluateVexStatement: Rejects not_affected VEX statement without approved justification', () => {
    const res = evaluateVexStatement({ status: 'not_affected', justification: 'unapproved_reason' });
    expect(res.isValid).toBe(false);
    expect(res.reasonCode).toBe('VEX-002');
  });

  test('evaluateVexStatement: Approves valid not_affected VEX statement with component_not_present', () => {
    const res = evaluateVexStatement({
      status: 'not_affected',
      justification: 'component_not_present',
      impactStatement: 'Lib is included as optional dev dependency and not packaged.'
    });
    expect(res.isValid).toBe(true);
    expect(res.reasonCode).toBe('VEX-001');
  });

  test('applyVexOverlays: Preserves raw CVSS score while suppressing effective risk score for mitigated CVE', () => {
    const vulns = [
      { id: 'CVE-2026-1001', cvssScore: 9.8, severity: 'CRITICAL' },
      { id: 'CVE-2026-1002', cvssScore: 5.3, severity: 'MEDIUM' }
    ];
    const vexStatements = [
      { id: 'vex-001', vulnerability_id: 'CVE-2026-1001', status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path' }
    ];

    const overlay = applyVexOverlays(vulns, vexStatements);

    expect(overlay.totalRawCvssScore).toBe(15.1); // 9.8 + 5.3 preserved!
    expect(overlay.vulnerabilities[0].rawCvssScore).toBe(9.8);
    expect(overlay.vulnerabilities[0].effectiveCvssScore).toBe(0);
    expect(overlay.vulnerabilities[0].suppressedByVex).toBe(true);

    expect(overlay.vulnerabilities[1].effectiveCvssScore).toBe(5.3);
    expect(overlay.vulnerabilities[1].suppressedByVex).toBe(false);
    expect(overlay.highestEffectiveSeverity).toBe('MEDIUM');
    expect(overlay.activeVexIds).toContain('vex-001');
  });
});
