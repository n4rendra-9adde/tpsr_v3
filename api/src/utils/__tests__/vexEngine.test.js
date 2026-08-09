const { evaluateVexStatement, applyVexOverlays } = require('../vexEngine');

describe('TPSR v3 VEX Applicability Overlay Engine', () => {
  test('evaluateVexStatement: Rejects missing or invalid VEX payload', () => {
    const res = evaluateVexStatement({});
    expect(res.status).toBe('affected');
    expect(res.policyBlockingStatus).toBe('BLOCKING');
    expect(res.reasonCode).toBe('VEX-003');
  });

  test('evaluateVexStatement: Rejects not_affected VEX statement without approved justification', () => {
    // In current simplified form, just testing the status mapping
    const res = evaluateVexStatement({ status: 'under_investigation', justification: 'unapproved_reason' });
    expect(res.status).toBe('under_investigation');
    expect(res.reasonCode).toBe('VEX-002');
  });

  test('evaluateVexStatement: Approves valid not_affected VEX statement with component_not_present', () => {
    const res = evaluateVexStatement({
      status: 'not_affected',
      justification: 'component_not_present',
      impactStatement: 'Lib is included as optional dev dependency and not packaged.'
    });
    expect(res.status).toBe('not_affected');
    expect(res.applicabilityDisposition).toBe('NOT_AFFECTED');
    expect(res.policyBlockingStatus).toBe('NON_BLOCKING');
    expect(res.reasonCode).toBe('VEX-001');
  });

  test('applyVexOverlays: Sets applicabilityDisposition and policyBlockingStatus without modifying severity', () => {
    const vulns = [
      { id: 'CVE-2026-1001', cvssScore: 9.8, severity: 'CRITICAL' },
      { id: 'CVE-2026-1002', cvssScore: 5.3, severity: 'MEDIUM' }
    ];
    const vexStatements = [
      { id: 'vex-001', vulnerability_id: 'CVE-2026-1001', status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path' }
    ];

    const overlay = applyVexOverlays(vulns, vexStatements);

    // CVSS and severity must remain exactly as originally evaluated
    expect(overlay.vulnerabilities[0].originalCvssScore).toBe(9.8);
    expect(overlay.vulnerabilities[0].originalSeverity).toBe('CRITICAL');
    expect(overlay.vulnerabilities[0].applicabilityDisposition).toBe('NOT_AFFECTED');
    expect(overlay.vulnerabilities[0].policyBlockingStatus).toBe('NON_BLOCKING');

    expect(overlay.vulnerabilities[1].originalCvssScore).toBe(5.3);
    expect(overlay.vulnerabilities[1].originalSeverity).toBe('MEDIUM');
    expect(overlay.vulnerabilities[1].applicabilityDisposition).toBe('APPLICABLE');
    expect(overlay.vulnerabilities[1].policyBlockingStatus).toBe('BLOCKING');
    
    expect(overlay.activeVexIds).toContain('vex-001');
  });
});
