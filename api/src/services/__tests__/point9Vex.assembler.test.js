const { assembleContextRiskEvidence } = require('../contextRiskEvidenceAssembler');

describe('Point 9 VEX Assembler and Overlay Propagation', () => {
  const baseSbom = { sbom_json: { components: [{ 'bom-ref': 'pkg:npm/test@1.0.0', vulnerabilities: [{ id: 'CVE-123', severity: 'HIGH' }] }] } };

  const validVex = {
    vex_authoritative: true,
    signature_status: 'VERIFIED',
    public_key_fingerprint: 'fp-123',
    policy_version: 'v1.1',
    target_binding: { artifact: 'pkg:npm/test@1.0.0' },
    canonical_payload_digest: 'hash123',
    applicability_status: 'not_affected',
    vulnerability_id: 'CVE-123'
  };

  test('1. vex_authoritative=true alone cannot suppress', () => {
    const vex = { vex_authoritative: true, applicability_status: 'not_affected', vulnerability_id: 'CVE-123' };
    const res = assembleContextRiskEvidence({ sbomDocument: baseSbom, vexStatements: [vex] });
    expect(res.vulnerabilities[0].vexApplicability).toBeUndefined();
  });

  test('2. missing cryptographic_valid cannot suppress', () => {
    const vex = { ...validVex, signature_status: null };
    const res = assembleContextRiskEvidence({ sbomDocument: baseSbom, vexStatements: [vex] });
    expect(res.vulnerabilities[0].vexApplicability).toBeUndefined();
  });

  test('3. missing issuer_authorized cannot suppress', () => {
    const vex = { ...validVex, public_key_fingerprint: null };
    const res = assembleContextRiskEvidence({ sbomDocument: baseSbom, vexStatements: [vex] });
    expect(res.vulnerabilities[0].vexApplicability).toBeUndefined();
  });

  test('4. missing target-binding metadata cannot suppress', () => {
    const vex = { ...validVex, target_binding: null };
    const res = assembleContextRiskEvidence({ sbomDocument: baseSbom, vexStatements: [vex] });
    expect(res.vulnerabilities[0].vexApplicability).toBeUndefined();
  });

  test('5. missing policy traceability cannot suppress', () => {
    const vex = { ...validVex, policy_version: null };
    const res = assembleContextRiskEvidence({ sbomDocument: baseSbom, vexStatements: [vex] });
    expect(res.vulnerabilities[0].vexApplicability).toBeUndefined();
  });

  test('6. incomplete verification metadata cannot enter activeVexIds', () => {
    const vex = { ...validVex, canonical_payload_digest: null };
    const res = assembleContextRiskEvidence({ sbomDocument: baseSbom, vexStatements: [vex] });
    expect(res.vexTrusted).toBe(false);
  });

  test('7. complete authoritative exact-target metadata can affect only its CVE/artifact/version', () => {
    const res = assembleContextRiskEvidence({ sbomDocument: baseSbom, vexStatements: [validVex] });
    expect(res.vulnerabilities[0].vexApplicability).toBe('NOT_AFFECTED');
    expect(res.vexTrusted).toBe(true);
  });

  test('8. invalid evidence remains auditable but inactive', () => {
    const vex = { ...validVex, applicability_disposition: 'VEX_INVALID' };
    const res = assembleContextRiskEvidence({ sbomDocument: baseSbom, vexStatements: [vex] });
    expect(res.vulnerabilities[0].vexApplicability).toBeUndefined();
  });

  test('9. raw valid/isValid/signer_trusted fields cannot suppress', () => {
    const vex = { valid: true, isValid: true, signer_trusted: true, applicability_status: 'not_affected', vulnerability_id: 'CVE-123' };
    const res = assembleContextRiskEvidence({ sbomDocument: baseSbom, vexStatements: [vex] });
    expect(res.vulnerabilities[0].vexApplicability).toBeUndefined();
  });
});
