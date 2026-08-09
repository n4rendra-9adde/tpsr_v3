/**
 * TPSR v3 Trust-Evaluation Orchestration Engine — Unit Tests
 *
 * Tests the authoritative four-state trust-decision model:
 *   TRUSTED, CONDITIONALLY_ACCEPTED, REVIEW_REQUIRED, REJECTED
 *
 * Note: evaluateTrust is async. All test cases must await the result.
 */

const { evaluateTrust, TRUST_STATUS } = require('../trustEngine');

describe('TPSR v3 Trust-Evaluation Orchestration Engine — Four-State Enum', () => {
  const sbomDoc = { sbom_id: 'test-trust-1', sbom_json: '{"components":[]}' };
  const validProv = [{ status: 'VALID', slsa_level: 'SLSA_BUILD_LEVEL_3' }];
  const validSig  = [{ verification_status: 'VERIFIED' }];

  // ── REJECTED: mandatory check failures ─────────────────────────────────────

  test('Returns REJECTED (not UNTRUSTED) when SBOM document is missing', async () => {
    const res = await evaluateTrust({});
    expect(res.trustStatus).toBe('REJECTED');
    expect(res.trustStatus).not.toBe('UNTRUSTED');
    expect(res.reasonCode).toBe('INT-002');
  });

  test('Returns REJECTED (not UNTRUSTED) when provenance is missing or invalid', async () => {
    const res = await evaluateTrust({ sbomDocument: sbomDoc, provenance: [], signatures: validSig });
    expect(res.trustStatus).toBe('REJECTED');
    expect(res.trustStatus).not.toBe('UNTRUSTED');
    expect(res.reasonCode).toBe('PRV-005');
  });

  test('Returns REJECTED (not UNTRUSTED) when signature is missing or verification failed', async () => {
    const res = await evaluateTrust({ sbomDocument: sbomDoc, provenance: validProv, signatures: [] });
    expect(res.trustStatus).toBe('REJECTED');
    expect(res.trustStatus).not.toBe('UNTRUSTED');
    expect(res.reasonCode).toBe('SIG-002');
  });

  test('Returns REJECTED when deployment context policy fails with no valid exception', async () => {
    const res = await evaluateTrust({
      sbomDocument: {
        sbom_id: 'test-trust-rej-ctx',
        sbom_json: JSON.stringify({
          components: [{ vulnerabilities: [{ id: 'CVE-2026-CRIT', cvssScore: 9.8, severity: 'CRITICAL' }] }]
        })
      },
      provenance: validProv,
      signatures: validSig,
      deploymentContext: { environment: 'PROD_CRITICAL', network_exposure: 'PUBLIC' },
      policyExceptions: []
    });
    expect(res.trustStatus).toBe('REJECTED');
    expect(res.trustStatus).not.toBe('UNTRUSTED');
  });

  // ── TRUSTED: all mandatory checks pass ─────────────────────────────────────

  test('Returns TRUSTED when provenance, signature, and deployment context checks all pass', async () => {
    const res = await evaluateTrust({
      sbomDocument: sbomDoc,
      provenance: validProv,
      signatures: validSig,
      deploymentContext: { environment: 'PROD', network_exposure: 'INTERNAL' }
    });
    expect(res.trustStatus).toBe('TRUSTED');
    expect(res.reasonCode).toBe('GOV-001');
    expect(res.evidenceSummary.provenanceCount).toBe(1);
    expect(res.evidenceSummary.signatureCount).toBe(1);
  });

  // ── CONDITIONALLY_ACCEPTED: policy violation covered by approved exception ─

  test('Returns CONDITIONALLY_ACCEPTED (not TRUSTED) when deployment context policy fails but covered by approved active exception', async () => {
    const futureDate = new Date(Date.now() + 86400000 * 30).toISOString(); // 30 days from now
    const res = await evaluateTrust({
      sbomDocument: {
        sbom_id: 'test-trust-cond',
        sbom_json: JSON.stringify({
          components: [{ vulnerabilities: [{ id: 'CVE-2026-1111', cvssScore: 9.8, severity: 'CRITICAL' }] }]
        })
      },
      provenance: validProv,
      signatures: validSig,
      deploymentContext: { environment: 'PROD_CRITICAL', network_exposure: 'PUBLIC' },
      policyExceptions: [{ id: 'exc-1', violation_id: 'CVE-2026-1111', status: 'APPROVED', valid_until: futureDate }]
    });
    expect(res.trustStatus).toBe('CONDITIONALLY_ACCEPTED');
    expect(res.trustStatus).not.toBe('TRUSTED');
    expect(res.trustStatus).not.toBe('UNTRUSTED');
    expect(res.reasonCode).toBe('EXC-001');
    expect(res.evidenceSummary.activeExceptionCount).toBeGreaterThanOrEqual(1);
  });

  test('Returns REJECTED when exception is expired (past valid_until)', async () => {
    const pastDate = new Date(Date.now() - 86400000).toISOString(); // 1 day ago
    const res = await evaluateTrust({
      sbomDocument: {
        sbom_id: 'test-trust-exp',
        sbom_json: JSON.stringify({
          components: [{ vulnerabilities: [{ id: 'CVE-2026-2222', cvssScore: 9.8, severity: 'CRITICAL' }] }]
        })
      },
      provenance: validProv,
      signatures: validSig,
      deploymentContext: { environment: 'PROD_CRITICAL', network_exposure: 'PUBLIC' },
      policyExceptions: [{ id: 'exc-2', violation_id: 'CVE-2026-2222', status: 'APPROVED', valid_until: pastDate }]
    });
    expect(res.trustStatus).toBe('REJECTED');
    expect(res.trustStatus).not.toBe('UNTRUSTED');
  });

  // ── CAECTD-R024 Triggering Tests ───────────────────────────────────────────

  test('Missing SBOM does not automatically trigger R024', async () => {
    const res = await evaluateTrust({});
    expect(res.trustStatus).toBe('REJECTED');
    expect(res.triggeredRuleIds).not.toContain('CAECTD-R024');
  });

  test('A blocking vulnerability with valid context does not trigger R024', async () => {
    const res = await evaluateTrust({
      sbomDocument: {
        sbom_id: 'test-trust-r024',
        sbom_json: JSON.stringify({
          components: [{ vulnerabilities: [{ id: 'CVE-2026-CRIT', cvssScore: 9.8, severity: 'CRITICAL' }] }]
        })
      },
      provenance: validProv,
      signatures: validSig,
      deploymentContext: { environment: 'PROD_CRITICAL', network_exposure: 'PUBLIC' },
      policyExceptions: []
    });
    // Context is present, so R024 shouldn't be triggered even if there's a blocking violation (which triggers R017)
    expect(res.trustStatus).toBe('REJECTED');
    expect(res.triggeredRuleIds).not.toContain('CAECTD-R024');
    expect(res.triggeredRuleIds).toContain('CAECTD-R017');
  });

  test('A policy requiring context with context absent triggers R024', async () => {
    const provEngine = require('../provenanceEngine');
    const spy = jest.spyOn(provEngine, 'getTrustPolicy').mockReturnValue({ requireDeploymentContext: true });

    const res = await evaluateTrust({
      sbomDocument: sbomDoc,
      provenance: validProv,
      signatures: validSig,
      deploymentContext: null, // missing context
      policyExceptions: []
    });

    expect(res.triggeredRuleIds).toContain('CAECTD-R024');
    spy.mockRestore();
  });

  // ── TRUST_STATUS constants exported ────────────────────────────────────────

  test('TRUST_STATUS constants export the correct authoritative four-state values', () => {
    expect(TRUST_STATUS.TRUSTED).toBe('TRUSTED');
    expect(TRUST_STATUS.CONDITIONALLY_ACCEPTED).toBe('CONDITIONALLY_ACCEPTED');
    expect(TRUST_STATUS.REVIEW_REQUIRED).toBe('REVIEW_REQUIRED');
    expect(TRUST_STATUS.REJECTED).toBe('REJECTED');
    // UNTRUSTED must NOT appear in authoritative constants
    expect(Object.values(TRUST_STATUS)).not.toContain('UNTRUSTED');
  });
});
