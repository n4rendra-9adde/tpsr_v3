#!/usr/bin/env node
/**
 * TPSR v3 Comprehensive Adversarial Validation Suite
 * 
 * Validates:
 * 1. Provenance Tampering (SLSA v1.0 / in-toto attestation forgery and build ID mismatch)
 * 2. Cryptographic Signature Tampering (Cosign offline/keyless verification failure & replay)
 * 3. VEX Applicability & Overlay Bypass Attempts (testing raw CVSS preservation vs effective risk)
 * 4. Deployment Context Gating (testing public exposure in PROD_CRITICAL without exception)
 * 5. Trust-Evaluation Orchestration & Reason Code Determinism (GOV, PRV, SIG, VEX, CTX, EXC codes)
 */

'use strict';

const assert = require('assert');

// Require TPSR v3 engines
const provenanceEngine = require('../api/src/utils/provenanceEngine');
const cosignEngine = require('../api/src/utils/cosignEngine');
const vexEngine = require('../api/src/utils/vexEngine');
const contextEngine = require('../api/src/utils/contextEngine');
const trustEngine = require('../api/src/utils/trustEngine');

let passed = 0;
let failed = 0;

function logTest(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    if (err.stack) console.error(err.stack);
    failed++;
  }
}

async function runAsyncTest(name, fn) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    if (err.stack) console.error(err.stack);
    failed++;
  }
}

async function main() {
  console.log('================================================================');
  console.log('       TPSR v3 Comprehensive Adversarial Validation Suite       ');
  console.log('================================================================\n');

  console.log('--- Stage 1: Provenance Tampering & Forgery Validation ---');
  logTest('1.1 Reject missing or malformed SLSA provenance envelope', () => {
    const res = provenanceEngine.verifyProvenance({}, null);
    assert.strictEqual(res.status, 'INVALID');
    assert.strictEqual(res.reasonCode, 'PRV-004');
  });

  logTest('1.2 Detect forged builder identity in SLSA attestation', () => {
    const attestation = {
      _type: 'https://in-toto.io/Statement/v0.1',
      predicateType: 'https://slsa.dev/provenance/v1',
      subject: [{ name: 'test-app', digest: { sha256: 'abc123hash' } }],
      predicate: {
        buildDefinition: {
          buildType: 'https://slsa.dev/container-based-build/v0.1',
          externalParameters: { source: 'https://github.com/org/repo' }
        },
        runDetails: {
          builder: { id: 'https://unauthorized-builder.example.com/build/v1' }
        }
      }
    };
    const res = provenanceEngine.verifyProvenance(attestation, 'abc123hash');
    assert.strictEqual(res.status, 'INVALID');
    assert.strictEqual(res.reasonCode, 'PRV-003');
  });

  logTest('1.3 Detect artifact digest mismatch between SBOM and in-toto subject', () => {
    const attestation = {
      _type: 'https://in-toto.io/Statement/v0.1',
      predicateType: 'https://slsa.dev/provenance/v1',
      subject: [{ name: 'test-app', digest: { sha256: 'wronghash999' } }],
      predicate: {
        buildDefinition: { buildType: 'https://slsa.dev/container-based-build/v0.1' },
        runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } }
      }
    };
    const res = provenanceEngine.verifyProvenance(attestation, 'realhash000');
    assert.strictEqual(res.status, 'INVALID');
    assert.strictEqual(res.reasonCode, 'BND-002');
  });

  logTest('1.4 Pass valid SLSA v1.0 attestation with matching digest and builder', () => {
    const attestation = {
      _type: 'https://in-toto.io/Statement/v0.1',
      predicateType: 'https://slsa.dev/provenance/v1',
      subject: [{ name: 'test-app', digest: { sha256: 'validhash111' } }],
      predicate: {
        buildDefinition: { buildType: 'https://slsa.dev/container-based-build/v0.1' },
        runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } }
      }
    };
    const res = provenanceEngine.verifyProvenance(attestation, 'validhash111');
    assert.strictEqual(res.status, 'VALID');
    assert.strictEqual(res.reasonCode, 'PRV-001');
    assert.strictEqual(res.slsaLevel, 'SLSA_BUILD_LEVEL_3');
  });

  console.log('\n--- Stage 2: Cryptographic Signature Adversarial Checks ---');
  await runAsyncTest('2.1 Reject signature verification when public key is missing or invalid', async () => {
    const res = await cosignEngine.verifySignature({
      signatureType: 'OFFLINE_KEYED',
      artifactHash: '0000000000000000000000000000000000000000000000000000000000000000',
      signatureValue: 'bad-sig',
      publicKey: 'bad-key'
    });
    assert.strictEqual(res.status, 'INVALID');
    assert.strictEqual(res.reasonCode, 'SIG-001');
  });

  await runAsyncTest('2.2 Verify KEYLESS mode is unsupported', async () => {
    const fakeHash = '1111111111111111111111111111111111111111111111111111111111111111';
    const bundleJson = {
      verificationMaterial: { content: 'test-cert' },
      messageSignature: { messageDigest: { digest: fakeHash } }
    };
    const res = await cosignEngine.verifySignature({
      signatureType: 'KEYLESS',
      artifactHash: fakeHash,
      bundleJson: bundleJson,
      expectedIssuer: 'https://token.actions.githubusercontent.com',
      expectedSubject: 'https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main'
    });
    assert.strictEqual(res.verificationStatus, 'FAILED');
    assert.strictEqual(res.reasonCode, 'SIG-009');
  });

  console.log('\n--- Stage 3: VEX Applicability & Risk Overlay Validation ---');
  logTest('3.1 Preserve raw CVSS score while calculating effective mitigated score', () => {
    const vulnerabilities = [
      { id: 'CVE-2026-0001', cvssScore: 9.8, severity: 'CRITICAL' },
      { id: 'CVE-2026-0002', cvssScore: 7.5, severity: 'HIGH' }
    ];
    const vexStatements = [
      { vulnerability_id: 'CVE-2026-0001', status: 'not_affected', justification: 'vulnerable_code_not_present' }
    ];
    const res = vexEngine.applyVexOverlays(vulnerabilities, vexStatements);
    assert.strictEqual(res.totalRawCvssScore, 17.3);
    assert.strictEqual(res.effectiveRiskScore, 3.75); // 9.8 mitigated to 0; (0 + 7.5)/2 = 3.75
    assert.strictEqual(res.highestEffectiveSeverity, 'HIGH');
  });

  logTest('3.2 Detect active unmitigated vulnerability affecting target', () => {
    const vulnerabilities = [
      { id: 'CVE-2026-9999', cvssScore: 8.5, severity: 'HIGH' }
    ];
    const vexStatements = [
      { vulnerability_id: 'CVE-2026-9999', status: 'affected' }
    ];
    const res = vexEngine.applyVexOverlays(vulnerabilities, vexStatements);
    assert.strictEqual(res.highestEffectiveSeverity, 'HIGH');
    assert.strictEqual(res.effectiveRiskScore, 8.5);
  });

  console.log('\n--- Stage 4: Deployment Context Policy Evaluation ---');
  logTest('4.1 Block PUBLIC network exposure with unmitigated CRITICAL/HIGH vulnerability', () => {
    const deploymentContext = {
      deploymentTier: 'PROD_CRITICAL',
      internetExposed: true,
      dataClassification: 'HIGH'
    };
    const vexSummary = {
      highestEffectiveSeverity: 'HIGH',
      effectiveRiskScore: 8.5
    };
    const res = contextEngine.evaluateDeploymentContext(deploymentContext, vexSummary);
    assert.strictEqual(res.compliant, false);
    assert.strictEqual(res.reasonCode, 'CTX-003');
  });

  logTest('4.2 Enforce risk threshold (< 7.0) for PROD environment without exception', () => {
    const deploymentContext = { deploymentTier: 'PROD', internetExposed: false };
    const vexSummary = { highestEffectiveSeverity: 'HIGH', effectiveRiskScore: 7.5 };
    const res = contextEngine.evaluateDeploymentContext(deploymentContext, vexSummary);
    assert.strictEqual(res.compliant, false);
    assert.strictEqual(res.reasonCode, 'CTX-002');
  });

  console.log('\n--- Stage 5: Trust-Evaluation Orchestration Engine ---');
  await runAsyncTest('5.1 Orchestrate full bundle and emit GOV-001 TRUSTED decision when all pass', async () => {
    const evidenceBundle = {
      sbomDocument: { sbom_id: 'test-sbom-1', sbom_json: { components: [] } },
      provenance: [{ status: 'VALID', slsa_level: 'SLSA_BUILD_LEVEL_3' }],
      signatures: [{ verification_status: 'VERIFIED', reasonCode: 'SIG-001' }],
      vexStatements: [],
      deploymentContext: { environment: 'DEV', network_exposure: 'INTERNAL', data_sensitivity: 'INTERNAL' },
      policyExceptions: []
    };
    const decision = await trustEngine.evaluateTrust(evidenceBundle);
    assert.strictEqual(decision.trustStatus, 'TRUSTED');
    assert.strictEqual(decision.reasonCode, 'GOV-001');
  });

  await runAsyncTest('5.2 Emit REJECTED (authoritative; not UNTRUSTED) when signature verification fails or is missing', async () => {
    const evidenceBundle = {
      sbomDocument: { sbom_id: 'test-sbom-1', sbom_json: '{"components":[]}' },
      provenance: [{ status: 'VALID', slsa_level: 'SLSA_BUILD_LEVEL_3' }],
      signatures: [],
      vexStatements: [],
      deploymentContext: { environment: 'DEV', network_exposure: 'INTERNAL' }
    };
    const decision = await trustEngine.evaluateTrust(evidenceBundle);
    assert.strictEqual(decision.trustStatus, 'REJECTED');
    assert.notStrictEqual(decision.trustStatus, 'UNTRUSTED', 'UNTRUSTED must not be emitted by authoritative evaluation');
    assert.strictEqual(decision.reasonCode, 'SIG-002');
  });

  await runAsyncTest('5.3 Emit CONDITIONALLY_ACCEPTED via EXC-001 when policy exception covers deployment violation', async () => {
    const futureDate = new Date(Date.now() + 86400000 * 30).toISOString();
    const evidenceBundle = {
      sbomDocument: {
        sbom_id: 'test-sbom-1',
        sbom_json: JSON.stringify({
          components: [
            { vulnerabilities: [{ id: 'CVE-2026-8888', cvssScore: 9.8, severity: 'CRITICAL' }] }
          ]
        })
      },
      provenance: [{ status: 'VALID', slsa_level: 'SLSA_BUILD_LEVEL_3' }],
      signatures: [{ verification_status: 'VERIFIED', reasonCode: 'SIG-001' }],
      vexStatements: [],
      deploymentContext: { environment: 'PROD_CRITICAL', network_exposure: 'PUBLIC' },
      policyExceptions: [{ id: 'exc-101', cve: 'CVE-2026-8888', status: 'APPROVED', valid_until: futureDate }]
    };
    const decision = await trustEngine.evaluateTrust(evidenceBundle);
    assert.strictEqual(decision.trustStatus, 'CONDITIONALLY_ACCEPTED');
    assert.notStrictEqual(decision.trustStatus, 'TRUSTED', 'Exception-covered violations must emit CONDITIONALLY_ACCEPTED, not TRUSTED');
    assert.notStrictEqual(decision.trustStatus, 'UNTRUSTED', 'UNTRUSTED must not be emitted by authoritative evaluation');
    assert.strictEqual(decision.reasonCode, 'EXC-001');
  });

  console.log('\n================================================================');
  console.log(`Validation Results: ${passed} PASSED | ${failed} FAILED`);
  console.log('================================================================\n');

  if (failed > 0) {
    process.exit(1);
  } else {
    console.log('All adversarial and governance validation checks passed successfully!');
    process.exit(0);
  }
}

main().catch(err => {
  console.error('Fatal error running suite:', err);
  process.exit(1);
});
