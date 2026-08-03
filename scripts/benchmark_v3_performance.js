#!/usr/bin/env node
/**
 * TPSR v3 High-Resolution Performance Benchmarking Script
 * 
 * Measures execution latency (min, max, p50, p95, avg in ms) and throughput (ops/sec)
 * across core TPSR v3 engines using process.hrtime.bigint():
 * 1. SLSA Provenance Verification Engine
 * 2. Sigstore Cosign Signature Verification Engine
 * 3. OpenVEX Applicability Overlay Engine
 * 4. Deployment Context Policy Evaluation Engine
 * 5. Trust-Evaluation Orchestration Engine
 */

'use strict';

const provenanceEngine = require('../api/src/utils/provenanceEngine');
const cosignEngine = require('../api/src/utils/cosignEngine');
const vexEngine = require('../api/src/utils/vexEngine');
const contextEngine = require('../api/src/utils/contextEngine');
const trustEngine = require('../api/src/utils/trustEngine');

const ITERATIONS = parseInt(process.env.BENCH_ITERATIONS || '1000', 10);

function formatLatency(bigintNs) {
  return Number(bigintNs) / 1e6; // ms
}

function calculateStats(latenciesMs) {
  latenciesMs.sort((a, b) => a - b);
  const sum = latenciesMs.reduce((acc, val) => acc + val, 0);
  const avg = sum / latenciesMs.length;
  const min = latenciesMs[0];
  const max = latenciesMs[latenciesMs.length - 1];
  const p50 = latenciesMs[Math.floor(latenciesMs.length * 0.5)];
  const p95 = latenciesMs[Math.floor(latenciesMs.length * 0.95)];
  const p99 = latenciesMs[Math.floor(latenciesMs.length * 0.99)];
  return { avg, min, max, p50, p95, p99, totalMs: sum };
}

async function benchmark(name, fn, isAsync = false) {
  console.log(`Benchmarking [${name}] over ${ITERATIONS} iterations...`);
  const latenciesMs = [];
  const startTotal = process.hrtime.bigint();

  for (let i = 0; i < ITERATIONS; i++) {
    const start = process.hrtime.bigint();
    if (isAsync) {
      await fn(i);
    } else {
      fn(i);
    }
    const end = process.hrtime.bigint();
    latenciesMs.push(formatLatency(end - start));
  }

  const endTotal = process.hrtime.bigint();
  const totalDurationSeconds = Number(endTotal - startTotal) / 1e9;
  const throughput = ITERATIONS / totalDurationSeconds;
  const stats = calculateStats(latenciesMs);

  console.log(`  -> Throughput: ${throughput.toFixed(2)} ops/sec`);
  console.log(`  -> Avg Latency: ${stats.avg.toFixed(4)} ms | Min: ${stats.min.toFixed(4)} ms | Max: ${stats.max.toFixed(4)} ms`);
  console.log(`  -> P50: ${stats.p50.toFixed(4)} ms | P95: ${stats.p95.toFixed(4)} ms | P99: ${stats.p99.toFixed(4)} ms\n`);

  return { name, iterations: ITERATIONS, throughput, ...stats };
}

async function main() {
  console.log('================================================================');
  console.log('     TPSR v3 High-Resolution Performance Benchmarking Suite     ');
  console.log('================================================================\n');

  const results = {};

  // 1. Provenance Benchmarking
  const sampleAttestation = {
    _type: 'https://in-toto.io/Statement/v0.1',
    predicateType: 'https://slsa.dev/provenance/v1',
    subject: [{ name: 'bench-app', digest: { sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0' } }],
    predicate: {
      buildDefinition: { buildType: 'https://slsa.dev/container-based-build/v0.1' },
      runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } }
    }
  };
  results.provenance = await benchmark('SLSA Provenance Verification', () => {
    provenanceEngine.verifyProvenance(sampleAttestation, 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0');
  });

  // 2. Signature Benchmarking
  const fs = require('fs');
  const path = require('path');
  const os = require('os');
  const { execSync } = require('child_process');

  const fakeHash = 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0';
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpsr-bench-'));
  const cosignBin = path.join(__dirname, '../bin/cosign');
  
  fs.writeFileSync(path.join(tmpDir, 'blob.txt'), fakeHash, 'utf8');
  execSync(`env COSIGN_PASSWORD="" ${cosignBin} generate-key-pair`, { cwd: tmpDir });
  execSync(`env COSIGN_PASSWORD="" ${cosignBin} sign-blob --key cosign.key --yes --tlog-upload=false --output-signature sig.bin blob.txt`, { cwd: tmpDir });
  
  const testPubKey = fs.readFileSync(path.join(tmpDir, 'cosign.pub'));
  const testSigValue = fs.readFileSync(path.join(tmpDir, 'sig.bin'), 'base64');
  
  results.signature = await benchmark('Sigstore Offline-Keyed Verification', async () => {
    await cosignEngine.verifySignature({
      signatureType: 'OFFLINE_KEYED',
      artifactHash: fakeHash,
      signatureValue: testSigValue,
      publicKey: testPubKey
    });
  }, true);

  fs.rmSync(tmpDir, { recursive: true, force: true });

  // 3. VEX Overlay Benchmarking
  const sampleVulns = [
    { id: 'CVE-2026-0001', cvssScore: 9.8, severity: 'CRITICAL' },
    { id: 'CVE-2026-0002', cvssScore: 8.1, severity: 'HIGH' },
    { id: 'CVE-2026-0003', cvssScore: 5.4, severity: 'MEDIUM' }
  ];
  const sampleVex = [
    { vulnerability_id: 'CVE-2026-0001', status: 'not_affected', justification: 'vulnerable_code_not_present' },
    { vulnerability_id: 'CVE-2026-0002', status: 'fixed' }
  ];
  results.vex = await benchmark('VEX Applicability Analysis', () => {
    vexEngine.applyVexOverlays(sampleVulns, sampleVex);
  });

  // 4. Deployment Context Benchmarking
  const sampleContext = { deploymentTier: 'PROD_CRITICAL', internetExposed: false, dataClassification: 'CONFIDENTIAL' };
  const sampleVexSummary = { highestEffectiveSeverity: 'MEDIUM', effectiveRiskScore: 3.5 };
  results.context = await benchmark('Deployment Context Policy Evaluation', () => {
    contextEngine.evaluateDeploymentContext(sampleContext, sampleVexSummary);
  });

  // 5. Trust Orchestration Benchmarking
  const sampleEvidenceBundle = {
    sbomDocument: { sbom_id: 'bench-sbom-100', sbom_json: { components: [{ vulnerabilities: sampleVulns }] } },
    provenance: [{ status: 'VALID', slsa_level: 'SLSA_BUILD_LEVEL_3' }],
    signatures: [{ verification_status: 'VERIFIED', reasonCode: 'SIG-001' }],
    vexStatements: sampleVex,
    deploymentContext: { environment: 'PROD', network_exposure: 'INTERNAL', data_sensitivity: 'CONFIDENTIAL' },
    policyExceptions: []
  };
  results.trust = await benchmark('Trust-Evaluation Orchestration Engine', async () => {
    await trustEngine.evaluateTrust(sampleEvidenceBundle);
  }, true);

  console.log('================================================================');
  console.log('               Benchmarking Summary & Performance               ');
  console.log('================================================================');
  Object.values(results).forEach(r => {
    console.log(`${r.name.padEnd(38)} | Throughput: ${r.throughput.toFixed(0).padStart(7)} ops/s | P95: ${r.p95.toFixed(4).padStart(8)} ms`);
  });
  console.log('================================================================\n');

  process.exit(0);
}

main().catch(err => {
  console.error('Fatal benchmarking error:', err);
  process.exit(1);
});
