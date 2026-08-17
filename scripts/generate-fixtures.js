const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const testFixturesDir = path.join(__dirname, '../test-fixtures');
if (!fs.existsSync(testFixturesDir)) {
  fs.mkdirSync(testFixturesDir, { recursive: true });
}

// Generate Keypair
const tmpDir = fs.mkdtempSync('/tmp/tpsr-key-');
const cosignBin = path.join(__dirname, '../bin/cosign');

execSync(`${cosignBin} generate-key-pair`, { cwd: tmpDir, env: { ...process.env, COSIGN_PASSWORD: '' } });

const pubKey = fs.readFileSync(path.join(tmpDir, 'cosign.pub'), 'utf8');

// 1. Valid SBOM
const sbomId = `SBOM-LIVE-${Date.now()}`;
const sbomPayload = {
  serialNumber: sbomId,
  buildID: 'auto-build-1',
  softwareName: 'tpsr-live-test',
  softwareVersion: '1.0.0',
  format: 'CycloneDX',
  offChainRef: 'https://registry.tpsr.com/sbom',
  signatures: [{ type: 'cosign', value: 'dummy' }]
};

const sbomPath = path.join(testFixturesDir, 'live-sbom.json');
fs.writeFileSync(sbomPath, JSON.stringify(sbomPayload, null, 2));
const sbomHash = crypto.createHash('sha256').update(JSON.stringify(sbomPayload)).digest('hex');

// 2. Valid Provenance
const attestationPayload = {
  buildDefinition: {
    buildType: "https://actions.github.io/buildtypes/workflow/v1",
    externalParameters: {
      source: {
        uri: "https://github.com/org/repo"
      }
    }
  },
  runDetails: {
    builder: { id: "https://github.com/actions/runner/github-hosted" },
    metadata: {
      startedOn: new Date(Date.now() - 3600000).toISOString(),
      finishedOn: new Date().toISOString()
    }
  }
};

const payloadStr = JSON.stringify(attestationPayload);
const payloadPath = path.join(tmpDir, 'payload.json');
fs.writeFileSync(payloadPath, payloadStr);
const b64Payload = Buffer.from(payloadStr).toString('base64');

// Create a dummy blob that is verified? Wait, verify-blob-attestation checks the blob.
// In verifyAttestationEnvelope, it writes 'dummy' to dummyBlob.
const dummyBlob = path.join(tmpDir, 'dummy.txt');
fs.writeFileSync(dummyBlob, 'dummy');

// Sign it - without --insecure-ignore-tlog, just use --tlog-upload=false or --yes
execSync(`${cosignBin} attest-blob --key cosign.key --predicate ${payloadPath} --type https://slsa.dev/provenance/v1 --tlog-upload=false --yes ${dummyBlob} > signed.json`, { cwd: tmpDir, env: { ...process.env, COSIGN_PASSWORD: '' } });

// Extract envelope from signed.json
const signedOutput = fs.readFileSync(path.join(tmpDir, 'signed.json'), 'utf8');
const envelopeLines = signedOutput.split('\n').filter(l => l.startsWith('{'));
// Actually, attest-blob outputs the JSON envelope directly if not uploading to tlog
let envelopeStr = signedOutput;
if (signedOutput.includes('{')) {
  envelopeStr = signedOutput.substring(signedOutput.indexOf('{'));
}
const envelope = JSON.parse(envelopeStr);

const provPayload = {
  envelope: envelope,
  signatureType: 'OFFLINE_KEYED',
  publicKey: pubKey,
  expectedArtifactHash: crypto.createHash('sha256').update('dummy').digest('hex')
};

const provPath = path.join(testFixturesDir, 'live-prov.json');
fs.writeFileSync(provPath, JSON.stringify(provPayload, null, 2));

console.log("Fixtures generated in test-fixtures/!");

fs.rmSync(tmpDir, { recursive: true, force: true });
