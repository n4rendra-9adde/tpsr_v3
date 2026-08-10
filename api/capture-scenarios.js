const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const crypto = require('crypto');
const axios = require('axios');
const { Pool } = require('pg');

const FINAL_RUN_ID = `point-5-context-${new Date().toISOString().replace(/[:\.\-]/g, '').slice(0, 15)}Z`;
const OUTPUT_DIR = '/tmp/tpsr-mentor-feedback/point-05/live-final';
const API_URL = 'http://localhost:3000/api';
const REPO_ROOT = '/home/ng/Documents/tpsr_v2';

const dbPool = new Pool({
  host: 'localhost',
  port: 5432,
  user: 'tpsr',
  password: 'tpsrpassword',
  database: 'tpsr'
});

async function main() {
  console.log(`Starting live scenario capture: ${FINAL_RUN_ID}`);
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  // 1. Generate cosign keypair
  const cosignKeyPath = path.join(OUTPUT_DIR, 'cosign.key');
  const cosignPubPath = path.join(OUTPUT_DIR, 'cosign.pub');
  process.env.COSIGN_PASSWORD = '';
  execSync(`${REPO_ROOT}/bin/cosign generate-key-pair`, { cwd: OUTPUT_DIR, env: process.env });
  
  const pubKey = fs.readFileSync(cosignPubPath, 'utf8');
  
  // 2. Temporarily patch TRUST_POLICY.json
  const policyPath = path.join(REPO_ROOT, 'docs/TRUST_POLICY.json');
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const policy = JSON.parse(originalPolicy);
  
  for (const identity in policy.signaturePolicy.trustedPublicKeys) {
    policy.signaturePolicy.trustedPublicKeys[identity] = pubKey;
  }
  const fingerprintHex = crypto.createHash('sha256').update(pubKey.trim()).digest('hex');
  for (const env in policy.contextAuthorities) {
    policy.contextAuthorities[env].approvedPublicKeyFingerprints = [fingerprintHex];
  }
  fs.writeFileSync(policyPath, JSON.stringify(policy, null, 2));
  
  // 3. Restart backend
  console.log('Restarting backend API...');
  try { execSync('pkill -f "node src/server.js"'); } catch(e){}
  await new Promise(r => setTimeout(r, 2000));
  const serverProc = require('child_process').spawn('node', ['src/server.js'], { cwd: path.join(REPO_ROOT, 'api'), detached: true, stdio: 'ignore' });
  serverProc.unref();
  
  // Wait for health
  let healthy = false;
  for (let i = 0; i < 20; i++) {
    try {
      await axios.get(`${API_URL}/../health`);
      healthy = true;
      break;
    } catch (e) {
      await new Promise(r => setTimeout(r, 1000));
    }
  }
  if (!healthy) throw new Error('Server did not start');

  // Helpers
  const signBlob = (payloadStr) => {
    const tmpBlob = path.join(OUTPUT_DIR, 'tmp.blob');
    fs.writeFileSync(tmpBlob, payloadStr);
    const sigOut = execSync(`${REPO_ROOT}/bin/cosign sign-blob --key ${cosignKeyPath} --tlog-upload=false ${tmpBlob}`, { env: process.env }).toString().trim();
    return sigOut;
  };

  const createSbom = async (idx, name, vulns = []) => {
    const sbomId = `${FINAL_RUN_ID}-${idx}`;
    const sbom = {
      bomFormat: "CycloneDX",
      specVersion: "1.4",
      metadata: { component: { type: "application", name: "TestApp", version: "1.0" } },
      components: [],
      vulnerabilities: vulns
    };
    
    console.log(`Submitting SBOM: ${sbomId}`);
    const subRes = await axios.post(`${API_URL}/submit`, {
      sbomID: sbomId,
      sbom: JSON.stringify(sbom),
      buildID: `build-${idx}`,
      softwareName: name,
      softwareVersion: "1.0",
      format: "CycloneDX",
      offChainRef: "ipfs://...",
      signatures: ["dummy"]
    }, { headers: { 'x-user-id': 'u1', 'x-user-role': 'developer' } });
    
    return { sbomId, sbomHash: subRes.data.hash };
  };
  
  const submitSig = async (sbomId, sbomHash, signer) => {
    const sig = signBlob(sbomHash);
    await axios.post(`${API_URL}/v1/sbom/${sbomId}/signatures`, {
      signatureType: "OFFLINE_KEYED",
      signatureValue: sig,
      publicKey: pubKey,
      verificationMode: "strict",
      signerIdentity: signer,
      artifactHash: sbomHash
    }, { headers: { 'x-user-id': 'u1', 'x-user-role': 'developer' } });
  };
  
  const submitProv = async (sbomId, sbomHash) => {
    const prov = {
      _type: "https://in-toto.io/Statement/v0.1",
      subject: [{ name: "artifact", digest: { sha256: sbomHash } }],
      predicateType: "https://slsa.dev/provenance/v0.2",
      predicate: {
        builder: { id: "https://github.com/actions/runner/github-hosted" },
        buildType: "https://actions.github.io/buildtypes/workflow/v1",
        invocation: { configSource: { uri: "https://github.com/org/repo" } }
      }
    };
    const b64Payload = Buffer.from(JSON.stringify(prov)).toString('base64');
    const env = {
      payloadType: "application/vnd.in-toto+json",
      payload: b64Payload,
      signatures: [{ sig: "" }]
    };
    const pae = `DSSEv1 ${env.payloadType.length} ${env.payloadType} ${JSON.stringify(prov).length} ${JSON.stringify(prov)}`;
    const sig = signBlob(pae);
    env.signatures[0].sig = sig;

    await axios.post(`${API_URL}/v1/sbom/${sbomId}/provenance`, {
      provenanceType: "SLSA",
      envelope: env,
      publicKey: pubKey,
      verificationMode: "strict",
      expectedArtifactHash: sbomHash,
      signerIdentity: "build-officer@tpsr.com"
    }, { headers: { 'x-user-id': 'u1', 'x-user-role': 'developer' } });
  };
  
  const submitVex = async (sbomId, sbomHash, vulnId, status, justification) => {
    const vex = {
      _type: "https://in-toto.io/Statement/v0.1",
      subject: [{ name: "artifact", digest: { sha256: sbomHash } }],
      predicateType: "https://openvex.dev/ns/v0.2.0",
      predicate: {
        timestamp: new Date().toISOString(),
        statements: [{
          vulnerability: { name: vulnId },
          products: [{ "@id": sbomHash }],
          status: status,
          justification: justification || 'component_not_present',
          impact_statement: 'Component not compiled in'
        }]
      }
    };
    const b64Payload = Buffer.from(JSON.stringify(vex)).toString('base64');
    const env = {
      payloadType: "application/vnd.in-toto+json",
      payload: b64Payload,
      signatures: [{ sig: "" }]
    };
    const pae = `DSSEv1 ${env.payloadType.length} ${env.payloadType} ${JSON.stringify(vex).length} ${JSON.stringify(vex)}`;
    const sig = signBlob(pae);
    env.signatures[0].sig = sig;

    await axios.post(`${API_URL}/v1/sbom/${sbomId}/vex`, {
      envelope: env,
      publicKey: pubKey,
      signatureType: 'OFFLINE_KEYED',
      targetContext: { vulnerabilityId: vulnId, productIdentifier: sbomHash },
      verificationMode: "strict",
      expectedArtifactHash: sbomHash,
      signerIdentity: "security-team@tpsr.com"
    }, { headers: { 'x-user-id': 'u1', 'x-user-role': 'developer' } });
  };
  
  const submitContext = async (sbomId, sbomHash, envVal = 'PRODUCTION', exploitability = 'UNKNOWN') => {
    const ctx = {
      environment: envVal,
      sbomId: sbomId,
      internetExposure: 'PUBLIC',
      assetCriticality: 'HIGH',
      componentPresence: exploitability.componentPresence || 'UNKNOWN',
      runtimeExecution: exploitability.runtimeExecution || 'UNKNOWN',
      validUntil: new Date(Date.now() + 86400000 * 0.5).toISOString(),
      assertedAt: new Date().toISOString(),
      assertorRole: 'security',
      assertedBy: 'u1',
      digestManifestDigest: `sha256:${sbomHash}`,
      signerIdentity: 'jenkins-service@tpsr.com'
    };
    
    const sortKeys = (obj) => {
      if (typeof obj !== 'object' || obj === null) return obj;
      if (Array.isArray(obj)) return obj.map(sortKeys);
      const sortedObj = {};
      Object.keys(obj).sort().forEach(key => {
        sortedObj[key] = sortKeys(obj[key]);
      });
      return sortedObj;
    };
    
    // Create the exact payload that will be canonicalized
    const fullPayload = { ...ctx, assertorRole: 'security', assertedBy: 'u1' };
    delete fullPayload.signerIdentity;
    const sortedPayload = sortKeys(fullPayload);
    const canonicalBytes = JSON.stringify(sortedPayload);
    const payloadHash = crypto.createHash('sha256').update(canonicalBytes, 'utf8').digest('hex');
    
    const sig = signBlob(payloadHash);

    try {
      await axios.post(`${API_URL}/v1/sbom/${sbomId}/context/assertions`, {
        assertion: ctx,
        signature: sig,
        publicKey: pubKey,
        verificationMode: "strict"
      }, { headers: { 'x-user-id': 'u1', 'x-user-role': 'security' } });
    } catch (err) {
      console.log(`Context submission failed (expected for conflicts): ${err.response?.data?.error || err.message}`);
    }
  };
  
  const submitException = async (sbomId, vulnId, expired = false) => {
    const reqBody = {
      policyRuleId: 'CAECTD-R017',
      reasonCode: 'EXC-001',
      vulnerabilityIds: [vulnId],
      justification: 'Vulnerability mitigated by WAF',
      compensatingControls: ['WAF_BLOCKING'],
      remediationPlan: 'Will patch in next sprint',
      residualRisk: 'LOW',
      validUntil: expired ? new Date(Date.now() + 2000).toISOString() : new Date(Date.now() + 86400000 * 30).toISOString()
    };

    const res = await axios.post(`${API_URL}/v1/sbom/${sbomId}/exceptions`, reqBody, { headers: { 'x-user-id': 'dev1', 'x-user-role': 'developer' } });
    const excId = res.data.id;
    
    // Auto-approve via the correct approve endpoint
    await axios.post(`${API_URL}/v1/sbom/${sbomId}/exceptions/${excId}/approve`, { approvalComment: "Approved by security" }, { headers: { 'x-user-id': 'admin', 'x-user-role': 'admin' } });
  };
  
  const evalAndSave = async (sbomId, scenarioName) => {
    console.log(`Evaluating trust for ${scenarioName}...`);
    await axios.post(`${API_URL}/v1/sbom/${sbomId}/trust-evaluation`, {}, { headers: { 'x-user-role': 'admin', 'x-user-id': 'u1' } });
    const decRes = await axios.get(`${API_URL}/v1/sbom/${sbomId}/trust-decision`, { headers: { 'x-user-role': 'admin', 'x-user-id': 'u1' } });
    fs.writeFileSync(path.join(OUTPUT_DIR, `${scenarioName}-http-response.json`), JSON.stringify(decRes.data, null, 2));
    
    const pgRes = await dbPool.query('SELECT * FROM trust_decision_history WHERE sbom_id = $1 ORDER BY evaluated_at DESC LIMIT 1', [sbomId]);
    fs.writeFileSync(path.join(OUTPUT_DIR, `${scenarioName}-pg-record.json`), JSON.stringify(pgRes.rows[0], null, 2));
  };
  
  const vulnsCritical = [{ id: "CVE-2026-9999", ratings: [{ score: 9.8, severity: "critical", method: "CVSSv3" }] }];

  try {
    // S1: PROD_PUBLIC_EXPLOITABLE (Critical, Prod, no VEX) -> REJECTED, CTX-003
    let s = await createSbom(1, 'scenario-01-production-public', vulnsCritical);
    await submitSig(s.sbomId, s.sbomHash, 'security-release@tpsr.com');
    await submitProv(s.sbomId, s.sbomHash);
    await submitContext(s.sbomId, s.sbomHash, 'PRODUCTION', { componentPresence: 'PRESENT', runtimeExecution: 'EXECUTED' });
    await evalAndSave(s.sbomId, 'scenario-01-production-public');

    // S2: DEV_INTERNAL_ACCEPTED (Critical, Dev, no VEX) -> TRUSTED (Dev multiplier reduces risk)
    s = await createSbom(2, 'scenario-02-development-internal', vulnsCritical);
    await submitSig(s.sbomId, s.sbomHash, 'security-release@tpsr.com');
    await submitProv(s.sbomId, s.sbomHash);
    await submitContext(s.sbomId, s.sbomHash, 'DEVELOPMENT');
    await evalAndSave(s.sbomId, 'scenario-02-development-internal');

    // S3: PROD_VEX_NOT_AFFECTED (Critical, Prod, VEX Not Affected) -> TRUSTED
    s = await createSbom(3, 'scenario-03-trusted-not-affected-vex', vulnsCritical);
    await submitSig(s.sbomId, s.sbomHash, 'security-release@tpsr.com');
    await submitProv(s.sbomId, s.sbomHash);
    await submitVex(s.sbomId, s.sbomHash, 'CVE-2026-9999', 'not_affected', 'vulnerable_code_not_in_execute_path');
    await submitContext(s.sbomId, s.sbomHash, 'PRODUCTION');
    await evalAndSave(s.sbomId, 'scenario-03-trusted-not-affected-vex');

    // S4: UNDER_INVESTIGATION VEX
    s = await createSbom(4, 'scenario-04-under-investigation-vex', vulnsCritical);
    await submitSig(s.sbomId, s.sbomHash, 'security-release@tpsr.com');
    await submitProv(s.sbomId, s.sbomHash);
    await submitVex(s.sbomId, s.sbomHash, 'CVE-2026-9999', 'under_investigation', 'under_investigation');
    await submitContext(s.sbomId, s.sbomHash, 'PRODUCTION');
    await evalAndSave(s.sbomId, 'scenario-04-under-investigation-vex');

    // S5: NO_CONTEXT (Critical, no context) -> REVIEW_REQUIRED
    s = await createSbom(5, 'scenario-05-missing-context', vulnsCritical);
    await submitSig(s.sbomId, s.sbomHash, 'security-release@tpsr.com');
    await submitProv(s.sbomId, s.sbomHash);
    await evalAndSave(s.sbomId, 'scenario-05-missing-context');

    // S6: CONFLICTING_CONTEXT
    s = await createSbom(6, 'scenario-06-conflicting-context', vulnsCritical);
    await submitSig(s.sbomId, s.sbomHash, 'security-release@tpsr.com');
    await submitProv(s.sbomId, s.sbomHash);
    await submitContext(s.sbomId, s.sbomHash, 'PRODUCTION');
    await submitContext(s.sbomId, s.sbomHash, 'STAGING');
    await evalAndSave(s.sbomId, 'scenario-06-conflicting-context');
    
    // S7: ACTIVE_EXCEPTION
    s = await createSbom(7, 'scenario-07-active-exception', vulnsCritical);
    await submitSig(s.sbomId, s.sbomHash, 'security-release@tpsr.com');
    await submitProv(s.sbomId, s.sbomHash);
    await submitContext(s.sbomId, s.sbomHash, 'PRODUCTION');
    await submitException(s.sbomId, 'CVE-2026-9999', false);
    await evalAndSave(s.sbomId, 'scenario-07-active-exception');
    
    // S8: EXPIRED_EXCEPTION
    s = await createSbom(8, 'scenario-08-expired-exception', vulnsCritical);
    await submitSig(s.sbomId, s.sbomHash, 'security-release@tpsr.com');
    await submitProv(s.sbomId, s.sbomHash);
    await submitContext(s.sbomId, s.sbomHash, 'PRODUCTION');
    await submitException(s.sbomId, 'CVE-2026-9999', true);
    
    // Evaluate while ACTIVE to get CONDITIONALLY_ACCEPTED
    const activeEval = await axios.post(`${API_URL}/v1/sbom/${s.sbomId}/trust-evaluation`, {}, { headers: { 'x-user-role': 'admin', 'x-user-id': 'u1' } });
    const initialDecisionId = activeEval.data.decisionId || activeEval.data.id;
    
    // Get the exception ID
    const excRes = await dbPool.query('SELECT id, status FROM policy_exceptions WHERE sbom_id = $1', [s.sbomId]);
    const exceptionId = excRes.rows[0].id;
    const initialStatus = excRes.rows[0].status; // ACTIVE
    
    // Wait for validity to expire
    console.log('Waiting for exception to expire (2.5s)...');
    await new Promise(r => setTimeout(r, 2500));
    
    // Run worker
    console.log('Running expiry worker...');
    const worker = require(path.join(REPO_ROOT, 'api/src/workers/exceptionExpiryWorker.js'));
    await worker.processExpiredExceptions();
    
    // Gather post-worker data
    const postExcRes = await dbPool.query('SELECT status FROM policy_exceptions WHERE id = $1', [exceptionId]);
    const postStatus = postExcRes.rows[0].status; // EXPIRED
    
    const eventRes = await dbPool.query('SELECT event_id, new_status FROM policy_exception_events WHERE exception_id = $1 ORDER BY event_timestamp DESC LIMIT 1', [exceptionId]);
    const expiryEventId = eventRes.rows.length > 0 ? eventRes.rows[0].event_id : null;
    
    const reevalRes = await dbPool.query('SELECT id, trust_status FROM trust_decision_history WHERE sbom_id = $1 ORDER BY evaluated_at DESC LIMIT 1', [s.sbomId]);
    const reevaluatedDecisionId = reevalRes.rows[0].id;
    const reevaluatedTrustStatus = reevalRes.rows[0].trust_status;
    
    const outboxRes = await dbPool.query('SELECT id FROM ledger_outbox WHERE decision_id = $1', [reevaluatedDecisionId]);
    const outboxId = outboxRes.rows.length > 0 ? outboxRes.rows[0].id : null;
    
    const prevDecisionRes = await dbPool.query('SELECT trust_status FROM trust_decision_history WHERE id = $1', [initialDecisionId]);
    const prevDecisionPreserved = prevDecisionRes.rows.length > 0 && prevDecisionRes.rows[0].trust_status === 'CONDITIONALLY_ACCEPTED';
    
    fs.writeFileSync(path.join(OUTPUT_DIR, 'scenario-08-expiry-sequence.json'), JSON.stringify({
      exceptionId,
      initialStatus,
      initialDecisionId,
      expiryEventId,
      postStatus,
      reevaluatedDecisionId,
      reevaluatedTrustStatus,
      outboxId,
      prevDecisionPreserved
    }, null, 2));

    // Evaluate after EXPIRED (already evaluated by worker, but we save pg-record)
    await evalAndSave(s.sbomId, 'scenario-08-expired-exception');
    
    // Capture second run metrics for S8
    const beforeEvt = await dbPool.query('SELECT count(*) FROM policy_exception_events');
    const beforeDec = await dbPool.query('SELECT count(*) FROM trust_decision_history');
    const beforeOut = await dbPool.query('SELECT count(*) FROM ledger_outbox');
    
    await worker.processExpiredExceptions();
    
    const afterEvt = await dbPool.query('SELECT count(*) FROM policy_exception_events');
    const afterDec = await dbPool.query('SELECT count(*) FROM trust_decision_history');
    const afterOut = await dbPool.query('SELECT count(*) FROM ledger_outbox');
    
    fs.writeFileSync(path.join(OUTPUT_DIR, 'expiry-second-run.json'), JSON.stringify({
      events: Number(afterEvt.rows[0].count) - Number(beforeEvt.rows[0].count),
      decisions: Number(afterDec.rows[0].count) - Number(beforeDec.rows[0].count),
      outboxRows: Number(afterOut.rows[0].count) - Number(beforeOut.rows[0].count)
    }, null, 2));

    console.log('Successfully captured 8 live scenarios.');

  } catch (err) {
    if (err.response && err.response.data) {
      console.error(err.response.data);
    } else {
      console.error(err);
    }
  } finally {
    // Restore
    fs.writeFileSync(policyPath, originalPolicy);
    console.log('Restored TRUST_POLICY.json. Restarting server to clean up...');
    try { execSync('pkill -f "node src/server.js"'); } catch(e){}
    await new Promise(r => setTimeout(r, 2000));
    const serverProc2 = require('child_process').spawn('node', ['src/server.js'], { cwd: path.join(REPO_ROOT, 'api'), detached: true, stdio: 'ignore' });
    serverProc2.unref();
    dbPool.end();
  }
}

main();
