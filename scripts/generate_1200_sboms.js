const { Pool } = require('pg');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid'); // Will use crypto if uuid isn't there, or just rely on PG gen_random_uuid()

const pool = new Pool({
  host: 'localhost',
  port: 5432,
  user: 'tpsr',
  password: 'tpsrpassword',
  database: 'tpsr'
});

async function generateData() {
  const client = await pool.connect();
  try {
    console.log('[+] Starting generation of 1200 SBOMs...');
    await client.query('BEGIN');
    
    const softwares = ['payment-gateway', 'auth-service', 'user-profile', 'notification-engine', 'billing-api'];
    const statuses = ['ACTIVE', 'SUPERSEDED', 'REGISTERED', 'REJECTED'];
    const trustStatuses = ['TRUSTED', 'CONDITIONALLY_ACCEPTED', 'REVIEW_REQUIRED', 'REJECTED'];

    for (let i = 0; i < 1250; i++) {
      const sbomId = `SBOM-GEN-${Date.now()}-${i}`;
      const swName = softwares[i % softwares.length];
      const version = `1.${Math.floor(i / 100)}.${i % 100}`;
      
      let status = statuses[Math.floor(Math.random() * statuses.length)];
      let trustStatus = trustStatuses[Math.floor(Math.random() * trustStatuses.length)];
      
      // Correlate statuses logically
      if (status === 'ACTIVE' && trustStatus === 'REJECTED') trustStatus = 'TRUSTED';
      if (status === 'ACTIVE' && trustStatus === 'REVIEW_REQUIRED') status = 'REGISTERED';
      
      const sbomJson = {
        bomFormat: 'CycloneDX',
        specVersion: '1.4',
        serialNumber: sbomId,
        metadata: {
          component: { name: swName, version: version }
        },
        components: [
          { name: 'express', version: '4.17.1' },
          { name: 'lodash', version: '4.17.21' }
        ]
      };
      
      const sbomHash = crypto.createHash('sha256').update(JSON.stringify(sbomJson)).digest('hex');
      const docId = uuidv4();
      
      await client.query(`
        INSERT INTO sbom_documents 
        (id, sbom_id, build_id, software_name, software_version, format, status, sbom_hash, sbom_json, submitter_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW() - interval '${Math.floor(Math.random() * 30)} days')
      `, [docId, sbomId, `build-${i}`, swName, version, 'CycloneDX', status, sbomHash, sbomJson, 'vendorAdmin']);

      const decId = uuidv4();
      await client.query(`
        INSERT INTO trust_decision_history
        (id, sbom_id, trust_status, reason_code, reason_description, evidence_summary, policy_version, evaluated_by, evaluated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW() - interval '${Math.floor(Math.random() * 30)} days')
      `, [decId, sbomId, trustStatus, `RSN-${trustStatus.substring(0, 10)}`, `Evaluated via CAECTD Engine`, JSON.stringify({}), 'v1', 'securityAdmin']);
      
      // If CONDITIONALLY_ACCEPTED, add an exception
      if (trustStatus === 'CONDITIONALLY_ACCEPTED') {
        await client.query(`
          INSERT INTO policy_exceptions
          (id, sbom_id, violation_id, violation_type, justification, compensating_controls, requested_by, approved_by, status, valid_until)
          VALUES (gen_random_uuid(), $1, 'CVE-2021-1234', 'VULNERABILITY', 'Functionally isolated via firewall.', '["Firewall"]', 'vendorAdmin', 'securityAdmin', 'APPROVED', NOW() + interval '30 days')
        `, [sbomId]);
      }
      
      if (i % 100 === 0) console.log(`[+] Inserted ${i} records...`);
    }

    await client.query('COMMIT');
    console.log('[+] Generation complete! 1250 SBOMs inserted.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error generating data:', err);
  } finally {
    client.release();
    pool.end();
  }
}

generateData();
