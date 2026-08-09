'use strict';
const db = require('../../config/database');
const fs = require('fs');
const path = require('path');

describe('Migration 013 - CAECTD explanation fields', () => {
  let client;

  beforeAll(async () => {
    client = await db.pool.connect();
    // 1. Run migrations through 012 is already done by setup
  });

  afterAll(async () => {
    if (client) client.release();
  });

  it('preserves historical decisions (TPSR v2 data intact)', async () => {
    // 1. Insert a dummy SBOM record to satisfy foreign key
    await client.query(`
      INSERT INTO sbom_documents (sbom_id, build_id, software_name, software_version, format, sbom_hash, sbom_json, status)
      VALUES ('test-v2-sbom', 'b1', 'test-app', '1.0.0', 'SPDX', 'sha256:1234', '{}'::jsonb, 'REGISTERED'),
             ('test-caectd-sbom', 'b2', 'test-app', '2.0.0', 'SPDX', 'sha256:5678', '{}'::jsonb, 'REGISTERED')
      ON CONFLICT (sbom_id) DO NOTHING;
    `);

    // 2. Insert a pre-013 decision (simulated)
    const res = await client.query(`
      INSERT INTO trust_decision_history (sbom_id, trust_status, reason_code, reason_description, evidence_summary, policy_version, evaluated_by)
      VALUES ('test-v2-sbom', 'TRUSTED', 'TRST-000', 'Legacy test', '{}'::jsonb, '3.0', 'system')
      RETURNING *;
    `);
    expect(res.rows[0].sbom_id).toBe('test-v2-sbom');
  });

  it('applies migration 013 safely', async () => {
    // 3. Apply 013
    const migrationPath = path.join(__dirname, '../../../../db/migrations/013_caectd_explanation_fields.sql');
    const sql = fs.readFileSync(migrationPath, 'utf8');
    await client.query(sql);

    // 4. Verify historical decision remains readable
    const res = await client.query(`SELECT * FROM trust_decision_history WHERE sbom_id = 'test-v2-sbom'`);
    expect(res.rows[0].caectd_model_version).toBeNull();

    // 5. Insert a CAECTD 0.1 decision
    const newRes = await client.query(`
      INSERT INTO trust_decision_history (sbom_id, trust_status, reason_code, reason_description, evidence_summary, policy_version, evaluated_by, caectd_model_version, triggered_rule_ids)
      VALUES ('test-caectd-sbom', 'TRUSTED', 'GOV-001', 'CAECTD test', '{}'::jsonb, '3.0', 'system', '0.1', '["CAECTD-R031"]'::jsonb)
      RETURNING *;
    `);
    
    // 6. Verify all new fields
    expect(newRes.rows[0].caectd_model_version).toBe('0.1');
    expect(newRes.rows[0].triggered_rule_ids).toEqual(['CAECTD-R031']);

    // 7. Apply 013 again
    await client.query(sql);
    
    // 8. Confirm success, no duplicate constraint or index
    const resAgain = await client.query(`SELECT * FROM trust_decision_history WHERE sbom_id = 'test-caectd-sbom'`);
    expect(resAgain.rows[0].caectd_model_version).toBe('0.1');
  });
});
