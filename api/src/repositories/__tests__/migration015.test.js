'use strict';
const db = require('../../config/database');

describe('Migration 015 Compatibility', () => {
  test('policy_exception_events.sbom_id matches sbom_documents.sbom_id type', async () => {
    const res = await db.pool.query(`
      SELECT table_name, data_type, character_maximum_length 
      FROM information_schema.columns 
      WHERE column_name = 'sbom_id' 
      AND table_name IN ('sbom_documents', 'policy_exception_events')
      ORDER BY table_name;
    `);
    
    expect(res.rows.length).toBe(2);
    
    const sbomDocCol = res.rows.find(r => r.table_name === 'sbom_documents');
    const exceptionEvCol = res.rows.find(r => r.table_name === 'policy_exception_events');
    
    expect(sbomDocCol.data_type).toBe(exceptionEvCol.data_type);
    expect(sbomDocCol.character_maximum_length).toBe(exceptionEvCol.character_maximum_length);
  });
});
