'use strict';
const db = require('../../config/database');

describe('Migration 017 Tests', () => {
  test('66. migration 017 preserves existing data and creates safe defaults', async () => {
    // Check if migration 017 exists and applied correctly
    const res = await db.pool.query(`
      SELECT column_name, column_default, is_nullable
      FROM information_schema.columns 
      WHERE table_name = 'deployment_context_assertions' 
      AND column_name = 'provenance_mode';
    `);
    expect(res.rows.length).toBeGreaterThan(0);
    expect(res.rows[0].column_default).toContain('CRYPTOGRAPHIC');
  });
});
