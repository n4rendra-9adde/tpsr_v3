'use strict';
const db = require('../config/database');

async function insertSnapshot(snapshotData) {
    const query = `
        INSERT INTO decision_snapshots 
        (snapshot_id, sbom_id, decision, policy_id, policy_generation, model_version, evaluated_at, snapshot_hash, payload)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
    `;
    const values = [
        snapshotData.snapshotId,
        snapshotData.sbomId,
        snapshotData.decision,
        snapshotData.policyId,
        snapshotData.policyGeneration,
        snapshotData.modelVersion,
        snapshotData.evaluatedAt,
        snapshotData.snapshotHash,
        JSON.stringify(snapshotData.payload)
    ];
    try {
        const res = await db.pool.query(query, values);
        return res.rows[0];
    } catch (e) {
        throw e;
    }
}

async function getSnapshot(snapshotId) {
    const query = `SELECT * FROM decision_snapshots WHERE snapshot_id = $1`;
    const res = await db.pool.query(query, [snapshotId]);
    return res.rows[0];
}

module.exports = {
    insertSnapshot,
    getSnapshot
};
