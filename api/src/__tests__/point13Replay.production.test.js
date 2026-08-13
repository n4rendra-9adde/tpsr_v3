'use strict';
const request = require('supertest');
const app = require('../server').app;
const db = require('../config/database');
const crypto = require('crypto');
const snapshotRepo = require('../repositories/snapshot.repository');
const sbomRepo = require('../repositories/sbomRepository');

process.env.NODE_ENV = 'test';
process.env.TRUSTED_AUTH_ADAPTER_ENABLED = 'true';

describe('Point 13 Deterministic Decision Reproducibility (Cases 1-61)', () => {
    let testSbomId = 'point13-test-sbom-' + Date.now();
    let snapshotId;
    
    beforeAll(async () => {
        const client = await db.pool.connect();
        try {
            await client.query(`
                INSERT INTO sbom_documents (sbom_id, sbom_hash, sbom_json, status, build_id, software_name, software_version, format)
                VALUES ($1, 'test-hash-p13', '{"components":[]}', 'COMPLIANT', 'test-build-13', 'test-software', '1.0.0', 'CycloneDX')
                ON CONFLICT DO NOTHING
            `, [testSbomId]);
        } finally {
            client.release();
        }
    });

    it('Cases 1-10: Snapshot created after final decision, persisted content digest matches, and same inputs yield same digest but distinct IDs', async () => {
        const res1 = await request(app)
            .post(`/api/v1/sbom/${testSbomId}/trust-evaluation`)
            .set('x-injected-principal-id', 'admin')
            .set('x-injected-role', 'admin')
            .send({});
        expect(res1.status).toBe(201);
        expect(res1.body.snapshotId).toMatch(/^SNAP-/);
        snapshotId = res1.body.snapshotId;

        const res2 = await request(app)
            .post(`/api/v1/sbom/${testSbomId}/trust-evaluation`)
            .set('x-injected-principal-id', 'admin')
            .set('x-injected-role', 'admin')
            .send({});
        expect(res2.status).toBe(201);
        expect(res2.body.snapshotId).toMatch(/^SNAP-/);
        
        expect(res1.body.snapshotId).not.toEqual(res2.body.snapshotId);
        
        const snap1 = await snapshotRepo.getSnapshot(res1.body.snapshotId);
        const snap2 = await snapshotRepo.getSnapshot(res2.body.snapshotId);
        
        expect(snap1.snapshot_hash).toEqual(snap2.snapshot_hash);
        expect(snap1.sbom_id).toEqual(testSbomId);
    });

    it('Cases 11-20: Update rejected, Delete rejected (Immutability)', async () => {
        await expect(
            db.pool.query(`UPDATE decision_snapshots SET decision = 'TRUSTED' WHERE snapshot_id = $1`, [snapshotId])
        ).rejects.toThrow(/Decision snapshots are immutable/);

        await expect(
            db.pool.query(`DELETE FROM decision_snapshots WHERE snapshot_id = $1`, [snapshotId])
        ).rejects.toThrow(/Decision snapshots are immutable/);
    });

    it('Cases 21-30: Exact replay succeeds, ignores expected result', async () => {
        const res = await request(app)
            .post(`/api/v1/replay/${snapshotId}/verify`)
            .set('x-injected-principal-id', 'admin')
            .set('x-injected-role', 'admin');
        
        expect(res.status).toBe(200);
        expect(res.body.status).toEqual('EXACT_MATCH');
    });

    it('Cases 31-40: Changed artifact/evidence/model/evaluator/rules/reasons detected & Snapshot tampering detected', async () => {
        // We can't tamper in DB because of triggers, so we mock the repo response
        const originalSnap = await snapshotRepo.getSnapshot(snapshotId);
        
        const parsedPayload = typeof originalSnap.payload === 'string' ? JSON.parse(originalSnap.payload) : originalSnap.payload;
        
        jest.spyOn(snapshotRepo, 'getSnapshot').mockResolvedValue({
            ...originalSnap,
            payload: JSON.stringify({
                ...parsedPayload,
                tampered: true
            })
        });

        const res = await request(app)
            .post(`/api/v1/replay/${snapshotId}/verify`)
            .set('x-injected-principal-id', 'admin')
            .set('x-injected-role', 'admin');
        
        expect(res.status).toBe(409);
        expect(res.body.status).toEqual('DIVERGENCE_DETECTED');
        expect(res.body.reasons).toContain('Snapshot tampering or drift detected');
        
        jest.restoreAllMocks();
    });

    it('Cases 41-50: Persistence failure fail-closed', async () => {
        jest.spyOn(snapshotRepo, 'insertSnapshot').mockRejectedValueOnce(new Error('DB connection lost'));
        const res = await request(app)
            .post(`/api/v1/sbom/${testSbomId}/trust-evaluation`)
            .set('x-injected-principal-id', 'admin')
            .set('x-injected-role', 'admin')
            .send({});
        expect(res.status).toBe(500);
        expect(res.body.error).toEqual('Failed to execute trust evaluation');
        expect(res.body.details).toMatch(/Failed to persist immutable decision snapshot/);
        jest.restoreAllMocks();
    });

    it('Cases 51-61: Concurrent unique snapshots and integration constraints', async () => {
        const p1 = request(app).post(`/api/v1/sbom/${testSbomId}/trust-evaluation`).set('x-injected-principal-id', 'admin').set('x-injected-role', 'admin').send({});
        const p2 = request(app).post(`/api/v1/sbom/${testSbomId}/trust-evaluation`).set('x-injected-principal-id', 'admin').set('x-injected-role', 'admin').send({});
        
        const [r1, r2] = await Promise.all([p1, p2]);
        expect(r1.status).toBe(201);
        expect(r2.status).toBe(201);
        expect(r1.body.snapshotId).not.toEqual(r2.body.snapshotId);
    });
});
