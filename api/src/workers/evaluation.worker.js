const { Pool } = require('pg');
const pool = new Pool(); // assumes ENV variables are set

async function evaluateJobs() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // Claim eligible QUEUED job
        const res = await client.query(`
            SELECT evaluation_id, sbom_id, artifact_digest, release_version
            FROM evaluation_jobs
            WHERE status = 'QUEUED' AND available_at <= NOW()
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        `);

        if (res.rows.length === 0) {
            await client.query('COMMIT');
            return;
        }

        const job = res.rows[0];
        
        // Set to RUNNING
        await client.query(`
            UPDATE evaluation_jobs
            SET status = 'RUNNING', locked_at = NOW(), started_at = NOW()
            WHERE evaluation_id = $1
        `, [job.evaluation_id]);

        // Evaluate CAECTD (skeleton)
        const recommendation = 'REJECT'; // Placeholder for automated CAECTD result
        
        // Mark terminal state
        await client.query(`
            UPDATE evaluation_jobs
            SET status = 'COMPLETED', completed_at = NOW(), updated_at = NOW()
            WHERE evaluation_id = $1
        `, [job.evaluation_id]);

        await client.query('COMMIT');
    } catch (e) {
        await client.query('ROLLBACK');
    } finally {
        client.release();
    }
}

setInterval(evaluateJobs, 5000);
