BEGIN;

CREATE TYPE evaluation_status AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'REVIEW_REQUIRED', 'FAILED', 'DEAD_LETTER');

CREATE TABLE evaluation_jobs (
    evaluation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id VARCHAR(255) NOT NULL,
    artifact_digest_algorithm VARCHAR(50),
    artifact_digest VARCHAR(255) NOT NULL,
    release_version VARCHAR(255),
    trigger_type VARCHAR(100) NOT NULL,
    trigger_evidence_ids JSONB,
    policy_generation VARCHAR(100),
    policy_snapshot_id VARCHAR(255),
    idempotency_key VARCHAR(255) UNIQUE NOT NULL,
    status evaluation_status NOT NULL DEFAULT 'QUEUED',
    attempt_count INT NOT NULL DEFAULT 0,
    maximum_attempts INT NOT NULL DEFAULT 3,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by VARCHAR(255),
    lock_expires_at TIMESTAMPTZ,
    safe_error_code VARCHAR(100),
    safe_error_message TEXT,
    correlation_id VARCHAR(255) NOT NULL,
    decision_id VARCHAR(255),
    snapshot_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_evaluation_jobs_status_available_at ON evaluation_jobs (status, available_at);
CREATE INDEX idx_evaluation_jobs_artifact_release ON evaluation_jobs (artifact_digest, release_version);
CREATE INDEX idx_evaluation_jobs_trigger ON evaluation_jobs (trigger_type);

-- Constraint preventing terminal jobs from returning to active states incorrectly
ALTER TABLE evaluation_jobs ADD CONSTRAINT chk_terminal_status CHECK (
    NOT (status IN ('COMPLETED', 'REVIEW_REQUIRED', 'DEAD_LETTER') AND (locked_at IS NOT NULL OR lock_expires_at IS NOT NULL))
);

-- Current Recommendation Model
CREATE TABLE current_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_digest VARCHAR(255) NOT NULL,
    release_version VARCHAR(255) NOT NULL,
    recommendation VARCHAR(100) NOT NULL,
    evaluation_id UUID NOT NULL REFERENCES evaluation_jobs(evaluation_id),
    decision_id VARCHAR(255) NOT NULL,
    snapshot_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(artifact_digest, release_version)
);

COMMIT;
