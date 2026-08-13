BEGIN;

CREATE TABLE trust_policy_generations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id VARCHAR(255) NOT NULL,
    generation INTEGER NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    policy_hash VARCHAR(255) NOT NULL,
    maximum_age_hours INTEGER,
    loaded_by VARCHAR(255) NOT NULL,
    loaded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_policy_generations_gen ON trust_policy_generations(policy_id, generation);

CREATE TABLE trust_policy_revocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_type VARCHAR(64) NOT NULL,
    subject_identifier VARCHAR(255) NOT NULL,
    revocation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    revocation_reason TEXT NOT NULL,
    revoked_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (subject_type, subject_identifier)
);

CREATE TABLE security_observability_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(64) NOT NULL,
    correlation_id UUID,
    policy_id VARCHAR(255),
    policy_generation INTEGER,
    rule_id VARCHAR(64),
    reason_code VARCHAR(64),
    subject_fingerprint VARCHAR(255),
    event_time TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMIT;
