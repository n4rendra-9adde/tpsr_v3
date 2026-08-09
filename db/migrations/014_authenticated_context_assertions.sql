-- TPSR v3 Migration 014: Authenticated Context Assertions
--
-- Purpose:
--   Add a fully authenticated, append-oriented ledger of deployment context assertions.
--   Retains legacy contexts as LEGACY_UNAUTHENTICATED for history.

BEGIN;

CREATE TABLE IF NOT EXISTS deployment_context_assertions (
    id UUID PRIMARY KEY,
    assertion_version VARCHAR(50) NOT NULL,
    sbom_id VARCHAR(255) NOT NULL,
    digest_manifest_digest VARCHAR(255) NOT NULL,
    canonical_assertion JSONB NOT NULL,
    assertion_payload_hash VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL,
    internet_exposure VARCHAR(50) NOT NULL,
    asset_criticality VARCHAR(50) NOT NULL,
    privilege_level VARCHAR(50) NOT NULL,
    data_sensitivity VARCHAR(50) NOT NULL,
    runtime_execution VARCHAR(50) NOT NULL,
    component_presence VARCHAR(50) NOT NULL,
    compensating_controls JSONB,
    asserted_by VARCHAR(255) NOT NULL,
    assertor_role VARCHAR(100) NOT NULL,
    asserted_at TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    justification TEXT,
    previous_assertion_id UUID,
    supersedes_assertion_id UUID,
    signature_type VARCHAR(50) NOT NULL,
    verification_mode VARCHAR(50) NOT NULL,
    signer_identity VARCHAR(255) NOT NULL,
    public_key_fingerprint VARCHAR(255) NOT NULL,
    signature_verified BOOLEAN NOT NULL,
    transparency_log_verified BOOLEAN NOT NULL,
    verification_status VARCHAR(50) NOT NULL,
    assurance_state VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    reason_codes JSONB,
    policy_version VARCHAR(50) NOT NULL,
    trust_policy_hash VARCHAR(255),
    verified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_context_assertion_sbom FOREIGN KEY (sbom_id) REFERENCES sbom_documents(sbom_id) ON DELETE RESTRICT,
    CONSTRAINT fk_previous_assertion FOREIGN KEY (previous_assertion_id) REFERENCES deployment_context_assertions(id) ON DELETE RESTRICT,
    CONSTRAINT fk_supersedes_assertion FOREIGN KEY (supersedes_assertion_id) REFERENCES deployment_context_assertions(id) ON DELETE RESTRICT,

    CONSTRAINT chk_context_assertion_env CHECK (environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')),
    CONSTRAINT chk_context_assertion_internet CHECK (internet_exposure IN ('NONE', 'INTERNAL', 'RESTRICTED_PUBLIC', 'PUBLIC')),
    CONSTRAINT chk_context_assertion_crit CHECK (asset_criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_context_assertion_priv CHECK (privilege_level IN ('UNPRIVILEGED', 'ELEVATED', 'SYSTEM')),
    CONSTRAINT chk_context_assertion_data CHECK (data_sensitivity IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    CONSTRAINT chk_context_assertion_rt CHECK (runtime_execution IN ('EXECUTED', 'PRESENT_NOT_EXECUTED', 'NOT_PRESENT', 'UNKNOWN')),
    CONSTRAINT chk_context_assertion_comp CHECK (component_presence IN ('PRESENT', 'NOT_PRESENT', 'PARTIAL', 'UNKNOWN')),
    CONSTRAINT chk_context_assertion_status CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'SUPERSEDED', 'INVALID'))
);

CREATE INDEX IF NOT EXISTS idx_deployment_context_assertions_sbom_id ON deployment_context_assertions(sbom_id);
CREATE INDEX IF NOT EXISTS idx_deployment_context_assertions_status ON deployment_context_assertions(status);
CREATE INDEX IF NOT EXISTS idx_deployment_context_assertions_valid_until ON deployment_context_assertions(valid_until);
CREATE INDEX IF NOT EXISTS idx_deployment_context_assertions_payload_hash ON deployment_context_assertions(assertion_payload_hash);

-- Do NOT migrate legacy rows into this table. Legacy unauthenticated contexts remain in deployment_contexts table.

COMMIT;
