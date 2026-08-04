-- TPSR v3 Migration 012: VEX and Context Schema Enhancements
-- Additive migration for Group 4 strict matching and cryptographic provenance fields.

-- 1. Extend vex_statements
ALTER TABLE vex_statements
ADD COLUMN IF NOT EXISTS statement_hash CHAR(64),
ADD COLUMN IF NOT EXISTS public_key_fingerprint VARCHAR(500),
ADD COLUMN IF NOT EXISTS signature_status VARCHAR(50),
ADD COLUMN IF NOT EXISTS format VARCHAR(50) DEFAULT 'OpenVEX',
ADD COLUMN IF NOT EXISTS format_version VARCHAR(50),
ADD COLUMN IF NOT EXISTS product_identifiers JSONB,
ADD COLUMN IF NOT EXISTS release_identifiers JSONB,
ADD COLUMN IF NOT EXISTS component_identifiers JSONB,
ADD COLUMN IF NOT EXISTS vulnerability_identifiers JSONB,
ADD COLUMN IF NOT EXISTS applicability_disposition VARCHAR(50),
ADD COLUMN IF NOT EXISTS policy_blocking_status VARCHAR(50),
ADD COLUMN IF NOT EXISTS reason_codes JSONB,
ADD COLUMN IF NOT EXISTS trust_policy_hash VARCHAR(64),
ADD COLUMN IF NOT EXISTS action_statement TEXT,
ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS policy_version VARCHAR(50),
ADD COLUMN IF NOT EXISTS verification_mode VARCHAR(50),
ADD COLUMN IF NOT EXISTS transparency_log_status VARCHAR(50),
ADD COLUMN IF NOT EXISTS digest_manifest_reference JSONB,
ADD COLUMN IF NOT EXISTS statement_id VARCHAR(255);

-- 2. Extend context_evaluations
ALTER TABLE context_evaluations
ADD COLUMN IF NOT EXISTS original_vulnerability JSONB,
ADD COLUMN IF NOT EXISTS original_cvss NUMERIC(4,1),
ADD COLUMN IF NOT EXISTS original_severity VARCHAR(20),
ADD COLUMN IF NOT EXISTS applicability_overlay JSONB,
ADD COLUMN IF NOT EXISTS policy_blocking_status VARCHAR(50),
ADD COLUMN IF NOT EXISTS reason_codes JSONB,
ADD COLUMN IF NOT EXISTS decision_reasons JSONB,
ADD COLUMN IF NOT EXISTS context_inputs JSONB;
