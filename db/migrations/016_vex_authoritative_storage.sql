-- TPSR v3 Migration 016: VEX Authoritative Storage Enhancements
-- Additive migration to persist required cryptographic and binding evidence for VEX

ALTER TABLE vex_statements
ADD COLUMN IF NOT EXISTS vex_authoritative BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS canonical_payload_digest CHAR(64),
ADD COLUMN IF NOT EXISTS issuer_identity VARCHAR(255),
ADD COLUMN IF NOT EXISTS policy_id VARCHAR(100),
ADD COLUMN IF NOT EXISTS target_binding JSONB,
ADD COLUMN IF NOT EXISTS verifier_version VARCHAR(50);
