-- TPSR v3 Migration 011: Provenance Schema Enhancement (Remediation Group 3)
-- Add missing fields to provenance_attestations to fully capture cryptographic envelopes,
-- parsed SLSA claims, policy evaluation decisions, and strict metadata.

ALTER TABLE provenance_attestations
  ADD COLUMN IF NOT EXISTS envelope_hash CHAR(64),
  ADD COLUMN IF NOT EXISTS predicate_type VARCHAR(100),
  ADD COLUMN IF NOT EXISTS predicate_version VARCHAR(50),
  ADD COLUMN IF NOT EXISTS source_repository VARCHAR(500),
  ADD COLUMN IF NOT EXISTS source_commit CHAR(40),
  ADD COLUMN IF NOT EXISTS build_type VARCHAR(200),
  ADD COLUMN IF NOT EXISTS external_parameters JSONB,
  ADD COLUMN IF NOT EXISTS build_started_on TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS build_finished_on TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS signature_status VARCHAR(50) DEFAULT 'UNVERIFIED',
  ADD COLUMN IF NOT EXISTS verification_status VARCHAR(50) DEFAULT 'FAILED',
  ADD COLUMN IF NOT EXISTS public_key_fingerprint VARCHAR(255),
  ADD COLUMN IF NOT EXISTS signer_identity VARCHAR(500),
  ADD COLUMN IF NOT EXISTS policy_version VARCHAR(50),
  ADD COLUMN IF NOT EXISTS trust_policy_hash CHAR(64),
  ADD COLUMN IF NOT EXISTS reason_codes JSONB,
  ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;

-- Maintain TPSR v2 compatibility by allowing these fields to be NULL for older rows,
-- but they will be populated for v3 SLSA-Compatible Provenance flows.
