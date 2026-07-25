-- TPSR v3 Migration 005: Evidence Governance and Outbox Reconciliation
-- All foreign key constraints enforce ON DELETE RESTRICT to guarantee audit immutability.
-- All audit tables include soft-deletion metadata (deleted_at, deleted_by, deletion_reason).

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Provenance Attestations
CREATE TABLE IF NOT EXISTS provenance_attestations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sbom_id VARCHAR(255) NOT NULL REFERENCES sbom_documents(sbom_id) ON DELETE RESTRICT,
  artifact_hash CHAR(64) NOT NULL,
  attestation_type VARCHAR(50) NOT NULL,
  builder_id VARCHAR(500) NOT NULL,
  slsa_level VARCHAR(50) NOT NULL,
  payload JSONB NOT NULL,
  attestation_hash CHAR(64) NOT NULL UNIQUE,
  status VARCHAR(50) NOT NULL DEFAULT 'VALID',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMPTZ,
  deleted_by VARCHAR(255),
  deletion_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_provenance_sbom_id ON provenance_attestations(sbom_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_provenance_artifact_hash ON provenance_attestations(artifact_hash) WHERE deleted_at IS NULL;

-- 2. Signature Verifications
CREATE TABLE IF NOT EXISTS signature_verifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sbom_id VARCHAR(255) NOT NULL REFERENCES sbom_documents(sbom_id) ON DELETE RESTRICT,
  artifact_hash CHAR(64) NOT NULL,
  signature_type VARCHAR(50) NOT NULL,
  signer_identity VARCHAR(500) NOT NULL,
  verification_status VARCHAR(50) NOT NULL DEFAULT 'VERIFIED',
  bundle_json JSONB,
  signature_hash CHAR(64) NOT NULL UNIQUE,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMPTZ,
  deleted_by VARCHAR(255),
  deletion_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_signature_sbom_id ON signature_verifications(sbom_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_signature_artifact_hash ON signature_verifications(artifact_hash) WHERE deleted_at IS NULL;

-- 3. VEX Statements
CREATE TABLE IF NOT EXISTS vex_statements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sbom_id VARCHAR(255) NOT NULL REFERENCES sbom_documents(sbom_id) ON DELETE RESTRICT,
  vulnerability_id VARCHAR(100) NOT NULL,
  original_severity VARCHAR(20) NOT NULL,
  original_cvss NUMERIC(4,1),
  applicability_status VARCHAR(50) NOT NULL,
  policy_impact VARCHAR(50) NOT NULL,
  justification VARCHAR(100),
  impact_statement TEXT,
  statement_payload JSONB NOT NULL,
  issuer_identity VARCHAR(500) NOT NULL,
  statement_issued_at TIMESTAMPTZ NOT NULL,
  statement_last_updated_at TIMESTAMPTZ NOT NULL,
  policy_valid_until TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMPTZ,
  deleted_by VARCHAR(255),
  deletion_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_vex_sbom_id ON vex_statements(sbom_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_vex_vuln_id ON vex_statements(vulnerability_id) WHERE deleted_at IS NULL;

-- 4. Deployment Contexts
CREATE TABLE IF NOT EXISTS deployment_contexts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sbom_id VARCHAR(255) NOT NULL REFERENCES sbom_documents(sbom_id) ON DELETE RESTRICT,
  environment VARCHAR(50) NOT NULL,
  network_exposure VARCHAR(50) NOT NULL,
  data_sensitivity VARCHAR(50) NOT NULL,
  privilege_level VARCHAR(50) NOT NULL,
  compensating_controls JSONB,
  risk_multiplier NUMERIC(4,2) NOT NULL DEFAULT 1.00,
  registered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMPTZ,
  deleted_by VARCHAR(255),
  deletion_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_context_sbom_id ON deployment_contexts(sbom_id) WHERE deleted_at IS NULL;

-- 5. Policy Exceptions
CREATE TABLE IF NOT EXISTS policy_exceptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sbom_id VARCHAR(255) NOT NULL REFERENCES sbom_documents(sbom_id) ON DELETE RESTRICT,
  violation_id VARCHAR(100) NOT NULL,
  violation_type VARCHAR(100) NOT NULL,
  justification TEXT NOT NULL,
  compensating_controls TEXT,
  requested_by VARCHAR(255) NOT NULL,
  approved_by VARCHAR(255),
  status VARCHAR(50) NOT NULL DEFAULT 'APPROVED',
  valid_until TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMPTZ,
  deleted_by VARCHAR(255),
  deletion_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_exceptions_sbom_id ON policy_exceptions(sbom_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_exceptions_valid_until ON policy_exceptions(valid_until) WHERE deleted_at IS NULL AND status = 'APPROVED';

-- 6. Context Evaluations
CREATE TABLE IF NOT EXISTS context_evaluations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sbom_id VARCHAR(255) NOT NULL REFERENCES sbom_documents(sbom_id) ON DELETE RESTRICT,
  vulnerability_id VARCHAR(100) NOT NULL,
  raw_cvss NUMERIC(4,1),
  adjusted_cvss NUMERIC(4,1),
  risk_multiplier NUMERIC(4,2) NOT NULL,
  context_factors JSONB,
  evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMPTZ,
  deleted_by VARCHAR(255),
  deletion_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_context_eval_sbom_id ON context_evaluations(sbom_id) WHERE deleted_at IS NULL;

-- 7. Trust Decision History
CREATE TABLE IF NOT EXISTS trust_decision_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sbom_id VARCHAR(255) NOT NULL REFERENCES sbom_documents(sbom_id) ON DELETE RESTRICT,
  trust_status VARCHAR(50) NOT NULL,
  reason_code VARCHAR(20) NOT NULL,
  reason_description TEXT NOT NULL,
  evidence_summary JSONB NOT NULL,
  policy_version VARCHAR(50) NOT NULL,
  evaluated_by VARCHAR(255) NOT NULL,
  idempotency_key UUID UNIQUE,
  evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMPTZ,
  deleted_by VARCHAR(255),
  deletion_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_trust_decision_sbom_id ON trust_decision_history(sbom_id, evaluated_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_trust_decision_idempotency ON trust_decision_history(idempotency_key) WHERE idempotency_key IS NOT NULL;

-- 8. Ledger Outbox
CREATE TABLE IF NOT EXISTS ledger_outbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sbom_id VARCHAR(255) NOT NULL REFERENCES sbom_documents(sbom_id) ON DELETE RESTRICT,
  decision_id UUID NOT NULL REFERENCES trust_decision_history(id) ON DELETE RESTRICT,
  payload JSONB NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'RETRY_PENDING', 'COMPLETED', 'FAILED_REQUIRES_REVIEW')),
  retry_count INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_attempt_at TIMESTAMPTZ,
  locked_at TIMESTAMPTZ,
  locked_by VARCHAR(255),
  fabric_tx_id VARCHAR(100),
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMPTZ,
  deleted_by VARCHAR(255),
  deletion_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_outbox_worker_claim ON ledger_outbox(status, next_attempt_at) WHERE deleted_at IS NULL AND status IN ('PENDING', 'RETRY_PENDING');
CREATE INDEX IF NOT EXISTS idx_outbox_sbom_id ON ledger_outbox(sbom_id, created_at DESC) WHERE deleted_at IS NULL;
