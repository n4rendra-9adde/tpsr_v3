-- =============================================================
-- TPSR Phase-2 Migration 002 — Policy Governance Metadata
-- =============================================================
-- Extends the sbom_documents table to persistently store
-- the outcomes of the automated security policy evaluations
-- generated during the initial SBOM submission phase.
-- =============================================================

ALTER TABLE sbom_documents 
ADD COLUMN policy_status VARCHAR(32) DEFAULT NULL CHECK (policy_status IN ('PASS', 'FAIL')),
ADD COLUMN policy_reason TEXT DEFAULT NULL,
ADD COLUMN policy_violations JSONB DEFAULT '[]'::jsonb,
ADD COLUMN policy_evaluation_mode VARCHAR(64) DEFAULT NULL;

-- Index for querying by policy status
CREATE INDEX IF NOT EXISTS idx_sbom_documents_policy_status ON sbom_documents(policy_status);
