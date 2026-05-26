-- =============================================================
-- TPSR Migration 004 — Lifecycle Governance Expansion
-- =============================================================
-- Expands the SBOM lifecycle to an 8-state governance model.
-- Statuses: REGISTERED, REVIEW_PENDING, SECURITY_REVIEWED, COMPLIANT,
--           APPROVED, ACTIVE, SUPERSEDED, REJECTED.
-- Existing PENDING records are normalized to REGISTERED.
-- =============================================================

BEGIN;

-- 1. Drop the old constraint
ALTER TABLE sbom_documents DROP CONSTRAINT sbom_documents_status_check;

-- 2. Migrate legacy PENDING rows safely to the new initial state
UPDATE sbom_documents 
SET status = 'REGISTERED' 
WHERE status = 'PENDING';

-- 3. Add the expanded strict constraint
ALTER TABLE sbom_documents ADD CONSTRAINT sbom_documents_status_check
  CHECK (status IN (
      'REGISTERED',
      'REVIEW_PENDING',
      'SECURITY_REVIEWED',
      'COMPLIANT',
      'APPROVED',
      'ACTIVE',
      'SUPERSEDED',
      'REJECTED'
  ));

COMMIT;
