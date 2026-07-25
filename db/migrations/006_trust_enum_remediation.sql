-- TPSR v3 Migration 006: Trust-Decision Enum Remediation (Remediation Group 1)
--
-- Purpose:
--   Enforce the authoritative four-state trust-decision enum on the
--   trust_decision_history.trust_status column.
--
-- Authoritative decisions:
--   TRUSTED               - all checks pass, no exception needed
--   CONDITIONALLY_ACCEPTED - checks pass; remaining violation covered by valid exception
--   REVIEW_REQUIRED       - evidence incomplete or ambiguous; manual review needed
--   REJECTED              - mandatory check failed; no valid mitigation
--
-- UNEVALUATED is excluded from trust_decision_history because this table stores only
-- authoritative evaluation results. UNEVALUATED is a presentation/caching state only.
--
-- Compatibility note:
--   Historical rows with trust_status = 'UNTRUSTED' are preserved as-is.
--   The application-layer normalizeTrustStatus() mapper translates 'UNTRUSTED' → 'REJECTED'
--   at read time without modifying stored data.
--   This migration does NOT destructively UPDATE or DELETE historical UNTRUSTED rows.
--
-- Safety check:
--   Count of existing UNTRUSTED rows is reported but not modified.
--   If the count is > 0, the operator is informed of the compatibility mapping.

DO $$
DECLARE
  untrusted_count INTEGER;
BEGIN
  -- Count historical UNTRUSTED rows for auditor awareness
  SELECT count(*) INTO untrusted_count
  FROM trust_decision_history
  WHERE trust_status = 'UNTRUSTED';

  IF untrusted_count > 0 THEN
    RAISE NOTICE
      'TPSR v3 Migration 006: Found % historical UNTRUSTED record(s) in trust_decision_history. '
      'These records are preserved unchanged. The application-layer normalizeTrustStatus() mapper '
      'translates UNTRUSTED → REJECTED at read time for compatibility.',
      untrusted_count;
  END IF;
END $$;

-- Add CHECK constraint to trust_decision_history.trust_status
-- The constraint permits 'UNTRUSTED' only for backward-compatibility with historical rows.
-- New authoritative evaluations must use TRUSTED, CONDITIONALLY_ACCEPTED,
-- REVIEW_REQUIRED, or REJECTED only. The application layer enforces this in code.
--
-- If you wish to enforce strict enum at the DB layer in a future migration (after all
-- historical rows are migrated), replace 'UNTRUSTED' with a comment-only note and remove
-- it from the IN list below.

ALTER TABLE trust_decision_history
  ADD CONSTRAINT chk_trust_decision_history_trust_status
  CHECK (trust_status IN (
    'TRUSTED',
    'CONDITIONALLY_ACCEPTED',
    'REVIEW_REQUIRED',
    'REJECTED',
    'UNTRUSTED'   -- legacy read-only; new evaluations must not write this value
  ));

-- Add idempotency_key column to ledger_outbox for outbox-level idempotency tracking
-- (Outbox currently relies only on decision_id FK; this adds an explicit key column
--  for the reconciliation improvements planned in Remediation Group 6)
ALTER TABLE ledger_outbox
  ADD COLUMN IF NOT EXISTS idempotency_key UUID;

CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_idempotency_key
  ON ledger_outbox(idempotency_key)
  WHERE idempotency_key IS NOT NULL AND deleted_at IS NULL;
