-- Migration: 007_outbox_action_routing
-- Description: Add strict action routing column to ledger_outbox to prevent payload inference defects.

BEGIN;

ALTER TABLE ledger_outbox
ADD COLUMN IF NOT EXISTS action VARCHAR(50);

-- Safely backfill using payload signatures if action is still NULL
UPDATE ledger_outbox 
SET action = 'RECORD_TRUST_DECISION'
WHERE action IS NULL 
  AND payload ? 'trustStatus' 
  AND payload ? 'reasonCode';

UPDATE ledger_outbox 
SET action = 'RECORD_TRUST_EVIDENCE'
WHERE action IS NULL 
  AND payload ? 'evidenceId' 
  AND payload ? 'evidenceHash';

-- This enforces action must be supplied by the application going forward,
-- and halts the migration if any ambiguous rows could not be guessed securely.
ALTER TABLE ledger_outbox ALTER COLUMN action SET NOT NULL;

DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_ledger_outbox_action') THEN
        ALTER TABLE ledger_outbox
        ADD CONSTRAINT chk_ledger_outbox_action
        CHECK (action IN ('RECORD_TRUST_DECISION', 'RECORD_TRUST_EVIDENCE'));
    END IF;
END $$;

COMMIT;
