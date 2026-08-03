-- Migration: 007_outbox_action_routing
-- Description: Add strict action routing column to ledger_outbox to prevent payload inference defects.

BEGIN;

ALTER TABLE ledger_outbox
ADD COLUMN IF NOT EXISTS action VARCHAR(50) NOT NULL DEFAULT 'RECORD_TRUST_DECISION';

DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_ledger_outbox_action') THEN
        ALTER TABLE ledger_outbox
        ADD CONSTRAINT chk_ledger_outbox_action
        CHECK (action IN ('RECORD_TRUST_DECISION', 'RECORD_TRUST_EVIDENCE'));
    END IF;
END $$;

-- Remove default to enforce explicit specification in new inserts
ALTER TABLE ledger_outbox ALTER COLUMN action DROP DEFAULT;

COMMIT;
