-- Migration: 009_outbox_event_retention
-- Description: Fix ON DELETE CASCADE on ledger_outbox_events to enforce append-only audit retention.

BEGIN;

ALTER TABLE ledger_outbox_events
DROP CONSTRAINT IF EXISTS ledger_outbox_events_outbox_id_fkey;

ALTER TABLE ledger_outbox_events
ADD CONSTRAINT ledger_outbox_events_outbox_id_fkey
FOREIGN KEY (outbox_id)
REFERENCES ledger_outbox(id)
ON DELETE RESTRICT;

COMMIT;
