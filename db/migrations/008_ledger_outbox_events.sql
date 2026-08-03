-- Migration: 008_ledger_outbox_events
-- Description: Add audit trail table for outbox attempts and administrative requeues.

BEGIN;

CREATE TABLE IF NOT EXISTS ledger_outbox_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    outbox_id UUID NOT NULL REFERENCES ledger_outbox(id) ON DELETE CASCADE,
    decision_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    previous_status VARCHAR(50),
    new_status VARCHAR(50) NOT NULL,
    attempt_number INTEGER,
    error_category VARCHAR(100),
    error_message TEXT,
    actor VARCHAR(255) NOT NULL,
    reason TEXT,
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_outbox_events_outbox_id ON ledger_outbox_events(outbox_id);

COMMIT;
