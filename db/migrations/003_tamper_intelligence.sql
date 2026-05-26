-- =============================================================
-- TPSR Phase-3 Migration 003 — Tamper Intelligence
-- =============================================================
-- Extends the verification_events table to persist enriched
-- tamper analysis metadata when integrity verification fails.
-- =============================================================

ALTER TABLE verification_events
ADD COLUMN tamper_detected BOOLEAN DEFAULT FALSE,
ADD COLUMN tamper_type VARCHAR(64) DEFAULT NULL,
ADD COLUMN affected_components JSONB DEFAULT '[]'::jsonb,
ADD COLUMN tamper_report JSONB DEFAULT NULL;
