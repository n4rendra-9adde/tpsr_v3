-- TPSR v3 Migration 010: Cosign Schema Enhancement
-- Adds fields for explicit offline-keyed signature verification storage

ALTER TABLE signature_verifications 
  ADD COLUMN IF NOT EXISTS public_key_fingerprint VARCHAR(255),
  ADD COLUMN IF NOT EXISTS verification_mode VARCHAR(50) DEFAULT 'offline-keyed',
  ADD COLUMN IF NOT EXISTS failure_reason TEXT;
