-- TPSR v3 Migration 013: CAECTD Explanation Fields
--
-- Purpose:
--   Add model correlation and explanation completeness fields to the
--   authoritative trust_decision_history table to support CAECTD 0.1.
--
-- Requirements:
--   - Additive and repeatable.
--   - Historical rows remain unchanged (fields will be NULL, indicating legacy evaluations).
--   - JSONB types for structured arrays and objects.

BEGIN;

DO $$
BEGIN
  -- 1. Add caectd_model_version
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'trust_decision_history' AND column_name = 'caectd_model_version'
  ) THEN
    ALTER TABLE trust_decision_history ADD COLUMN caectd_model_version VARCHAR(50);
  END IF;

  -- 2. Add triggered_rule_ids
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'trust_decision_history' AND column_name = 'triggered_rule_ids'
  ) THEN
    ALTER TABLE trust_decision_history ADD COLUMN triggered_rule_ids JSONB;
  END IF;

  -- 3. Add evaluated_rule_ids
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'trust_decision_history' AND column_name = 'evaluated_rule_ids'
  ) THEN
    ALTER TABLE trust_decision_history ADD COLUMN evaluated_rule_ids JSONB;
  END IF;

  -- 4. Add evidence_dependencies
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'trust_decision_history' AND column_name = 'evidence_dependencies'
  ) THEN
    ALTER TABLE trust_decision_history ADD COLUMN evidence_dependencies JSONB;
  END IF;

  -- 5. Add explanation_completeness
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'trust_decision_history' AND column_name = 'explanation_completeness'
  ) THEN
    ALTER TABLE trust_decision_history ADD COLUMN explanation_completeness JSONB;
  END IF;

END $$;

COMMIT;
