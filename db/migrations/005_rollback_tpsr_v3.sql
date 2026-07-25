-- TPSR v3 Migration 005 Rollback: Destructive Schema Rollback
-- WARNING: This script drops all v3 evidence governance tables. 
-- For non-destructive compatibility rollback, set policy_evaluation_mode = 'COMPATIBILITY_V2' in application configuration instead of running this script.

DROP TABLE IF EXISTS ledger_outbox CASCADE;
DROP TABLE IF EXISTS trust_decision_history CASCADE;
DROP TABLE IF EXISTS context_evaluations CASCADE;
DROP TABLE IF EXISTS policy_exceptions CASCADE;
DROP TABLE IF EXISTS deployment_contexts CASCADE;
DROP TABLE IF EXISTS vex_statements CASCADE;
DROP TABLE IF EXISTS signature_verifications CASCADE;
DROP TABLE IF EXISTS provenance_attestations CASCADE;
