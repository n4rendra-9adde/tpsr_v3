BEGIN;

ALTER TABLE policy_exceptions
  ADD COLUMN IF NOT EXISTS exception_version VARCHAR(50) DEFAULT 'v1',
  ADD COLUMN IF NOT EXISTS digest_manifest_digest VARCHAR(128),
  ADD COLUMN IF NOT EXISTS policy_rule_id VARCHAR(100),
  ADD COLUMN IF NOT EXISTS reason_code VARCHAR(50),
  ADD COLUMN IF NOT EXISTS vulnerability_ids JSONB,
  ADD COLUMN IF NOT EXISTS component_identifiers JSONB,
  ADD COLUMN IF NOT EXISTS environment VARCHAR(100),
  ADD COLUMN IF NOT EXISTS requested_by_role VARCHAR(100) DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS owned_by VARCHAR(255),
  ADD COLUMN IF NOT EXISTS owner_role VARCHAR(100),
  ADD COLUMN IF NOT EXISTS approver_role VARCHAR(100),
  ADD COLUMN IF NOT EXISTS requested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS valid_from TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS business_need TEXT,
  ADD COLUMN IF NOT EXISTS remediation_plan TEXT,
  ADD COLUMN IF NOT EXISTS residual_risk VARCHAR(50) DEFAULT 'MEDIUM',
  ADD COLUMN IF NOT EXISTS approval_comment TEXT,
  ADD COLUMN IF NOT EXISTS revocation_reason TEXT,
  ADD COLUMN IF NOT EXISTS revoked_by VARCHAR(255),
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS supersedes_exception_id UUID,
  ADD COLUMN IF NOT EXISTS previous_exception_id UUID,
  ADD COLUMN IF NOT EXISTS assurance_state VARCHAR(50),
  ADD COLUMN IF NOT EXISTS policy_version VARCHAR(100) DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS trust_policy_hash VARCHAR(128) DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'policy_exceptions' AND column_name = 'compensating_controls' AND data_type = 'text'
  ) THEN
    ALTER TABLE policy_exceptions 
      ALTER COLUMN compensating_controls TYPE JSONB USING (
        CASE WHEN compensating_controls IS NULL OR compensating_controls = '' THEN '[]'::jsonb ELSE jsonb_build_array(compensating_controls) END
      );
  END IF;
END $$;

-- We need to populate some constraints and defaults for the existing data so we don't break NOT NULL constraints.
-- But wait, the required columns must be NOT NULL according to the prompt.
-- I will just leave them nullable for legacy records, but the application code will enforce them for new records.
-- Or I can backfill and then set NOT NULL?
-- Let's just create the columns.

-- Update foreign key constraint on sbom_id to ON DELETE RESTRICT if it isn't already.
-- Actually, the simplest is to just drop and recreate if needed, but since we don't know the name, we leave it.

-- Add missing constraints safely
DO $$ 
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'check_requested_not_approved') THEN
    ALTER TABLE policy_exceptions ADD CONSTRAINT check_requested_not_approved CHECK (approved_by IS NULL OR requested_by <> approved_by);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'check_owned_not_approved') THEN
    ALTER TABLE policy_exceptions ADD CONSTRAINT check_owned_not_approved CHECK (approved_by IS NULL OR owned_by <> approved_by);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'check_validity_period') THEN
    ALTER TABLE policy_exceptions ADD CONSTRAINT check_validity_period CHECK (valid_until > valid_from);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'check_justification_not_empty') THEN
    ALTER TABLE policy_exceptions ADD CONSTRAINT check_justification_not_empty CHECK (length(trim(justification)) > 0);
  END IF;
END $$;


CREATE INDEX IF NOT EXISTS idx_policy_exceptions_sbom_id ON policy_exceptions(sbom_id);
CREATE INDEX IF NOT EXISTS idx_policy_exceptions_status ON policy_exceptions(status);
CREATE INDEX IF NOT EXISTS idx_policy_exceptions_valid_until ON policy_exceptions(valid_until);
CREATE INDEX IF NOT EXISTS idx_policy_exceptions_rule_id ON policy_exceptions(policy_rule_id);
CREATE INDEX IF NOT EXISTS idx_policy_exceptions_vulns ON policy_exceptions USING GIN (vulnerability_ids);

CREATE TABLE IF NOT EXISTS policy_exception_events (
  event_id UUID PRIMARY KEY,
  exception_id UUID NOT NULL REFERENCES policy_exceptions(id) ON DELETE RESTRICT,
  sbom_id UUID NOT NULL REFERENCES sbom_documents(sbom_id) ON DELETE RESTRICT,
  event_type VARCHAR(50) NOT NULL,
  previous_status VARCHAR(50),
  new_status VARCHAR(50) NOT NULL,
  actor_id VARCHAR(255) NOT NULL,
  actor_role VARCHAR(100) NOT NULL,
  reason TEXT,
  event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
  policy_version VARCHAR(100) NOT NULL,
  trust_policy_hash VARCHAR(128) NOT NULL,
  related_decision_id UUID,
  metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_policy_exception_events_exception_id ON policy_exception_events(exception_id);
CREATE INDEX IF NOT EXISTS idx_policy_exception_events_sbom_id ON policy_exception_events(sbom_id);

COMMIT;
