-- TPSR v3 Migration 017: Context Provenance Audit
-- Additive migration to persist full provenance metadata for context assertions.

ALTER TABLE deployment_context_assertions
ADD COLUMN IF NOT EXISTS evidence_source VARCHAR(255),
ADD COLUMN IF NOT EXISTS matched_authorization_rule VARCHAR(255),
ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(255),
ADD COLUMN IF NOT EXISTS authority_trusted BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS provenance_mode VARCHAR(50) DEFAULT 'CRYPTOGRAPHIC',
ADD COLUMN IF NOT EXISTS revoked_by VARCHAR(255),
ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS authentication_mode VARCHAR(50),
ADD COLUMN IF NOT EXISTS authentication_assurance VARCHAR(50);

ALTER TABLE deployment_context_assertions
ALTER COLUMN signer_identity DROP NOT NULL,
ALTER COLUMN public_key_fingerprint DROP NOT NULL;

-- Enforce provenance mode constraint safely
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_context_provenance_mode') THEN
    ALTER TABLE deployment_context_assertions
    ADD CONSTRAINT chk_context_provenance_mode CHECK (
      (provenance_mode = 'CRYPTOGRAPHIC' 
       AND signer_identity IS NOT NULL 
       AND public_key_fingerprint IS NOT NULL 
       AND signature_type IS NOT NULL 
       AND verification_mode IS NOT NULL 
       AND signature_verified IS NOT NULL 
       AND transparency_log_verified IS NOT NULL 
       AND verification_status IS NOT NULL)
      OR
      (provenance_mode = 'AUTHENTICATED_API' 
       AND asserted_by IS NOT NULL 
       AND assertor_role IS NOT NULL 
       AND authentication_mode IS NOT NULL 
       AND authentication_assurance IS NOT NULL 
       AND authority_trusted IS NOT NULL
       AND signature_type = 'NONE'
       AND signer_identity IS NULL
       AND public_key_fingerprint IS NULL)
    );
  END IF;
END $$;
