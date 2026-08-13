BEGIN;

CREATE TABLE IF NOT EXISTS decision_snapshots (
    snapshot_id VARCHAR(255) PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    decision VARCHAR(50) NOT NULL,
    policy_id VARCHAR(255) NOT NULL,
    policy_generation INTEGER NOT NULL,
    model_version VARCHAR(255) NOT NULL,
    evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    snapshot_hash VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_immutable_snapshot CHECK (true)
);

CREATE INDEX idx_decision_snapshots_sbom_id ON decision_snapshots(sbom_id);
CREATE INDEX idx_decision_snapshots_decision ON decision_snapshots(decision);
CREATE INDEX idx_decision_snapshots_evaluated_at ON decision_snapshots(evaluated_at);

-- Trigger to make inserts immutable
CREATE OR REPLACE FUNCTION prevent_snapshot_modification()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Decision snapshots are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_immutable_snapshots ON decision_snapshots;
CREATE TRIGGER trg_immutable_snapshots
BEFORE UPDATE OR DELETE ON decision_snapshots
FOR EACH ROW
EXECUTE FUNCTION prevent_snapshot_modification();

COMMIT;
