package main

import (
	"encoding/json"
	"testing"
)

func TestTrustGovernanceTypes(t *testing.T) {
	record := &SBOMRecord{
		SBOMID: "test-sbom-001",
		Hash:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	record.EnsureSlices()
	if record.Signatures == nil || len(record.Signatures) != 0 {
		t.Fatalf("expected empty Signatures slice, got %v", record.Signatures)
	}
	if record.PolicyViolations == nil || len(record.PolicyViolations) != 0 {
		t.Fatalf("expected empty PolicyViolations slice, got %v", record.PolicyViolations)
	}
	if record.SignatureHashes == nil || len(record.SignatureHashes) != 0 {
		t.Fatalf("expected empty SignatureHashes slice, got %v", record.SignatureHashes)
	}
	if record.ActiveVexIds == nil || len(record.ActiveVexIds) != 0 {
		t.Fatalf("expected empty ActiveVexIds slice, got %v", record.ActiveVexIds)
	}

	bytes, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("failed to marshal record: %v", err)
	}

	jsonStr := string(bytes)
	if !contains(jsonStr, `"signatures":[]`) || !contains(jsonStr, `"policyViolations":[]`) || !contains(jsonStr, `"signatureHashes":[]`) || !contains(jsonStr, `"activeVexIds":[]`) {
		t.Fatalf("marshaled JSON does not contain empty arrays: %s", jsonStr)
	}
}

func TestTrustEvidenceInputMarshalling(t *testing.T) {
	input := RecordTrustEvidenceInput{
		Version:      "3.0",
		SBOMID:       "sbom-123",
		EvidenceType: "SLSA_PROVENANCE_V1",
		EvidenceHash: "hash-456",
		EvidenceId:   "ev-789",
	}

	bytes, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("failed to marshal input: %v", err)
	}

	var unmarshaled RecordTrustEvidenceInput
	if err := json.Unmarshal(bytes, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal input: %v", err)
	}

	if unmarshaled.EvidenceId != "ev-789" || unmarshaled.Version != "3.0" {
		t.Fatalf("mismatched unmarshaled fields: %+v", unmarshaled)
	}
}

// TestTrustDecisionConstants validates the authoritative TPSR v3 four-state trust-decision enum.
// This test must always pass. If any constant changes, re-run migration and update docs.
func TestTrustDecisionConstants(t *testing.T) {
	// Authoritative decisions
	if TrustStatusTrusted != "TRUSTED" {
		t.Errorf("TrustStatusTrusted = %q, want %q", TrustStatusTrusted, "TRUSTED")
	}
	if TrustStatusConditionallyAccepted != "CONDITIONALLY_ACCEPTED" {
		t.Errorf("TrustStatusConditionallyAccepted = %q, want %q", TrustStatusConditionallyAccepted, "CONDITIONALLY_ACCEPTED")
	}
	if TrustStatusReviewRequired != "REVIEW_REQUIRED" {
		t.Errorf("TrustStatusReviewRequired = %q, want %q", TrustStatusReviewRequired, "REVIEW_REQUIRED")
	}
	if TrustStatusRejected != "REJECTED" {
		t.Errorf("TrustStatusRejected = %q, want %q", TrustStatusRejected, "REJECTED")
	}

	// Non-authoritative states
	if TrustStatusUnevaluated != "UNEVALUATED" {
		t.Errorf("TrustStatusUnevaluated = %q, want %q", TrustStatusUnevaluated, "UNEVALUATED")
	}

	// Legacy read-only alias — must never be written as a new decision
	if TrustStatusUntrustedLegacy != "UNTRUSTED" {
		t.Errorf("TrustStatusUntrustedLegacy = %q, want %q (legacy alias must remain stable for historical record compatibility)", TrustStatusUntrustedLegacy, "UNTRUSTED")
	}

	// Ensure UNTRUSTED is NOT equal to any authoritative decision string
	authoritative := []string{TrustStatusTrusted, TrustStatusConditionallyAccepted, TrustStatusReviewRequired, TrustStatusRejected}
	for _, d := range authoritative {
		if TrustStatusUntrustedLegacy == d {
			t.Errorf("TrustStatusUntrustedLegacy must not equal any authoritative decision, but equals %q", d)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
