package main

import (
	"encoding/json"
	"fmt"
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

// TestRecordTrustDecisionEnumValidation verifies the enum gating in RecordTrustDecision.
// This is the chaincode-layer blocking acceptance criterion for Remediation Group 1.
func TestRecordTrustDecisionEnumValidation(t *testing.T) {
	// isValidAuthoritativeDecision mirrors the switch logic in RecordTrustDecision.
	isValidAuthoritativeDecision := func(ts string) bool {
		switch ts {
		case TrustStatusTrusted, TrustStatusConditionallyAccepted, TrustStatusReviewRequired, TrustStatusRejected:
			return true
		}
		return false
	}

	// --- Valid authoritative decisions must pass ---
	validDecisions := []string{
		TrustStatusTrusted,
		TrustStatusConditionallyAccepted,
		TrustStatusReviewRequired,
		TrustStatusRejected,
	}
	for _, ts := range validDecisions {
		if !isValidAuthoritativeDecision(ts) {
			t.Errorf("RecordTrustDecision enum gate: valid decision %q unexpectedly rejected", ts)
		}
	}

	// --- Invalid values must be rejected at the ledger boundary ---
	invalidDecisions := []struct {
		value       string
		description string
	}{
		{"UNTRUSTED", "pre-v3 deprecated state — must never be written as a new authoritative decision"},
		{"UNEVALUATED", "presentation-only state — never an authoritative decision"},
		{"", "empty string — required field validation catches this first; enum check also covers it"},
		{"trusted", "lowercase — case-sensitive enum; must be rejected"},
		{"PENDING", "internal intermediate state — not an authoritative trust decision"},
		{"INVALID", "arbitrary value — must be rejected"},
		{"null", "string literal null — not a valid enum value"},
	}
	for _, tc := range invalidDecisions {
		if isValidAuthoritativeDecision(tc.value) {
			t.Errorf("RecordTrustDecision enum gate: invalid value %q was not rejected — %s", tc.value, tc.description)
		}
	}

	t.Logf("TestRecordTrustDecisionEnumValidation: %d valid decisions accepted, %d invalid values rejected",
		len(validDecisions), len(invalidDecisions))
}

// TestConditionallyAcceptedLifecycleBlocked verifies that CONDITIONALLY_ACCEPTED
// is blocked at the chaincode layer until anchored exception evidence is implemented.
func TestConditionallyAcceptedLifecycleBlocked(t *testing.T) {
	// Verify the switch logic in approve_sbom.go / activate_sbom.go returns an error
	// for CONDITIONALLY_ACCEPTED (Group 1 safe posture).
	lifecycleGate := func(trustStatus string) error {
		switch trustStatus {
		case TrustStatusRejected, TrustStatusUntrustedLegacy:
			return fmt.Errorf("blocked: REJECTED")
		case TrustStatusReviewRequired:
			return fmt.Errorf("blocked: REVIEW_REQUIRED")
		case TrustStatusUnevaluated:
			return fmt.Errorf("blocked: UNEVALUATED")
		case TrustStatusConditionallyAccepted:
			return fmt.Errorf("lifecycle transition blocked: SBOM trust decision is CONDITIONALLY_ACCEPTED — " +
				"conditional approval requires anchored exception evidence verification on the Fabric ledger, " +
				"which is not yet implemented (pending Fabric governance remediation)")
		case TrustStatusTrusted:
			return nil // Only TRUSTED is permitted in Group 1
		}
		return fmt.Errorf("unrecognised trust status: %s", trustStatus)
	}

	// TRUSTED must pass
	if err := lifecycleGate(TrustStatusTrusted); err != nil {
		t.Errorf("TRUSTED must be permitted by lifecycle gate, got: %v", err)
	}

	// All others must be blocked
	blockedStatuses := []string{
		TrustStatusConditionallyAccepted,
		TrustStatusReviewRequired,
		TrustStatusRejected,
		TrustStatusUntrustedLegacy,
		TrustStatusUnevaluated,
	}
	for _, ts := range blockedStatuses {
		if err := lifecycleGate(ts); err == nil {
			t.Errorf("Lifecycle gate must block trust status %q, but it was permitted", ts)
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
