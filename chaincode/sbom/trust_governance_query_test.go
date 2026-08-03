package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGetTrustDecisionQuerySchema(t *testing.T) {
	// Simple testing context rather than using full contractapi mock dependencies

	decisionId := "decision-123"
	sbomID := "sbom-123"

	// 1. Complete decision with all optional values populated
	t.Run("Complete Decision", func(t *testing.T) {
		pointer := &TrustDecisionPointer{
			DecisionId:         decisionId,
			SBOMID:             sbomID,
			TrustStatus:        TrustStatusConditionallyAccepted,
			ReasonCode:         "EXC-001",
			ReasonDescription:  "Exception applied",
			PolicyVersion:      "1.0",
			IdempotencyKey:     "idem-1",
			ProvenanceHash:     "prov-hash",
			SignatureHashes:    []string{"sig1"},
			ActiveVexIds:       []string{"vex1"},
			EffectiveRiskScore: 4.5,
			RecordedAt:         123456,
			RecordedBy:         "secadmin",
		}

		// Simulate GetTrustDecision logic:
		bytes, _ := json.Marshal(pointer)
		var p TrustDecisionPointer
		json.Unmarshal(bytes, &p)

		resp := &TrustDecisionResponse{
			DecisionId:         p.DecisionId,
			SBOMID:             p.SBOMID,
			TrustStatus:        p.TrustStatus,
			ReasonCode:         p.ReasonCode,
			ReasonDescription:  p.ReasonDescription,
			PolicyVersion:      p.PolicyVersion,
			IdempotencyKey:     p.IdempotencyKey,
			ProvenanceHash:     p.ProvenanceHash,
			SignatureHashes:    p.SignatureHashes,
			ActiveVexIds:       p.ActiveVexIds,
			EffectiveRiskScore: p.EffectiveRiskScore,
			RecordedAt:         p.RecordedAt,
			RecordedBy:         p.RecordedBy,
		}
		if resp.SignatureHashes == nil {
			resp.SignatureHashes = []string{}
		}
		if resp.ActiveVexIds == nil {
			resp.ActiveVexIds = []string{}
		}

		if resp.ProvenanceHash != "prov-hash" {
			t.Fatalf("wrong prov hash")
		}
		if len(resp.SignatureHashes) != 1 || resp.SignatureHashes[0] != "sig1" {
			t.Fatalf("wrong sig hashes")
		}
		if len(resp.ActiveVexIds) != 1 || resp.ActiveVexIds[0] != "vex1" {
			t.Fatalf("wrong vex ids")
		}
		if resp.EffectiveRiskScore != 4.5 {
			t.Fatalf("wrong score")
		}
	})

	// 2. Sparse decision with omitted arrays and fields (simulating v6.0 record)
	t.Run("Sparse Decision", func(t *testing.T) {
		// Native json marshal of struct with omitempty empty fields will omit them
		pointer := &TrustDecisionPointer{
			DecisionId:        decisionId,
			SBOMID:            sbomID,
			TrustStatus:       TrustStatusTrusted,
			ReasonCode:        "GOV-001",
			ReasonDescription: "All passed",
			PolicyVersion:     "1.0",
			IdempotencyKey:    "idem-2",
			RecordedAt:        123456,
			RecordedBy:        "secadmin",
		}
		bytes, _ := json.Marshal(pointer)

		var p TrustDecisionPointer
		json.Unmarshal(bytes, &p)

		resp := &TrustDecisionResponse{
			DecisionId:         p.DecisionId,
			SBOMID:             p.SBOMID,
			TrustStatus:        p.TrustStatus,
			ReasonCode:         p.ReasonCode,
			ReasonDescription:  p.ReasonDescription,
			PolicyVersion:      p.PolicyVersion,
			IdempotencyKey:     p.IdempotencyKey,
			ProvenanceHash:     p.ProvenanceHash,
			SignatureHashes:    p.SignatureHashes,
			ActiveVexIds:       p.ActiveVexIds,
			EffectiveRiskScore: p.EffectiveRiskScore,
			RecordedAt:         p.RecordedAt,
			RecordedBy:         p.RecordedBy,
		}
		if resp.SignatureHashes == nil {
			resp.SignatureHashes = []string{}
		}
		if resp.ActiveVexIds == nil {
			resp.ActiveVexIds = []string{}
		}

		if resp.ProvenanceHash != "" {
			t.Fatalf("expected empty prov hash")
		}
		if len(resp.SignatureHashes) != 0 {
			t.Fatalf("expected empty sig hashes, got %v", resp.SignatureHashes)
		}
		if len(resp.ActiveVexIds) != 0 {
			t.Fatalf("expected empty vex ids")
		}
		if resp.EffectiveRiskScore != 0.0 {
			t.Fatalf("expected 0 score")
		}

		// Finally, test marshaling it back to ensure slices are in the JSON output!
		outBytes, _ := json.Marshal(resp)
		outStr := string(outBytes)
		if !strings.Contains(outStr, `"signatureHashes":[]`) {
			t.Fatalf("JSON doesn't have signatureHashes slice: %s", outStr)
		}
		if !strings.Contains(outStr, `"activeVexIds":[]`) {
			t.Fatalf("JSON doesn't have activeVexIds slice: %s", outStr)
		}
		if !strings.Contains(outStr, `"provenanceHash":""`) {
			t.Fatalf("JSON doesn't have provenanceHash: %s", outStr)
		}
		if !strings.Contains(outStr, `"effectiveRiskScore":0`) {
			t.Fatalf("JSON doesn't have effectiveRiskScore: %s", outStr)
		}
	})
}
