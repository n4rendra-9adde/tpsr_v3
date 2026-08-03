package main

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// RecordTrustEvidence records an immutable trust evidence artifact reference (provenance, signature, VEX) on the ledger.
func (c *SBOMContract) RecordTrustEvidence(ctx contractapi.TransactionContextInterface, inputJSON string) error {
	var input RecordTrustEvidenceInput
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("invalid JSON input for RecordTrustEvidence: %v", err)
	}

	if input.Version != "3.0" {
		return fmt.Errorf("unsupported trust evidence input version: %s (expected 3.0)", input.Version)
	}
	if input.SBOMID == "" || input.EvidenceId == "" || input.EvidenceHash == "" {
		return fmt.Errorf("missing required fields in RecordTrustEvidenceInput: sbomID, evidenceId, and evidenceHash are required")
	}

	if err := validateSHA256Digest(input.EvidenceHash); err != nil {
		return fmt.Errorf("invalid evidenceHash: %v", err)
	}

	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %v", err)
	}
	if mspID != "VendorMSP" && mspID != "SecurityMSP" && mspID != "AuditorMSP" {
		return fmt.Errorf("unauthorized MSP %s for RecordTrustEvidence: only participating MSPs are allowed", mspID)
	}

	submitter, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		submitter = "unknown"
	}
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %v", err)
	}

	// Store under composite key: tpsr.trust.evidence~sbomID~evidenceId
	key, err := ctx.GetStub().CreateCompositeKey("tpsr.trust.evidence", []string{input.SBOMID, input.EvidenceId})
	if err != nil {
		return fmt.Errorf("failed to create composite key for trust evidence: %v", err)
	}

	existingBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to get existing state: %v", err)
	}

	record := &TrustEvidenceRecord{
		EvidenceId:      input.EvidenceId,
		SBOMID:          input.SBOMID,
		EvidenceType:    input.EvidenceType,
		EvidenceHash:    input.EvidenceHash,
		EvidencePayload: input.EvidencePayload,
		RecordedAt:      timestamp.Seconds,
		RecordedBy:      submitter,
	}

	if existingBytes != nil {
		var existing TrustEvidenceRecord
		if err := json.Unmarshal(existingBytes, &existing); err != nil {
			return fmt.Errorf("failed to unmarshal existing evidence: %v", err)
		}
		if existing.EvidenceType == record.EvidenceType && existing.EvidenceHash == record.EvidenceHash && existing.EvidencePayload == record.EvidencePayload {
			return nil // Idempotent success
		}
		return fmt.Errorf("duplicate evidence ID with conflicting payload")
	}

	// Verify that target SBOM exists
	sbomBytes, err := ctx.GetStub().GetState(input.SBOMID)
	if err != nil {
		return fmt.Errorf("failed to read target SBOM %s from world state: %v", input.SBOMID, err)
	}
	if sbomBytes == nil {
		return fmt.Errorf("target SBOM %s does not exist on the ledger", input.SBOMID)
	}

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal TrustEvidenceRecord: %v", err)
	}

	if err := ctx.GetStub().PutState(key, recordBytes); err != nil {
		return fmt.Errorf("failed to put TrustEvidenceRecord into world state: %v", err)
	}

	// Emit chaincode event
	ctx.GetStub().SetEvent("TrustEvidenceRecorded", recordBytes)

	return nil
}

// RecordTrustDecision records an authoritative trust evaluation decision and updates the target SBOM record.
func (c *SBOMContract) RecordTrustDecision(ctx contractapi.TransactionContextInterface, inputJSON string) error {
	var input RecordTrustDecisionInput
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("invalid JSON input for RecordTrustDecision: %v", err)
	}

	if input.Version != "3.0" {
		return fmt.Errorf("unsupported trust decision input version: %s (expected 3.0)", input.Version)
	}
	if input.SBOMID == "" || input.DecisionId == "" || input.TrustStatus == "" {
		return fmt.Errorf("missing required fields in RecordTrustDecisionInput: sbomID, decisionId, and trustStatus are required")
	}

	if err := validateOptionalSHA256Digest(input.ProvenanceHash); err != nil {
		return fmt.Errorf("invalid provenanceHash: %v", err)
	}
	for _, h := range input.SignatureHashes {
		if err := validateSHA256Digest(h); err != nil {
			return fmt.Errorf("invalid signatureHash: %v", err)
		}
	}

	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %v", err)
	}
	if mspID != "SecurityMSP" && mspID != "AuditorMSP" {
		return fmt.Errorf("unauthorized MSP %s for RecordTrustDecision: only governance MSPs are allowed", mspID)
	}

	// Enforce the authoritative four-state trust-decision enum at the ledger boundary.
	// Any caller submitting UNTRUSTED, UNEVALUATED, or an arbitrary string is rejected here.
	switch input.TrustStatus {
	case TrustStatusTrusted, TrustStatusConditionallyAccepted, TrustStatusReviewRequired, TrustStatusRejected:
		// Valid authoritative decision — proceed
	default:
		return fmt.Errorf(
			"invalid trust decision value %q: only TRUSTED, CONDITIONALLY_ACCEPTED, REVIEW_REQUIRED, or REJECTED are accepted; "+
				"UNTRUSTED is not an authoritative v3 decision (use REJECTED instead); UNEVALUATED is not an authoritative decision",
			input.TrustStatus,
		)
	}

	submitter, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		submitter = "unknown"
	}
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %v", err)
	}

	key, err := ctx.GetStub().CreateCompositeKey("tpsr.trust.decision", []string{input.SBOMID, input.DecisionId})
	if err != nil {
		return fmt.Errorf("failed to create composite key for trust decision: %v", err)
	}

	existingDecisionBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to get existing decision state: %v", err)
	}

	if existingDecisionBytes != nil {
		var existing TrustDecisionPointer
		if err := json.Unmarshal(existingDecisionBytes, &existing); err != nil {
			return fmt.Errorf("failed to unmarshal existing decision: %v", err)
		}
		// Compare canonical payload hashes (all important fields)
		if existing.TrustStatus == input.TrustStatus &&
			existing.ReasonCode == input.ReasonCode &&
			existing.ReasonDescription == input.ReasonDescription &&
			existing.PolicyVersion == input.PolicyVersion &&
			existing.IdempotencyKey == input.IdempotencyKey &&
			existing.ProvenanceHash == input.ProvenanceHash &&
			reflect.DeepEqual(existing.SignatureHashes, input.SignatureHashes) &&
			reflect.DeepEqual(existing.ActiveVexIds, input.ActiveVexIds) &&
			existing.EffectiveRiskScore == input.EffectiveRiskScore {
			return nil // Idempotent success
		}
		return fmt.Errorf("duplicate decision ID with conflicting payload")
	}

	// Read existing SBOM record
	sbomBytes, err := ctx.GetStub().GetState(input.SBOMID)
	if err != nil {
		return fmt.Errorf("failed to read target SBOM %s from world state: %v", input.SBOMID, err)
	}
	if sbomBytes == nil {
		return fmt.Errorf("target SBOM %s does not exist on the ledger", input.SBOMID)
	}

	var sbom SBOMRecord
	if err := json.Unmarshal(sbomBytes, &sbom); err != nil {
		return fmt.Errorf("failed to unmarshal target SBOM record: %v", err)
	}
	sbom.EnsureSlices()

	// Update trust governance fields on SBOMRecord
	sbom.TrustStatus = input.TrustStatus
	sbom.TrustReasonCode = input.ReasonCode
	sbom.TrustReasonDesc = input.ReasonDescription
	sbom.TrustEvaluatedAt = timestamp.Seconds
	sbom.TrustEvaluatedBy = submitter
	sbom.ProvenanceHash = input.ProvenanceHash

	if input.SignatureHashes != nil {
		sbom.SignatureHashes = input.SignatureHashes
	} else if sbom.SignatureHashes == nil {
		sbom.SignatureHashes = []string{}
	}

	if input.ActiveVexIds != nil {
		sbom.ActiveVexIds = input.ActiveVexIds
	} else if sbom.ActiveVexIds == nil {
		sbom.ActiveVexIds = []string{}
	}

	sbom.EffectiveRiskScore = input.EffectiveRiskScore

	updatedSBOMBytes, err := json.Marshal(sbom)
	if err != nil {
		return fmt.Errorf("failed to marshal updated SBOMRecord: %v", err)
	}

	// Put updated SBOM record back into world state
	if err := ctx.GetStub().PutState(input.SBOMID, updatedSBOMBytes); err != nil {
		return fmt.Errorf("failed to update SBOMRecord in world state: %v", err)
	}

	// Create historical decision pointer
	pointer := &TrustDecisionPointer{
		DecisionId:         input.DecisionId,
		SBOMID:             input.SBOMID,
		TrustStatus:        input.TrustStatus,
		ReasonCode:         input.ReasonCode,
		ReasonDescription:  input.ReasonDescription,
		PolicyVersion:      input.PolicyVersion,
		IdempotencyKey:     input.IdempotencyKey,
		ProvenanceHash:     input.ProvenanceHash,
		SignatureHashes:    sbom.SignatureHashes,
		ActiveVexIds:       sbom.ActiveVexIds,
		EffectiveRiskScore: input.EffectiveRiskScore,
		RecordedAt:         timestamp.Seconds,
		RecordedBy:         submitter,
	}

	pointerBytes, err := json.Marshal(pointer)
	if err != nil {
		return fmt.Errorf("failed to marshal TrustDecisionPointer: %v", err)
	}

	if err := ctx.GetStub().PutState(key, pointerBytes); err != nil {
		return fmt.Errorf("failed to put TrustDecisionPointer into world state: %v", err)
	}

	ctx.GetStub().SetEvent("TrustDecisionRecorded", pointerBytes)

	return nil
}

// GetTrustDecision retrieves an exact immutable decision record by SBOM ID and Decision ID.
func (c *SBOMContract) GetTrustDecision(ctx contractapi.TransactionContextInterface, sbomID string, decisionId string) (*TrustDecisionResponse, error) {
	if sbomID == "" {
		return nil, fmt.Errorf("sbomID is required")
	}
	if decisionId == "" {
		return nil, fmt.Errorf("decisionId is required")
	}

	key, err := ctx.GetStub().CreateCompositeKey("tpsr.trust.decision", []string{sbomID, decisionId})
	if err != nil {
		return nil, fmt.Errorf("failed to create composite key: %v", err)
	}
	bytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("trust decision not found")
	}
	var pointer TrustDecisionPointer
	if err := json.Unmarshal(bytes, &pointer); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trust decision: %v", err)
	}

	// Normalize sparse fields to satisfy stable return schema
	resp := &TrustDecisionResponse{
		DecisionId:         pointer.DecisionId,
		SBOMID:             pointer.SBOMID,
		TrustStatus:        pointer.TrustStatus,
		ReasonCode:         pointer.ReasonCode,
		ReasonDescription:  pointer.ReasonDescription,
		PolicyVersion:      pointer.PolicyVersion,
		IdempotencyKey:     pointer.IdempotencyKey,
		ProvenanceHash:     pointer.ProvenanceHash,
		SignatureHashes:    pointer.SignatureHashes,
		ActiveVexIds:       pointer.ActiveVexIds,
		EffectiveRiskScore: pointer.EffectiveRiskScore,
		RecordedAt:         pointer.RecordedAt,
		RecordedBy:         pointer.RecordedBy,
	}

	if resp.SignatureHashes == nil {
		resp.SignatureHashes = []string{}
	}
	if resp.ActiveVexIds == nil {
		resp.ActiveVexIds = []string{}
	}

	return resp, nil
}

// GetTrustEvidence retrieves all trust evidence records recorded for an SBOM.
func (c *SBOMContract) GetTrustEvidence(ctx contractapi.TransactionContextInterface, sbomID string) ([]*TrustEvidenceRecord, error) {
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey("tpsr.trust.evidence", []string{sbomID})
	if err != nil {
		return nil, fmt.Errorf("failed to read trust evidence from world state: %v", err)
	}
	defer iterator.Close()

	var evidenceList []*TrustEvidenceRecord
	for iterator.HasNext() {
		response, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("iterator iteration error: %v", err)
		}
		if response.Value == nil {
			continue
		}
		var record TrustEvidenceRecord
		if err := json.Unmarshal(response.Value, &record); err != nil {
			return nil, fmt.Errorf("failed to unmarshal TrustEvidenceRecord JSON: %v", err)
		}
		evidenceList = append(evidenceList, &record)
	}

	if evidenceList == nil {
		evidenceList = make([]*TrustEvidenceRecord, 0)
	}

	return evidenceList, nil
}
