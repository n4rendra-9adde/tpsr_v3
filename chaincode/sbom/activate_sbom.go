package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *SBOMContract) ActivateSBOM(ctx contractapi.TransactionContextInterface, sbomID string) error {
	if sbomID == "" {
		return fmt.Errorf("sbomID is required")
	}

	existingBytes, err := ctx.GetStub().GetState(sbomID)
	if err != nil {
		return fmt.Errorf("failed to read world state: %w", err)
	}
	if existingBytes == nil {
		return fmt.Errorf("SBOM record with ID %q does not exist", sbomID)
	}

	var record SBOMRecord
	if err := json.Unmarshal(existingBytes, &record); err != nil {
		return fmt.Errorf("failed to unmarshal existing record: %w", err)
	}

	if record.Status != StatusApproved {
		return fmt.Errorf("can only activate SBOMs in APPROVED status, current status is %s", record.Status)
	}

	// Authoritative trust-decision gating (TPSR v3 four-state model).
	// REJECTED and legacy UNTRUSTED records are both hard-blocked.
	// REVIEW_REQUIRED requires completed manual review workflow before activation.
	// UNEVALUATED records must complete authoritative v3 evaluation first.
	// CONDITIONALLY_ACCEPTED requires valid exception (validated at API layer before this call).
	// TRUSTED records proceed normally.
	switch record.TrustStatus {
	case TrustStatusRejected, TrustStatusUntrustedLegacy:
		return fmt.Errorf("lifecycle transition blocked: SBOM trust decision is REJECTED (reason code: %s) — remediate all blocking violations before activation", record.TrustReasonCode)
	case TrustStatusReviewRequired:
		return fmt.Errorf("lifecycle transition blocked: SBOM trust decision is REVIEW_REQUIRED (reason code: %s) — complete the manual review workflow before activation", record.TrustReasonCode)
	case TrustStatusUnevaluated:
		return fmt.Errorf("lifecycle transition blocked: SBOM has not undergone authoritative TPSR v3 trust evaluation — submit evidence and request evaluation before activation")
	case TrustStatusTrusted, TrustStatusConditionallyAccepted:
		// Permitted to advance; fall through
	}

	submitterID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %w", err)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %w", err)
	}

	record.Status = StatusActive
	record.SubmitterID = submitterID
	record.Timestamp = txTimestamp.Seconds

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal updated SBOM record: %w", err)
	}

	if err := ctx.GetStub().PutState(sbomID, recordBytes); err != nil {
		return fmt.Errorf("failed to put updated state: %w", err)
	}

	return nil
}
