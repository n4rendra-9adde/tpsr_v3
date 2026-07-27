package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *SBOMContract) ApproveSBOM(ctx contractapi.TransactionContextInterface, sbomID string) error {
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

	if record.Status != StatusCompliant {
		return fmt.Errorf("can only approve SBOMs in COMPLIANT status, current status is %s", record.Status)
	}

	// Authoritative trust-decision gating (TPSR v3 four-state model).
	// REJECTED and legacy UNTRUSTED records are both hard-blocked.
	// REVIEW_REQUIRED requires manual review workflow before advancement.
	// UNEVALUATED records must complete authoritative v3 evaluation first.
	//
	// CONDITIONALLY_ACCEPTED: BLOCKED in Group 1.
	// Chaincode cannot verify that the conditional exception evidence is
	// current, anchored, and validly scoped on the Fabric ledger.
	// This gate will be relaxed in the Fabric governance remediation group
	// once exception evidence anchoring and on-chain verification are implemented.
	// API layer also blocks CONDITIONALLY_ACCEPTED approval separately.
	//
	// TRUSTED records proceed normally.
	switch record.TrustStatus {
	case TrustStatusRejected, TrustStatusUntrustedLegacy:
		return fmt.Errorf("lifecycle transition blocked: SBOM trust decision is REJECTED (reason code: %s) — remediate all blocking violations before approval", record.TrustReasonCode)
	case TrustStatusReviewRequired:
		return fmt.Errorf("lifecycle transition blocked: SBOM trust decision is REVIEW_REQUIRED (reason code: %s) — complete the manual review workflow before approval", record.TrustReasonCode)
	case TrustStatusUnevaluated:
		return fmt.Errorf("lifecycle transition blocked: SBOM has not undergone authoritative TPSR v3 trust evaluation — submit evidence and request evaluation before approval")
	case TrustStatusConditionallyAccepted:
		return fmt.Errorf("lifecycle transition blocked: SBOM trust decision is CONDITIONALLY_ACCEPTED — " +
			"conditional approval requires anchored exception evidence verification on the Fabric ledger, " +
			"which is not yet implemented (pending Fabric governance remediation). " +
			"Remediate the underlying policy violation to advance to TRUSTED, or await the governance remediation.")
	case TrustStatusTrusted:
		// Permitted to advance; fall through
	}

	// Fetch new submitter identity
	submitterID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %w", err)
	}

	// Fetch new transaction timestamp
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %w", err)
	}

	record.Status = StatusApproved
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
