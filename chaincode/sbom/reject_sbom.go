package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *SBOMContract) RejectSBOM(ctx contractapi.TransactionContextInterface, sbomID string, reason string) error {
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

	if record.Status == StatusSuperseded || record.Status == StatusRejected {
		return fmt.Errorf("cannot reject SBOM from terminal status %s", record.Status)
	}

	submitterID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %w", err)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %w", err)
	}

	record.Status = StatusRejected
	record.SubmitterID = submitterID
	record.Timestamp = txTimestamp.Seconds
	// Note: We intentionally do NOT overwrite PolicyReason here to avoid
	// mixing policy engine results with manual governance rejection rationale.
	// The reason parameter is captured in the transaction history on the ledger.

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal updated SBOM record: %w", err)
	}

	if err := ctx.GetStub().PutState(sbomID, recordBytes); err != nil {
		return fmt.Errorf("failed to put updated state: %w", err)
	}

	return nil
}
