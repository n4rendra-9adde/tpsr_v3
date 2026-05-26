package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *SBOMContract) MarkCompliant(ctx contractapi.TransactionContextInterface, sbomID string) error {
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

	if record.Status != StatusSecurityReviewed {
		return fmt.Errorf("can only mark COMPLIANT from SECURITY_REVIEWED status, current status is %s", record.Status)
	}

	submitterID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %w", err)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %w", err)
	}

	record.Status = StatusCompliant
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
