package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *SBOMContract) SubmitSBOM(
	ctx contractapi.TransactionContextInterface,
	sbomID string,
	hash string,
	buildID string,
	softwareName string,
	softwareVersion string,
	format string,
	offChainRef string,
	signatures []string,
	policyStatus string,
	policyReason string,
	policyViolations []string,
	policyEvaluationMode string,
) error {

	// A. Validate required inputs
	if sbomID == "" {
		return fmt.Errorf("sbomID is required")
	}
	if hash == "" {
		return fmt.Errorf("hash is required")
	}
	if buildID == "" {
		return fmt.Errorf("buildID is required")
	}
	if softwareName == "" {
		return fmt.Errorf("softwareName is required")
	}
	if softwareVersion == "" {
		return fmt.Errorf("softwareVersion is required")
	}
	if format == "" {
		return fmt.Errorf("format is required")
	}
	if offChainRef == "" {
		return fmt.Errorf("offChainRef is required")
	}

	// B. Validate format
	if format != "SPDX" && format != "CycloneDX" {
		return fmt.Errorf("invalid format %q: must be SPDX or CycloneDX", format)
	}

	// C. Validate signatures
	if len(signatures) == 0 {
		return fmt.Errorf("at least one signature is required")
	}

	// D. Check for duplicate record
	existing, err := ctx.GetStub().GetState(sbomID)
	if err != nil {
		return fmt.Errorf("failed to read world state: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("SBOM record with ID %q already exists", sbomID)
	}

	// E. Get submitter identity
	submitterID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %w", err)
	}

	// F. Get transaction timestamp
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %w", err)
	}
	timestamp := txTimestamp.Seconds

	// G. Build the SBOM record
	record := SBOMRecord{
		SBOMID:          sbomID,
		Hash:            hash,
		Timestamp:       timestamp,
		SubmitterID:     submitterID,
		BuildID:         buildID,
		SoftwareName:    softwareName,
		SoftwareVersion: softwareVersion,
		Format:               format,
		Status:               StatusRegistered,
		OffChainRef:          offChainRef,
		Signatures:           signatures,
		PolicyStatus:         policyStatus,
		PolicyReason:         policyReason,
		PolicyViolations:     policyViolations,
		PolicyEvaluationMode: policyEvaluationMode,
	}

	record.EnsureSlices()

	// H. Marshal to JSON
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM record: %w", err)
	}

	// I. Store in world state
	if err := ctx.GetStub().PutState(sbomID, recordBytes); err != nil {
		return fmt.Errorf("failed to put state: %w", err)
	}

	return nil
}
