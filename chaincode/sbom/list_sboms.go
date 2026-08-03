package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *SBOMContract) ListSBOMs(ctx contractapi.TransactionContextInterface) ([]*SBOMRecordResponse, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	defer resultsIterator.Close()

	var sboms []*SBOMRecordResponse
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("iterator iteration error: %v", err)
		}
		if response.Value == nil {
			continue
		}

		var sbom SBOMRecord
		err = json.Unmarshal(response.Value, &sbom)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
		}
		sbom.EnsureSlices()

		// Skip non-SBOM records (e.g. TrustDecisionPointers)
		if sbom.SBOMID == "" || sbom.Format == "" {
			continue
		}

		sboms = append(sboms, mapToSBOMResponse(&sbom))
	}

	if sboms == nil {
		sboms = make([]*SBOMRecordResponse, 0)
	}

	return sboms, nil
}
