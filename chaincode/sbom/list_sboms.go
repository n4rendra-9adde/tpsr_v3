package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *SBOMContract) ListSBOMs(ctx contractapi.TransactionContextInterface) ([]*SBOMRecord, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	defer resultsIterator.Close()

	var sboms []*SBOMRecord
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
		sboms = append(sboms, &sbom)
	}

	if sboms == nil {
		sboms = make([]*SBOMRecord, 0)
	}

	return sboms, nil
}
