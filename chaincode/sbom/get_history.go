package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *SBOMContract) GetHistory(
	ctx contractapi.TransactionContextInterface,
	sbomID string,
) ([]*HistoryRecord, error) {
	if sbomID == "" {
		return nil, fmt.Errorf("sbomID is required")
	}

	iterator, err := ctx.GetStub().GetHistoryForKey(sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to get history for key %q: %w", sbomID, err)
	}
	defer iterator.Close()

	var history []*HistoryRecord

	for iterator.HasNext() {
		response, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate history: %w", err)
		}

		entry := &HistoryRecord{
			TxID:      response.TxId,
			Timestamp: response.Timestamp.Seconds,
			IsDelete:  response.IsDelete,
		}

		if !response.IsDelete && response.Value != nil {
			var record SBOMRecord
			if err := json.Unmarshal(response.Value, &record); err != nil {
				return nil, fmt.Errorf("failed to unmarshal history record: %w", err)
			}
			record.EnsureSlices()
			entry.Record = &record
		}

		history = append(history, entry)
	}

	return history, nil
}
