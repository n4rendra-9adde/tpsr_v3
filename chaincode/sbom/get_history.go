package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func mapToSBOMResponse(r *SBOMRecord) *SBOMRecordResponse {
	resp := &SBOMRecordResponse{
		SBOMID:               r.SBOMID,
		Hash:                 r.Hash,
		Timestamp:            r.Timestamp,
		SubmitterID:          r.SubmitterID,
		BuildID:              r.BuildID,
		SoftwareName:         r.SoftwareName,
		SoftwareVersion:      r.SoftwareVersion,
		Format:               r.Format,
		Status:               r.Status,
		OffChainRef:          r.OffChainRef,
		Signatures:           r.Signatures,
		PolicyStatus:         r.PolicyStatus,
		PolicyReason:         r.PolicyReason,
		PolicyViolations:     r.PolicyViolations,
		PolicyEvaluationMode: r.PolicyEvaluationMode,
		TrustStatus:          r.TrustStatus,
		TrustReasonCode:      r.TrustReasonCode,
		TrustReasonDesc:      r.TrustReasonDesc,
		TrustEvaluatedAt:     r.TrustEvaluatedAt,
		TrustEvaluatedBy:     r.TrustEvaluatedBy,
		ProvenanceHash:       r.ProvenanceHash,
		SignatureHashes:      r.SignatureHashes,
		ActiveVexIds:         r.ActiveVexIds,
		EffectiveRiskScore:   r.EffectiveRiskScore,
	}

	if resp.Signatures == nil {
		resp.Signatures = []string{}
	}
	if resp.PolicyViolations == nil {
		resp.PolicyViolations = []string{}
	}
	if resp.SignatureHashes == nil {
		resp.SignatureHashes = []string{}
	}
	if resp.ActiveVexIds == nil {
		resp.ActiveVexIds = []string{}
	}

	return resp
}

func (c *SBOMContract) GetHistory(
	ctx contractapi.TransactionContextInterface,
	sbomID string,
) ([]*HistoryRecordResponse, error) {
	if sbomID == "" {
		return nil, fmt.Errorf("sbomID is required")
	}

	iterator, err := ctx.GetStub().GetHistoryForKey(sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to get history for key %q: %w", sbomID, err)
	}
	defer iterator.Close()

	var history []*HistoryRecordResponse

	for iterator.HasNext() {
		response, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate history: %w", err)
		}

		entry := &HistoryRecordResponse{
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
			entry.Record = mapToSBOMResponse(&record)
		}

		history = append(history, entry)
	}

	return history, nil
}
