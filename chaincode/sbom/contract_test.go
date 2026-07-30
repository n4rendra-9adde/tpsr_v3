package main

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrRequiredField(t *testing.T) {
	err := ErrRequiredField("sbomID")
	expected := "sbomID is required"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidFormat(t *testing.T) {
	err := ErrInvalidFormat("XML")
	expected := `invalid format "XML": must be SPDX or CycloneDX`
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSBOMAlreadyExists(t *testing.T) {
	err := ErrSBOMAlreadyExists("sbom-001")
	expected := `SBOM record with ID "sbom-001" already exists`
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSBOMNotFound(t *testing.T) {
	err := ErrSBOMNotFound("sbom-999")
	expected := `SBOM record with ID "sbom-999" not found`
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrWorldStateRead(t *testing.T) {
	cause := fmt.Errorf("connection refused")
	err := ErrWorldStateRead(cause)
	expected := "failed to read world state: connection refused"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatalf("expected wrapped error to match cause")
	}
}

func TestErrWorldStateWrite(t *testing.T) {
	cause := fmt.Errorf("write timeout")
	err := ErrWorldStateWrite(cause)
	expected := "failed to put state: write timeout"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrMarshalSBOMRecord(t *testing.T) {
	cause := fmt.Errorf("json error")
	err := ErrMarshalSBOMRecord(cause)
	expected := "failed to marshal SBOM record: json error"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrUnmarshalSBOMRecord(t *testing.T) {
	cause := fmt.Errorf("invalid character")
	err := ErrUnmarshalSBOMRecord(cause)
	expected := "failed to unmarshal SBOM record: invalid character"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrHistoryQuery(t *testing.T) {
	cause := fmt.Errorf("ledger error")
	err := ErrHistoryQuery("sbom-001", cause)
	expected := `failed to get history for key "sbom-001": ledger error`
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrHistoryIteration(t *testing.T) {
	cause := fmt.Errorf("iterator exhausted")
	err := ErrHistoryIteration(cause)
	expected := "failed to iterate history: iterator exhausted"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestSBOMRecordInitialization(t *testing.T) {
	record := SBOMRecord{
		SBOMID:               "sbom-001",
		Hash:                 "abc123",
		Timestamp:            1700000000,
		SubmitterID:          "user1",
		BuildID:              "build-42",
		SoftwareName:         "myapp",
		SoftwareVersion:      "1.0.0",
		Format:               "SPDX",
		Status:               StatusRegistered,
		OffChainRef:          "QmXyz",
		Signatures:           []string{"sig1", "sig2"},
		PolicyStatus:         "PASS",
		PolicyReason:         "No vulnerabilities found",
		PolicyViolations:     []string{},
		PolicyEvaluationMode: "EMBEDDED_VULNERABILITY",
	}
	if record.SBOMID != "sbom-001" {
		t.Errorf("expected SBOMID %q, got %q", "sbom-001", record.SBOMID)
	}
	if record.Status != StatusRegistered {
		t.Errorf("expected Status %q, got %q", StatusRegistered, record.Status)
	}
	if len(record.Signatures) != 2 {
		t.Errorf("expected 2 signatures, got %d", len(record.Signatures))
	}
}

func TestVerificationResultInitialization(t *testing.T) {
	result := VerificationResult{
		SBOMID:        "sbom-001",
		SubmittedHash: "abc123",
		StoredHash:    "abc123",
		Match:         true,
		Status:        StatusActive,
	}
	if result.SBOMID != "sbom-001" {
		t.Errorf("expected SBOMID %q, got %q", "sbom-001", result.SBOMID)
	}
	if !result.Match {
		t.Errorf("expected Match to be true")
	}
	if result.Status != StatusActive {
		t.Errorf("expected Status %q, got %q", StatusActive, result.Status)
	}
}

func TestVerificationResultMismatch(t *testing.T) {
	result := VerificationResult{
		SBOMID:        "sbom-002",
		SubmittedHash: "aaa",
		StoredHash:    "bbb",
		Match:         false,
		Status:        StatusRegistered,
	}
	if result.Match {
		t.Errorf("expected Match to be false")
	}
}

func TestHistoryRecordInitialization(t *testing.T) {
	record := SBOMRecord{
		SBOMID: "sbom-001",
		Hash:   "abc123",
		Status: StatusActive,
	}
	entry := HistoryRecord{
		TxID:      "tx-001",
		Timestamp: 1700000000,
		IsDelete:  false,
		Record:    &record,
	}
	if entry.TxID != "tx-001" {
		t.Errorf("expected TxID %q, got %q", "tx-001", entry.TxID)
	}
	if entry.IsDelete {
		t.Errorf("expected IsDelete to be false")
	}
	if entry.Record == nil {
		t.Fatalf("expected Record to not be nil")
	}
	if entry.Record.SBOMID != "sbom-001" {
		t.Errorf("expected Record.SBOMID %q, got %q", "sbom-001", entry.Record.SBOMID)
	}
}

func TestHistoryRecordDeleteEntry(t *testing.T) {
	entry := HistoryRecord{
		TxID:      "tx-002",
		Timestamp: 1700000100,
		IsDelete:  true,
		Record:    nil,
	}
	if !entry.IsDelete {
		t.Errorf("expected IsDelete to be true")
	}
	if entry.Record != nil {
		t.Errorf("expected Record to be nil for delete entry")
	}
}

func TestStatusConstants(t *testing.T) {
	if StatusRegistered != "REGISTERED" {
		t.Errorf("expected %q, got %q", "REGISTERED", StatusRegistered)
	}
	if StatusReviewPending != "REVIEW_PENDING" {
		t.Errorf("expected %q, got %q", "REVIEW_PENDING", StatusReviewPending)
	}
	if StatusSecurityReviewed != "SECURITY_REVIEWED" {
		t.Errorf("expected %q, got %q", "SECURITY_REVIEWED", StatusSecurityReviewed)
	}
	if StatusCompliant != "COMPLIANT" {
		t.Errorf("expected %q, got %q", "COMPLIANT", StatusCompliant)
	}
	if StatusApproved != "APPROVED" {
		t.Errorf("expected %q, got %q", "APPROVED", StatusApproved)
	}
	if StatusActive != "ACTIVE" {
		t.Errorf("expected %q, got %q", "ACTIVE", StatusActive)
	}
	if StatusSuperseded != "SUPERSEDED" {
		t.Errorf("expected %q, got %q", "SUPERSEDED", StatusSuperseded)
	}
	if StatusRejected != "REJECTED" {
		t.Errorf("expected %q, got %q", "REJECTED", StatusRejected)
	}
}
