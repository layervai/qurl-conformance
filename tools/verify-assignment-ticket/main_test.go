package main

import (
	"strings"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

func TestCommittedAssignmentTicketVectors(t *testing.T) {
	if err := verify(); err != nil {
		t.Fatal(err)
	}
}

func TestClaimsRejectClassMismatchFails(t *testing.T) {
	af, err := conformance.AssignmentTicket()
	if err != nil {
		t.Fatal(err)
	}
	af.ClaimsRejects[0].RejectClass = "time"
	if err := verifyClaimsCases(af); err == nil || !strings.Contains(err.Error(), `reached "claims" boundary, want "time"`) {
		t.Fatalf("error = %v, want classified boundary mismatch", err)
	}
}
