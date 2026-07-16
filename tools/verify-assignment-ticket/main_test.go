package main

import (
	"encoding/asn1"
	"math/big"
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

func TestDERRejectClassMismatchFails(t *testing.T) {
	af, err := conformance.AssignmentTicket()
	if err != nil {
		t.Fatal(err)
	}
	af.KMSDERCases[1].RejectClass = "claims"
	if err := verifyDERCases(af.KMSDERCases); err == nil || !strings.Contains(err.Error(), `class = "claims", want der`) {
		t.Fatalf("error = %v, want DER class mismatch", err)
	}
}

func TestDERToRawLowSRejectsUnexpectedSequenceElement(t *testing.T) {
	der, err := asn1.Marshal(struct {
		R     *big.Int
		S     *big.Int
		Extra int
	}{R: big.NewInt(1), S: big.NewInt(1), Extra: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := derToRawLowS(der); err == nil {
		t.Fatal("DER with an unexpected sequence element was accepted")
	}
}
