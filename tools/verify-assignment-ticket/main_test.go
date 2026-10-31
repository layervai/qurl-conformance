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

func TestExecutableFenceRejectBoundaries(t *testing.T) {
	af, err := conformance.AssignmentTicket()
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range af.FenceVectors {
		if got := fenceInputBoundary(base.Parts, base.Parts); got != "" {
			t.Fatalf("positive %s rejected at %s", base.Kind, got)
		}
	}
	boundaries := map[string]string{
		"credential_hash_wrong_length": "key_length", "credential_scopes_unsorted": "canonical_scopes",
		"credential_scopes_duplicate": "canonical_scopes", "uint64_negative_or_overflow": "uint64",
		"bool_not_single_byte": "encoding", "missing_required_cell_part": "required_part",
	}
	count := 0
	for _, reject := range af.FenceRejects {
		for _, input := range reject.Inputs {
			if expected, ok := boundaries[reject.Name]; !ok || input.Boundary != expected {
				t.Fatalf("recipe %s boundary=%s", reject.Name, input.Boundary)
			}
			count++
			t.Run(input.Name, func(t *testing.T) {
				var base conformance.AssignmentTicketFenceVector
				for _, v := range af.FenceVectors {
					if v.Kind == input.Kind {
						base = v
					}
				}
				if got := fenceInputBoundary(input.Parts, base.Parts); got != input.Boundary {
					t.Fatalf("boundary=%q want=%q", got, input.Boundary)
				}
			})
		}
	}
	if count != 13 {
		t.Fatalf("executed %d inputs, want 13", count)
	}
	// A renamed boundary or an accidentally restored positive must fail even when
	// the caller bypasses the artifact loader's structural checks.
	af.FenceRejects[0].Inputs[0].Parts = af.FenceVectors[0].Parts
	if err := verifyFenceRejectInputs(af); err == nil {
		t.Fatal("accepted positive input as a reject")
	}
	af, err = conformance.AssignmentTicket()
	if err != nil {
		t.Fatal(err)
	}
	af.FenceRejects[0].Inputs[0].Boundary = "unknown"
	if err := verifyFenceRejectInputs(af); err == nil {
		t.Fatal("accepted unknown boundary")
	}
}
