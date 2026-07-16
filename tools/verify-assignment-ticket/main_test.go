package main

import "testing"

func TestCommittedAssignmentTicketVectors(t *testing.T) {
	if err := verify(); err != nil {
		t.Fatal(err)
	}
}
