package main

import (
	"strings"
	"testing"
)

func TestEncodeTransportFragmentPreservesFieldsAndChunkOrder(t *testing.T) {
	claims := strings.Repeat("A", 241)
	got, err := encodeTransportFragment("qv2." + claims + ".B.C")
	if err != nil {
		t.Fatal(err)
	}
	want := "qv2t1.2.1.1." + strings.Repeat("A", 240) + ".A.B.C"
	if got != want {
		t.Fatalf("transport fragment = %q, want %q", got, want)
	}
}

func TestEncodeTransportFragmentRejectsMalformedCanonicalInput(t *testing.T) {
	for _, input := range []string{"qv2.A.B", "qv1.A.B.C", "qv2.A..C"} {
		if _, err := encodeTransportFragment(input); err == nil {
			t.Fatalf("encodeTransportFragment(%q) accepted malformed input", input)
		}
	}
}

func TestReplaceExactJSONStringEnforcesOccurrenceCount(t *testing.T) {
	input := []byte(`{"a":"old","b":"old"}`)
	got, err := replaceExactJSONString(input, "old", "new", 2)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":"new","b":"new"}` {
		t.Fatalf("replacement = %s", got)
	}
	if _, err := replaceExactJSONString(input, "old", "new", 1); err == nil {
		t.Fatal("replacement accepted the wrong occurrence count")
	}
}
