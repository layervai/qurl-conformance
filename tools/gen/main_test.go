package main

import (
	"strings"
	"testing"
)

func TestEncodeTransportFragmentPreservesFieldsAndChunkOrder(t *testing.T) {
	claims := strings.Repeat("A", 241)
	got, err := encodeTransportFragment("qv2."+claims+".B.C", 240)
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
		if _, err := encodeTransportFragment(input, 240); err == nil {
			t.Fatalf("encodeTransportFragment(%q) accepted malformed input", input)
		}
	}
	if _, err := encodeTransportFragment("qv2.A.B.C", 0); err == nil {
		t.Fatal("encodeTransportFragment accepted a non-positive component maximum")
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
	htmlInput := []byte(`{"value":"<&>"}`)
	htmlGot, err := replaceExactJSONString(htmlInput, "<&>", "safe&exact", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(htmlGot) != `{"value":"safe&exact"}` {
		t.Fatalf("HTML-sensitive replacement = %s", htmlGot)
	}
}

func TestFixedP256PrivateKeysAreStableAndDistinct(t *testing.T) {
	issuer, err := fixedP256PrivateKey(0x07)
	if err != nil {
		t.Fatal(err)
	}
	again, err := fixedP256PrivateKey(0x07)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := fixedP256PrivateKey(0x08)
	if err != nil {
		t.Fatal(err)
	}
	if issuer.D.Cmp(again.D) != 0 || issuer.X.Cmp(again.X) != 0 || issuer.Y.Cmp(again.Y) != 0 {
		t.Fatal("fixed issuer key is not stable")
	}
	if issuer.D.Cmp(resource.D) == 0 || issuer.X.Cmp(resource.X) == 0 && issuer.Y.Cmp(resource.Y) == 0 {
		t.Fatal("fixed issuer and resource keys are not distinct")
	}
}
