package main

import (
	"strings"
	"testing"
)

func TestEncodeTransportFragmentPreservesFieldsAndChunkOrder(t *testing.T) {
	claims := strings.Repeat("A", 241)
	got, err := encodeTransportFragment("qv2."+claims+".B.C", testTransportEncodingContract())
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
		if _, err := encodeTransportFragment(input, testTransportEncodingContract()); err == nil {
			t.Fatalf("encodeTransportFragment(%q) accepted malformed input", input)
		}
	}
	invalid := testTransportEncodingContract()
	invalid.ComponentMax = 0
	if _, err := encodeTransportFragment("qv2.A.B.C", invalid); err == nil {
		t.Fatal("encodeTransportFragment accepted a non-positive component maximum")
	}
}

func TestEncodeTransportFragmentEnforcesAllPublishedBounds(t *testing.T) {
	for name, mutate := range map[string]func(*transportEncodingContract, *string){
		"claims encoded length": func(_ *transportEncodingContract, fragment *string) {
			*fragment = "qv2." + strings.Repeat("A", 6_145) + ".B.C"
		},
		"secret encoded length": func(_ *transportEncodingContract, fragment *string) {
			*fragment = "qv2.A." + strings.Repeat("B", 513) + ".C"
		},
		"signature encoded length": func(_ *transportEncodingContract, fragment *string) {
			*fragment = "qv2.A.B." + strings.Repeat("C", 129)
		},
		"field chunk count": func(contract *transportEncodingContract, fragment *string) {
			contract.Fields.Claims.MaxChunks = 1
			*fragment = "qv2." + strings.Repeat("A", 241) + ".B.C"
		},
		"total transport length": func(contract *transportEncodingContract, _ *string) {
			contract.MaxTransportLength = len("qv2t1.1.1.1.A.B.C") - 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			contract := testTransportEncodingContract()
			fragment := "qv2.A.B.C"
			mutate(&contract, &fragment)
			if _, err := encodeTransportFragment(fragment, contract); err == nil {
				t.Fatalf("encodeTransportFragment accepted input outside %s", name)
			}
		})
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
	if issuer.D.Cmp(resource.D) == 0 || (issuer.X.Cmp(resource.X) == 0 && issuer.Y.Cmp(resource.Y) == 0) {
		t.Fatal("fixed issuer and resource keys are not distinct")
	}
}

func testTransportEncodingContract() transportEncodingContract {
	contract := transportEncodingContract{ComponentMax: 240, MaxTransportLength: 6_826}
	contract.Fields.Claims = transportFieldContract{MaxEncodedLength: 6_144, MaxChunks: 26}
	contract.Fields.Secret = transportFieldContract{MaxEncodedLength: 512, MaxChunks: 3}
	contract.Fields.Signature = transportFieldContract{MaxEncodedLength: 128, MaxChunks: 1}
	return contract
}
