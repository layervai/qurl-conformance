package genkit

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestEncodeTransportFragmentPreservesFieldsAndChunkOrder(t *testing.T) {
	contract := publishedTransportEncodingContract(t)
	claims := strings.Repeat("A", contract.ComponentMax+1)
	got, err := EncodeTransportFragment("qv2."+claims+".B.C", contract)
	if err != nil {
		t.Fatal(err)
	}
	want := "qv2t1.2.1.1." + strings.Repeat("A", contract.ComponentMax) + ".A.B.C"
	if got != want {
		t.Fatalf("transport fragment = %q, want %q", got, want)
	}
}

func TestEncodeTransportFragmentRejectsMalformedCanonicalInput(t *testing.T) {
	for _, input := range []string{"qv2.A.B", "qv1.A.B.C", "qv2.A..C"} {
		if _, err := EncodeTransportFragment(input, publishedTransportEncodingContract(t)); err == nil {
			t.Fatalf("EncodeTransportFragment(%q) accepted malformed input", input)
		}
	}
	invalid := publishedTransportEncodingContract(t)
	invalid.ComponentMax = 0
	if _, err := EncodeTransportFragment("qv2.A.B.C", invalid); err == nil {
		t.Fatal("EncodeTransportFragment accepted a non-positive component maximum")
	}
}

func TestEncodeTransportFragmentEnforcesAllPublishedBounds(t *testing.T) {
	for name, mutate := range map[string]func(*TransportEncodingContract, *string){
		"claims encoded length": func(contract *TransportEncodingContract, fragment *string) {
			*fragment = "qv2." + strings.Repeat("A", contract.Fields.Claims.MaxEncodedLength+1) + ".B.C"
		},
		"secret encoded length": func(contract *TransportEncodingContract, fragment *string) {
			*fragment = "qv2.A." + strings.Repeat("B", contract.Fields.Secret.MaxEncodedLength+1) + ".C"
		},
		"signature encoded length": func(contract *TransportEncodingContract, fragment *string) {
			*fragment = "qv2.A.B." + strings.Repeat("C", contract.Fields.Signature.MaxEncodedLength+1)
		},
		"field chunk count": func(contract *TransportEncodingContract, fragment *string) {
			contract.Fields.Claims.MaxChunks = 1
			*fragment = "qv2." + strings.Repeat("A", contract.ComponentMax+1) + ".B.C"
		},
		"total transport length": func(contract *TransportEncodingContract, _ *string) {
			contract.MaxTransportLength = len("qv2t1.1.1.1.A.B.C") - 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			contract := publishedTransportEncodingContract(t)
			fragment := "qv2.A.B.C"
			mutate(&contract, &fragment)
			if _, err := EncodeTransportFragment(fragment, contract); err == nil {
				t.Fatalf("EncodeTransportFragment accepted input outside %s", name)
			}
		})
	}
}

func TestReplaceExactJSONStringEnforcesOccurrenceCount(t *testing.T) {
	input := []byte(`{"a":"old","b":"old"}`)
	got, err := ReplaceExactJSONString(input, "old", "new", 2)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":"new","b":"new"}` {
		t.Fatalf("replacement = %s", got)
	}
	if _, err := ReplaceExactJSONString(input, "old", "new", 1); err == nil {
		t.Fatal("replacement accepted the wrong occurrence count")
	}
	htmlInput := []byte(`{"value":"<&>"}`)
	htmlGot, err := ReplaceExactJSONString(htmlInput, "<&>", "safe&exact", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(htmlGot) != `{"value":"safe&exact"}` {
		t.Fatalf("HTML-sensitive replacement = %s", htmlGot)
	}
}

func TestFixedP256PrivateKeysAreStableAndDistinct(t *testing.T) {
	issuer, err := FixedP256PrivateKey(0x07)
	if err != nil {
		t.Fatal(err)
	}
	again, err := FixedP256PrivateKey(0x07)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := FixedP256PrivateKey(0x08)
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

func TestFixedX25519PrivateKeyIsStableAndAlreadyClamped(t *testing.T) {
	privateKey := FixedX25519PrivateKey(0x09)
	again := FixedX25519PrivateKey(0x09)
	if !bytes.Equal(privateKey, again) {
		t.Fatal("fixed qURL-user private key is not stable")
	}
	if len(privateKey) != 32 || privateKey[0]&7 != 0 || privateKey[31]&0x80 != 0 || privateKey[31]&0x40 == 0 {
		t.Fatalf("fixed qURL-user private key is not in canonical clamped form: %x", privateKey)
	}
}

func publishedTransportEncodingContract(t *testing.T) TransportEncodingContract {
	t.Helper()
	// The helper tests intentionally read the published root contract instead
	// of a module-local copy. This makes contract drift change the test inputs.
	raw, err := os.ReadFile("../../../../vectors/qv2_conformance_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		TransportContract TransportEncodingContract `json:"transport_contract"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc.TransportContract
}
