package conformance

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestDecodeRequestNonceAcceptsCommittedFixtures(t *testing.T) {
	resource, err := ConnectorResourceLSTV1()
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"assignment refresh fixture": AgentAssignmentRefreshRequestNonceFixture,
		"resource create nonce":      resource.Fixtures.CreateRequestNonce,
		"resource existing nonce":    resource.Fixtures.ExistingRequestNonce,
		"resource no-CRID nonce":     resource.Fixtures.NoCRIDRequestNonce,
	} {
		nonce, err := DecodeRequestNonce(value)
		if err != nil {
			t.Fatalf("%s: DecodeRequestNonce(%q) = %v, want accept", name, value, err)
		}
		if len(nonce) != RequestNonceBytes {
			t.Fatalf("%s: decoded %d bytes, want %d", name, len(nonce), RequestNonceBytes)
		}
	}
}

func TestDecodeRequestNonceRejects(t *testing.T) {
	raw := make([]byte, RequestNonceBytes)
	for i := range raw {
		raw[i] = byte(0xa0 + i)
	}
	canonical := base64.RawURLEncoding.EncodeToString(raw)
	cases := map[string]string{
		"empty":                    "",
		"padded":                   canonical + "=",
		"short":                    canonical[:len(canonical)-1],
		"long":                     canonical + "A",
		"standard alphabet plus":   "+" + canonical[1:],
		"standard alphabet slash":  "/" + canonical[1:],
		"whitespace":               " " + canonical[1:],
		"non-canonical tail bits":  canonical[:len(canonical)-1] + "B",
		"31 bytes":                 base64.RawURLEncoding.EncodeToString(raw[:31]),
		"33 bytes":                 base64.RawURLEncoding.EncodeToString(append(append([]byte{}, raw...), 0)),
		"non-ascii":                strings.Repeat("\u00e9", 22),
		"embedded newline":         canonical[:20] + "\n" + canonical[20:],
		"trailing newline":         canonical + "\n",
		"embedded carriage return": canonical[:20] + "\r" + canonical[20:],
	}
	for name, value := range cases {
		if _, err := DecodeRequestNonce(value); !errors.Is(err, ErrRequestNonce) {
			t.Errorf("%s: DecodeRequestNonce(%q) = %v, want ErrRequestNonce", name, value, err)
		}
	}
	if got, err := DecodeRequestNonce(canonical); err != nil || base64.RawURLEncoding.EncodeToString(got) != canonical {
		t.Fatalf("canonical nonce = %x, %v; want round trip", got, err)
	}
}
