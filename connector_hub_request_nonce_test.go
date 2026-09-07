package conformance

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestDecodeConnectorHubRequestNonceAcceptsCommittedFixtures(t *testing.T) {
	assignment, err := AgentAssignmentGolden()
	if err != nil {
		t.Fatal(err)
	}
	resource, err := ConnectorResourceLSTV1()
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"assignment refresh fixture": AgentAssignmentRefreshRequestNonceFixture,
		"resource create nonce":      resource.Fixtures.CreateRequestNonce,
	} {
		nonce, err := DecodeConnectorHubRequestNonce(value)
		if err != nil {
			t.Fatalf("%s: DecodeConnectorHubRequestNonce(%q) = %v, want accept", name, value, err)
		}
		if len(nonce) != ConnectorHubRequestNonceBytes {
			t.Fatalf("%s: decoded %d bytes, want %d", name, len(nonce), ConnectorHubRequestNonceBytes)
		}
	}
	_ = assignment
}

func TestDecodeConnectorHubRequestNonceRejects(t *testing.T) {
	raw := make([]byte, ConnectorHubRequestNonceBytes)
	for i := range raw {
		raw[i] = byte(0xa0 + i)
	}
	canonical := base64.RawURLEncoding.EncodeToString(raw)
	cases := map[string]string{
		"empty":                   "",
		"padded":                  canonical + "=",
		"short":                   canonical[:len(canonical)-1],
		"long":                    canonical + "A",
		"standard alphabet plus":  "+" + canonical[1:],
		"standard alphabet slash": "/" + canonical[1:],
		"whitespace":              " " + canonical[1:],
		"non-canonical tail bits": canonical[:len(canonical)-1] + "B",
		"31 bytes":                base64.RawURLEncoding.EncodeToString(raw[:31]),
		"33 bytes":                base64.RawURLEncoding.EncodeToString(append(append([]byte{}, raw...), 0)),
		"non-ascii":               strings.Repeat("\u00e9", 22),
	}
	for name, value := range cases {
		if _, err := DecodeConnectorHubRequestNonce(value); !errors.Is(err, ErrConnectorHubRequestNonce) {
			t.Errorf("%s: DecodeConnectorHubRequestNonce(%q) = %v, want ErrConnectorHubRequestNonce", name, value, err)
		}
	}
	if got, err := DecodeConnectorHubRequestNonce(canonical); err != nil || base64.RawURLEncoding.EncodeToString(got) != canonical {
		t.Fatalf("canonical nonce = %x, %v; want round trip", got, err)
	}
}
