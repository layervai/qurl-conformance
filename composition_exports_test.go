package conformance

import (
	"strings"
	"testing"
)

// The two exported composition points exist so the private conformance module
// applies this module's exact gates instead of copies. Pin their signatures and
// outcomes here so a drift breaks this repository before it breaks a consumer.

func TestValidateConnectorResourceLSTV1EnvironmentPinsTheLabelGrammar(t *testing.T) {
	for _, accept := range []string{"sandbox", "prod", "a", "a-b1", "a" + strings.Repeat("b", 31)} {
		if err := ValidateConnectorResourceLSTV1Environment(accept); err != nil {
			t.Errorf("ValidateConnectorResourceLSTV1Environment(%q) = %v, want accept", accept, err)
		}
	}
	for _, reject := range []string{"", "Sandbox", "1abc", "-abc", "abc-", "a b", "a_b", "a" + strings.Repeat("b", 32)} {
		err := ValidateConnectorResourceLSTV1Environment(reject)
		if err == nil || !strings.HasPrefix(err.Error(), "conformance: ") {
			t.Errorf("ValidateConnectorResourceLSTV1Environment(%q) = %v, want prefixed reject", reject, err)
		}
	}
}

func TestCRIDV1KeyMatchExpectationPinsTheDeliveredKeyOutcome(t *testing.T) {
	file, err := CRIDV1()
	if err != nil {
		t.Fatal(err)
	}
	if len(file.ProducerCases) == 0 {
		t.Fatal("need a producer case")
	}
	first := file.ProducerCases[0]
	// Flip one payload character of the delivered key so it still decodes but
	// no longer re-derives the held CRID.
	other := []byte(first.DERSPKIB64URL)
	i := len(other) / 2
	if other[i] == 'A' {
		other[i] = 'B'
	} else {
		other[i] = 'A'
	}
	second := struct{ DERSPKIB64URL string }{string(other)}
	if got, err := CRIDV1KeyMatchExpectation(first.ExpectedCRID, first.DERSPKIB64URL); err != nil || got != CRIDV1OutcomeMatch {
		t.Fatalf("same key: outcome %q, %v; want %q", got, err, CRIDV1OutcomeMatch)
	}
	if got, err := CRIDV1KeyMatchExpectation(first.ExpectedCRID, second.DERSPKIB64URL); err != nil || got != CRIDV1OutcomeMismatch {
		t.Fatalf("other key: outcome %q, %v; want %q", got, err, CRIDV1OutcomeMismatch)
	}
	if _, err := CRIDV1KeyMatchExpectation("not-a-crid", first.DERSPKIB64URL); err == nil {
		t.Fatal("held CRID that fails the local gate was accepted")
	}
	if _, err := CRIDV1KeyMatchExpectation(first.ExpectedCRID, "!!"); err == nil {
		t.Fatal("malformed der_spki_b64url was accepted")
	}
}
