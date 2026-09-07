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
	if len(file.KeyMatchCases) == 0 {
		t.Fatal("need key_match_cases")
	}
	seen := map[string]bool{}
	for _, c := range file.KeyMatchCases {
		got, err := CRIDV1KeyMatchExpectation(c.CRID, c.DERSPKIB64URL)
		if err != nil || got != c.Outcome {
			t.Errorf("%s: outcome %q, %v; want %q", c.Name, got, err, c.Outcome)
		}
		seen[c.Outcome] = true
	}
	if !seen[CRIDV1OutcomeMatch] || !seen[CRIDV1OutcomeMismatch] {
		t.Fatalf("key_match_cases must cover both outcomes, saw %v", seen)
	}
	first := file.KeyMatchCases[0]
	if _, err := CRIDV1KeyMatchExpectation("not-a-crid", first.DERSPKIB64URL); err == nil {
		t.Fatal("held CRID that fails the local gate was accepted")
	}
	if _, err := CRIDV1KeyMatchExpectation(first.CRID, "!!"); err == nil {
		t.Fatal("malformed der_spki_b64url was accepted")
	}
}
