package conformance

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestEmbeddedConnectorHubLSTCookieLoads(t *testing.T) {
	file, err := ConnectorHubLSTCookie()
	if err != nil {
		t.Fatal(err)
	}
	if file.Artifact != ConnectorHubLSTCookieArtifactID || file.SchemaVersion != ConnectorHubLSTCookieSchemaVersion {
		t.Fatalf("identity = %q/v%d", file.Artifact, file.SchemaVersion)
	}
	if len(file.CookieKATs) != 3 || len(file.Flows) != 2 || len(file.SizeCases) != 6 ||
		len(file.SuccessSizes) != 3 || len(file.KeyCases) != 5 || len(file.RejectCases) != 13 || len(file.ChallengeCases) != 12 {
		t.Fatalf("case counts = KAT:%d flow:%d size:%d success:%d key:%d reject:%d challenge:%d",
			len(file.CookieKATs), len(file.Flows), len(file.SizeCases), len(file.SuccessSizes), len(file.KeyCases), len(file.RejectCases), len(file.ChallengeCases))
	}
	if file.Contract.ProofFlagHex != "0002" || !file.Contract.ProofFlagExclusive || file.Contract.ChallengeCompressed ||
		file.Contract.ChallengeHeaderFlagsHex != ConnectorHubLSTCookieChallengeFlagsHex ||
		file.Contract.AuthorityBeforeProofAllowed || file.Contract.HTTPFallbackAllowed || file.Contract.RequestPaddingFallbackAllowed {
		t.Fatalf("security contract drifted: %+v", file.Contract)
	}
	if file.Contract.EmptyBodyPacketBytes != 160 || file.Contract.NonemptyPacketOverheadBytes != 176 ||
		file.Contract.MaxPlaintextBodyBytes != 3920 || file.Contract.MaxPacketBytes != 4096 ||
		file.Contract.ChallengeMaxBodyBytes != 86 || file.Contract.ChallengeMaxPacketBytes != 262 {
		t.Fatalf("size contract drifted: %+v", file.Contract)
	}
	if file.Flows[0].UnprovenBodyJSON != file.Flows[0].ProofBodyJSON ||
		file.Flows[1].UnprovenBodyJSON != file.Flows[1].ProofBodyJSON {
		t.Fatal("proof resend changed an authenticated assignment body")
	}
}

func TestConnectorHubLSTCookieAssignmentNarrativeConsistent(t *testing.T) {
	assignment, err := AgentAssignmentGolden()
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(assignment.Notes, "\n")
	if strings.Contains(notes, "LST/LRT never uses NHP_COK") ||
		!strings.Contains(notes, "Connector Hub assignment profile") ||
		!strings.Contains(notes, ConnectorHubLSTCookieArtifactID) {
		t.Fatal("assignment golden does not distinguish the Hub return-routability COK profile")
	}
}

func TestConnectorHubLSTCookieAddressCanonicalization(t *testing.T) {
	file, err := ConnectorHubLSTCookie()
	if err != nil {
		t.Fatal(err)
	}
	key := mustDecodeHubTestHex(t, file.CookieKATs[0].SigningKeyHex)
	peer := mustDecodeHubTestBase64(t, file.CookieKATs[0].AuthenticatedPeerPublicKeyB64)
	ipv4, err := DeriveConnectorHubLSTCookie(key, "203.0.113.7", peer, 59472000)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := DeriveConnectorHubLSTCookie(key, "::ffff:203.0.113.7", peer, 59472000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ipv4, mapped) {
		t.Fatalf("IPv4/mapped cookies differ: %x/%x", ipv4, mapped)
	}
	ipv6, err := DeriveConnectorHubLSTCookie(key, "2001:db8::7", peer, 59472000)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ipv4, ipv6) {
		t.Fatal("IPv4 and IPv6 cookies unexpectedly match")
	}
}

func TestConnectorHubLSTHeaderMACKATShape(t *testing.T) {
	file, err := ConnectorHubLSTCookie()
	if err != nil {
		t.Fatal(err)
	}
	if file.HeaderMACKAT.Purpose != ConnectorHubLSTHeaderMACKATPurpose ||
		len(mustDecodeHubTestHex(t, file.HeaderMACKAT.ChainKeyHex)) != 32 ||
		len(mustDecodeHubTestHex(t, file.HeaderMACKAT.HeaderPrefixHex)) != 128 ||
		len(mustDecodeHubTestHex(t, file.HeaderMACKAT.RawCookieHex)) != 32 ||
		len(mustDecodeHubTestHex(t, file.HeaderMACKAT.ExpectedMACHex)) != 32 {
		t.Fatalf("header-MAC KAT shape drifted: %+v", file.HeaderMACKAT)
	}
}

func TestConnectorHubLSTCookieDerivationRejectsInvalidInputs(t *testing.T) {
	key := bytes.Repeat([]byte{1}, ConnectorHubLSTCookieSigningKeyBytes)
	peer := bytes.Repeat([]byte{2}, ConnectorHubLSTCookiePeerBytes)
	for _, test := range []struct {
		name, source string
		key, peer    []byte
	}{
		{name: "short key", source: "203.0.113.7", key: key[:31], peer: peer},
		{name: "short peer", source: "203.0.113.7", key: key, peer: peer[:31]},
		{name: "missing source", source: "", key: key, peer: peer},
		{name: "zone source", source: "fe80::1%en0", key: key, peer: peer},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DeriveConnectorHubLSTCookie(test.key, test.source, test.peer, 1); err == nil {
				t.Fatal("invalid cookie input accepted")
			}
		})
	}
	if _, err := ConnectorHubLSTChallengeBody(1, peer[:31]); err == nil {
		t.Fatal("short challenge cookie accepted")
	}
}

func TestConnectorHubLSTCookieSizeGateIsStrict(t *testing.T) {
	file, err := ConnectorHubLSTCookie()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range file.SizeCases {
		allowed := c.CandidateCOKPacketBytes < c.ReceivedLSTPacketBytes
		if allowed != (c.SizeGateAction == ConnectorHubLSTCookieActionSizeSafe) {
			t.Fatalf("case %q violates strict comparison: %+v", c.Name, c)
		}
	}
	if got := file.SuccessSizes[1]; got.ResultBodyBytes != 2820 || got.ResultPacketBytes != 2996 ||
		got.AmplificationNumeratorBytes != 2996 || got.AmplificationDenominatorBytes != 413 {
		t.Fatalf("max ticket success size = %+v", got)
	}
}

func mustDecodeHubTestHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func mustDecodeHubTestBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestParseConnectorHubLSTCookieFileFailsClosed(t *testing.T) {
	raw := ConnectorHubLSTCookieVectors()
	mutate := func(t *testing.T, change func(*ConnectorHubLSTCookieFile)) []byte {
		t.Helper()
		var file ConnectorHubLSTCookieFile
		if err := json.Unmarshal(raw, &file); err != nil {
			t.Fatal(err)
		}
		change(&file)
		body, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	assertRejects := func(t *testing.T, body []byte, contains string) {
		t.Helper()
		_, err := ParseConnectorHubLSTCookieFile(body)
		if err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("error = %v, want %q", err, contains)
		}
	}

	tests := []struct {
		name, contains string
		change         func(*ConnectorHubLSTCookieFile)
	}{
		{"identity", "identity", func(file *ConnectorHubLSTCookieFile) { file.Artifact = "other" }},
		{"contract", "contract drift", func(file *ConnectorHubLSTCookieFile) { file.Contract.ProofFlagHex = "0004" }},
		{"challenge contract flags", "contract drift", func(file *ConnectorHubLSTCookieFile) { file.Contract.ChallengeHeaderFlagsHex = "0001" }},
		{"cookie KAT", "preimage drift", func(file *ConnectorHubLSTCookieFile) {
			file.CookieKATs[0].PreimageHex = strings.Repeat("0", len(file.CookieKATs[0].PreimageHex))
		}},
		{"mapped KAT", "identity drift", func(file *ConnectorHubLSTCookieFile) { file.CookieKATs[1].EqualTo = "" }},
		{"header MAC", "header-MAC KAT", func(file *ConnectorHubLSTCookieFile) { file.HeaderMACKAT.HeaderPrefixHex = strings.Repeat("0", 416) }},
		{"header MAC output", "output drift", func(file *ConnectorHubLSTCookieFile) {
			file.HeaderMACKAT.ExpectedMACHex = strings.Repeat("0", 64)
		}},
		{"flow body", "flow drift", func(file *ConnectorHubLSTCookieFile) { file.Flows[0].ProofBodyJSON += " " }},
		{"size equality", "size case", func(file *ConnectorHubLSTCookieFile) {
			file.SizeCases[2].SizeGateAction = ConnectorHubLSTCookieActionContinue
		}},
		{"success envelope", "success-size", func(file *ConnectorHubLSTCookieFile) { file.SuccessSizes[1].ResultBodyBytes = 2304 }},
		{"key overlap", "key case", func(file *ConnectorHubLSTCookieFile) { file.KeyCases[2].PreviousKeyPresent = false }},
		{"reject disposition", "reject", func(file *ConnectorHubLSTCookieFile) { file.RejectCases[0].AuthorityInvocations = 1 }},
		{"challenge disposition", "challenge", func(file *ConnectorHubLSTCookieFile) {
			file.ChallengeCases[0].ClientAction = ConnectorHubLSTCookieClientStop
		}},
		{"challenge flags", "challenge", func(file *ConnectorHubLSTCookieFile) {
			file.ChallengeCases[0].HeaderFlagsHex = "0001"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { assertRejects(t, mutate(t, test.change), test.contains) })
	}

	assertRejects(t, bytes.Replace(raw, []byte(`"artifact":`), []byte(`"artifact":"duplicate","artifact":`), 1), "duplicate object key")
	assertRejects(t, bytes.Replace(raw, []byte(`"artifact":`), []byte(`"future":true,"artifact":`), 1), "unknown field")
	assertRejects(t, append(append([]byte(nil), raw...), []byte("{}")...), "multiple JSON values")
}

func TestOpenConnectorHubLSTCookieArtifact(t *testing.T) {
	want := ConnectorHubLSTCookieVectors()
	for _, name := range []string{"connector_hub_lst_cookie_v1_vectors.json", "vectors/connector_hub_lst_cookie_v1_vectors.json"} {
		got, err := Open(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Open(%q) returned different bytes", name)
		}
	}
}
