package conformance

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEmbeddedAssignmentTicketLoads(t *testing.T) {
	af, err := AssignmentTicket()
	if err != nil {
		t.Fatal(err)
	}
	if af.Artifact != AssignmentTicketArtifactID || af.SchemaVersion != AssignmentTicketSchemaVersion {
		t.Fatalf("identity = %q/v%d", af.Artifact, af.SchemaVersion)
	}
	if len(af.FenceVectors) != 3 || len(af.VerifyRejects) != 16 || len(af.ClaimsRejects) != 20 ||
		len(af.KMSDERCases) != 6 || len(af.FenceRejects) != 6 || len(af.TrustKeyRejects) != 3 {
		t.Fatalf("fixture counts = fences:%d verify:%d claims:%d DER:%d fence rejects:%d trust rejects:%d",
			len(af.FenceVectors), len(af.VerifyRejects), len(af.ClaimsRejects), len(af.KMSDERCases), len(af.FenceRejects), len(af.TrustKeyRejects))
	}
	if len(af.Golden.Token) > af.Contract.MaxTicketASCIIBytes || af.Golden.LRTBodyBytes > af.Contract.NHPBodyMaxBytes ||
		af.Golden.CompleteNHPPacketBytes > af.Contract.NHPPacketMaxBytes {
		t.Fatal("golden exceeds a frozen size budget")
	}
	for _, c := range af.VerifyRejects {
		input, err := c.ResolveToken(af.Golden)
		if err != nil || input == "" {
			t.Errorf("verify reject %q input = %q/%v", c.Name, input, err)
		}
	}
	for _, c := range af.ClaimsRejects {
		input, err := c.ResolveClaims()
		if err != nil || input == "" {
			t.Errorf("claims reject %q input = %q/%v", c.Name, input, err)
		}
	}
}

func TestAssignmentTicketMaximumLRTEnvelopeIncludesJSONOverhead(t *testing.T) {
	af, err := AssignmentTicket()
	if err != nil {
		t.Fatal(err)
	}
	envelopeWithoutTicket := len(af.Golden.LRTBodyTemplate) - len(af.Golden.TicketMarker)
	maxBody := envelopeWithoutTicket + af.Contract.MaxTicketASCIIBytes
	maxPacket := maxBody + af.Golden.NHPPacketOverheadBytes
	if af.Contract.NHPBodyMaxBytes != 3840 || envelopeWithoutTicket != 518 || maxBody != 2822 || maxPacket != 3078 {
		t.Fatalf("NHP/LRT budget = body-max:%d envelope:%d max-body:%d max-packet:%d, want 3840/518/2822/3078",
			af.Contract.NHPBodyMaxBytes, envelopeWithoutTicket, maxBody, maxPacket)
	}
	if maxBody > af.Contract.NHPBodyMaxBytes || maxPacket > af.Contract.NHPPacketMaxBytes {
		t.Fatal("maximum ticket plus exact LRT JSON envelope exceeds NHP packet budget")
	}
}

func TestParseAssignmentTicketFileFailsClosed(t *testing.T) {
	raw := AssignmentTicketVectors()
	mutate := func(t *testing.T, change func(*AssignmentTicketFile)) []byte {
		t.Helper()
		var af AssignmentTicketFile
		if err := json.Unmarshal(raw, &af); err != nil {
			t.Fatal(err)
		}
		change(&af)
		body, err := json.Marshal(af)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	assertRejects := func(t *testing.T, body []byte, contains string) {
		t.Helper()
		if _, err := ParseAssignmentTicketFile(body); err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("error = %v, want %q", err, contains)
		}
	}

	t.Run("identity", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) { af.Artifact = "other" }), "identity")
	})
	t.Run("contract", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) { af.Contract.SigningDomain = "other" }), "contract")
	})
	t.Run("key", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) { af.SyntheticSigningKey.Curve = "P-384" }), "synthetic key")
	})
	t.Run("fence", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) { af.FenceVectors[0].Domain = "other" }), "fence")
	})
	t.Run("unknown fence encoding", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) {
			af.FenceVectors[0].Parts[0].Encoding = "hex"
		}), "unknown encoding")
	})
	t.Run("golden", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) { af.Golden.SignatureB64URL = "AA" }), "signature")
	})
	t.Run("missing reject", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) { af.VerifyRejects = af.VerifyRejects[1:] }), "count")
	})
	t.Run("duplicate reject", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) { af.ClaimsRejects[1] = af.ClaimsRejects[0] }), "duplicate")
	})
	t.Run("unknown reject class", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) {
			af.VerifyRejects[0].RejectClass = "signatuer"
		}), "unknown reject class")
	})
	t.Run("reject class drift", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) {
			af.VerifyRejects[0].RejectClass = "claims"
		}), "reject class")
	})
	t.Run("unknown fence reject kind", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) {
			af.FenceRejects[0].FenceKind = "credntial"
		}), "unknown fence kind")
	})
	t.Run("ambiguous reject input", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) {
			af.ClaimsRejects[0].Derivation = &AssignmentTicketRepeatDerivation{Target: "claims_json", ASCIIChar: " ", Count: 1}
		}), "ambiguous")
	})
	t.Run("ambiguous verifier input", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AssignmentTicketFile) {
			af.VerifyRejects[0].Token = af.Golden.Token
		}), "ambiguous")
	})
}

func TestOpenAssignmentTicketArtifact(t *testing.T) {
	want := AssignmentTicketVectors()
	for _, name := range []string{"assignment_ticket_v1_vectors.json", "vectors/assignment_ticket_v1_vectors.json"} {
		got, err := Open(name)
		if err != nil {
			t.Fatalf("Open(%q): %v", name, err)
		}
		if string(got) != string(want) {
			t.Fatalf("Open(%q) returned different bytes", name)
		}
	}
}
