package conformance

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestEmbeddedAgentSessionControlLoads(t *testing.T) {
	af, err := AgentSessionControl()
	if err != nil {
		t.Fatalf("AgentSessionControl(): %v", err)
	}
	if af.Artifact != AgentSessionControlArtifactID || af.SchemaVersion != 1 || af.ProducerRevision != AgentSessionControlProducerRevision {
		t.Fatalf("identity = %q/v%d/%q", af.Artifact, af.SchemaVersion, af.ProducerRevision)
	}
	if len(af.CookieBodyCases) != 16 || len(af.FlowCases) != 19 {
		t.Fatalf("case counts = cookie:%d flow:%d, want 16/19", len(af.CookieBodyCases), len(af.FlowCases))
	}
	if af.Protocol.COKWireCounterCorrelation != "unconstrained" || af.Protocol.ExitCookieChallengeAllowed {
		t.Fatalf("protocol = %+v", af.Protocol)
	}
	for _, p := range []AgentSessionPacket{
		af.OverloadReknock.KnockRequest,
		af.OverloadReknock.CookieReply,
		af.OverloadReknock.ReknockRequest,
		af.OverloadReknock.ACK,
		af.CleanExit.Request,
		af.CleanExit.ACK,
	} {
		if p.PacketHex == "" || p.BodyHex == "" || p.HeaderDigestHex == "" {
			t.Fatalf("incomplete packet %+v", p)
		}
	}

	raw := AgentSessionControlVectors()
	for _, name := range []string{"agent_session_control_vectors.json", "vectors/agent_session_control_vectors.json"} {
		got, err := Open(name)
		if err != nil {
			t.Fatalf("Open(%q): %v", name, err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("Open(%q) did not return canonical bytes", name)
		}
	}
}

func TestParseAgentSessionControlFileFailsClosed(t *testing.T) {
	raw := AgentSessionControlVectors()
	mutate := func(t *testing.T, change func(*AgentSessionControlFile)) []byte {
		t.Helper()
		var af AgentSessionControlFile
		if err := json.Unmarshal(raw, &af); err != nil {
			t.Fatal(err)
		}
		change(&af)
		b, err := json.Marshal(af)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	assertRejects := func(t *testing.T, body []byte, contains string) {
		t.Helper()
		_, err := ParseAgentSessionControlFile(body)
		if err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("error = %v, want text %q", err, contains)
		}
	}

	tests := []struct {
		name, contains string
		change         func(*AgentSessionControlFile)
	}{
		{"artifact", "artifact", func(af *AgentSessionControlFile) { af.Artifact = "other" }},
		{"schema", "schema_version", func(af *AgentSessionControlFile) { af.SchemaVersion++ }},
		{"producer", "producer revision", func(af *AgentSessionControlFile) { af.ProducerRevision = strings.Repeat("0", 40) }},
		{"metadata", "metadata", func(af *AgentSessionControlFile) { af.Description = "" }},
		{"protocol", "protocol contract", func(af *AgentSessionControlFile) { af.Protocol.COKWireCounterCorrelation = "must_echo_request" }},
		{"keypair", "keys do not form", func(af *AgentSessionControlFile) {
			af.Keys.Agent.StaticPublicHex = af.Keys.AssignedCell.StaticPublicHex
		}},
		{"packet role", "type or key roles", func(af *AgentSessionControlFile) { af.CleanExit.Request.SenderKey = "assigned_cell" }},
		{"packet body bytes", "body_hex", func(af *AgentSessionControlFile) { af.OverloadReknock.ReknockRequest.BodyHex = "00" }},
		{"packet framing", "size", func(af *AgentSessionControlFile) {
			af.CleanExit.ACK.PacketHex = af.CleanExit.ACK.PacketHex[:len(af.CleanExit.ACK.PacketHex)-2]
		}},
		{"packet limit", "packet exceeds 4096-byte limit", func(af *AgentSessionControlFile) {
			body := strings.Repeat("x", 4096-AgentSessionHeaderSize-AgentSessionTagSize+1)
			af.OverloadReknock.KnockRequest.BodyJSON = body
			af.OverloadReknock.KnockRequest.BodyHex = hex.EncodeToString([]byte(body))
			af.OverloadReknock.KnockRequest.PacketHex = strings.Repeat("00", 4097)
		}},
		{"packet digest", "header_digest_hex", func(af *AgentSessionControlFile) {
			af.OverloadReknock.ReknockRequest.HeaderDigestHex = strings.Repeat("0", 64)
		}},
		{"packet ephemeral", "ephemeral key", func(af *AgentSessionControlFile) { af.CleanExit.Request.EphemeralPrivateHex = strings.Repeat("1", 64) }},
		{"cookie", "cookie encoding", func(af *AgentSessionControlFile) { af.OverloadReknock.CookieB64 = "***" }},
		{"cok transaction", "canonical COK body", func(af *AgentSessionControlFile) {
			af.OverloadReknock.CookieReply.BodyJSON = `{"trxId":42,"cookie":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}`
			af.OverloadReknock.CookieReply.BodyHex = hex.EncodeToString([]byte(af.OverloadReknock.CookieReply.BodyJSON))
		}},
		{"immutable run id", "identity, resource, or RunID", func(af *AgentSessionControlFile) {
			af.CleanExit.Request.BodyJSON = strings.Replace(af.CleanExit.Request.BodyJSON, "0123456789abcdef", "fedcba9876543210", 1)
			af.CleanExit.Request.BodyHex = hex.EncodeToString([]byte(af.CleanExit.Request.BodyJSON))
		}},
		{"ack semantics", "success body drifted", func(af *AgentSessionControlFile) {
			af.CleanExit.ACK.BodyJSON = strings.Replace(af.CleanExit.ACK.BodyJSON, `"opnTime":1`, `"opnTime":2`, 1)
			af.CleanExit.ACK.BodyHex = hex.EncodeToString([]byte(af.CleanExit.ACK.BodyJSON))
		}},
		{"cookie case", "classified", func(af *AgentSessionControlFile) { af.CookieBodyCases[0].Outcome = AgentSessionOutcomeReject }},
		{"duplicate cookie case", "duplicate cookie case", func(af *AgentSessionControlFile) { af.CookieBodyCases[1] = af.CookieBodyCases[0] }},
		{"flow case", "fields drifted", func(af *AgentSessionControlFile) { af.FlowCases[0].Mutation = "future" }},
		{"duplicate flow case", "duplicate flow case", func(af *AgentSessionControlFile) { af.FlowCases[1] = af.FlowCases[0] }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertRejects(t, mutate(t, tc.change), tc.contains)
		})
	}

	t.Run("unknown field", func(t *testing.T) {
		body := bytes.Replace(raw, []byte(`"artifact":`), []byte(`"future":true,"artifact":`), 1)
		assertRejects(t, body, "unknown field")
	})
	t.Run("duplicate field", func(t *testing.T) {
		body := bytes.Replace(raw, []byte(`"artifact":`), []byte(`"artifact":"duplicate","artifact":`), 1)
		assertRejects(t, body, "duplicate object key")
	})
	t.Run("trailing value", func(t *testing.T) {
		assertRejects(t, append(append([]byte(nil), raw...), []byte("{}")...), "multiple JSON values")
	})
}

func TestAgentSessionControlREADMERevisionPin(t *testing.T) {
	for _, name := range []string{"README.md", "vectors/README_agent_session_control_vectors.md"} {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte(AgentSessionControlProducerRevision)) {
			t.Errorf("%s is missing producer revision %s", name, AgentSessionControlProducerRevision)
		}
	}
}

func TestAgentSessionCOKWireCounterIsUnconstrained(t *testing.T) {
	af, err := AgentSessionControl()
	if err != nil {
		t.Fatal(err)
	}
	af.OverloadReknock.CookieReply.Counter = "18446744073709551615"
	if err := validateAgentSessionFlowBindings(af); err != nil {
		t.Fatalf("different authenticated COK wire counter must not affect body transaction correlation: %v", err)
	}
}
