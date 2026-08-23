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
	if af.Artifact != AgentSessionControlArtifactID || af.SchemaVersion != AgentSessionControlSchemaVersion || af.ProducerRevision != AgentSessionControlProducerRevision {
		t.Fatalf("identity = %q/v%d/%q", af.Artifact, af.SchemaVersion, af.ProducerRevision)
	}
	if len(af.CookieBodyCases) != 16 || len(af.FlowCases) != 28 {
		t.Fatalf("case counts = cookie:%d flow:%d, want 16/28", len(af.CookieBodyCases), len(af.FlowCases))
	}
	if af.Protocol.COKWireCounterCorrelation != "unconstrained" || af.Protocol.ExitCookieChallengeAllowed {
		t.Fatalf("protocol = %+v", af.Protocol)
	}
	for _, p := range []AgentSessionPacket{
		af.OverloadReknock.KnockRequest,
		af.OverloadReknock.CookieReply,
		af.OverloadReknock.ReknockRequest,
		af.OverloadReknock.ACK,
		af.ExactSessionExit.Request,
		af.ExactSessionExit.ACK,
		af.DenialACKs.Knock,
		af.DenialACKs.Exit,
	} {
		if p.PacketHex == "" || p.BodyHex == "" || p.HeaderDigestHex == "" {
			t.Fatalf("incomplete packet %+v", p)
		}
	}
	if af.ExactSessionExit.Request.HeaderType != AgentSessionHeaderEXT || af.ExactSessionExit.ACK.HeaderType != AgentSessionHeaderACK {
		t.Fatalf("invalid exact-session exit exchange %+v", af.ExactSessionExit)
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
		{"packet role", "type or key roles", func(af *AgentSessionControlFile) { af.ExactSessionExit.Request.SenderKey = "assigned_cell" }},
		{"exit ack role", "type or key roles", func(af *AgentSessionControlFile) { af.ExactSessionExit.ACK.ReceiverKey = "assigned_cell" }},
		{"denial ack role", "type or key roles", func(af *AgentSessionControlFile) { af.DenialACKs.Knock.ReceiverKey = "assigned_cell" }},
		{"packet body bytes", "body_hex", func(af *AgentSessionControlFile) { af.OverloadReknock.ReknockRequest.BodyHex = "00" }},
		{"packet framing", "size", func(af *AgentSessionControlFile) {
			af.OverloadReknock.ACK.PacketHex = af.OverloadReknock.ACK.PacketHex[:len(af.OverloadReknock.ACK.PacketHex)-2]
		}},
		{"packet limit", "packet exceeds 4096-byte limit", func(af *AgentSessionControlFile) {
			body := strings.Repeat("x", AgentSessionPacketMaxBytes-AgentSessionHeaderSize-AgentSessionTagSize+1)
			af.OverloadReknock.KnockRequest.BodyJSON = body
			af.OverloadReknock.KnockRequest.BodyHex = hex.EncodeToString([]byte(body))
			af.OverloadReknock.KnockRequest.PacketHex = strings.Repeat("00", AgentSessionPacketMaxBytes+1)
		}},
		{"packet protocol version", "protocol version", func(af *AgentSessionControlFile) {
			af.OverloadReknock.ACK.PacketHex = downgradeNHPPacketVersion(af.OverloadReknock.ACK.PacketHex)
		}},
		{"packet digest", "header_digest_hex", func(af *AgentSessionControlFile) {
			af.OverloadReknock.ReknockRequest.HeaderDigestHex = strings.Repeat("0", 64)
		}},
		{"packet ephemeral", "ephemeral key", func(af *AgentSessionControlFile) {
			af.ExactSessionExit.Request.EphemeralPrivateHex = strings.Repeat("1", 64)
		}},
		{"cookie", "cookie encoding", func(af *AgentSessionControlFile) { af.OverloadReknock.CookieB64 = "***" }},
		{"cok transaction", "canonical COK body", func(af *AgentSessionControlFile) {
			af.OverloadReknock.CookieReply.BodyJSON = `{"trxId":42,"cookie":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}`
			af.OverloadReknock.CookieReply.BodyHex = hex.EncodeToString([]byte(af.OverloadReknock.CookieReply.BodyJSON))
		}},
		{"immutable run id", "identity, resource, RunID, or runAttempt", func(af *AgentSessionControlFile) {
			af.OverloadReknock.ReknockRequest.BodyJSON = strings.Replace(af.OverloadReknock.ReknockRequest.BodyJSON, "0123456789abcdef", "fedcba9876543210", 1)
			af.OverloadReknock.ReknockRequest.BodyHex = hex.EncodeToString([]byte(af.OverloadReknock.ReknockRequest.BodyJSON))
		}},
		{"exit body", "packet size is inconsistent with body", func(af *AgentSessionControlFile) {
			af.ExactSessionExit.Request.BodyJSON = `{}`
			af.ExactSessionExit.Request.BodyHex = hex.EncodeToString([]byte(af.ExactSessionExit.Request.BodyJSON))
		}},
		{"exit ack counter", "exact_session_exit.ack wire counter", func(af *AgentSessionControlFile) {
			af.ExactSessionExit.ACK.Counter = "44"
		}},
		{"ack semantics", "success body drifted", func(af *AgentSessionControlFile) {
			af.OverloadReknock.ACK.BodyJSON = strings.Replace(af.OverloadReknock.ACK.BodyJSON, `"opnTime":900`, `"opnTime":901`, 1)
			af.OverloadReknock.ACK.BodyHex = hex.EncodeToString([]byte(af.OverloadReknock.ACK.BodyJSON))
		}},
		{"ack missing receipt", "success body drifted", func(af *AgentSessionControlFile) {
			before := af.OverloadReknock.ACK.BodyJSON
			af.OverloadReknock.ACK.BodyJSON = strings.Replace(before, `"cellId":"cell0",`, "", 1)
			af.OverloadReknock.ACK.BodyJSON += strings.Repeat(" ", len(before)-len(af.OverloadReknock.ACK.BodyJSON))
			af.OverloadReknock.ACK.BodyHex = hex.EncodeToString([]byte(af.OverloadReknock.ACK.BodyJSON))
		}},
		{"exit receipt drift", "EXT receipt drifted", func(af *AgentSessionControlFile) {
			af.ExactSessionExit.Request.BodyJSON = strings.Replace(af.ExactSessionExit.Request.BodyJSON, `"sessId":72623859790382856`, `"sessId":72623859790382857`, 1)
			af.ExactSessionExit.Request.BodyHex = hex.EncodeToString([]byte(af.ExactSessionExit.Request.BodyJSON))
		}},
		{"close event drift", "success authority drifted", func(af *AgentSessionControlFile) {
			before := af.ExactSessionExit.ACK.BodyJSON
			af.ExactSessionExit.ACK.BodyJSON = strings.Replace(before, `"state":"closing"`, `"state":"ready"`, 1)
			af.ExactSessionExit.ACK.BodyJSON += strings.Repeat(" ", len(before)-len(af.ExactSessionExit.ACK.BodyJSON))
			af.ExactSessionExit.ACK.BodyHex = hex.EncodeToString([]byte(af.ExactSessionExit.ACK.BodyJSON))
		}},
		{"knock denial receipt", "unknown field", func(af *AgentSessionControlFile) {
			before := af.DenialACKs.Knock.BodyJSON
			af.DenialACKs.Knock.BodyJSON = `{"errCode":"52004","sessId":1,"opnTime":0}`
			af.DenialACKs.Knock.BodyJSON += strings.Repeat(" ", len(before)-len(af.DenialACKs.Knock.BodyJSON))
			af.DenialACKs.Knock.BodyHex = hex.EncodeToString([]byte(af.DenialACKs.Knock.BodyJSON))
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

func TestAgentSessionFlowBindingsRejectBodylessExactExit(t *testing.T) {
	af, err := AgentSessionControl()
	if err != nil {
		t.Fatal(err)
	}
	af.ExactSessionExit.Request.BodyJSON = ""
	af.ExactSessionExit.Request.BodyHex = ""
	if err := validateAgentSessionFlowBindings(af); err == nil || !strings.Contains(err.Error(), "exact-session EXT body") {
		t.Fatalf("validateAgentSessionFlowBindings() error = %v, want bodyless EXT rejection", err)
	}
}

func TestAgentSessionFlowBindingsRejectExitReceiptDrift(t *testing.T) {
	af, err := AgentSessionControl()
	if err != nil {
		t.Fatal(err)
	}
	af.ExactSessionExit.Request.BodyJSON = strings.Replace(af.ExactSessionExit.Request.BodyJSON, `"runAttempt":1`, `"runAttempt":2`, 1)
	af.ExactSessionExit.Request.BodyHex = hex.EncodeToString([]byte(af.ExactSessionExit.Request.BodyJSON))
	if err := validateAgentSessionFlowBindings(af); err == nil || !strings.Contains(err.Error(), "EXT receipt drifted") {
		t.Fatalf("validateAgentSessionFlowBindings() error = %v, want exact receipt rejection", err)
	}
}

func TestAgentSessionFlowBindingsRejectExitACKCounterDrift(t *testing.T) {
	af, err := AgentSessionControl()
	if err != nil {
		t.Fatal(err)
	}
	af.ExactSessionExit.ACK.Counter = "44"
	if err := validateAgentSessionFlowBindings(af); err == nil || !strings.Contains(err.Error(), "exact-session exit ACK counter") {
		t.Fatalf("validateAgentSessionFlowBindings() error = %v, want exact-session ACK counter rejection", err)
	}
}

func TestAgentSessionACKBodyRequiresSingleResourceMaps(t *testing.T) {
	af, err := AgentSessionControl()
	if err != nil {
		t.Fatal(err)
	}
	knock, err := decodeAgentSessionKnockBody(af.OverloadReknock.KnockRequest.BodyJSON)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*agentSessionACKBody)
	}{
		{"resource host", func(ack *agentSessionACKBody) { ack.ResourceHost["other"] = "other.example:7000" }},
		{"access token", func(ack *agentSessionACKBody) { ack.ACTokens["other"] = "other-token" }},
		{"pre-action", func(ack *agentSessionACKBody) { ack.PreActions["other"] = json.RawMessage("null") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ack agentSessionACKBody
			if err := json.Unmarshal([]byte(af.OverloadReknock.ACK.BodyJSON), &ack); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&ack)
			body, err := json.Marshal(ack)
			if err != nil {
				t.Fatal(err)
			}
			_, err = validateAgentSessionACKBody("RKN ACK", string(body), 900, knock.ResourceID)
			if err == nil || !strings.Contains(err.Error(), "resource maps must each contain exactly one entry") {
				t.Fatalf("error = %v, want single-resource-map rejection", err)
			}
		})
	}
}

func TestAgentSessionExactReceiptAndDenialBodiesFailClosed(t *testing.T) {
	af, err := AgentSessionControl()
	if err != nil {
		t.Fatal(err)
	}
	knock, err := decodeAgentSessionKnockBody(af.OverloadReknock.KnockRequest.BodyJSON)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := validateAgentSessionACKBody("RKN ACK", af.OverloadReknock.ACK.BodyJSON, 900, knock.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	if receipt != (agentSessionReceipt{
		CellID: "cell0", SessionID: 72623859790382856,
		SessionIssuedAtMillis: 1800000000000,
		RunID:                 "0123456789abcdef", RunAttempt: 1,
	}) {
		t.Fatalf("success receipt = %+v", receipt)
	}

	for name, body := range map[string]string{
		"knock missing run attempt": strings.Replace(af.OverloadReknock.KnockRequest.BodyJSON, `,"runAttempt":1`, "", 1),
		"knock zero run attempt":    strings.Replace(af.OverloadReknock.KnockRequest.BodyJSON, `"runAttempt":1`, `"runAttempt":0`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeAgentSessionKnockBody(body); err == nil {
				t.Fatalf("decodeAgentSessionKnockBody(%s) succeeded", body)
			}
		})
	}

	for name, body := range map[string]string{
		"success missing cell":        strings.Replace(af.OverloadReknock.ACK.BodyJSON, `,"cellId":"cell0"`, "", 1),
		"success missing issuance":    strings.Replace(af.OverloadReknock.ACK.BodyJSON, `,"sessIssuedAtMillis":1800000000000`, "", 1),
		"success zero attempt":        strings.Replace(af.OverloadReknock.ACK.BodyJSON, `"runAttempt":1`, `"runAttempt":0`, 1),
		"success unknown receipt key": strings.TrimSuffix(af.OverloadReknock.ACK.BodyJSON, "}") + `,"future":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateAgentSessionACKBody("RKN ACK", body, 900, knock.ResourceID); err == nil {
				t.Fatalf("validateAgentSessionACKBody(%s) succeeded", body)
			}
		})
	}

	exit, err := decodeAgentSessionExactExitBody(af.ExactSessionExit.Request.BodyJSON)
	if err != nil || exit.agentSessionReceipt != receipt {
		t.Fatalf("exact EXT = %+v, %v", exit, err)
	}
	for name, body := range map[string]string{
		"resource scoped shim": `{"headerType":16,"usrId":"agent-conformance-01","devId":"agent-conformance-01","aspId":"agent","resId":"connector-conformance-01","runId":"0123456789abcdef","runAttempt":1}`,
		"receipt mismatch":     strings.Replace(af.ExactSessionExit.Request.BodyJSON, `"sessId":72623859790382856`, `"sessId":72623859790382857`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := decodeAgentSessionExactExitBody(body)
			if err == nil && got.agentSessionReceipt == receipt {
				t.Fatalf("exact EXT mutation was accepted: %+v", got)
			}
		})
	}

	for name, body := range map[string]string{
		"missing event":    strings.Replace(af.ExactSessionExit.ACK.BodyJSON, `,"closeEventId":"0123456789abcdef0123456789abcdef"`, "", 1),
		"uppercase event":  strings.Replace(af.ExactSessionExit.ACK.BodyJSON, `0123456789abcdef0123456789abcdef`, `0123456789ABCDEF0123456789ABCDEF`, 1),
		"invalid state":    strings.Replace(af.ExactSessionExit.ACK.BodyJSON, `"state":"closing"`, `"state":"ready"`, 1),
		"receipt mismatch": strings.Replace(af.ExactSessionExit.ACK.BodyJSON, `"runAttempt":1`, `"runAttempt":2`, 1),
	} {
		t.Run("close "+name, func(t *testing.T) {
			if err := validateAgentSessionCloseACKBody("exact-session exit ACK", body, receipt); err == nil {
				t.Fatalf("validateAgentSessionCloseACKBody(%s) succeeded", body)
			}
		})
	}

	if err := validateAgentSessionKnockDenialACKBody(af.DenialACKs.Knock.BodyJSON); err != nil {
		t.Fatal(err)
	}
	if err := validateAgentSessionExitDenialACKBody(af.DenialACKs.Exit.BodyJSON); err != nil {
		t.Fatal(err)
	}
	if err := validateAgentSessionKnockDenialACKBody(strings.TrimSuffix(af.DenialACKs.Knock.BodyJSON, "}") + `,"sessId":1}`); err == nil {
		t.Fatal("knock denial accepted a session receipt")
	}
	if err := validateAgentSessionExitDenialACKBody(strings.TrimSuffix(af.DenialACKs.Exit.BodyJSON, "}") + `,"closeEventId":"0123456789abcdef0123456789abcdef"}`); err == nil {
		t.Fatal("exit denial accepted close-event authority")
	}
}
