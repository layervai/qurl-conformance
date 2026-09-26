package conformance

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestEmbeddedAgentCredentialRecoveryLoads(t *testing.T) {
	file, err := AgentCredentialRecovery()
	if err != nil {
		t.Fatalf("AgentCredentialRecovery(): %v", err)
	}
	if file.Artifact != AgentCredentialRecoveryArtifactID || file.SchemaVersion != AgentCredentialRecoverySchemaVersion {
		t.Fatalf("identity = %q/v%d", file.Artifact, file.SchemaVersion)
	}
	if len(file.PublicExchanges) != 2 || len(file.RequestRejects) != 16 || len(file.ResultRejects) != 9 || len(file.ErrorCases) != 12 || len(file.IssueReplayCases) != 7 || len(file.GrantBindingCases) != 24 || len(file.FlowCases) != 10 || len(file.HubCookie.Cases) != 10 {
		t.Fatalf("case counts = exchanges:%d request-rejects:%d result-rejects:%d errors:%d issue-replays:%d grants:%d flows:%d cookie:%d", len(file.PublicExchanges), len(file.RequestRejects), len(file.ResultRejects), len(file.ErrorCases), len(file.IssueReplayCases), len(file.GrantBindingCases), len(file.FlowCases), len(file.HubCookie.Cases))
	}
	if file.Protocol.HTTPFallbackAllowed || file.Protocol.RelayFallbackAllowed || file.Protocol.ClientCellSelectionAllowed || file.Protocol.TakeoverPolicy != "forbidden" {
		t.Fatalf("unsafe recovery protocol = %+v", file.Protocol)
	}
	if file.Protocol.RecoveryHorizonSeconds != 90*24*60*60 || file.Protocol.LaterGrantOrLocalClockExtensionAllowed {
		t.Fatalf("recovery horizon = %+v", file.Protocol)
	}
}

// The public artifact is the SDK-facing half of the recovery contract. It must
// never carry the platform's internal invocation bodies, its internal operation
// names, or the inputs and output of the private replay-key derivation.
func TestAgentCredentialRecoveryPublishesNoPlatformInternalSection(t *testing.T) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(AgentCredentialRecoveryVectors(), &document); err != nil {
		t.Fatal(err)
	}
	if _, ok := document["private_operations"]; ok {
		t.Fatal("public recovery artifact carries private_operations")
	}
	var sections struct {
		Protocol map[string]json.RawMessage `json:"protocol"`
		Fixtures map[string]json.RawMessage `json:"fixtures"`
	}
	if err := json.Unmarshal(AgentCredentialRecoveryVectors(), &sections); err != nil {
		t.Fatal(err)
	}
	if _, ok := sections.Protocol["hub_request_id_operation"]; ok {
		t.Fatal("public recovery protocol names the private replay-key operation")
	}
	for _, private := range []string{"environment", "authenticated_peer_public_key_b64", "hub_request_id"} {
		if _, ok := sections.Fixtures[private]; ok {
			t.Errorf("public recovery fixtures carry private replay-key input %q", private)
		}
	}
	// Wire bodies are stored as JSON strings, so a token is checked both as a
	// literal and in its string-escaped form.
	raw := string(AgentCredentialRecoveryVectors())
	for _, private := range []string{"IssueCredentialRecovery", "CompleteCredentialRecovery", `"hub_request_id"`, `"cell_request_id"`, `"version":1,"result"`, `"version":1,"error"`} {
		for _, form := range []string{private, strings.ReplaceAll(private, `"`, `\"`)} {
			if strings.Contains(raw, form) {
				t.Errorf("public recovery artifact contains private token %q", form)
			}
		}
	}
}

// Every published fixture must be carried by a public body; a fixture that no
// public body carries would be a private input leaking into this artifact.
func TestAgentCredentialRecoveryFixturesAreCarriedByPublicBodies(t *testing.T) {
	file, err := AgentCredentialRecovery()
	if err != nil {
		t.Fatal(err)
	}
	var bodies strings.Builder
	for _, exchange := range file.PublicExchanges {
		bodies.WriteString(exchange.RequestBodyJSON)
		bodies.WriteString(exchange.SuccessBodyJSON)
	}
	encoded, err := json.Marshal(file.Fixtures)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fixtures); err != nil {
		t.Fatal(err)
	}
	// A fixture is carried when a public body has the exact "key":value pair.
	// These fixtures name the wire field they populate differently.
	wireKey := map[string]string{
		"recovery_credential":      "credential",
		"device_api_key_candidate": "device_api_key",
		"nhp_host":                 "host",
		"nhp_port":                 "port",
	}
	carried := bodies.String()
	for name, value := range fixtures {
		key := name
		if alias, ok := wireKey[name]; ok {
			key = alias
		}
		if !strings.Contains(carried, `"`+key+`":`+string(value)) {
			t.Errorf("fixture %s=%s is not carried by any public body as %q", name, value, key)
		}
	}
}

func TestAgentCredentialRecoveryPublicGoldensExcludeFallbackAndResourceIdentity(t *testing.T) {
	file, err := AgentCredentialRecovery()
	if err != nil {
		t.Fatal(err)
	}
	for name, exchange := range file.PublicExchanges {
		goldens := exchange.RequestBodyJSON + exchange.SuccessBodyJSON
		for _, forbidden := range []string{"http://", "https://", "relay_url", "resource_id", "knock_resource_id", `"takeover"`, "amazonaws.com"} {
			if strings.Contains(goldens, forbidden) {
				t.Errorf("%s golden contains forbidden %q", name, forbidden)
			}
		}
	}
	cell := file.PublicExchanges["assigned_cell_complete_recovery"]
	if strings.Contains(cell.SuccessBodyJSON, file.Fixtures.DeviceAPIKeyCandidate) {
		t.Fatal("recovery result echoes the replacement device secret")
	}
	for _, errorCase := range file.ErrorCases {
		for _, secret := range []string{file.Fixtures.RecoveryCredential, file.Fixtures.RecoveryGrant, file.Fixtures.DeviceAPIKeyCandidate} {
			if strings.Contains(errorCase.BodyJSON, secret) {
				t.Fatalf("error %q leaks a credential or grant", errorCase.Name)
			}
		}
	}
}

func TestAgentCredentialRecoveryProductionShapedFixturesAreExact(t *testing.T) {
	const (
		recoveryCredential = "lv_live_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
		deviceCandidate    = "lv_live_ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
		malformedFixture   = "lv_live_bad"
		secretEchoFixture  = "lv_live_secret"
	)
	allowed := map[string]bool{
		recoveryCredential: false,
		deviceCandidate:    false,
		malformedFixture:   false,
		secretEchoFixture:  false,
	}
	for _, token := range regexp.MustCompile(`lv_live_[A-Za-z0-9_-]+`).FindAllString(string(AgentCredentialRecoveryVectors()), -1) {
		if _, ok := allowed[token]; !ok {
			t.Errorf("unexpected recovery production-shaped fixture %q; scanner exceptions must be exact", token)
			continue
		}
		allowed[token] = true
	}
	for token, found := range allowed {
		if !found {
			t.Errorf("recovery production-shaped fixture %q is not load-bearing", token)
		}
	}
}

func TestAgentCredentialRecoveryMaximumGrantFitsPublicPackets(t *testing.T) {
	file, err := AgentCredentialRecovery()
	if err != nil {
		t.Fatal(err)
	}
	if AgentCredentialRecoveryMaxBodyBytes+AgentCredentialRecoveryPacketOverheadBytes != AgentCredentialRecoveryMaxPacketBytes {
		t.Fatal("recovery body and packet budgets are inconsistent")
	}
	maximumGrant := AgentCredentialRecoveryGrantPrefix + strings.Repeat("a", AgentCredentialRecoveryMaxGrantBytes-len(AgentCredentialRecoveryGrantPrefix))
	if !validAgentCredentialRecoveryGrant(maximumGrant) || len(maximumGrant) != AgentCredentialRecoveryMaxGrantBytes {
		t.Fatal("failed to construct the canonical maximum-size grant")
	}
	for name, body := range map[string]string{
		"Hub LRT":  strings.Replace(file.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON, file.Fixtures.RecoveryGrant, maximumGrant, 1),
		"cell LST": strings.Replace(file.PublicExchanges["assigned_cell_complete_recovery"].RequestBodyJSON, file.Fixtures.RecoveryGrant, maximumGrant, 1),
	} {
		if len(body) > AgentCredentialRecoveryMaxBodyBytes || len(body)+AgentCredentialRecoveryPacketOverheadBytes > AgentCredentialRecoveryMaxPacketBytes {
			t.Fatalf("maximum-grant %s is %d body bytes / %d packet bytes", name, len(body), len(body)+AgentCredentialRecoveryPacketOverheadBytes)
		}
	}
}

func TestParseAgentCredentialRecoveryFileFailsClosed(t *testing.T) {
	raw := AgentCredentialRecoveryVectors()
	for name, invalid := range map[string][]byte{
		"duplicate key":  bytes.Replace(raw, []byte(`"artifact":`), []byte(`"artifact":"duplicate","artifact":`), 1),
		"unknown field":  bytes.Replace(raw, []byte("{"), []byte(`{"future":true,`), 1),
		"trailing value": append(append([]byte(nil), raw...), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAgentCredentialRecoveryFile(invalid); err == nil {
				t.Fatal("invalid artifact unexpectedly accepted")
			}
		})
	}
	// Positive controls: both re-encoding paths below must round-trip the
	// unmodified artifact, or every mutation subtest would pass vacuously.
	t.Run("identity map round-trip", func(t *testing.T) {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentCredentialRecoveryFile(body); err != nil {
			t.Fatalf("unmodified map round-trip rejected: %v", err)
		}
	})
	for _, missing := range []string{
		"later_grant_or_local_clock_extension_allowed",
		"http_fallback_allowed",
		"relay_fallback_allowed",
		"client_cell_selection_allowed",
	} {
		t.Run("missing protocol "+missing, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			delete(document["protocol"].(map[string]any), missing)
			body, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseAgentCredentialRecoveryFile(body); err == nil {
				t.Fatal("artifact with missing security decision unexpectedly accepted")
			}
		})
	}

	mutate := func(t *testing.T, change func(*AgentCredentialRecoveryFile)) []byte {
		t.Helper()
		var file AgentCredentialRecoveryFile
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
	t.Run("identity struct round-trip", func(t *testing.T) {
		if _, err := ParseAgentCredentialRecoveryFile(mutate(t, func(*AgentCredentialRecoveryFile) {})); err != nil {
			t.Fatalf("unmodified struct round-trip rejected: %v", err)
		}
	})
	for _, test := range []struct {
		name     string
		change   func(*AgentCredentialRecoveryFile)
		contains string
	}{
		{name: "protocol takeover", change: func(file *AgentCredentialRecoveryFile) { file.Protocol.TakeoverPolicy = "allowed" }, contains: "protocol drift"},
		{name: "protocol HTTP", change: func(file *AgentCredentialRecoveryFile) { file.Protocol.HTTPFallbackAllowed = true }, contains: "protocol drift"},
		{name: "horizon", change: func(file *AgentCredentialRecoveryFile) { file.Protocol.RecoveryHorizonSeconds++ }, contains: "protocol drift"},
		{name: "grant lifetime", change: func(file *AgentCredentialRecoveryFile) { file.Protocol.RecoveryGrantLifetimeSeconds++ }, contains: "protocol drift"},
		{name: "request nonce", change: func(file *AgentCredentialRecoveryFile) { file.Fixtures.RequestNonce += "=" }, contains: "fixture request nonce"},
		{name: "agent id", change: func(file *AgentCredentialRecoveryFile) { file.Fixtures.AgentID = "Agent-CONFORM" }, contains: "fixture agent_id"},
		{name: "timestamp", change: func(file *AgentCredentialRecoveryFile) { file.Fixtures.LeaseExpiresAt = "2026-07-20T12:00:00.000Z" }, contains: "fixture lease must be canonical"},
		{name: "low-order server key", change: func(file *AgentCredentialRecoveryFile) {
			file.Fixtures.ServerPublicKeyB64 = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}, contains: "low-order X25519"},
		{name: "raw AWS host", change: func(file *AgentCredentialRecoveryFile) { file.Fixtures.NHPHost = "internal.amazonaws.com" }, contains: "fixture assignment is invalid"},
		{name: "missing exchange", change: func(file *AgentCredentialRecoveryFile) { delete(file.PublicExchanges, "hub_issue_recovery") }, contains: "public exchange count"},
		{name: "cookie proof body", change: func(file *AgentCredentialRecoveryFile) { file.HubCookie.ProofBodyJSON = "{}" }, contains: "Hub cookie composition drift"},
		{name: "golden fixture binding", change: func(file *AgentCredentialRecoveryFile) { file.Fixtures.DeviceAPIKeyID = "key_AbCdEf123456" }, contains: "cell result fixture bindings drifted"},
		{name: "request reject", change: func(file *AgentCredentialRecoveryFile) { file.RequestRejects[0].RejectClass = "semantic" }, contains: "request reject \"reject_duplicate_hub_credential\" metadata drifted"},
		{name: "result reject", change: func(file *AgentCredentialRecoveryFile) { file.ResultRejects = file.ResultRejects[1:] }, contains: "result reject count"},
		{name: "public diagnostic", change: func(file *AgentCredentialRecoveryFile) {
			file.ErrorCases[0].BodyJSON = `{"errCode":"52400","errMsg":"changed","retryAfterSeconds":5}`
		}, contains: "error case \"hub_unavailable\" metadata drifted"},
		{name: "retry terminal", change: func(file *AgentCredentialRecoveryFile) { file.ErrorCases[1].RetryAfterSeconds = 1 }, contains: "error case \"recovery_credential_rejected\" metadata drifted"},
		{name: "issue replay", change: func(file *AgentCredentialRecoveryFile) { file.IssueReplayCases[1].Outcome = ExpectReject }, contains: "issue replay case \"accept_exact_issue_replay\" drifted"},
		{name: "grant mutation", change: func(file *AgentCredentialRecoveryFile) { file.GrantBindingCases[0].Mutation = "agent_id" }, contains: "grant binding case \"accept_exact_binding\" drifted"},
		{name: "flow outcome", change: func(file *AgentCredentialRecoveryFile) { file.FlowCases[0].Outcome = ExpectReject }, contains: "flow case \"accept_explicit_recovery\" drifted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Pin the gate that fires, so a mutation rejected for an unrelated
			// reason cannot stand in for a missing check.
			_, err := ParseAgentCredentialRecoveryFile(mutate(t, test.change))
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want %q", err, test.contains)
			}
		})
	}
}
