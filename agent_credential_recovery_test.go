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
	raw := string(AgentCredentialRecoveryVectors())
	for _, private := range []string{"IssueCredentialRecovery", "CompleteCredentialRecovery", `"hub_request_id"`, `"version":1,"result"`, `"version":1,"error"`} {
		if strings.Contains(raw, private) {
			t.Errorf("public recovery artifact contains private token %q", private)
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
	for name, value := range fixtures {
		if !strings.Contains(bodies.String(), `"`+name+`":`+string(value)) && !strings.Contains(bodies.String(), ":"+string(value)) {
			t.Errorf("fixture %s=%s is not carried by any public body", name, value)
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
	for _, test := range []struct {
		name   string
		change func(*AgentCredentialRecoveryFile)
	}{
		{name: "protocol takeover", change: func(file *AgentCredentialRecoveryFile) { file.Protocol.TakeoverPolicy = "allowed" }},
		{name: "protocol HTTP", change: func(file *AgentCredentialRecoveryFile) { file.Protocol.HTTPFallbackAllowed = true }},
		{name: "horizon", change: func(file *AgentCredentialRecoveryFile) { file.Protocol.RecoveryHorizonSeconds++ }},
		{name: "grant lifetime", change: func(file *AgentCredentialRecoveryFile) { file.Protocol.RecoveryGrantLifetimeSeconds++ }},
		{name: "request nonce", change: func(file *AgentCredentialRecoveryFile) { file.Fixtures.RequestNonce += "=" }},
		{name: "agent id", change: func(file *AgentCredentialRecoveryFile) { file.Fixtures.AgentID = "Agent-CONFORM" }},
		{name: "timestamp", change: func(file *AgentCredentialRecoveryFile) { file.Fixtures.LeaseExpiresAt = "2026-07-20T12:00:00.000Z" }},
		{name: "low-order server key", change: func(file *AgentCredentialRecoveryFile) {
			file.Fixtures.ServerPublicKeyB64 = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}},
		{name: "raw AWS host", change: func(file *AgentCredentialRecoveryFile) { file.Fixtures.NHPHost = "internal.amazonaws.com" }},
		{name: "missing exchange", change: func(file *AgentCredentialRecoveryFile) { delete(file.PublicExchanges, "hub_issue_recovery") }},
		{name: "cookie proof body", change: func(file *AgentCredentialRecoveryFile) { file.HubCookie.ProofBodyJSON = "{}" }},
		{name: "golden fixture binding", change: func(file *AgentCredentialRecoveryFile) { file.Fixtures.DeviceAPIKeyID = "key_AbCdEf123456" }},
		{name: "request reject", change: func(file *AgentCredentialRecoveryFile) { file.RequestRejects[0].RejectClass = "semantic" }},
		{name: "result reject", change: func(file *AgentCredentialRecoveryFile) { file.ResultRejects = file.ResultRejects[1:] }},
		{name: "public diagnostic", change: func(file *AgentCredentialRecoveryFile) {
			file.ErrorCases[0].BodyJSON = `{"errCode":"52400","errMsg":"changed","retryAfterSeconds":5}`
		}},
		{name: "retry terminal", change: func(file *AgentCredentialRecoveryFile) { file.ErrorCases[1].RetryAfterSeconds = 1 }},
		{name: "issue replay", change: func(file *AgentCredentialRecoveryFile) { file.IssueReplayCases[1].Outcome = ExpectReject }},
		{name: "grant mutation", change: func(file *AgentCredentialRecoveryFile) { file.GrantBindingCases[0].Mutation = "agent_id" }},
		{name: "flow outcome", change: func(file *AgentCredentialRecoveryFile) { file.FlowCases[0].Outcome = ExpectReject }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseAgentCredentialRecoveryFile(mutate(t, test.change)); err == nil {
				t.Fatal("mutated artifact unexpectedly accepted")
			}
		})
	}
}
