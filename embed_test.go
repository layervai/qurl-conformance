package conformance

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// wantClasses is the closed set of conformance classes the artifact must carry.
var wantClasses = []string{
	"claims_parse",
	"secret_parse",
	"strict_base64",
	"fragment",
	"relay_allowlist",
	"server_id",
}

func TestEmbeddedConformanceFileLoads(t *testing.T) {
	cf, err := ConformanceVectors()
	if err != nil {
		t.Fatalf("ConformanceVectors(): %v", err)
	}

	if cf.Artifact != ConformanceArtifactID {
		t.Errorf("artifact = %q, want %q", cf.Artifact, ConformanceArtifactID)
	}
	if cf.SchemaVersion == 0 {
		t.Errorf("schema_version = 0, want non-zero")
	}

	// All six classes must be present.
	if got, want := len(cf.Classes), len(wantClasses); got != want {
		got := classNames(cf)
		t.Errorf("class count = %d, want %d; got classes %v", len(cf.Classes), want, got)
	}
	for _, name := range wantClasses {
		class, ok := cf.Classes[name]
		if !ok {
			t.Errorf("missing class %q", name)
			continue
		}
		if len(class.Vectors) == 0 {
			t.Errorf("class %q has no vectors", name)
		}
		if class.EntryPoint == "" {
			t.Errorf("class %q has empty entry_point", name)
		}
		if class.Input == "" {
			t.Errorf("class %q has empty input", name)
		}
	}
}

func TestEmbeddedSignatureClassWellFormed(t *testing.T) {
	cf, err := ConformanceVectors()
	if err != nil {
		t.Fatalf("ConformanceVectors(): %v", err)
	}

	sc := cf.SignatureClass
	if sc.EntryPoint == "" {
		t.Errorf("signature_class.entry_point is empty")
	}
	if sc.Composes == "" {
		t.Errorf("signature_class.composes is empty")
	}

	td := sc.TamperDerivation
	if td == nil {
		t.Fatalf("signature_class.tamper_derivation is missing")
	}
	if td.RejectClass != RejectClassTamper {
		t.Errorf("tamper_derivation.reject_class = %q, want %q", td.RejectClass, RejectClassTamper)
	}
	if td.DeriveFrom != TamperDeriveFromAccept {
		t.Errorf("tamper_derivation.derive_from = %q, want %q", td.DeriveFrom, TamperDeriveFromAccept)
	}
	if td.ClaimsTransform != TamperTransformFlipFirstB64 {
		t.Errorf("tamper_derivation.claims_transform = %q, want %q", td.ClaimsTransform, TamperTransformFlipFirstB64)
	}
}

func TestEmbeddedSignatureFileLoads(t *testing.T) {
	vf, err := SignatureVectors()
	if err != nil {
		t.Fatalf("SignatureVectors(): %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatalf("signature vector file has no vectors")
	}
	if vf.Issuer.SPKIDERB64 == "" {
		t.Errorf("issuer.spki_der_b64 is empty")
	}
	if vf.Issuer.JWK.Crv == "" {
		t.Errorf("issuer.jwk.crv is empty")
	}

	var sawAccept bool
	for _, v := range vf.Vectors {
		if v.Expect == ExpectAccept {
			sawAccept = true
		}
		if v.ClaimsB64 == "" {
			t.Errorf("vector %q has empty claims_b64", v.Name)
		}
		if v.SigB64Raw == "" {
			t.Errorf("vector %q has empty sig_b64", v.Name)
		}
	}
	if !sawAccept {
		t.Errorf("signature vector file has no accept vector (tamper derivation needs one)")
	}
}

func TestParseVectorFileRejectsStaleSignatureRejectShape(t *testing.T) {
	_, err := ParseVectorFile([]byte(`{"vectors":[{"name":"stale_reject","expect":"reject","reason":"high_s"}]}`))
	if err == nil {
		t.Fatal("ParseVectorFile() accepted a reject signature vector without reject_class")
	}
	if !strings.Contains(err.Error(), "reject_class") {
		t.Fatalf("ParseVectorFile() error = %q, want reject_class", err)
	}
}

func TestEmbeddedRelayKnockLoads(t *testing.T) {
	rf, err := RelayKnockGolden()
	if err != nil {
		t.Fatalf("RelayKnockGolden(): %v", err)
	}
	if rf.Artifact != RelayKnockArtifactID {
		t.Errorf("artifact = %q, want %q", rf.Artifact, RelayKnockArtifactID)
	}
	if rf.SchemaVersion == 0 {
		t.Errorf("schema_version = 0, want non-zero")
	}
	if rf.Knock.PacketHex == "" {
		t.Errorf("knock.packet_hex is empty")
	}
	if rf.Ack.PacketHex == "" {
		t.Errorf("ack.packet_hex is empty")
	}
}

func TestEmbeddedAgentRegistrationLoads(t *testing.T) {
	af, err := AgentRegistrationGolden()
	if err != nil {
		t.Fatalf("AgentRegistrationGolden(): %v", err)
	}
	if af.Artifact != AgentRegistrationArtifactID {
		t.Errorf("artifact = %q, want %q", af.Artifact, AgentRegistrationArtifactID)
	}
	if af.SchemaVersion == 0 {
		t.Errorf("schema_version = 0, want non-zero")
	}

	// Every case must carry a non-empty packet_hex and body_hex.
	for _, c := range []struct {
		name string
		c    AgentRegistrationCase
	}{
		{"otp", af.OTP},
		{"reg_emailed", af.RegEmailed},
		{"reg_preissued", af.RegPreissued},
		{"rak_success", af.RakSuccess},
		{"rak_error", af.RakError},
	} {
		if c.c.PacketHex == "" {
			t.Errorf("%s.packet_hex is empty", c.name)
		}
		if c.c.BodyHex == "" {
			t.Errorf("%s.body_hex is empty", c.name)
		}
	}

	// conformance#19: the RAK cases must echo reg_emailed's counter. reg_emailed
	// carries the counter as a decimal string; the RAK cases carry it as hex.
	regCounter, err := strconv.ParseUint(af.RegEmailed.Counter, 10, 64)
	if err != nil {
		t.Fatalf("parse reg_emailed.counter %q: %v", af.RegEmailed.Counter, err)
	}
	for _, c := range []struct {
		name string
		hex  string
	}{
		{"rak_success", af.RakSuccess.CounterHex},
		{"rak_error", af.RakError.CounterHex},
	} {
		rakCounter, err := strconv.ParseUint(c.hex, 16, 64)
		if err != nil {
			t.Fatalf("parse %s.counter_hex %q: %v", c.name, c.hex, err)
		}
		if rakCounter != regCounter {
			t.Errorf("%s.counter_hex = %d, want %d (must echo reg_emailed.counter)", c.name, rakCounter, regCounter)
		}
	}
}

func TestEmbeddedAgentKnockApplicationLoads(t *testing.T) {
	af, err := AgentKnockApplication()
	if err != nil {
		t.Fatalf("AgentKnockApplication(): %v", err)
	}
	if af.Artifact != AgentKnockApplicationArtifactID {
		t.Errorf("artifact = %q, want %q", af.Artifact, AgentKnockApplicationArtifactID)
	}
	if af.SchemaVersion != 2 {
		t.Errorf("schema_version = %d, want 2", af.SchemaVersion)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(af.Request.BodyJSON), &body); err != nil {
		t.Fatalf("request.body_json: %v", err)
	}
	wantRequestKeys := map[string]bool{
		"headerType": false,
		"usrId":      false,
		"devId":      false,
		"aspId":      false,
		"resId":      false,
		"runId":      false,
	}
	if len(body) != len(wantRequestKeys) {
		t.Fatalf("request body field count = %d, want %d: %v", len(body), len(wantRequestKeys), body)
	}
	for key := range body {
		if _, ok := wantRequestKeys[key]; !ok {
			t.Errorf("request body has unexpected key %q", key)
		} else {
			wantRequestKeys[key] = true
		}
	}
	for key, present := range wantRequestKeys {
		if !present {
			t.Errorf("request body missing key %q", key)
		}
	}
	if got := body["runId"]; got != af.Request.Fields.RunID {
		t.Errorf("request body runId = %v, want semantic run_id %q", got, af.Request.Fields.RunID)
	}

	wantRequestCases := map[string]bool{
		"canonical_run_id": false, "missing_run_id": false, "empty_run_id": false,
		"reject_duplicate_run_id": false, "reject_alias_run_id": false,
		"reject_alias_snake_case_run_id": false, "reject_whitespace_run_id": false,
		"reject_internal_whitespace_run_id": false, "reject_uppercase_run_id": false, "reject_short_run_id": false,
		"reject_long_run_id": false, "reject_nonhex_run_id": false,
	}
	for _, c := range af.RequestCases {
		if _, ok := wantRequestCases[c.Name]; !ok {
			t.Errorf("unexpected request case %q", c.Name)
			continue
		}
		wantRequestCases[c.Name] = true
	}
	for name, present := range wantRequestCases {
		if !present {
			t.Errorf("missing request case %q", name)
		}
	}
	assertAgentKnockRequestPolicies(t, af)

	wantCases := map[string]bool{
		"ack_success": false, "ack_deny": false, "cookie_challenge": false,
		"reject_wrong_resource": false, "reject_missing_ac_token": false,
		"reject_empty_ac_token": false, "reject_missing_resource_host": false,
		"reject_empty_resource_host": false, "reject_malformed_ac_tokens_map": false,
		"reject_malformed_resource_host_map": false, "reject_counter_mismatch": false,
		"reject_reply_type_mismatch": false,
	}
	for _, c := range af.ReplyCases {
		if _, ok := wantCases[c.Name]; !ok {
			t.Errorf("unexpected reply case %q", c.Name)
			continue
		}
		wantCases[c.Name] = true
	}
	for name, present := range wantCases {
		if !present {
			t.Errorf("missing reply case %q", name)
		}
	}
	assertAgentKnockReplyBodySemantics(t, af)
}

func assertAgentKnockRequestPolicies(t *testing.T, af *AgentKnockApplicationFile) {
	t.Helper()
	byName := make(map[string]AgentKnockRequestCase, len(af.RequestCases))
	for _, c := range af.RequestCases {
		byName[c.Name] = c
	}
	assertAccept := func(caseName, entryPoint string, got AgentKnockRequestExpectation, runID string) {
		t.Helper()
		if got.Outcome != ExpectAccept || got.ParsedRunID == nil || *got.ParsedRunID != runID || got.RejectClass != "" {
			t.Errorf("%s.%s = %+v, want accept run_id %q", caseName, entryPoint, got, runID)
		}
	}
	assertReject := func(caseName, entryPoint string, got AgentKnockRequestExpectation, class string) {
		t.Helper()
		if got.Outcome != ExpectReject || got.ParsedRunID != nil || got.RejectClass != class {
			t.Errorf("%s.%s = %+v, want reject class %q", caseName, entryPoint, got, class)
		}
	}

	canonical := byName["canonical_run_id"]
	assertAccept(canonical.Name, "generic_parser", canonical.GenericParser, af.Request.Fields.RunID)
	assertAccept(canonical.Name, "native_connector", canonical.NativeConnector, af.Request.Fields.RunID)
	if canonical.BodyJSON != af.Request.BodyJSON {
		t.Errorf("canonical_run_id body differs from request golden")
	}
	for _, name := range []string{"missing_run_id", "empty_run_id"} {
		c := byName[name]
		assertAccept(name, "generic_parser", c.GenericParser, "")
		assertReject(name, "native_connector", c.NativeConnector, AgentKnockRejectMissingRunID)
	}
	for _, name := range []string{"reject_duplicate_run_id", "reject_alias_run_id", "reject_alias_snake_case_run_id"} {
		c := byName[name]
		assertReject(name, "generic_parser", c.GenericParser, AgentKnockRejectBodyParse)
		assertReject(name, "native_connector", c.NativeConnector, AgentKnockRejectBodyParse)
	}
	for _, name := range []string{
		"reject_whitespace_run_id", "reject_internal_whitespace_run_id",
		"reject_uppercase_run_id", "reject_short_run_id",
		"reject_long_run_id", "reject_nonhex_run_id",
	} {
		c := byName[name]
		assertReject(name, "generic_parser", c.GenericParser, AgentKnockRejectInvalidRunID)
		assertReject(name, "native_connector", c.NativeConnector, AgentKnockRejectInvalidRunID)
	}

	if got := strings.Count(byName["reject_duplicate_run_id"].BodyJSON, `"runId"`); got != 2 {
		t.Errorf("duplicate case has %d runId keys, want 2", got)
	}
	if body := byName["reject_alias_run_id"].BodyJSON; !strings.Contains(body, `"runID"`) || strings.Contains(body, `"runId"`) {
		t.Errorf("runID alias case does not isolate the alias: %s", body)
	}
	if body := byName["reject_alias_snake_case_run_id"].BodyJSON; !strings.Contains(body, `"run_id"`) || strings.Contains(body, `"runId"`) {
		t.Errorf("run_id alias case does not isolate the alias: %s", body)
	}
}

func TestAgentKnockRequestExactKeyGateIsLoadBearing(t *testing.T) {
	af, err := AgentKnockApplication()
	if err != nil {
		t.Fatal(err)
	}
	var alias AgentKnockRequestCase
	for _, c := range af.RequestCases {
		if c.Name == "reject_alias_run_id" {
			alias = c
			break
		}
	}
	if alias.Name == "" {
		t.Fatal("missing reject_alias_run_id fixture")
	}

	// This documents why rejectUnknownAgentKnockRequestKeys cannot be folded
	// into strictDecodeArtifact: encoding/json treats runID as a case-insensitive
	// match for the runId struct tag even when unknown fields are disallowed.
	var wire agentKnockRequestWireBody
	dec := json.NewDecoder(strings.NewReader(alias.BodyJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		t.Fatalf("stdlib alias decode = %v, want acceptance that the exact-key gate overrides", err)
	}
	if string(wire.RunID) != `"0123456789abcdef"` {
		t.Fatalf("stdlib runID alias decoded as %s, want canonical value", wire.RunID)
	}

	generic, connector := deriveAgentKnockRequestExpectations(af.Request.Fields, []byte(alias.BodyJSON))
	for name, got := range map[string]AgentKnockRequestExpectation{"generic": generic, "connector": connector} {
		if got.Outcome != ExpectReject || got.RejectClass != AgentKnockRejectBodyParse || got.ParsedRunID != nil {
			t.Errorf("%s exact-key outcome = %+v, want body_parse rejection", name, got)
		}
	}
}

func assertAgentKnockReplyBodySemantics(t *testing.T, af *AgentKnockApplicationFile) {
	t.Helper()
	byName := make(map[string]AgentKnockReplyCase, len(af.ReplyCases))
	for _, c := range af.ReplyCases {
		byName[c.Name] = c
	}
	const resourceID = "connector-conformance-01"

	body := func(name string) map[string]json.RawMessage {
		t.Helper()
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(byName[name].BodyJSON), &fields); err != nil {
			t.Fatalf("%s body: %v", name, err)
		}
		return fields
	}
	stringField := func(name, field string) string {
		t.Helper()
		var value string
		if err := json.Unmarshal(body(name)[field], &value); err != nil {
			t.Fatalf("%s.%s: %v", name, field, err)
		}
		return value
	}
	stringMap := func(name, field string) (map[string]string, error) {
		var value map[string]string
		err := json.Unmarshal(body(name)[field], &value)
		return value, err
	}

	if got := stringField("ack_success", "errCode"); got != "0" {
		t.Errorf("ack_success errCode = %q, want 0", got)
	}
	for _, field := range []string{"resHost", "acTokens"} {
		values, err := stringMap("ack_success", field)
		if err != nil || values[resourceID] == "" {
			t.Errorf("ack_success %s = %v, %v; want requested non-empty value", field, values, err)
		}
	}
	if got := stringField("ack_deny", "errCode"); got == "" || got == "0" {
		t.Errorf("ack_deny errCode = %q, want non-success code", got)
	}
	if fields := body("cookie_challenge"); len(fields["cookie"]) == 0 || len(fields["trxId"]) == 0 {
		t.Errorf("cookie_challenge body = %v, want cookie and trxId", fields)
	}
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"reject_wrong_resource", "resHost"},
		{"reject_wrong_resource", "acTokens"},
		{"reject_missing_ac_token", "acTokens"},
		{"reject_empty_ac_token", "acTokens"},
		{"reject_missing_resource_host", "resHost"},
		{"reject_empty_resource_host", "resHost"},
	} {
		values, err := stringMap(tc.name, tc.field)
		if err != nil || values[resourceID] != "" {
			t.Errorf("%s %s = %v, %v; want requested value absent or empty", tc.name, tc.field, values, err)
		}
	}
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"reject_malformed_ac_tokens_map", "acTokens"},
		{"reject_malformed_resource_host_map", "resHost"},
	} {
		if _, err := stringMap(tc.name, tc.field); err == nil {
			t.Errorf("%s.%s decoded as map[string]string, want type error", tc.name, tc.field)
		}
	}
}

func TestAllArtifactParsersRejectDuplicateKeysAndTrailingValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		raw             []byte
		duplicatePrefix string
		parse           func([]byte) error
	}{
		{"qv2", QV2Vectors(), `{"artifact":"duplicate",`, func(b []byte) error { _, err := ParseConformanceFile(b); return err }},
		{"issuer signature", IssuerSignatureVectors(), `{"description":"duplicate",`, func(b []byte) error { _, err := ParseVectorFile(b); return err }},
		{"relay knock", RelayKnockVectors(), `{"artifact":"duplicate",`, func(b []byte) error { _, err := ParseRelayKnockFile(b); return err }},
		{"agent registration", AgentRegistrationVectors(), `{"artifact":"duplicate",`, func(b []byte) error { _, err := ParseAgentRegistrationFile(b); return err }},
		{"agent knock application", AgentKnockApplicationVectors(), `{"artifact":"duplicate",`, func(b []byte) error { _, err := ParseAgentKnockApplicationFile(b); return err }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			duplicate := append([]byte(tc.duplicatePrefix), tc.raw[1:]...)
			if err := tc.parse(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
				t.Errorf("duplicate-key error = %v, want duplicate object key", err)
			}
			trailing := append(append([]byte(nil), tc.raw...), []byte("\n{}")...)
			if err := tc.parse(trailing); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
				t.Errorf("trailing-value error = %v, want multiple JSON values", err)
			}
		})
	}
}

func TestParseAgentKnockApplicationFileFailsClosed(t *testing.T) {
	raw := AgentKnockApplicationVectors()
	mutateRequestCase := func(t *testing.T, name string, mutate func(*AgentKnockRequestCase)) []byte {
		t.Helper()
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for i := range doc.RequestCases {
			if doc.RequestCases[i].Name == name {
				mutate(&doc.RequestCases[i])
				b, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
		}
		t.Fatalf("missing fixture request case %q", name)
		return nil
	}
	mutateCase := func(t *testing.T, name string, mutate func(*AgentKnockReplyCase)) []byte {
		t.Helper()
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for i := range doc.ReplyCases {
			if doc.ReplyCases[i].Name == name {
				mutate(&doc.ReplyCases[i])
				b, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
		}
		t.Fatalf("missing fixture case %q", name)
		return nil
	}

	t.Run("unknown field", func(t *testing.T) {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc["unexpected"] = true
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("error = %v, want unknown field", err)
		}
	})

	// Duplicate-key and trailing-value behavior is covered for this parser and
	// every older artifact parser by
	// TestAllArtifactParsersRejectDuplicateKeysAndTrailingValues.

	t.Run("stale schema", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc.SchemaVersion = 1
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "want 2") {
			t.Fatalf("error = %v, want schema version rejection", err)
		}
	})

	t.Run("request body drift", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc.Request.BodyJSON = `{"headerType":1,"usrId":"wrong","devId":"agent-conformance-01","aspId":"agent","resId":"connector-conformance-01","runId":"0123456789abcdef"}`
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "does not match fields") {
			t.Fatalf("error = %v, want request body mismatch", err)
		}
	})

	t.Run("noncanonical request semantic run id", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc.Request.Fields.RunID = "0123456789ABCDEF"
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "lowercase hexadecimal") {
			t.Fatalf("error = %v, want canonical run_id rejection", err)
		}
	})

	t.Run("missing mandatory request case", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc.RequestCases = doc.RequestCases[1:]
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), `missing request case "canonical_run_id"`) {
			t.Fatalf("error = %v, want missing canonical_run_id", err)
		}
	})

	t.Run("duplicate request case", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc.RequestCases = append(doc.RequestCases, doc.RequestCases[0])
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "duplicate agent-knock request case") {
			t.Fatalf("error = %v, want duplicate request case", err)
		}
	})

	t.Run("unknown request case", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		extra := doc.RequestCases[0]
		extra.Name = "unexpected_run_id_case"
		doc.RequestCases = append(doc.RequestCases, extra)
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "unknown agent-knock request case") {
			t.Fatalf("error = %v, want unknown request case rejection", err)
		}
	})

	t.Run("request policy label drift", func(t *testing.T) {
		b := mutateRequestCase(t, "missing_run_id", func(c *AgentKnockRequestCase) {
			c.NativeConnector = requestAcceptExpectation("")
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "native_connector expectation") {
			t.Fatalf("error = %v, want derived expectation mismatch", err)
		}
	})

	t.Run("request body and label drift together", func(t *testing.T) {
		b := mutateRequestCase(t, "reject_uppercase_run_id", func(c *AgentKnockRequestCase) {
			c.BodyJSON = `{"headerType":1,"usrId":"agent-conformance-01","devId":"agent-conformance-01","aspId":"agent","resId":"connector-conformance-01","runId":"0123456789abcdef"}`
			c.GenericParser = requestAcceptExpectation("0123456789abcdef")
			c.NativeConnector = requestAcceptExpectation("0123456789abcdef")
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "required exact vector") {
			t.Fatalf("error = %v, want required case body rejection", err)
		}
	})

	t.Run("missing mandatory case", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc.ReplyCases = doc.ReplyCases[1:]
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), `missing reply case "ack_success"`) {
			t.Fatalf("error = %v, want missing ack_success", err)
		}
	})

	t.Run("duplicate case", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc.ReplyCases = append(doc.ReplyCases, doc.ReplyCases[0])
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("error = %v, want duplicate case", err)
		}
	})

	t.Run("unknown disposition", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc.ReplyCases[0].Outcome = "maybe"
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "unknown outcome") {
			t.Fatalf("error = %v, want unknown outcome", err)
		}
	})

	t.Run("nonnumeric counter", func(t *testing.T) {
		b := mutateCase(t, "ack_success", func(c *AgentKnockReplyCase) {
			c.RequestCounter = "not-a-counter"
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "request_counter") {
			t.Fatalf("error = %v, want invalid counter rejection", err)
		}
	})

	t.Run("retry counter mismatch remains valid", func(t *testing.T) {
		b := mutateCase(t, "cookie_challenge", func(c *AgentKnockReplyCase) {
			c.ReplyCounter = "43"
		})
		if _, err := ParseAgentKnockApplicationFile(b); err != nil {
			t.Fatalf("ParseAgentKnockApplicationFile = %v, want NHP_COK counters intentionally unconstrained", err)
		}
	})

	t.Run("success with reject class", func(t *testing.T) {
		b := mutateCase(t, "ack_success", func(c *AgentKnockReplyCase) {
			c.RejectClass = AgentKnockRejectServerDeny
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "no reject_class") {
			t.Fatalf("error = %v, want outcome/reject inconsistency rejection", err)
		}
	})

	t.Run("unknown reject class", func(t *testing.T) {
		b := mutateCase(t, "reject_wrong_resource", func(c *AgentKnockReplyCase) {
			c.RejectClass = "maybe"
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "unknown reject_class") {
			t.Fatalf("error = %v, want unknown reject class rejection", err)
		}
	})
}

func TestOpenKnownAndUnknown(t *testing.T) {
	for _, name := range []string{
		"qv2_conformance_vectors.json",
		"vectors/qv2_conformance_vectors.json",
		"issuer_signature_vectors.json",
		"vectors/issuer_signature_vectors.json",
		"relay_knock_golden.json",
		"vectors/relay_knock_golden.json",
		"agent_registration_golden.json",
		"vectors/agent_registration_golden.json",
		"agent_knock_application_vectors.json",
		"vectors/agent_knock_application_vectors.json",
	} {
		b, err := Open(name)
		if err != nil {
			t.Errorf("Open(%q): %v", name, err)
		}
		if len(b) == 0 {
			t.Errorf("Open(%q): empty bytes", name)
		}
	}
	if _, err := Open("does_not_exist.json"); err == nil {
		t.Errorf("Open(unknown): want error, got nil")
	}
}

func classNames(cf *ConformanceFile) []string {
	names := make([]string, 0, len(cf.Classes))
	for k := range cf.Classes {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
