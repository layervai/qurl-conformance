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
	if af.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", af.SchemaVersion)
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
}

func TestParseAgentKnockApplicationFileFailsClosed(t *testing.T) {
	raw := AgentKnockApplicationVectors()

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

	t.Run("duplicate field", func(t *testing.T) {
		b := append([]byte(`{"artifact":"duplicate",`), raw[1:]...)
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), `duplicate object key "artifact"`) {
			t.Fatalf("error = %v, want duplicate artifact field", err)
		}
	})

	t.Run("trailing value", func(t *testing.T) {
		b := append(append([]byte(nil), raw...), []byte("\n{}")...)
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
			t.Fatalf("error = %v, want multiple JSON values", err)
		}
	})

	t.Run("stale schema", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc.SchemaVersion = 2
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "want 1") {
			t.Fatalf("error = %v, want schema version rejection", err)
		}
	})

	t.Run("request body drift", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc.Request.BodyJSON = `{"headerType":1,"usrId":"wrong","devId":"agent-conformance-01","aspId":"agent","resId":"tunnel-conformance-01"}`
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "does not match fields") {
			t.Fatalf("error = %v, want request body mismatch", err)
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
