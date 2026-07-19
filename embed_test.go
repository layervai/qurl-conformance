package conformance

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"slices"
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

func TestEmbeddedAgentAssignmentLoads(t *testing.T) {
	af, err := AgentAssignmentGolden()
	if err != nil {
		t.Fatalf("AgentAssignmentGolden(): %v", err)
	}
	if af.Artifact != AgentAssignmentArtifactID {
		t.Errorf("artifact = %q, want %q", af.Artifact, AgentAssignmentArtifactID)
	}
	if af.SchemaVersion != 4 {
		t.Errorf("schema_version = %d, want 4", af.SchemaVersion)
	}
	if !slices.Equal(af.PublicRegistrationKeyKinds, []string{"bootstrap", "connector_bootstrap", "account", "agent"}) {
		t.Errorf("public registration key kinds = %v", af.PublicRegistrationKeyKinds)
	}

	for _, exchange := range []struct {
		name     string
		exchange AgentAssignmentExchange
	}{
		{"initial_assignment", af.InitialAssignment},
		{"refresh_assignment", af.RefreshAssignment},
		{"registration_completion", af.RegistrationCompletion},
	} {
		if exchange.exchange.Request.HeaderType != AgentAssignmentRequestHeaderType || exchange.exchange.Request.HeaderName != AgentAssignmentRequestHeaderName {
			t.Errorf("%s request header = %q/%d, want %q/%d", exchange.name, exchange.exchange.Request.HeaderName, exchange.exchange.Request.HeaderType, AgentAssignmentRequestHeaderName, AgentAssignmentRequestHeaderType)
		}
		if exchange.exchange.Result.HeaderType != AgentAssignmentResultHeaderType || exchange.exchange.Result.HeaderName != AgentAssignmentResultHeaderName {
			t.Errorf("%s result header = %q/%d, want %q/%d", exchange.name, exchange.exchange.Result.HeaderName, exchange.exchange.Result.HeaderType, AgentAssignmentResultHeaderName, AgentAssignmentResultHeaderType)
		}
		if exchange.exchange.Result.Counter != exchange.exchange.Request.Counter {
			t.Errorf("%s result counter = %q, want request counter %q", exchange.name, exchange.exchange.Result.Counter, exchange.exchange.Request.Counter)
		}
	}
	registration := af.AssignedCellRegistration
	if registration.Request.HeaderName != AgentAssignmentRegistrationRequestHeaderName || registration.Request.HeaderType != AgentAssignmentRegistrationRequestHeaderType || registration.Result.HeaderName != AgentAssignmentRegistrationResultHeaderName || registration.Result.HeaderType != AgentAssignmentRegistrationResultHeaderType {
		t.Errorf("assigned-cell registration headers = %q/%d -> %q/%d, want NHP_REG/13 -> NHP_RAK/14", registration.Request.HeaderName, registration.Request.HeaderType, registration.Result.HeaderName, registration.Result.HeaderType)
	}
	if registration.Request.Counter != registration.Result.Counter {
		t.Errorf("assigned-cell registration result counter = %q, want request counter %q", registration.Result.Counter, registration.Request.Counter)
	}
	otp := af.AccountCredentialOTP
	if otp.ProducerRevision != AgentAssignmentOTPProducerRevision || !otp.RawBodyRequired || !otp.AuthenticatedPeerPublicKeyRequired {
		t.Errorf("account OTP producer/raw trust boundary drifted: %+v", otp)
	}
	if otp.Request.HeaderName != AgentAssignmentOTPRequestHeaderName || otp.Request.HeaderType != AgentAssignmentOTPRequestHeaderType || otp.Request.SenderKey != "agent" || otp.Request.ReceiverKey != "assigned_cell" {
		t.Errorf("account OTP header/roles = %q/%d %q->%q, want NHP_OTP/12 agent->assigned_cell", otp.Request.HeaderName, otp.Request.HeaderType, otp.Request.SenderKey, otp.Request.ReceiverKey)
	}
	if !slices.Equal(otp.OTPRegistrationKeyKinds, []string{"account"}) || !slices.Equal(otp.OTPFreeRegistrationKeyKinds, []string{"bootstrap", "connector_bootstrap", "agent"}) {
		t.Errorf("account OTP key-kind split drifted: OTP=%v OTP-free=%v", otp.OTPRegistrationKeyKinds, otp.OTPFreeRegistrationKeyKinds)
	}
	var otpRequest struct {
		UsrID   string `json:"usrId"`
		DevID   string `json:"devId"`
		AspID   string `json:"aspId"`
		Pass    string `json:"pass"`
		UsrData struct {
			Query            string `json:"query"`
			Version          int    `json:"version"`
			AssignmentTicket string `json:"assignment_ticket"`
		} `json:"usrData"`
	}
	if err := json.Unmarshal([]byte(otp.Request.BodyJSON), &otpRequest); err != nil {
		t.Fatalf("account OTP request body: %v", err)
	}
	if otpRequest.UsrID != otp.EnrollmentBinding.RequestRegistrationKeyID || otpRequest.DevID != otp.EnrollmentBinding.RequestAgentID || otpRequest.AspID != "agent" || otpRequest.Pass != AgentAssignmentAccountCredentialFixture || otpRequest.UsrData.Query != "agent_registration_otp" || otpRequest.UsrData.Version != 1 || otpRequest.UsrData.AssignmentTicket != otp.EnrollmentBinding.RequestAssignmentTicket {
		t.Errorf("account OTP request/binding drifted: %+v / %+v", otpRequest, otp.EnrollmentBinding)
	}
	if otp.EnrollmentBinding.RecomputedCredentialFenceB64 != otp.EnrollmentBinding.TicketCredentialFenceB64 ||
		otp.ChallengeBinding.TicketJTI != otp.EnrollmentBinding.TicketJTI ||
		otp.ChallengeBinding.AuthenticatedPeerPublicKeyB64 != otp.EnrollmentBinding.AuthenticatedPeerPublicKeyB64 ||
		otp.ChallengeBinding.DevID != otp.EnrollmentBinding.RequestAgentID ||
		otp.ChallengeBinding.CredentialKeyID != otp.EnrollmentBinding.RequestRegistrationKeyID ||
		otp.ChallengeBinding.EnvironmentID != otp.EnrollmentBinding.LocalEnvironmentID ||
		otp.ChallengeBinding.CellID != otp.EnrollmentBinding.LocalCellID {
		t.Errorf("account OTP fence/challenge binding drifted: %+v / %+v", otp.EnrollmentBinding, otp.ChallengeBinding)
	}
	if got, want := len(otp.RequestCases), 17; got != want {
		t.Errorf("account OTP request case count = %d, want %d", got, want)
	}
	if got, want := len(otp.BindingCases), 13; got != want {
		t.Errorf("account OTP binding case count = %d, want %d", got, want)
	}
	if got, want := len(otp.ChallengeBindingCases), 7; got != want {
		t.Errorf("account OTP challenge-binding case count = %d, want %d", got, want)
	}
	if got, want := len(otp.PacketSizeContract.Cases), 2; got != want {
		t.Errorf("account OTP packet-size case count = %d, want %d", got, want)
	}

	var initialRequest struct {
		UsrID   string `json:"usrId"`
		DevID   string `json:"devId"`
		UsrData struct {
			Query        string `json:"query"`
			Mode         string `json:"mode"`
			RequestNonce string `json:"request_nonce"`
			Credential   string `json:"credential"`
		} `json:"usrData"`
	}
	if err := json.Unmarshal([]byte(af.InitialAssignment.Request.BodyJSON), &initialRequest); err != nil {
		t.Fatalf("initial request body: %v", err)
	}
	if initialRequest.UsrID != "" || initialRequest.DevID != "agent-conform" || initialRequest.UsrData.Query != "cell_assignment" || initialRequest.UsrData.Mode != "enroll" || initialRequest.UsrData.RequestNonce != AgentAssignmentInitialRequestNonceFixture || initialRequest.UsrData.Credential == "" {
		t.Errorf("initial request identity/query fields drifted: %+v", initialRequest)
	}
	if strings.Contains(af.InitialAssignment.Result.BodyJSON, initialRequest.UsrData.Credential) {
		t.Error("initial assignment result echoes enrollment credential")
	}

	var initialResult struct {
		List struct {
			Assignment struct {
				Endpoint struct {
					ServerPublicKeyB64 string `json:"server_public_key_b64"`
				} `json:"nhp_udp_endpoint"`
			} `json:"assignment"`
			AssignmentTicket string `json:"assignment_ticket"`
		} `json:"list"`
	}
	if err := json.Unmarshal([]byte(af.InitialAssignment.Result.BodyJSON), &initialResult); err != nil {
		t.Fatalf("initial result body: %v", err)
	}
	endpointKey, err := base64.StdEncoding.DecodeString(initialResult.List.Assignment.Endpoint.ServerPublicKeyB64)
	if err != nil {
		t.Fatalf("decode assigned endpoint key: %v", err)
	}
	wantCellKey, err := hex.DecodeString(af.Keys.AssignedCell.StaticPubHex)
	if err != nil {
		t.Fatalf("decode assigned-cell fixture key: %v", err)
	}
	if !bytes.Equal(endpointKey, wantCellKey) {
		t.Errorf("assignment endpoint key = %x, want assigned-cell key %x", endpointKey, wantCellKey)
	}
	if initialResult.List.AssignmentTicket == "" {
		t.Error("initial assignment result is missing assignment_ticket")
	}
	var refreshResultFields map[string]any
	if err := json.Unmarshal([]byte(af.RefreshAssignment.Result.BodyJSON), &refreshResultFields); err != nil {
		t.Fatalf("refresh result fields: %v", err)
	}
	refreshList := refreshResultFields["list"].(map[string]any)
	if _, ok := refreshList["assignment_ticket"]; ok {
		t.Error("ordinary refresh result issues assignment_ticket")
	}
	if _, ok := refreshList["assignment_ticket_expires_at"]; ok {
		t.Error("ordinary refresh result issues assignment_ticket_expires_at")
	}
	var initialResultFields map[string]any
	if err := json.Unmarshal([]byte(af.InitialAssignment.Result.BodyJSON), &initialResultFields); err != nil {
		t.Fatalf("initial result fields: %v", err)
	}
	initialList := initialResultFields["list"].(map[string]any)
	registrationMetadata := initialList["registration"].(map[string]any)
	if _, ok := registrationMetadata["masked_email"]; ok {
		t.Error("initial assignment registration metadata commits to masked_email")
	}
	var registrationRequest struct {
		OTP     string `json:"otp"`
		UsrData struct {
			AssignmentTicket string `json:"assignment_ticket"`
		} `json:"usrData"`
	}
	if err := json.Unmarshal([]byte(af.AssignedCellRegistration.Request.BodyJSON), &registrationRequest); err != nil {
		t.Fatalf("registration request body: %v", err)
	}
	if registrationRequest.OTP != initialRequest.UsrData.Credential || registrationRequest.UsrData.AssignmentTicket != initialResult.List.AssignmentTicket {
		t.Errorf("assigned-cell REG did not carry exact credential/ticket handoff: %+v", registrationRequest)
	}

	var completionRequest map[string]any
	if err := json.Unmarshal([]byte(af.RegistrationCompletion.Request.BodyJSON), &completionRequest); err != nil {
		t.Fatalf("completion request body: %v", err)
	}
	completionUserData, ok := completionRequest["usrData"].(map[string]any)
	if !ok {
		t.Fatalf("completion request usrData = %#v, want object", completionRequest["usrData"])
	}
	if _, ok := completionUserData["assignment_ticket"]; ok {
		t.Error("completion request reuses the REG-consumed assignment_ticket")
	}
	deviceSecret, ok := completionUserData["device_api_key"].(string)
	if !ok || deviceSecret == "" {
		t.Fatalf("completion request device_api_key = %#v, want non-empty synthetic secret", completionUserData["device_api_key"])
	}
	if strings.Contains(af.RegistrationCompletion.Result.BodyJSON, deviceSecret) {
		t.Error("completion result echoes device_api_key secret")
	}
	if af.RegistrationCompletion.Request.ReceiverKey != "assigned_cell" || af.RegistrationCompletion.Result.SenderKey != "assigned_cell" {
		t.Errorf("completion trust boundary = %q/%q, want assigned_cell/assigned_cell", af.RegistrationCompletion.Request.ReceiverKey, af.RegistrationCompletion.Result.SenderKey)
	}
	if got, want := len(af.RequestCases), 30; got != want {
		t.Errorf("request case count = %d, want %d", got, want)
	}
	requestCases := make(map[string]AgentAssignmentRequestCase, len(af.RequestCases))
	for _, c := range af.RequestCases {
		requestCases[c.Name] = c
	}
	for name, wantClass := range map[string]string{
		"reject_duplicate_outer_dev_id":                       AgentAssignmentRejectBodyParse,
		"reject_missing_initial_request_nonce":                AgentAssignmentRejectMissingField,
		"reject_null_initial_request_nonce":                   AgentAssignmentRejectWrongType,
		"reject_short_refresh_request_nonce":                  AgentAssignmentRejectSemantic,
		"reject_standard_base64_refresh_request_nonce":        AgentAssignmentRejectSemantic,
		"reject_noncanonical_tail_bits_refresh_request_nonce": AgentAssignmentRejectSemantic,
		"reject_alias_outer_dev_id":                           AgentAssignmentRejectUnknownField,
		"reject_client_public_key":                            AgentAssignmentRejectUnknownField,
		"reject_refresh_assignment_ticket":                    AgentAssignmentRejectUnknownField,
		"reject_duplicate_registration_ticket":                AgentAssignmentRejectBodyParse,
		"reject_wrong_mode":                                   AgentAssignmentRejectSemantic,
	} {
		c, ok := requestCases[name]
		if !ok {
			t.Errorf("request cases missing %q", name)
			continue
		}
		if c.RejectClass != wantClass {
			t.Errorf("request case %q reject_class = %q, want %q", name, c.RejectClass, wantClass)
		}
	}
	if got, want := len(af.SuccessResultCases), 12; got != want {
		t.Errorf("success result case count = %d, want %d", got, want)
	}
	resultCases := make(map[string]AgentAssignmentResultCase, len(af.SuccessResultCases))
	for _, c := range af.SuccessResultCases {
		resultCases[c.Name] = c
	}
	for _, name := range []string{"reject_initial_private_key_kind", "reject_initial_unknown_key_kind"} {
		if c, ok := resultCases[name]; !ok || c.RejectClass != AgentAssignmentRejectSemantic {
			t.Errorf("result case %q = %#v, want semantic reject", name, c)
		}
	}
	if af.ErrorContract.Status != "ready" || af.ErrorContract.ProducerRevision != AgentAssignmentNHPProducerRevision {
		t.Errorf("error taxonomy status/producer = %q/%q, want merged NHP producer pin", af.ErrorContract.Status, af.ErrorContract.ProducerRevision)
	}
	if got, want := len(af.ErrorContract.AssignmentCases), 6; got != want {
		t.Errorf("assignment error case count = %d, want %d", got, want)
	}
	var invalidAssignment *AgentAssignmentErrorCase
	for i := range af.ErrorContract.AssignmentCases {
		if af.ErrorContract.AssignmentCases[i].ErrCode == "52205" {
			invalidAssignment = &af.ErrorContract.AssignmentCases[i]
			break
		}
	}
	if invalidAssignment == nil {
		t.Error("assignment error contract is missing 52205")
	} else if want := []string{"initial_assignment", "refresh_assignment"}; !slices.Equal(invalidAssignment.AcceptedPhases, want) {
		t.Errorf("52205 accepted_phases = %v, want %v", invalidAssignment.AcceptedPhases, want)
	}
	if got, want := len(af.ErrorContract.InitialCredentialCases), 4; got != want {
		t.Errorf("initial credential error case count = %d, want %d", got, want)
	}
	if got, want := len(af.ErrorContract.CompletionCases), 5; got != want {
		t.Errorf("completion error case count = %d, want %d", got, want)
	}
	if got, want := len(af.ErrorContract.RegistrationCases), 4; got != want {
		t.Errorf("registration error case count = %d, want %d", got, want)
	}
}

func TestAgentAssignmentProductionShapedFixturesAreExact(t *testing.T) {
	allowed := map[string]bool{
		AgentAssignmentBootstrapCredentialFixture: false,
		AgentAssignmentAccountCredentialFixture:   false,
		AgentAssignmentDeviceAPIKeyFixture:        false,
	}
	for _, token := range regexp.MustCompile(`lv_live_[A-Za-z0-9_-]+`).FindAllString(string(AgentAssignmentVectors()), -1) {
		if _, ok := allowed[token]; !ok {
			t.Errorf("unexpected production-shaped fixture %q; scanner exceptions must be exact", token)
			continue
		}
		allowed[token] = true
	}
	for token, found := range allowed {
		if !found {
			t.Errorf("production-shaped fixture %q is not load-bearing", token)
		}
	}
}

func TestAgentAssignmentDeviceAPIKeyFixtureIsCanonical(t *testing.T) {
	const prefix = "lv_live_"
	if len(AgentAssignmentDeviceAPIKeyFixture) != len(prefix)+base64.RawURLEncoding.EncodedLen(agentAssignmentDeviceKeySecretBytes) ||
		!strings.HasPrefix(AgentAssignmentDeviceAPIKeyFixture, prefix) {
		t.Fatalf("device API-key fixture has noncanonical length or prefix: %q", AgentAssignmentDeviceAPIKeyFixture)
	}
	body := strings.TrimPrefix(AgentAssignmentDeviceAPIKeyFixture, prefix)
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil {
		t.Fatalf("decode device API-key fixture: %v", err)
	}
	if len(raw) != agentAssignmentDeviceKeySecretBytes || base64.RawURLEncoding.EncodeToString(raw) != body {
		t.Fatalf("device API-key fixture body is not canonical unpadded base64url for 32 bytes")
	}
	for i, value := range raw {
		if value != byte(i) {
			t.Fatalf("device API-key fixture byte %d = 0x%02x, want 0x%02x", i, value, byte(i))
		}
	}
}

func TestAgentAssignmentREADMERevisionPins(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	for name, revision := range map[string]string{
		"qurl-go":         AgentAssignmentQURLGoProducerRevision,
		"NHP errors":      AgentAssignmentNHPProducerRevision,
		"NHP OTP RawBody": AgentAssignmentOTPProducerRevision,
	} {
		if !bytes.Contains(readme, []byte(revision)) {
			t.Errorf("README is missing the %s producer revision %s", name, revision)
		}
	}
}

func TestAgentAssignmentPublicRegistrationKeyKindVocabulary(t *testing.T) {
	af, err := AgentAssignmentGolden()
	if err != nil {
		t.Fatal(err)
	}
	for _, keyKind := range af.PublicRegistrationKeyKinds {
		body := strings.Replace(af.InitialAssignment.Result.BodyJSON, `"key_kind":"bootstrap"`, `"key_kind":"`+keyKind+`"`, 1)
		got := classifyAgentAssignmentResult(AgentAssignmentResultCase{
			Phase:      "initial_assignment",
			HeaderName: AgentAssignmentResultHeaderName,
			HeaderType: AgentAssignmentResultHeaderType,
			BodyJSON:   body,
		})
		if got != "" {
			t.Errorf("key_kind %q classified as %q, want accept", keyKind, got)
		}
	}
}

func TestParseAgentAssignmentFileFailsClosed(t *testing.T) {
	raw := AgentAssignmentVectors()
	mutate := func(t *testing.T, change func(*AgentAssignmentFile)) []byte {
		t.Helper()
		var doc AgentAssignmentFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		change(&doc)
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("counter mismatch", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.InitialAssignment.Result.Counter = "99"
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "does not echo") {
			t.Fatalf("error = %v, want counter-echo rejection", err)
		}
	})

	t.Run("public registration key kind drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.PublicRegistrationKeyKinds[0] = "tunnel_bootstrap"
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "key_kind vocabulary drifted") {
			t.Fatalf("error = %v, want public key_kind vocabulary rejection", err)
		}
	})

	t.Run("completion routed to hub", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.RegistrationCompletion.Request.ReceiverKey = "hub"
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "key roles") {
			t.Fatalf("error = %v, want completion trust-boundary rejection", err)
		}
	})

	t.Run("account OTP RawBody requirement disabled", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.AccountCredentialOTP.RawBodyRequired = false
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "requires exact RawBody") {
			t.Fatalf("error = %v, want account OTP RawBody rejection", err)
		}
	})

	t.Run("account OTP key-kind policy drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.AccountCredentialOTP.OTPFreeRegistrationKeyKinds[0] = "account"
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "key-kind policy drifted") {
			t.Fatalf("error = %v, want account OTP key-kind rejection", err)
		}
	})

	t.Run("account OTP exact binding drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			body := strings.Replace(doc.AccountCredentialOTP.Request.BodyJSON, doc.AccountCredentialOTP.EnrollmentBinding.RequestAssignmentTicket, "different-ticket", 1)
			doc.AccountCredentialOTP.Request.BodyJSON = body
			doc.AccountCredentialOTP.Request.BodyHex = hex.EncodeToString([]byte(body))
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "exact enrollment binding") {
			t.Fatalf("error = %v, want account OTP binding rejection", err)
		}
	})

	t.Run("account OTP binding-case classifier drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.AccountCredentialOTP.BindingCases[1].RejectClass = AgentAssignmentRejectSemantic
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "fields drifted") {
			t.Fatalf("error = %v, want account OTP binding-case rejection", err)
		}
	})

	t.Run("account OTP credential-fence drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.AccountCredentialOTP.EnrollmentBinding.TicketCredentialFenceB64 = "SQl2Ef0ECANpbqb0zHnNgyQ0Q2bgxI-Mf5SglNcgMGE"
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "credential fence does not match") {
			t.Fatalf("error = %v, want account OTP credential-fence rejection", err)
		}
	})

	t.Run("account OTP challenge binding drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.AccountCredentialOTP.ChallengeBinding.CellID = "cell1"
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "challenge-store binding drifted") {
			t.Fatalf("error = %v, want account OTP challenge-binding rejection", err)
		}
	})

	t.Run("account OTP challenge binding-case drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.AccountCredentialOTP.ChallengeBindingCases[1].MutationValue = doc.AccountCredentialOTP.EnrollmentBinding.TicketJTI
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "challenge-binding case") {
			t.Fatalf("error = %v, want account OTP challenge-binding case rejection", err)
		}
	})

	t.Run("account OTP packet-size drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.AccountCredentialOTP.PacketSizeContract.MaxPlaintextBodyBytes++
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "packet-size contract drifted") {
			t.Fatalf("error = %v, want account OTP packet-size rejection", err)
		}
	})

	t.Run("body bytes drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.RefreshAssignment.Request.BodyHex = "7b7d"
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "does not encode body_json") {
			t.Fatalf("error = %v, want body-byte rejection", err)
		}
	})

	t.Run("wrong header type", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.RegistrationCompletion.Result.HeaderType = 2
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "header") {
			t.Fatalf("error = %v, want header-type rejection", err)
		}
	})

	t.Run("duplicate nested case name", func(t *testing.T) {
		needle := []byte(`"name": "completion_unavailable",`)
		if got := bytes.Count(raw, needle); got != 1 {
			t.Fatalf("completion_unavailable name count = %d, want 1", got)
		}
		replacement := []byte(`"name": "completion_unavailable", "name": "duplicate",`)
		b := bytes.Replace(raw, needle, replacement, 1)
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), `duplicate object key "name"`) {
			t.Fatalf("error = %v, want nested duplicate-name rejection", err)
		}
	})

	t.Run("REG ticket handoff mismatch", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			body := strings.Replace(doc.AssignedCellRegistration.Request.BodyJSON, "conformance-assignment-ticket-0001", "different-assignment-ticket", 1)
			doc.AssignedCellRegistration.Request.BodyJSON = body
			doc.AssignedCellRegistration.Request.BodyHex = hex.EncodeToString([]byte(body))
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "exact hub registration metadata") {
			t.Fatalf("error = %v, want exact REG ticket-handoff rejection", err)
		}
	})

	t.Run("completion ticket reuse", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			body := strings.Replace(doc.RegistrationCompletion.Request.BodyJSON, `"device_api_key":`, `"assignment_ticket":"reused","device_api_key":`, 1)
			doc.RegistrationCompletion.Request.BodyJSON = body
			doc.RegistrationCompletion.Request.BodyHex = hex.EncodeToString([]byte(body))
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("error = %v, want completion assignment_ticket rejection", err)
		}
	})

	t.Run("request case classifier drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.RequestCases[0].RejectClass = AgentAssignmentRejectSemantic
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "fields drifted") {
			t.Fatalf("error = %v, want request-classifier rejection", err)
		}
	})

	t.Run("success result case classifier drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.SuccessResultCases[0].RejectClass = AgentAssignmentRejectSemantic
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "fields drifted") {
			t.Fatalf("error = %v, want success-result classifier rejection", err)
		}
	})

	t.Run("mode-unknown response phase acceptance drift", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			for i := range doc.ErrorContract.AssignmentCases {
				if doc.ErrorContract.AssignmentCases[i].ErrCode == "52205" {
					doc.ErrorContract.AssignmentCases[i].AcceptedPhases = []string{"initial_assignment"}
					return
				}
			}
			t.Fatal("missing 52205 fixture")
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "accepted_phases") {
			t.Fatalf("error = %v, want accepted_phases rejection", err)
		}
	})

	t.Run("case-insensitive request alias", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			body := strings.Replace(doc.InitialAssignment.Request.BodyJSON, `"devId":`, `"devID":`, 1)
			doc.InitialAssignment.Request.BodyJSON = body
			doc.InitialAssignment.Request.BodyHex = hex.EncodeToString([]byte(body))
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), `unknown field "devID"`) {
			t.Fatalf("error = %v, want exact-key request rejection", err)
		}
	})

	t.Run("case-insensitive result alias", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			body := strings.Replace(doc.InitialAssignment.Result.BodyJSON, `"errCode":`, `"ErrCode":`, 1)
			doc.InitialAssignment.Result.BodyJSON = body
			doc.InitialAssignment.Result.BodyHex = hex.EncodeToString([]byte(body))
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), `unknown field "ErrCode"`) {
			t.Fatalf("error = %v, want exact-key result rejection", err)
		}
	})

	t.Run("static keypair mismatch", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.Keys.Hub.StaticPubHex = doc.Keys.AssignedCell.StaticPubHex
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "do not form an X25519 pair") {
			t.Fatalf("error = %v, want X25519 keypair rejection", err)
		}
	})

	t.Run("uppercase hex", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.InitialAssignment.Request.EphemeralPrivHex = strings.ToUpper(doc.InitialAssignment.Request.EphemeralPrivHex)
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "canonical lowercase hex") {
			t.Fatalf("error = %v, want canonical-hex rejection", err)
		}
	})

	t.Run("leading-zero counter", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.InitialAssignment.Request.Counter = "021"
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "canonical positive uint64 decimal") {
			t.Fatalf("error = %v, want canonical-decimal rejection", err)
		}
	})

	t.Run("preamble packet mismatch", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			doc.InitialAssignment.Request.PreambleHex = "01020304"
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "does not start with preamble_hex") {
			t.Fatalf("error = %v, want packet-preamble rejection", err)
		}
	})

	t.Run("noncanonical endpoint base64", func(t *testing.T) {
		b := mutate(t, func(doc *AgentAssignmentFile) {
			body := strings.Replace(doc.InitialAssignment.Result.BodyJSON, `Xwm3+XpAtQIgaXBktDsnQRsHpKof4FNwsnUZgmmD0w0=`, `Xwm3+XpAtQIgaXBktDsnQRsHpKof4FNwsnUZgmmD0w1=`, 1)
			doc.InitialAssignment.Result.BodyJSON = body
			doc.InitialAssignment.Result.BodyHex = hex.EncodeToString([]byte(body))
		})
		if _, err := ParseAgentAssignmentFile(b); err == nil || !strings.Contains(err.Error(), "canonical padded standard base64") {
			t.Fatalf("error = %v, want canonical-base64 rejection", err)
		}
	})
}

func TestEmbeddedAgentKnockApplicationLoads(t *testing.T) {
	af, err := AgentKnockApplication()
	if err != nil {
		t.Fatalf("AgentKnockApplication(): %v", err)
	}
	if af.Artifact != AgentKnockApplicationArtifactID {
		t.Errorf("artifact = %q, want %q", af.Artifact, AgentKnockApplicationArtifactID)
	}
	if af.SchemaVersion != 3 {
		t.Errorf("schema_version = %d, want 3", af.SchemaVersion)
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
		"ack_success": false, "ack_success_optional_metadata": false,
		"ack_deny": false, "cookie_challenge": false,
		"reject_wrong_resource": false, "reject_missing_ac_token": false,
		"reject_empty_ac_token": false, "reject_missing_resource_host": false,
		"reject_empty_resource_host": false, "reject_malformed_ac_tokens_map": false,
		"reject_malformed_resource_host_map":      false,
		"reject_pre_access_action_requested":      false,
		"reject_pre_access_action_other_resource": false,
		"reject_malformed_pre_actions":            false,
		"reject_malformed_asp_token":              false,
		"reject_malformed_redirect_url":           false,
		"reject_malformed_opn_time":               false,
		"reject_malformed_agent_addr":             false,
		"reject_unknown_ack_field":                false,
		"reject_duplicate_ack_field":              false,
		"reject_trailing_ack_data":                false,
		"reject_null_ack_body":                    false,
		"reject_non_object_ack_body":              false,
		"reject_counter_mismatch":                 false,
		"reject_reply_type_mismatch":              false,
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
	rawMap := func(name, field string) (map[string]json.RawMessage, error) {
		var value map[string]json.RawMessage
		err := json.Unmarshal(body(name)[field], &value)
		return value, err
	}
	// producerACK mirrors OpenNHP nhp/common/nhpmsg.go's ServerKnockAckMsg at main commit
	// 1dbedcadee2018cd6a8684cc4b53b9e6a9048da4.
	type producerACK struct {
		ErrCode           string            `json:"errCode"`
		ErrMsg            string            `json:"errMsg,omitempty"`
		ResourceHost      map[string]string `json:"resHost"`
		OpenTime          uint32            `json:"opnTime"`
		AuthProviderToken string            `json:"aspToken,omitempty"`
		AgentAddr         string            `json:"agentAddr"`
		ACTokens          map[string]string `json:"acTokens"`
		// preActions maps the requested resource only to null in the producer's
		// no-NHP_ACC success shape. Populated action fields live in the
		// reject_pre_access_* vectors rather than this serialization fixture.
		PreAccessActions map[string]*struct{} `json:"preActions,omitempty"`
		RedirectURL      string               `json:"redirectUrl,omitempty"`
	}
	standard := producerACK{
		ErrCode:          "0",
		ResourceHost:     map[string]string{resourceID: "frps.sandbox.example:7000"},
		OpenTime:         900,
		AgentAddr:        "203.0.113.9:49152",
		ACTokens:         map[string]string{resourceID: "ac-token-conformance-01"},
		PreAccessActions: map[string]*struct{}{resourceID: nil},
	}
	// This shallow copy deliberately changes only scalar metadata; its shared
	// routing, admission, and pre-access maps remain immutable below.
	optionalMetadata := standard
	optionalMetadata.AuthProviderToken = "asp-token-must-not-authorize"
	optionalMetadata.RedirectURL = "https://redirect.example/conformance"
	denied := producerACK{
		ErrCode:   "52004",
		ErrMsg:    "failed to find resource",
		AgentAddr: "203.0.113.9:49152",
	}
	for name, ack := range map[string]producerACK{
		"ack_success":                   standard,
		"ack_success_optional_metadata": optionalMetadata,
		"ack_deny":                      denied,
	} {
		golden, err := json.Marshal(ack)
		if err != nil {
			t.Fatalf("marshal %s producer ACK: %v", name, err)
		}
		if byName[name].BodyJSON != string(golden) {
			t.Errorf("%s body_json drifted from producer serialization:\n got %s\nwant %s", name, byName[name].BodyJSON, golden)
		}
	}

	for _, name := range []string{"ack_success", "ack_success_optional_metadata"} {
		if got := stringField(name, "errCode"); got != "0" {
			t.Errorf("%s errCode = %q, want 0", name, got)
		}
		acTokens, acErr := stringMap(name, "acTokens")
		resourceHosts, hostErr := stringMap(name, "resHost")
		if hostErr != nil || resourceHosts[resourceID] == "" {
			t.Errorf("%s resHost = %v, %v; want requested non-empty value", name, resourceHosts, hostErr)
		}
		if acErr != nil || acTokens[resourceID] == "" {
			t.Errorf("%s acTokens = %v, %v; want requested non-empty value", name, acTokens, acErr)
		}
		preActions, err := rawMap(name, "preActions")
		if err != nil || string(preActions[resourceID]) != "null" {
			t.Errorf("%s preActions = %v, %v; want exact-resource null", name, preActions, err)
		}
		c := byName[name]
		if c.ExpectedACToken != acTokens[resourceID] || c.ExpectedResourceHost != resourceHosts[resourceID] {
			t.Errorf("%s expected result = %q/%q, want exact resource maps %q/%q", name,
				c.ExpectedACToken, c.ExpectedResourceHost, acTokens[resourceID], resourceHosts[resourceID])
		}
	}
	optional := body("ack_success_optional_metadata")
	var aspToken, redirectURL string
	if err := json.Unmarshal(optional["aspToken"], &aspToken); err != nil || aspToken != "asp-token-must-not-authorize" {
		t.Errorf("optional aspToken = %q, %v; want typed non-authorizing metadata", aspToken, err)
	}
	if err := json.Unmarshal(optional["redirectUrl"], &redirectURL); err != nil || redirectURL != "https://redirect.example/conformance" {
		t.Errorf("optional redirectUrl = %q, %v; want typed metadata", redirectURL, err)
	}
	if aspToken == byName["ack_success_optional_metadata"].ExpectedACToken {
		t.Error("optional aspToken aliases expected_ac_token; vector would not catch alternate authorization")
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
		name string
		key  string
	}{
		{"reject_pre_access_action_requested", resourceID},
		{"reject_pre_access_action_other_resource", "connector-other-01"},
	} {
		preActions, err := rawMap(tc.name, "preActions")
		if err != nil || len(preActions[tc.key]) == 0 || string(preActions[tc.key]) == "null" {
			t.Errorf("%s preActions = %v, %v; want non-null action under %q", tc.name, preActions, err, tc.key)
		}
		if byName[tc.name].RejectClass != AgentKnockRejectUnsupportedPreAccess {
			t.Errorf("%s reject_class = %q, want %q", tc.name, byName[tc.name].RejectClass, AgentKnockRejectUnsupportedPreAccess)
		}
	}
	if preActions, err := rawMap("reject_pre_access_action_other_resource", "preActions"); err != nil || string(preActions[resourceID]) != "null" {
		t.Errorf("other-resource preActions = %v, %v; want requested-resource null plus foreign non-null action", preActions, err)
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
	if _, err := rawMap("reject_malformed_pre_actions", "preActions"); err == nil {
		t.Error("reject_malformed_pre_actions.preActions decoded as object, want type error")
	}
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"reject_malformed_asp_token", "aspToken"},
		{"reject_malformed_redirect_url", "redirectUrl"},
		{"reject_malformed_agent_addr", "agentAddr"},
	} {
		var value string
		if err := json.Unmarshal(body(tc.name)[tc.field], &value); err == nil {
			t.Errorf("%s.%s decoded as string, want type error", tc.name, tc.field)
		}
	}
	var openTime uint32
	if err := json.Unmarshal(body("reject_malformed_opn_time")["opnTime"], &openTime); err == nil {
		t.Error("reject_malformed_opn_time.opnTime decoded as uint32, want type error")
	}
	if fields := body("reject_unknown_ack_field"); len(fields["futureField"]) == 0 {
		t.Error("reject_unknown_ack_field does not carry its unknown field")
	}
	if got := strings.Count(byName["reject_duplicate_ack_field"].BodyJSON, `"errCode"`); got != 2 {
		t.Errorf("duplicate ACK case has %d errCode keys, want 2", got)
	}
	if json.Valid([]byte(byName["reject_trailing_ack_data"].BodyJSON)) {
		t.Error("trailing ACK case unexpectedly contains one valid JSON value")
	}
	if byName["reject_null_ack_body"].BodyJSON != "null" || byName["reject_non_object_ack_body"].BodyJSON != "[]" {
		t.Errorf("null/non-object ACK bodies drifted: %q / %q", byName["reject_null_ack_body"].BodyJSON, byName["reject_non_object_ack_body"].BodyJSON)
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
		{"agent assignment", AgentAssignmentVectors(), `{"artifact":"duplicate",`, func(b []byte) error { _, err := ParseAgentAssignmentFile(b); return err }},
		{"agent knock application", AgentKnockApplicationVectors(), `{"artifact":"duplicate",`, func(b []byte) error { _, err := ParseAgentKnockApplicationFile(b); return err }},
		{"agent session control", AgentSessionControlVectors(), `{"artifact":"duplicate",`, func(b []byte) error { _, err := ParseAgentSessionControlFile(b); return err }},
		{"agent API-key ID", AgentAPIKeyIDVectors(), `{"artifact":"duplicate",`, func(b []byte) error { _, err := ParseAgentAPIKeyIDFile(b); return err }},
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
		doc.SchemaVersion = 2
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "want 3") {
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

	t.Run("unknown reply case", func(t *testing.T) {
		var doc AgentKnockApplicationFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		extra := doc.ReplyCases[0]
		extra.Name = "unexpected_reply_case"
		doc.ReplyCases = append(doc.ReplyCases, extra)
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "unknown agent-knock reply case") {
			t.Fatalf("error = %v, want unknown reply case rejection", err)
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

	t.Run("success without expected result", func(t *testing.T) {
		b := mutateCase(t, "ack_success", func(c *AgentKnockReplyCase) {
			c.ExpectedACToken = ""
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "non-empty expected result") {
			t.Fatalf("error = %v, want missing expected result rejection", err)
		}
	})

	t.Run("success expected token drift", func(t *testing.T) {
		b := mutateCase(t, "ack_success", func(c *AgentKnockReplyCase) {
			c.ExpectedACToken = "wrong-token"
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "expected_ac_token") {
			t.Fatalf("error = %v, want expected token mismatch rejection", err)
		}
	})

	t.Run("success expected resource host drift", func(t *testing.T) {
		b := mutateCase(t, "ack_success", func(c *AgentKnockReplyCase) {
			c.ExpectedResourceHost = "wrong.example:7000"
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "expected_resource_host") {
			t.Fatalf("error = %v, want expected resource host mismatch rejection", err)
		}
	})

	t.Run("success with non-null pre-access action", func(t *testing.T) {
		b := mutateCase(t, "ack_success", func(c *AgentKnockReplyCase) {
			var body map[string]any
			if err := json.Unmarshal([]byte(c.BodyJSON), &body); err != nil {
				t.Fatal(err)
			}
			body["preActions"] = map[string]any{"foreign-resource": map[string]any{"acIp": "198.51.100.8"}}
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			c.BodyJSON = string(encoded)
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "non-null preActions") {
			t.Fatalf("error = %v, want non-null success preActions rejection", err)
		}
	})

	t.Run("reject with expected result", func(t *testing.T) {
		b := mutateCase(t, "reject_wrong_resource", func(c *AgentKnockReplyCase) {
			c.ExpectedACToken = "unexpected"
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "must not carry an expected result") {
			t.Fatalf("error = %v, want non-success expected result rejection", err)
		}
	})

	t.Run("invalid JSON requires body_parse disposition", func(t *testing.T) {
		b := mutateCase(t, "ack_success", func(c *AgentKnockReplyCase) {
			c.BodyJSON += "{}"
		})
		if _, err := ParseAgentKnockApplicationFile(b); err == nil || !strings.Contains(err.Error(), "body_json is not valid JSON") {
			t.Fatalf("error = %v, want invalid success body rejection", err)
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
		"agent_assignment_golden.json",
		"vectors/agent_assignment_golden.json",
		"agent_knock_application_vectors.json",
		"vectors/agent_knock_application_vectors.json",
		"agent_session_control_vectors.json",
		"vectors/agent_session_control_vectors.json",
		"agent_api_key_id_vectors.json",
		"vectors/agent_api_key_id_vectors.json",
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
