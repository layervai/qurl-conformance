package conformance

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// AgentSessionControlArtifactID identifies the registered-agent overload
	// re-knock and clean-exit packet artifact.
	AgentSessionControlArtifactID = "qurl-agent-session-control-vectors"
	// AgentSessionControlProducerRevision is the exact reviewed NHP producer
	// revision used to seal the golden packets.
	AgentSessionControlProducerRevision = "e0fedfec0cf3215d8af291b21ef9eb5889ae9906"

	AgentSessionHeaderKNK = 1
	AgentSessionHeaderACK = 2
	AgentSessionHeaderCOK = 7
	AgentSessionHeaderRKN = 8
	AgentSessionHeaderEXT = 16

	AgentSessionCookieSize = 32
	AgentSessionHeaderSize = 240
	AgentSessionTagSize    = 16
)

const (
	AgentSessionOutcomeAccept = "accept"
	AgentSessionOutcomeReject = "reject"

	AgentSessionRejectBodyParse          = "body_parse"
	AgentSessionRejectCookieEncoding     = "cookie_encoding"
	AgentSessionRejectCookieLength       = "cookie_length"
	AgentSessionRejectCookieCanonical    = "cookie_canonical"
	AgentSessionRejectCounter            = "counter"
	AgentSessionRejectHeaderType         = "header_type"
	AgentSessionRejectReplyType          = "reply_type"
	AgentSessionRejectHeaderDigest       = "header_digest"
	AgentSessionRejectApplicationBody    = "application_body"
	AgentSessionRejectPeerAuthentication = "peer_authentication"
)

// AgentSessionControlFile is the complete packet and negative-case contract for
// one overload KNK/COK/RKN/ACK sequence and one clean EXT/ACK sequence.
type AgentSessionControlFile struct {
	Artifact         string                       `json:"artifact"`
	SchemaVersion    int                          `json:"schema_version"`
	Description      string                       `json:"description"`
	SourceOfTruth    string                       `json:"source_of_truth"`
	ProducerRevision string                       `json:"producer_revision"`
	Notes            []string                     `json:"notes"`
	Protocol         AgentSessionProtocol         `json:"protocol"`
	Keys             AgentSessionKeys             `json:"keys"`
	OverloadReknock  AgentSessionOverloadReknock  `json:"overload_reknock"`
	CleanExit        AgentSessionCleanExit        `json:"clean_exit"`
	CookieBodyCases  []AgentSessionCookieBodyCase `json:"cookie_body_cases"`
	// FlowCases is a closed, consumer-driven expectation table. Each consumer
	// synthesizes the named mutations against its real session implementation.
	FlowCases []AgentSessionFlowCase `json:"flow_cases"`
}

type AgentSessionProtocol struct {
	CookieSizeBytes               int    `json:"cookie_size_bytes"`
	CookieEncoding                string `json:"cookie_encoding"`
	COKWireCounterCorrelation     string `json:"cok_wire_counter_correlation"`
	COKBodyTransactionCorrelation string `json:"cok_body_transaction_correlation"`
	ACKCounterCorrelation         string `json:"ack_counter_correlation"`
	RKNHeaderDigest               string `json:"rkn_header_digest"`
	ExitCookieChallengeAllowed    bool   `json:"exit_cookie_challenge_allowed"`
}

type AgentSessionKeys struct {
	AssignedCell AgentSessionKey `json:"assigned_cell"`
	Agent        AgentSessionKey `json:"agent"`
}

type AgentSessionKey struct {
	StaticPrivateHex string `json:"static_private_hex"`
	StaticPublicHex  string `json:"static_public_hex"`
}

type AgentSessionOverloadReknock struct {
	CookieHex      string             `json:"cookie_hex"`
	CookieB64      string             `json:"cookie_b64"`
	KnockRequest   AgentSessionPacket `json:"knock_request"`
	CookieReply    AgentSessionPacket `json:"cookie_reply"`
	ReknockRequest AgentSessionPacket `json:"reknock_request"`
	ACK            AgentSessionPacket `json:"ack"`
}

type AgentSessionCleanExit struct {
	Request AgentSessionPacket `json:"request"`
	ACK     AgentSessionPacket `json:"ack"`
}

// AgentSessionPacket carries every deterministic input plus the full packet.
// Replies are deterministic in this artifact too, so both directions can be
// authenticated and reproduced independently.
type AgentSessionPacket struct {
	HeaderName          string `json:"header_name"`
	HeaderType          int    `json:"header_type"`
	SenderKey           string `json:"sender_key"`
	ReceiverKey         string `json:"receiver_key"`
	EphemeralPrivateHex string `json:"ephemeral_private_hex"`
	TimestampNanos      string `json:"timestamp_nanos"`
	Counter             string `json:"counter"`
	PreambleHex         string `json:"preamble_hex"`
	BodyJSON            string `json:"body_json"`
	BodyHex             string `json:"body_hex"`
	HeaderDigestHex     string `json:"header_digest_hex"`
	PacketHex           string `json:"packet_hex"`
}

type AgentSessionCookieBodyCase struct {
	Name        string `json:"name"`
	BodyJSON    string `json:"body_json"`
	Outcome     string `json:"outcome"`
	RejectClass string `json:"reject_class,omitempty"`
}

type AgentSessionFlowCase struct {
	Name        string `json:"name"`
	Stage       string `json:"stage"`
	Mutation    string `json:"mutation"`
	Outcome     string `json:"outcome"`
	RejectClass string `json:"reject_class,omitempty"`
}

// ParseAgentSessionControlFile strictly parses and semantically validates the
// registered-agent RKN/EXT artifact. It never accepts a partial fixture.
func ParseAgentSessionControlFile(data []byte) (*AgentSessionControlFile, error) {
	var f AgentSessionControlFile
	if err := strictDecodeArtifact(data, &f); err != nil {
		return nil, fmt.Errorf("conformance: parse agent-session control file: %w", err)
	}
	if f.Artifact != AgentSessionControlArtifactID {
		return nil, fmt.Errorf("conformance: agent-session artifact = %q, want %q", f.Artifact, AgentSessionControlArtifactID)
	}
	if f.SchemaVersion != 1 {
		return nil, fmt.Errorf("conformance: agent-session schema_version = %d, want 1", f.SchemaVersion)
	}
	if f.ProducerRevision != AgentSessionControlProducerRevision {
		return nil, fmt.Errorf("conformance: agent-session producer revision = %q, want %q", f.ProducerRevision, AgentSessionControlProducerRevision)
	}
	if f.Description == "" || f.SourceOfTruth == "" || len(f.Notes) == 0 {
		return nil, errors.New("conformance: agent-session metadata is incomplete")
	}
	if err := validateAgentSessionProtocol(f.Protocol); err != nil {
		return nil, err
	}
	if err := validateAgentSessionKeys(f.Keys); err != nil {
		return nil, err
	}

	packets := []struct {
		name, headerName, sender, receiver string
		headerType                         int
		packet                             AgentSessionPacket
	}{
		{"overload_reknock.knock_request", "NHP_KNK", "agent", "assigned_cell", AgentSessionHeaderKNK, f.OverloadReknock.KnockRequest},
		{"overload_reknock.cookie_reply", "NHP_COK", "assigned_cell", "agent", AgentSessionHeaderCOK, f.OverloadReknock.CookieReply},
		{"overload_reknock.reknock_request", "NHP_RKN", "agent", "assigned_cell", AgentSessionHeaderRKN, f.OverloadReknock.ReknockRequest},
		{"overload_reknock.ack", "NHP_ACK", "assigned_cell", "agent", AgentSessionHeaderACK, f.OverloadReknock.ACK},
		{"clean_exit.request", "NHP_EXT", "agent", "assigned_cell", AgentSessionHeaderEXT, f.CleanExit.Request},
		{"clean_exit.ack", "NHP_ACK", "assigned_cell", "agent", AgentSessionHeaderACK, f.CleanExit.ACK},
	}
	for _, p := range packets {
		if err := validateAgentSessionPacket(p.name, p.packet, p.headerName, p.headerType, p.sender, p.receiver); err != nil {
			return nil, err
		}
	}
	if err := validateAgentSessionFlowBindings(&f); err != nil {
		return nil, err
	}
	if err := validateAgentSessionCookieCases(&f); err != nil {
		return nil, err
	}
	if err := validateAgentSessionFlowCases(f.FlowCases); err != nil {
		return nil, err
	}
	return &f, nil
}

func validateAgentSessionProtocol(p AgentSessionProtocol) error {
	if p.CookieSizeBytes != AgentSessionCookieSize || p.CookieEncoding != "base64_std_padded_canonical" ||
		p.COKWireCounterCorrelation != "unconstrained" || p.COKBodyTransactionCorrelation != "must_equal_knock_counter" ||
		p.ACKCounterCorrelation != "must_echo_request" ||
		p.RKNHeaderDigest != "BLAKE2s-256(initial_hash || server_static_public_key || header[0:208] || cookie)" ||
		p.ExitCookieChallengeAllowed {
		return errors.New("conformance: agent-session protocol contract drifted")
	}
	return nil
}

func validateAgentSessionKeys(keys AgentSessionKeys) error {
	for _, k := range []struct {
		name string
		key  AgentSessionKey
	}{{"assigned_cell", keys.AssignedCell}, {"agent", keys.Agent}} {
		if err := validateAgentAssignmentHex("agent-session "+k.name+" private key", k.key.StaticPrivateHex, 32); err != nil {
			return err
		}
		if err := validateAgentAssignmentHex("agent-session "+k.name+" public key", k.key.StaticPublicHex, 32); err != nil {
			return err
		}
		privateBytes, _ := hex.DecodeString(k.key.StaticPrivateHex)
		privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
		if err != nil {
			return fmt.Errorf("conformance: agent-session %s private key: %w", k.name, err)
		}
		if hex.EncodeToString(privateKey.PublicKey().Bytes()) != k.key.StaticPublicHex {
			return fmt.Errorf("conformance: agent-session %s keys do not form an X25519 pair", k.name)
		}
	}
	if keys.AssignedCell.StaticPublicHex == keys.Agent.StaticPublicHex {
		return errors.New("conformance: agent-session cell and agent identities must be distinct")
	}
	return nil
}

// validateAgentSessionPacket is the stdlib-only structural gate. The independent
// verify-sdk gate rebuilds and cryptographically authenticates every packet.
func validateAgentSessionPacket(name string, p AgentSessionPacket, wantName string, wantType int, wantSender, wantReceiver string) error {
	if p.HeaderName != wantName || p.HeaderType != wantType || p.SenderKey != wantSender || p.ReceiverKey != wantReceiver {
		return fmt.Errorf("conformance: agent-session %s type or key roles drifted", name)
	}
	if err := validateAgentAssignmentHex("agent-session "+name+" ephemeral private key", p.EphemeralPrivateHex, 32); err != nil {
		return err
	}
	if err := validateAgentAssignmentHex("agent-session "+name+" preamble", p.PreambleHex, 4); err != nil {
		return err
	}
	if err := validateAgentAssignmentHex("agent-session "+name+" header digest", p.HeaderDigestHex, 32); err != nil {
		return err
	}
	if err := validateAgentAssignmentUint64("agent-session "+name+" timestamp", p.TimestampNanos); err != nil {
		return err
	}
	if err := validateAgentAssignmentUint64("agent-session "+name+" counter", p.Counter); err != nil {
		return err
	}
	body, err := hex.DecodeString(p.BodyHex)
	if err != nil || hex.EncodeToString(body) != p.BodyHex || !bytes.Equal(body, []byte(p.BodyJSON)) {
		return fmt.Errorf("conformance: agent-session %s body_hex does not encode body_json", name)
	}
	packet, err := hex.DecodeString(p.PacketHex)
	if err != nil || hex.EncodeToString(packet) != p.PacketHex {
		return fmt.Errorf("conformance: agent-session %s packet_hex is not canonical hex", name)
	}
	if len(packet) != AgentSessionHeaderSize+len(body)+AgentSessionTagSize || len(packet) > 4096 {
		return fmt.Errorf("conformance: agent-session %s packet size is inconsistent with body", name)
	}
	preamble := binary.BigEndian.Uint32(packet[0:4])
	word := preamble ^ binary.BigEndian.Uint32(packet[4:8])
	if int(word>>16) != wantType || int(word&0xffff) != len(body)+AgentSessionTagSize || fmt.Sprintf("%08x", preamble) != p.PreambleHex {
		return fmt.Errorf("conformance: agent-session %s header type, size, or preamble drifted", name)
	}
	if packet[8] != 1 || packet[9] != 0 || binary.BigEndian.Uint16(packet[10:12]) != 0 {
		return fmt.Errorf("conformance: agent-session %s version or flags drifted", name)
	}
	counter, _ := strconv.ParseUint(p.Counter, 10, 64)
	if binary.BigEndian.Uint64(packet[16:24]) != counter {
		return fmt.Errorf("conformance: agent-session %s wire counter drifted", name)
	}
	if !bytes.Equal(packet[208:240], mustDecodeAgentSessionHex(p.HeaderDigestHex)) {
		return fmt.Errorf("conformance: agent-session %s header_digest_hex does not match packet", name)
	}
	ephemeralPrivate, _ := hex.DecodeString(p.EphemeralPrivateHex)
	ephemeral, err := ecdh.X25519().NewPrivateKey(ephemeralPrivate)
	if err != nil || !bytes.Equal(packet[24:56], ephemeral.PublicKey().Bytes()) {
		return fmt.Errorf("conformance: agent-session %s ephemeral key does not match packet", name)
	}
	for _, b := range packet[56:136] {
		if b != 0 {
			return fmt.Errorf("conformance: agent-session %s identity padding is nonzero", name)
		}
	}
	return nil
}

func mustDecodeAgentSessionHex(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}

type agentSessionKnockBody struct {
	HeaderType    int    `json:"headerType"`
	UserID        string `json:"usrId"`
	DeviceID      string `json:"devId"`
	AuthServiceID string `json:"aspId"`
	ResourceID    string `json:"resId"`
	RunID         string `json:"runId"`
}

type agentSessionCookieBody struct {
	TransactionID uint64 `json:"trxId"`
	Cookie        string `json:"cookie"`
}

type agentSessionACKBody struct {
	ErrCode      string                     `json:"errCode"`
	ResourceHost map[string]string          `json:"resHost"`
	OpenTime     uint32                     `json:"opnTime"`
	AgentAddr    string                     `json:"agentAddr"`
	ACTokens     map[string]string          `json:"acTokens"`
	PreActions   map[string]json.RawMessage `json:"preActions"`
}

func validateAgentSessionFlowBindings(f *AgentSessionControlFile) error {
	o := f.OverloadReknock
	knockCounter, _ := strconv.ParseUint(o.KnockRequest.Counter, 10, 64)
	rknCounter, _ := strconv.ParseUint(o.ReknockRequest.Counter, 10, 64)
	exitCounter, _ := strconv.ParseUint(f.CleanExit.Request.Counter, 10, 64)
	if o.ACK.Counter != o.ReknockRequest.Counter || f.CleanExit.ACK.Counter != f.CleanExit.Request.Counter {
		return errors.New("conformance: agent-session ACK counter bindings drifted")
	}
	if knockCounter == rknCounter || rknCounter == exitCounter || knockCounter == exitCounter {
		return errors.New("conformance: agent-session request counters must be distinct")
	}

	if err := validateAgentAssignmentHex("agent-session cookie", o.CookieHex, AgentSessionCookieSize); err != nil {
		return err
	}
	cookie, err := base64.StdEncoding.Strict().DecodeString(o.CookieB64)
	if err != nil || len(cookie) != AgentSessionCookieSize || base64.StdEncoding.EncodeToString(cookie) != o.CookieB64 || hex.EncodeToString(cookie) != o.CookieHex {
		return errors.New("conformance: agent-session cookie encoding is not canonical 32-byte standard base64")
	}

	knock, err := decodeAgentSessionKnockBody(o.KnockRequest.BodyJSON)
	if err != nil {
		return fmt.Errorf("conformance: agent-session KNK body: %w", err)
	}
	rkn, err := decodeAgentSessionKnockBody(o.ReknockRequest.BodyJSON)
	if err != nil {
		return fmt.Errorf("conformance: agent-session RKN body: %w", err)
	}
	exit, err := decodeAgentSessionKnockBody(f.CleanExit.Request.BodyJSON)
	if err != nil {
		return fmt.Errorf("conformance: agent-session EXT body: %w", err)
	}
	if knock.HeaderType != AgentSessionHeaderKNK || rkn.HeaderType != AgentSessionHeaderRKN || exit.HeaderType != AgentSessionHeaderEXT {
		return errors.New("conformance: agent-session authenticated body headerType does not match outer type")
	}
	knock.HeaderType, rkn.HeaderType, exit.HeaderType = 0, 0, 0
	if knock != rkn || knock != exit || !isCanonicalAgentKnockRunID(knock.RunID) || knock.AuthServiceID != "agent" {
		return errors.New("conformance: agent-session identity, resource, or RunID changed across KNK/RKN/EXT")
	}

	if class := classifyAgentSessionCookieBody(o.CookieReply.BodyJSON, knockCounter); class != "" {
		return fmt.Errorf("conformance: agent-session canonical COK body classified as %q", class)
	}
	var cok agentSessionCookieBody
	if err := json.Unmarshal([]byte(o.CookieReply.BodyJSON), &cok); err != nil || cok.Cookie != o.CookieB64 {
		return errors.New("conformance: agent-session COK cookie differs from RKN digest cookie")
	}
	for _, a := range []struct {
		name     string
		body     string
		openTime uint32
	}{{"RKN ACK", o.ACK.BodyJSON, 900}, {"EXT ACK", f.CleanExit.ACK.BodyJSON, 1}} {
		if err := validateAgentSessionACKBody(a.name, a.body, a.openTime, knock.ResourceID); err != nil {
			return err
		}
	}
	return nil
}

func decodeAgentSessionKnockBody(body string) (agentSessionKnockBody, error) {
	var raw map[string]json.RawMessage
	if err := strictDecodeArtifact([]byte(body), &raw); err != nil {
		return agentSessionKnockBody{}, err
	}
	want := map[string]bool{"headerType": true, "usrId": true, "devId": true, "aspId": true, "resId": true, "runId": true}
	if len(raw) != len(want) {
		return agentSessionKnockBody{}, errors.New("wrong field count")
	}
	for key := range raw {
		if !want[key] {
			return agentSessionKnockBody{}, fmt.Errorf("unknown exact field %q", key)
		}
	}
	var decoded agentSessionKnockBody
	if err := strictDecodeArtifact([]byte(body), &decoded); err != nil {
		return agentSessionKnockBody{}, err
	}
	canonical, _ := json.Marshal(decoded)
	if string(canonical) != body {
		return agentSessionKnockBody{}, errors.New("body is not canonical compact JSON")
	}
	if decoded.UserID == "" || decoded.DeviceID == "" || decoded.ResourceID == "" {
		return agentSessionKnockBody{}, errors.New("required identity is empty")
	}
	return decoded, nil
}

func validateAgentSessionACKBody(name, body string, openTime uint32, resourceID string) error {
	var ack agentSessionACKBody
	if err := strictDecodeArtifact([]byte(body), &ack); err != nil {
		return fmt.Errorf("conformance: agent-session %s body: %w", name, err)
	}
	if ack.ErrCode != "0" || ack.OpenTime != openTime || strings.TrimSpace(ack.AgentAddr) == "" ||
		strings.TrimSpace(ack.ResourceHost[resourceID]) == "" || strings.TrimSpace(ack.ACTokens[resourceID]) == "" {
		return fmt.Errorf("conformance: agent-session %s success body drifted", name)
	}
	if len(ack.PreActions) != 1 || string(ack.PreActions[resourceID]) != "null" {
		return fmt.Errorf("conformance: agent-session %s preActions drifted", name)
	}
	canonical, _ := json.Marshal(ack)
	if string(canonical) != body {
		return fmt.Errorf("conformance: agent-session %s body is not canonical producer JSON", name)
	}
	return nil
}

// classifyAgentSessionCookieBody is mirrored independently by verify-sdk; both
// classifiers must execute every closed cookie_body_cases entry in lockstep.
func classifyAgentSessionCookieBody(body string, requestCounter uint64) string {
	if err := rejectDuplicateJSONKeys([]byte(body)); err != nil {
		return AgentSessionRejectBodyParse
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &fields); err != nil || len(fields) != 2 || fields["trxId"] == nil || fields["cookie"] == nil {
		return AgentSessionRejectBodyParse
	}
	if bytes.Equal(bytes.TrimSpace(fields["trxId"]), []byte("null")) || bytes.Equal(bytes.TrimSpace(fields["cookie"]), []byte("null")) {
		return AgentSessionRejectBodyParse
	}
	var message *agentSessionCookieBody
	if err := strictDecodeArtifact([]byte(body), &message); err != nil || message == nil || message.Cookie == "" {
		return AgentSessionRejectBodyParse
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(message.Cookie)
	if err != nil {
		if unpadded, rawErr := base64.RawStdEncoding.Strict().DecodeString(message.Cookie); rawErr == nil && len(unpadded) == AgentSessionCookieSize {
			return AgentSessionRejectCookieCanonical
		}
		return AgentSessionRejectCookieEncoding
	}
	if len(raw) != AgentSessionCookieSize {
		return AgentSessionRejectCookieLength
	}
	if base64.StdEncoding.EncodeToString(raw) != message.Cookie {
		return AgentSessionRejectCookieCanonical
	}
	if message.TransactionID != requestCounter {
		return AgentSessionRejectCounter
	}
	return ""
}

func validateAgentSessionCookieCases(f *AgentSessionControlFile) error {
	knockCounter, _ := strconv.ParseUint(f.OverloadReknock.KnockRequest.Counter, 10, 64)
	required := map[string]struct {
		outcome, class string
	}{
		"accept_canonical":              {AgentSessionOutcomeAccept, ""},
		"reject_invalid_cookie_base64":  {AgentSessionOutcomeReject, AgentSessionRejectCookieEncoding},
		"reject_cookie_31_bytes":        {AgentSessionOutcomeReject, AgentSessionRejectCookieLength},
		"reject_cookie_33_bytes":        {AgentSessionOutcomeReject, AgentSessionRejectCookieLength},
		"reject_unpadded_cookie":        {AgentSessionOutcomeReject, AgentSessionRejectCookieCanonical},
		"reject_cookie_whitespace":      {AgentSessionOutcomeReject, AgentSessionRejectCookieEncoding},
		"reject_transaction_string":     {AgentSessionOutcomeReject, AgentSessionRejectBodyParse},
		"reject_null_transaction":       {AgentSessionOutcomeReject, AgentSessionRejectBodyParse},
		"reject_cookie_number":          {AgentSessionOutcomeReject, AgentSessionRejectBodyParse},
		"reject_duplicate_transaction":  {AgentSessionOutcomeReject, AgentSessionRejectBodyParse},
		"reject_duplicate_cookie":       {AgentSessionOutcomeReject, AgentSessionRejectBodyParse},
		"reject_unknown_cookie_field":   {AgentSessionOutcomeReject, AgentSessionRejectBodyParse},
		"reject_trailing_cookie_value":  {AgentSessionOutcomeReject, AgentSessionRejectBodyParse},
		"reject_null_cookie_body":       {AgentSessionOutcomeReject, AgentSessionRejectBodyParse},
		"reject_non_object_cookie_body": {AgentSessionOutcomeReject, AgentSessionRejectBodyParse},
	}
	if len(f.CookieBodyCases) != len(required) {
		return fmt.Errorf("conformance: agent-session cookie case count = %d, want %d", len(f.CookieBodyCases), len(required))
	}
	seen := make(map[string]struct{}, len(required))
	for _, c := range f.CookieBodyCases {
		want, ok := required[c.Name]
		if !ok {
			return fmt.Errorf("conformance: agent-session unknown cookie case %q", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: agent-session duplicate cookie case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		class := classifyAgentSessionCookieBody(c.BodyJSON, knockCounter)
		outcome := AgentSessionOutcomeAccept
		if class != "" {
			outcome = AgentSessionOutcomeReject
		}
		if outcome != c.Outcome || class != c.RejectClass || c.Outcome != want.outcome || c.RejectClass != want.class {
			return fmt.Errorf("conformance: agent-session cookie case %q classified as (%q,%q), declared (%q,%q)", c.Name, outcome, class, c.Outcome, c.RejectClass)
		}
	}
	return nil
}

func validateAgentSessionFlowCases(cases []AgentSessionFlowCase) error {
	required := map[string]AgentSessionFlowCase{
		"accept_canonical":                      {Name: "accept_canonical", Stage: "flow", Mutation: "none", Outcome: AgentSessionOutcomeAccept},
		"accept_cok_wire_counter_unconstrained": {Name: "accept_cok_wire_counter_unconstrained", Stage: "cookie_reply", Mutation: "wire_counter_differs_from_knock", Outcome: AgentSessionOutcomeAccept},
		"reject_cok_body_transaction_mismatch":  {Name: "reject_cok_body_transaction_mismatch", Stage: "cookie_reply", Mutation: "body_trx_id_differs_from_knock", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectCounter},
		"reject_rkn_wire_type_knk":              {Name: "reject_rkn_wire_type_knk", Stage: "reknock_request", Mutation: "wire_type_1_body_type_8", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectHeaderType},
		"reject_rkn_body_type_knk":              {Name: "reject_rkn_body_type_knk", Stage: "reknock_request", Mutation: "wire_type_8_body_type_1", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectHeaderType},
		"reject_exit_wire_type_knk":             {Name: "reject_exit_wire_type_knk", Stage: "exit_request", Mutation: "wire_type_1_body_type_16", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectHeaderType},
		"reject_exit_body_type_knk":             {Name: "reject_exit_body_type_knk", Stage: "exit_request", Mutation: "wire_type_16_body_type_1", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectHeaderType},
		"reject_rkn_ack_type_cok":               {Name: "reject_rkn_ack_type_cok", Stage: "reknock_ack", Mutation: "reply_type_7", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectReplyType},
		"reject_exit_ack_type_cok":              {Name: "reject_exit_ack_type_cok", Stage: "exit_ack", Mutation: "reply_type_7", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectReplyType},
		"reject_rkn_ack_counter_mismatch":       {Name: "reject_rkn_ack_counter_mismatch", Stage: "reknock_ack", Mutation: "reply_counter_differs_from_rkn", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectCounter},
		"reject_exit_ack_counter_mismatch":      {Name: "reject_exit_ack_counter_mismatch", Stage: "exit_ack", Mutation: "reply_counter_differs_from_exit", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectCounter},
		"reject_rkn_wrong_cookie_digest":        {Name: "reject_rkn_wrong_cookie_digest", Stage: "reknock_request", Mutation: "digest_uses_different_cookie", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectHeaderDigest},
		"reject_rkn_tampered_digest":            {Name: "reject_rkn_tampered_digest", Stage: "reknock_request", Mutation: "header_digest_bit_flip", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectHeaderDigest},
		"reject_rkn_trailing_body":              {Name: "reject_rkn_trailing_body", Stage: "reknock_request", Mutation: "body_trailing_value", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectApplicationBody},
		"reject_exit_trailing_body":             {Name: "reject_exit_trailing_body", Stage: "exit_request", Mutation: "body_trailing_value", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectApplicationBody},
		"reject_rkn_changed_run_id":             {Name: "reject_rkn_changed_run_id", Stage: "reknock_request", Mutation: "run_id_differs_from_knock", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectApplicationBody},
		"reject_exit_changed_run_id":            {Name: "reject_exit_changed_run_id", Stage: "exit_request", Mutation: "run_id_differs_from_knock", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectApplicationBody},
		"reject_reply_wrong_server_key":         {Name: "reject_reply_wrong_server_key", Stage: "reply_authentication", Mutation: "decrypt_with_different_server_key", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectPeerAuthentication},
		"reject_request_wrong_agent_key":        {Name: "reject_request_wrong_agent_key", Stage: "request_authentication", Mutation: "open_with_different_agent_key", Outcome: AgentSessionOutcomeReject, RejectClass: AgentSessionRejectPeerAuthentication},
	}
	if len(cases) != len(required) {
		return fmt.Errorf("conformance: agent-session flow case count = %d, want %d", len(cases), len(required))
	}
	seen := make(map[string]struct{}, len(required))
	for _, c := range cases {
		want, ok := required[c.Name]
		if !ok || c != want {
			return fmt.Errorf("conformance: agent-session flow case %q fields drifted", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: agent-session duplicate flow case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
	}
	return nil
}
