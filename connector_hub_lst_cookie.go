package conformance

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
)

const (
	// ConnectorHubLSTCookieArtifactID identifies the Hub assignment
	// return-routability challenge contract.
	ConnectorHubLSTCookieArtifactID = "qurl-connector-hub-lst-cookie-v1-vectors"
	// ConnectorHubLSTCookieSchemaVersion is the only schema accepted by this
	// release.
	ConnectorHubLSTCookieSchemaVersion = 1

	ConnectorHubLSTCookieAlgorithm       = "HMAC-SHA-256"
	ConnectorHubLSTCookieDomain          = "nhp-connector-hub-lst-cookie-v1"
	ConnectorHubLSTCookieDomainSuffixHex = "00"
	ConnectorHubLSTCookieInputFraming    = "domain_then_00_then_u8_ip_family_then_u32be_length_framed_raw_ip_and_peer_then_u64be_window"
	ConnectorHubLSTCookieSigningKeyBytes = 32
	ConnectorHubLSTCookieBytes           = 32
	ConnectorHubLSTCookieEncoding        = "base64_std_padded_canonical"
	ConnectorHubLSTCookiePeerBytes       = 32
	ConnectorHubLSTCookieWindowSeconds   = 30

	ConnectorHubLSTCookieProofFlagName     = "NHP_FLAG_HUB_LST_COOKIE_PROOF"
	ConnectorHubLSTCookieProofFlagHex      = "0004"
	ConnectorHubLSTCookieProofFlag         = uint16(0x0004)
	ConnectorHubLSTCookieChallengeFlagsHex = "0000"
	ConnectorHubLSTProofKATPurpose         = "digest_primitive_with_fresh_proof_header_not_complete_encrypted_packet"
	connectorHubLSTProofExpectedDigest     = "7aaa44aaf8f8876973120c8870b761603b6125bbe5322bb7c242fc9ca502efe3"

	ConnectorHubLSTCookieHeaderBytes       = 240
	ConnectorHubLSTCookieBodyAEADTagBytes  = 16
	ConnectorHubLSTCookiePacketMaxBytes    = 4096
	ConnectorHubLSTCookiePacketOverhead    = ConnectorHubLSTCookieHeaderBytes + ConnectorHubLSTCookieBodyAEADTagBytes
	ConnectorHubLSTCookiePlaintextMaxBytes = ConnectorHubLSTCookiePacketMaxBytes - ConnectorHubLSTCookiePacketOverhead

	ConnectorHubLSTCookieOutcomeAccept  = "accept"
	ConnectorHubLSTCookieOutcomeReject  = "reject"
	ConnectorHubLSTCookieActionDrop     = "drop_silently"
	ConnectorHubLSTCookieActionSizeSafe = "challenge_size_eligible"
	ConnectorHubLSTCookieActionContinue = "continue_strict_request_validation"
	ConnectorHubLSTCookieClientProof    = "send_one_fresh_proof_lst"
	ConnectorHubLSTCookieClientStop     = "stop_without_third_lst_or_fallback"
)

var connectorHubLSTCookieRejects = map[string]struct {
	stage, mutation string
}{
	"unproven_header_or_framing_invalid": {"unproven_request", "invalid_nhp_header_or_packet_framing"},
	"unproven_static_decrypt_failed":     {"unproven_request", "initiator_static_key_decrypt_failed"},
	"unproven_body_aead_failed":          {"unproven_request", "application_body_aead_open_failed"},
	"proof_malformed_initial_body":       {"proof_request", "malformed_initial_assignment_body"},
	"proof_malformed_refresh_body":       {"proof_request", "malformed_refresh_assignment_body"},
	"proof_wrong_source_ip":              {"proof_request", "cookie_bound_to_different_source_ip"},
	"proof_wrong_peer":                   {"proof_request", "cookie_bound_to_different_authenticated_peer"},
	"proof_expired_window":               {"proof_request", "cookie_from_window_minus_2"},
	"proof_future_window":                {"proof_request", "cookie_from_window_plus_1"},
	"proof_wrong_flag":                   {"proof_request", "proof_flag_missing_or_combined_with_another_flag"},
	"proof_rkn_cookie_transplant":        {"proof_request", "cookie_from_nhp_overload_cookie_v1_domain"},
	"replayed_proof_packet":              {"proof_request", "exact_authenticated_packet_replay"},
	"proof_wrong_phase":                  {"proof_request", "proof_flag_on_non_assignment_lst"},
}

var connectorHubLSTCookieChallengeCases = map[string]struct {
	stage, mutation, flags, outcome, action string
}{
	"accept_initial_challenge":      {"challenge_reply", "none_initial", ConnectorHubLSTCookieChallengeFlagsHex, ConnectorHubLSTCookieOutcomeAccept, ConnectorHubLSTCookieClientProof},
	"accept_refresh_challenge":      {"challenge_reply", "none_refresh", ConnectorHubLSTCookieChallengeFlagsHex, ConnectorHubLSTCookieOutcomeAccept, ConnectorHubLSTCookieClientProof},
	"reject_malformed_body":         {"challenge_reply", "malformed_json", ConnectorHubLSTCookieChallengeFlagsHex, ConnectorHubLSTCookieOutcomeReject, ConnectorHubLSTCookieClientStop},
	"reject_unknown_field":          {"challenge_reply", "unknown_field", ConnectorHubLSTCookieChallengeFlagsHex, ConnectorHubLSTCookieOutcomeReject, ConnectorHubLSTCookieClientStop},
	"reject_duplicate_field":        {"challenge_reply", "duplicate_trx_id", ConnectorHubLSTCookieChallengeFlagsHex, ConnectorHubLSTCookieOutcomeReject, ConnectorHubLSTCookieClientStop},
	"reject_wrong_transaction":      {"challenge_reply", "trx_id_not_equal_unproven_lst_counter", ConnectorHubLSTCookieChallengeFlagsHex, ConnectorHubLSTCookieOutcomeReject, ConnectorHubLSTCookieClientStop},
	"reject_cookie_encoding":        {"challenge_reply", "cookie_not_canonical_padded_base64", ConnectorHubLSTCookieChallengeFlagsHex, ConnectorHubLSTCookieOutcomeReject, ConnectorHubLSTCookieClientStop},
	"reject_cookie_length":          {"challenge_reply", "decoded_cookie_not_32_bytes", ConnectorHubLSTCookieChallengeFlagsHex, ConnectorHubLSTCookieOutcomeReject, ConnectorHubLSTCookieClientStop},
	"reject_untrusted_server":       {"challenge_reply", "cok_not_authenticated_by_pinned_hub_key", ConnectorHubLSTCookieChallengeFlagsHex, ConnectorHubLSTCookieOutcomeReject, ConnectorHubLSTCookieClientStop},
	"reject_compressed_challenge":   {"challenge_reply", "compress_flag_set", "0002", ConnectorHubLSTCookieOutcomeReject, ConnectorHubLSTCookieClientStop},
	"reject_unknown_flag_challenge": {"challenge_reply", "unknown_flag_set", "0008", ConnectorHubLSTCookieOutcomeReject, ConnectorHubLSTCookieClientStop},
	"reject_second_challenge":       {"proof_reply", "authenticated_cok_after_proof_lst", ConnectorHubLSTCookieChallengeFlagsHex, ConnectorHubLSTCookieOutcomeReject, ConnectorHubLSTCookieClientStop},
}

// ConnectorHubLSTCookieFile freezes the strict challenge/proof contract that
// must complete before a public Hub invokes Connector Authority.
type ConnectorHubLSTCookieFile struct {
	Artifact       string                              `json:"artifact"`
	SchemaVersion  int                                 `json:"schema_version"`
	Description    string                              `json:"description"`
	SourceOfTruth  string                              `json:"source_of_truth"`
	Contract       ConnectorHubLSTCookieContract       `json:"contract"`
	CookieKATs     []ConnectorHubLSTCookieKAT          `json:"cookie_kats"`
	ProofDigestKAT ConnectorHubLSTProofDigestKAT       `json:"proof_digest_kat"`
	Flows          []ConnectorHubLSTCookieFlow         `json:"flows"`
	SizeCases      []ConnectorHubLSTCookieSizeCase     `json:"size_cases"`
	SuccessSizes   []ConnectorHubAssignmentSuccessSize `json:"assignment_success_sizes"`
	KeyCases       []ConnectorHubLSTCookieKeyCase      `json:"key_cases"`
	RejectCases    []ConnectorHubLSTCookieRejectCase   `json:"reject_cases"`
	ChallengeCases []ConnectorHubLSTChallengeBodyCase  `json:"challenge_cases"`
}

// ConnectorHubLSTCookieContract is the closed protocol and size profile.
type ConnectorHubLSTCookieContract struct {
	CookieAlgorithm               string   `json:"cookie_algorithm"`
	CookieDomainASCII             string   `json:"cookie_domain_ascii"`
	CookieDomainSuffixHex         string   `json:"cookie_domain_suffix_hex"`
	CookieInputFraming            string   `json:"cookie_input_framing"`
	SigningKeyBytes               int      `json:"signing_key_bytes"`
	CookieBytes                   int      `json:"cookie_bytes"`
	CookieEncoding                string   `json:"cookie_encoding"`
	SourceIPEncoding              string   `json:"source_ip_encoding"`
	SourcePortBound               bool     `json:"source_port_bound"`
	AuthenticatedPeerBytes        int      `json:"authenticated_peer_bytes"`
	WindowSeconds                 int      `json:"window_seconds"`
	AcceptedWindowOffsets         []int    `json:"accepted_window_offsets"`
	FutureWindowAccepted          bool     `json:"future_window_accepted"`
	SigningKeySlots               int      `json:"signing_key_slots"`
	ActiveSigningKeyRequired      bool     `json:"active_signing_key_required"`
	PreviousSigningKeyOptional    bool     `json:"previous_signing_key_optional"`
	MintKeySlot                   string   `json:"mint_key_slot"`
	VerifyKeyWindowOrder          []string `json:"verify_key_window_order"`
	CookieKeyIDOnWire             bool     `json:"cookie_key_id_on_wire"`
	RequestHeaderName             string   `json:"request_header_name"`
	RequestHeaderType             int      `json:"request_header_type"`
	ChallengeHeaderName           string   `json:"challenge_header_name"`
	ChallengeHeaderType           int      `json:"challenge_header_type"`
	ChallengeCompressed           bool     `json:"challenge_compressed"`
	ChallengeHeaderFlagsHex       string   `json:"challenge_header_flags_hex"`
	ChallengeSizeRule             string   `json:"challenge_size_rule"`
	SuccessHeaderName             string   `json:"success_header_name"`
	SuccessHeaderType             int      `json:"success_header_type"`
	UnprovenHeaderFlagsHex        string   `json:"unproven_header_flags_hex"`
	ProofFlagName                 string   `json:"proof_flag_name"`
	ProofFlagHex                  string   `json:"proof_flag_hex"`
	ProofFlagExclusive            bool     `json:"proof_flag_exclusive"`
	ProofHeaderDigest             string   `json:"proof_header_digest"`
	ProofCookieDigestInput        string   `json:"proof_cookie_digest_input"`
	ProofHeaderFreshnessRule      string   `json:"proof_header_freshness_rule"`
	ProofBodyRule                 string   `json:"proof_body_rule"`
	ProofRequestNonceRule         string   `json:"proof_request_nonce_rule"`
	ProofResendLimit              int      `json:"proof_resend_limit"`
	SecondChallengeAction         string   `json:"second_challenge_action"`
	AuthorityBeforeProofAllowed   bool     `json:"authority_before_proof_allowed"`
	HTTPFallbackAllowed           bool     `json:"http_fallback_allowed"`
	RequestPaddingFallbackAllowed bool     `json:"request_padding_fallback_allowed"`
	AdditiveApplicationProfiles   []string `json:"additive_application_profiles"`
	CurveHeaderBytes              int      `json:"curve_header_bytes"`
	BodyAEADTagBytes              int      `json:"body_aead_tag_bytes"`
	EmptyBodyPacketBytes          int      `json:"empty_body_packet_bytes"`
	NonemptyPacketOverheadBytes   int      `json:"nonempty_packet_overhead_bytes"`
	MaxPlaintextBodyBytes         int      `json:"max_plaintext_body_bytes"`
	MaxPacketBytes                int      `json:"max_packet_bytes"`
	ChallengeMaxTransactionID     string   `json:"challenge_max_transaction_id"`
	ChallengeMaxBodyJSON          string   `json:"challenge_max_body_json"`
	ChallengeMaxBodyBytes         int      `json:"challenge_max_body_bytes"`
	ChallengeMaxPacketBytes       int      `json:"challenge_max_packet_bytes"`
}

// ConnectorHubLSTCookieKAT is one exact HMAC derivation. The signing key is
// synthetic and exists only to make the contract independently executable.
type ConnectorHubLSTCookieKAT struct {
	Name                          string `json:"name"`
	SigningKeyHex                 string `json:"signing_key_hex"`
	SourceIP                      string `json:"source_ip"`
	AuthenticatedPeerPublicKeyB64 string `json:"authenticated_peer_public_key_b64"`
	WindowIndex                   string `json:"window_index"`
	PreimageHex                   string `json:"preimage_hex"`
	CookieHex                     string `json:"cookie_hex"`
	CookieB64                     string `json:"cookie_b64"`
	EqualTo                       string `json:"equal_to,omitempty"`
}

// ConnectorHubLSTProofDigestKAT freezes an executable digest over a fresh
// deterministic Curve header prefix and the opaque Hub cookie. It is a digest
// primitive, not a complete encrypted packet; flow fixtures separately pin
// the byte-identical body and request nonce. Cryptographic consumers recompute
// ExpectedDigestHex with BLAKE2s-256.
type ConnectorHubLSTProofDigestKAT struct {
	Purpose                     string `json:"purpose"`
	InitialHashHex              string `json:"initial_hash_hex"`
	HubServerStaticPublicKeyHex string `json:"hub_server_static_public_key_hex"`
	HeaderPrefixHex             string `json:"header_prefix_hex"`
	HeaderType                  int    `json:"header_type"`
	HeaderFlagsHex              string `json:"header_flags_hex"`
	Counter                     string `json:"counter"`
	TimestampNanos              string `json:"timestamp_nanos"`
	EphemeralPublicKeyHex       string `json:"ephemeral_public_key_hex"`
	RawCookieHex                string `json:"raw_cookie_hex"`
	ExpectedDigestHex           string `json:"expected_digest_hex"`
}

// ConnectorHubLSTCookieFlow freezes one initial or refresh
// LST/COK/LST/LRT sequence. The proof body is duplicated intentionally so a
// consumer can compare the exact authenticated bytes, not reconstructed JSON.
type ConnectorHubLSTCookieFlow struct {
	Phase                                    string `json:"phase"`
	UnprovenCounter                          string `json:"unproven_counter"`
	ProofCounter                             string `json:"proof_counter"`
	UnprovenBodyJSON                         string `json:"unproven_body_json"`
	ProofBodyJSON                            string `json:"proof_body_json"`
	RequestNonce                             string `json:"request_nonce"`
	UnprovenHeaderFlagsHex                   string `json:"unproven_header_flags_hex"`
	ProofHeaderFlagsHex                      string `json:"proof_header_flags_hex"`
	UnprovenRequestPacketBytes               int    `json:"unproven_request_packet_bytes"`
	ChallengeBodyJSON                        string `json:"challenge_body_json"`
	ChallengeBodyBytes                       int    `json:"challenge_body_bytes"`
	ChallengePacketBytes                     int    `json:"challenge_packet_bytes"`
	ProofRequestPacketBytes                  int    `json:"proof_request_packet_bytes"`
	LegacyAssignmentFixtureResultPacketBytes int    `json:"legacy_assignment_fixture_result_packet_bytes"`
	AuthorityInvocationsBeforeProof          int    `json:"authority_invocations_before_proof"`
	AuthorityInvocationsAfterProof           int    `json:"authority_invocations_after_proof"`
}

// ConnectorHubLSTCookieRejectCase is a server-side fail-closed mutation. All
// cases are deliberately silent and stop before Connector Authority.
type ConnectorHubLSTCookieRejectCase struct {
	Name                 string `json:"name"`
	Stage                string `json:"stage"`
	Mutation             string `json:"mutation"`
	Outcome              string `json:"outcome"`
	ServerAction         string `json:"server_action"`
	AuthorityInvocations int    `json:"authority_invocations"`
}

// ConnectorHubLSTCookieSizeCase drives the pre-challenge amplification gate
// with cryptographically valid NHP framing. The application body remains
// opaque until cookie proof succeeds; passing this gate only permits COK.
type ConnectorHubLSTCookieSizeCase struct {
	Name                      string `json:"name"`
	CryptoValidNHPFraming     bool   `json:"crypto_valid_nhp_framing"`
	ApplicationBodyClass      string `json:"application_body_class"`
	ChallengeTransactionID    string `json:"challenge_transaction_id"`
	RequestPlaintextBodyBytes int    `json:"request_plaintext_body_bytes"`
	ReceivedLSTPacketBytes    int    `json:"received_lst_packet_bytes"`
	CandidateCOKPacketBytes   int    `json:"candidate_cok_packet_bytes"`
	SizeGateAction            string `json:"size_gate_action"`
}

// ConnectorHubAssignmentSuccessSize cross-links the return-routability request
// to real assignment-success envelopes. Ratios are exact byte fractions rather
// than rounded decimal claims.
type ConnectorHubAssignmentSuccessSize struct {
	Name                               string `json:"name"`
	Phase                              string `json:"phase"`
	Basis                              string `json:"basis"`
	RequestPacketBytes                 int    `json:"request_packet_bytes"`
	ResultBodyBytes                    int    `json:"result_body_bytes"`
	ResultPacketBytes                  int    `json:"result_packet_bytes"`
	AmplificationNumeratorBytes        int    `json:"amplification_numerator_bytes"`
	AmplificationDenominatorBytes      int    `json:"amplification_denominator_bytes"`
	LegacyAssignmentFixturePacketBytes int    `json:"legacy_assignment_fixture_packet_bytes,omitempty"`
}

// ConnectorHubLSTCookieKeyCase freezes rolling-key overlap without exposing a
// key identifier on the public wire.
type ConnectorHubLSTCookieKeyCase struct {
	Name               string `json:"name"`
	ActiveKeyPresent   bool   `json:"active_key_present"`
	PreviousKeyPresent bool   `json:"previous_key_present"`
	CookieKeySlot      string `json:"cookie_key_slot"`
	WindowOffset       int    `json:"window_offset"`
	Outcome            string `json:"outcome"`
	ServerAction       string `json:"server_action"`
}

// ConnectorHubLSTChallengeBodyCase drives the SDK's strict authenticated COK
// parser and its one-proof-flight state machine.
type ConnectorHubLSTChallengeBodyCase struct {
	Name           string `json:"name"`
	Stage          string `json:"stage"`
	Mutation       string `json:"mutation"`
	HeaderFlagsHex string `json:"header_flags_hex"`
	BodyJSON       string `json:"body_json,omitempty"`
	Outcome        string `json:"outcome"`
	ClientAction   string `json:"client_action"`
}

type connectorHubLSTChallengeBody struct {
	TransactionID uint64 `json:"trxId"`
	Cookie        string `json:"cookie"`
}

// DeriveConnectorHubLSTCookie derives the opaque stateless Hub-LST cookie from
// a canonical source IP, authenticated initiator key, and rolling window.
func DeriveConnectorHubLSTCookie(signingKey []byte, sourceIP string, authenticatedPeerPublicKey []byte, windowIndex uint64) ([]byte, error) {
	preimage, err := connectorHubLSTCookiePreimage(sourceIP, authenticatedPeerPublicKey, windowIndex)
	if err != nil {
		return nil, err
	}
	if len(signingKey) != ConnectorHubLSTCookieSigningKeyBytes {
		return nil, errors.New("conformance: Connector Hub LST cookie signing key must be exactly 32 bytes")
	}
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write(preimage)
	return mac.Sum(nil), nil
}

func connectorHubLSTCookiePreimage(sourceIP string, authenticatedPeerPublicKey []byte, windowIndex uint64) ([]byte, error) {
	addr, err := netip.ParseAddr(sourceIP)
	if err != nil || addr.Zone() != "" {
		return nil, errors.New("conformance: Connector Hub LST cookie source IP is invalid")
	}
	addr = addr.Unmap()
	rawIP := addr.AsSlice()
	familyTag := byte(0x06)
	if addr.Is4() {
		familyTag = 0x04
	}
	if len(authenticatedPeerPublicKey) != ConnectorHubLSTCookiePeerBytes {
		return nil, errors.New("conformance: Connector Hub LST cookie peer key must be exactly 32 bytes")
	}

	preimage := make([]byte, 0, len(ConnectorHubLSTCookieDomain)+1+1+4+len(rawIP)+4+len(authenticatedPeerPublicKey)+8)
	preimage = append(preimage, ConnectorHubLSTCookieDomain...)
	preimage = append(preimage, 0)
	preimage = append(preimage, familyTag)
	var frame [8]byte
	binary.BigEndian.PutUint32(frame[:4], uint32(len(rawIP)))
	preimage = append(preimage, frame[:4]...)
	preimage = append(preimage, rawIP...)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(authenticatedPeerPublicKey)))
	preimage = append(preimage, frame[:4]...)
	preimage = append(preimage, authenticatedPeerPublicKey...)
	binary.BigEndian.PutUint64(frame[:], windowIndex)
	return append(preimage, frame[:]...), nil
}

// ConnectorHubLSTChallengeBody returns the exact compact COK JSON envelope.
func ConnectorHubLSTChallengeBody(transactionID uint64, cookie []byte) (string, error) {
	if len(cookie) != ConnectorHubLSTCookieBytes {
		return "", errors.New("conformance: Connector Hub LST cookie must be exactly 32 bytes")
	}
	return `{"trxId":` + strconv.FormatUint(transactionID, 10) + `,"cookie":"` + base64.StdEncoding.EncodeToString(cookie) + `"}`, nil
}

// ParseConnectorHubLSTCookieFile strictly parses and independently validates
// every derivation, size bound, assignment linkage, and closed disposition.
func ParseConnectorHubLSTCookieFile(data []byte) (*ConnectorHubLSTCookieFile, error) {
	var file ConnectorHubLSTCookieFile
	if err := strictDecodeArtifact(data, &file); err != nil {
		return nil, fmt.Errorf("conformance: parse Connector Hub LST cookie file: %w", err)
	}
	if file.Artifact != ConnectorHubLSTCookieArtifactID || file.SchemaVersion != ConnectorHubLSTCookieSchemaVersion ||
		strings.TrimSpace(file.Description) == "" || strings.TrimSpace(file.SourceOfTruth) == "" {
		return nil, errors.New("conformance: Connector Hub LST cookie artifact identity is invalid")
	}
	if err := validateConnectorHubLSTCookieContract(file.Contract); err != nil {
		return nil, err
	}
	if err := validateConnectorHubLSTCookieKATs(file.CookieKATs); err != nil {
		return nil, err
	}
	assignment, err := AgentAssignmentGolden()
	if err != nil {
		return nil, fmt.Errorf("conformance: load Connector Hub assignment linkage: %w", err)
	}
	ticket, err := AssignmentTicket()
	if err != nil {
		return nil, fmt.Errorf("conformance: load Connector Hub ticket linkage: %w", err)
	}
	if err := validateConnectorHubLSTProofDigestKAT(file.ProofDigestKAT, file.CookieKATs, assignment); err != nil {
		return nil, err
	}
	if err := validateConnectorHubLSTCookieFlows(file.Flows, file.CookieKATs[0], assignment); err != nil {
		return nil, err
	}
	if err := validateConnectorHubLSTCookieSizes(file.SizeCases, file.Contract); err != nil {
		return nil, err
	}
	if err := validateConnectorHubAssignmentSuccessSizes(file.SuccessSizes, assignment, ticket); err != nil {
		return nil, err
	}
	if err := validateConnectorHubLSTCookieKeyCases(file.KeyCases); err != nil {
		return nil, err
	}
	if err := validateConnectorHubLSTCookieRejects(file.RejectCases); err != nil {
		return nil, err
	}
	if err := validateConnectorHubLSTCookieChallenges(file.ChallengeCases, file.Flows); err != nil {
		return nil, err
	}
	return &file, nil
}

func validateConnectorHubLSTCookieContract(contract ConnectorHubLSTCookieContract) error {
	maxCookie := bytes.Repeat([]byte{0}, ConnectorHubLSTCookieBytes)
	maxBody, _ := ConnectorHubLSTChallengeBody(^uint64(0), maxCookie)
	want := ConnectorHubLSTCookieContract{
		CookieAlgorithm: ConnectorHubLSTCookieAlgorithm, CookieDomainASCII: ConnectorHubLSTCookieDomain,
		CookieDomainSuffixHex: ConnectorHubLSTCookieDomainSuffixHex, CookieInputFraming: ConnectorHubLSTCookieInputFraming,
		SigningKeyBytes: ConnectorHubLSTCookieSigningKeyBytes, CookieBytes: ConnectorHubLSTCookieBytes,
		CookieEncoding: ConnectorHubLSTCookieEncoding, SourceIPEncoding: "netip_unmap_then_u8_family_04_or_06_then_u32be_raw_length_then_raw_bytes", SourcePortBound: false,
		AuthenticatedPeerBytes: ConnectorHubLSTCookiePeerBytes, WindowSeconds: ConnectorHubLSTCookieWindowSeconds,
		AcceptedWindowOffsets: []int{0, -1}, FutureWindowAccepted: false,
		SigningKeySlots: 2, ActiveSigningKeyRequired: true, PreviousSigningKeyOptional: true,
		MintKeySlot: "active_only", VerifyKeyWindowOrder: []string{"active_current", "active_previous_window", "previous_current", "previous_previous_window"},
		CookieKeyIDOnWire: false,
		RequestHeaderName: AgentAssignmentRequestHeaderName, RequestHeaderType: AgentAssignmentRequestHeaderType,
		ChallengeHeaderName: "NHP_COK", ChallengeHeaderType: 7, ChallengeCompressed: false,
		ChallengeHeaderFlagsHex: ConnectorHubLSTCookieChallengeFlagsHex,
		ChallengeSizeRule:       "sealed_cok_packet_bytes_strictly_less_than_received_lst_packet_bytes",
		SuccessHeaderName:       AgentAssignmentResultHeaderName, SuccessHeaderType: AgentAssignmentResultHeaderType,
		UnprovenHeaderFlagsHex: "0000", ProofFlagName: ConnectorHubLSTCookieProofFlagName,
		ProofFlagHex: ConnectorHubLSTCookieProofFlagHex, ProofFlagExclusive: true,
		ProofHeaderDigest:      "BLAKE2s-256(initial_hash || hub_server_static_public_key || header[0:208] || raw_cookie)",
		ProofCookieDigestInput: "raw_32_bytes", ProofHeaderFreshnessRule: "fresh_ephemeral_timestamp_and_counter",
		ProofBodyRule:         "byte_identical_to_unproven_authenticated_body",
		ProofRequestNonceRule: "same_request_nonce_inside_identical_body", ProofResendLimit: 1,
		SecondChallengeAction: ConnectorHubLSTCookieClientStop, AuthorityBeforeProofAllowed: false,
		HTTPFallbackAllowed: false, RequestPaddingFallbackAllowed: false,
		AdditiveApplicationProfiles: []string{"qurl-agent-credential-recovery-v1-vectors/hub_cookie_composition"},
		CurveHeaderBytes:            ConnectorHubLSTCookieHeaderBytes, BodyAEADTagBytes: ConnectorHubLSTCookieBodyAEADTagBytes,
		EmptyBodyPacketBytes: ConnectorHubLSTCookieHeaderBytes, NonemptyPacketOverheadBytes: ConnectorHubLSTCookiePacketOverhead,
		MaxPlaintextBodyBytes: ConnectorHubLSTCookiePlaintextMaxBytes,
		MaxPacketBytes:        ConnectorHubLSTCookiePacketMaxBytes, ChallengeMaxTransactionID: strconv.FormatUint(^uint64(0), 10),
		ChallengeMaxBodyJSON: maxBody, ChallengeMaxBodyBytes: len(maxBody), ChallengeMaxPacketBytes: len(maxBody) + ConnectorHubLSTCookiePacketOverhead,
	}
	if !reflect.DeepEqual(contract, want) {
		return errors.New("conformance: Connector Hub LST cookie contract drift")
	}
	return nil
}

func validateConnectorHubLSTCookieKATs(kats []ConnectorHubLSTCookieKAT) error {
	want := map[string]string{
		"ipv4":        "",
		"ipv4_mapped": "ipv4",
		"ipv6":        "",
	}
	if len(kats) != len(want) {
		return fmt.Errorf("conformance: Connector Hub LST cookie KAT count = %d, want %d", len(kats), len(want))
	}
	seen := make(map[string]ConnectorHubLSTCookieKAT, len(kats))
	for _, kat := range kats {
		equalTo, ok := want[kat.Name]
		if !ok || kat.EqualTo != equalTo {
			return fmt.Errorf("conformance: Connector Hub LST cookie KAT %q identity drift", kat.Name)
		}
		if _, duplicate := seen[kat.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector Hub LST cookie KAT %q", kat.Name)
		}
		key, err := hex.DecodeString(kat.SigningKeyHex)
		if err != nil || hex.EncodeToString(key) != kat.SigningKeyHex || len(key) != ConnectorHubLSTCookieSigningKeyBytes {
			return fmt.Errorf("conformance: Connector Hub LST cookie KAT %q signing key is invalid", kat.Name)
		}
		peer, err := base64.StdEncoding.Strict().DecodeString(kat.AuthenticatedPeerPublicKeyB64)
		if err != nil || base64.StdEncoding.EncodeToString(peer) != kat.AuthenticatedPeerPublicKeyB64 || len(peer) != ConnectorHubLSTCookiePeerBytes {
			return fmt.Errorf("conformance: Connector Hub LST cookie KAT %q peer key is invalid", kat.Name)
		}
		window, err := strconv.ParseUint(kat.WindowIndex, 10, 64)
		if err != nil || window == 0 || strconv.FormatUint(window, 10) != kat.WindowIndex {
			return fmt.Errorf("conformance: Connector Hub LST cookie KAT %q window is invalid", kat.Name)
		}
		preimage, err := connectorHubLSTCookiePreimage(kat.SourceIP, peer, window)
		if err != nil || hex.EncodeToString(preimage) != kat.PreimageHex {
			return fmt.Errorf("conformance: Connector Hub LST cookie KAT %q preimage drift", kat.Name)
		}
		cookie, err := DeriveConnectorHubLSTCookie(key, kat.SourceIP, peer, window)
		if err != nil || hex.EncodeToString(cookie) != kat.CookieHex || base64.StdEncoding.EncodeToString(cookie) != kat.CookieB64 {
			return fmt.Errorf("conformance: Connector Hub LST cookie KAT %q output drift", kat.Name)
		}
		seen[kat.Name] = kat
	}
	if mapped, ipv4 := seen["ipv4_mapped"], seen["ipv4"]; mapped.PreimageHex != ipv4.PreimageHex || mapped.CookieHex != ipv4.CookieHex || mapped.CookieB64 != ipv4.CookieB64 {
		return errors.New("conformance: IPv4-mapped Connector Hub LST cookie KAT does not normalize to IPv4")
	}
	if ipv6, ipv4 := seen["ipv6"], seen["ipv4"]; ipv6.PreimageHex == ipv4.PreimageHex || ipv6.CookieHex == ipv4.CookieHex {
		return errors.New("conformance: IPv6 Connector Hub LST cookie KAT is not domain-separated by address family")
	}
	return nil
}

func validateConnectorHubLSTProofDigestKAT(kat ConnectorHubLSTProofDigestKAT, cookieKATs []ConnectorHubLSTCookieKAT, assignment *AgentAssignmentFile) error {
	initialHash := []byte("NHP hashgen v.20230421@deepcloudsdp.com")
	hubKey, err := hex.DecodeString(kat.HubServerStaticPublicKeyHex)
	if err != nil || hex.EncodeToString(hubKey) != kat.HubServerStaticPublicKeyHex || len(hubKey) != 32 ||
		kat.HubServerStaticPublicKeyHex != assignment.Keys.Hub.StaticPubHex {
		return errors.New("conformance: Connector Hub LST proof-digest Hub key is invalid")
	}
	initialPacket, err := hex.DecodeString(assignment.InitialAssignment.Request.PacketHex)
	if err != nil || len(initialPacket) < 208 {
		return errors.New("conformance: Connector Hub LST proof-digest linked request is invalid")
	}
	refreshPacket, err := hex.DecodeString(assignment.RefreshAssignment.Request.PacketHex)
	if err != nil || len(refreshPacket) < 208 {
		return errors.New("conformance: Connector Hub LST proof-digest fresh-header source is invalid")
	}
	wantPrefix := bytes.Clone(refreshPacket[:208])
	binary.BigEndian.PutUint16(wantPrefix[10:12], ConnectorHubLSTCookieProofFlag)
	binary.BigEndian.PutUint64(wantPrefix[16:24], 23)
	prefix, err := hex.DecodeString(kat.HeaderPrefixHex)
	if err != nil || len(prefix) != 208 || hex.EncodeToString(prefix) != kat.HeaderPrefixHex || !bytes.Equal(prefix, wantPrefix) {
		return errors.New("conformance: Connector Hub LST proof-digest header prefix drift")
	}
	counter, err := strconv.ParseUint(kat.Counter, 10, 64)
	if err != nil || strconv.FormatUint(counter, 10) != kat.Counter {
		return errors.New("conformance: Connector Hub LST proof-digest counter is invalid")
	}
	word := binary.BigEndian.Uint32(prefix[0:4]) ^ binary.BigEndian.Uint32(prefix[4:8])
	if kat.Purpose != ConnectorHubLSTProofKATPurpose || kat.InitialHashHex != hex.EncodeToString(initialHash) ||
		kat.HeaderType != AgentAssignmentRequestHeaderType ||
		int(word>>16) != kat.HeaderType || kat.HeaderFlagsHex != ConnectorHubLSTCookieProofFlagHex ||
		binary.BigEndian.Uint16(prefix[10:12]) != ConnectorHubLSTCookieProofFlag || kat.Counter != "23" ||
		binary.BigEndian.Uint64(prefix[16:24]) != counter || kat.TimestampNanos != assignment.RefreshAssignment.Request.TimestampNanos ||
		kat.EphemeralPublicKeyHex != hex.EncodeToString(prefix[24:56]) {
		return errors.New("conformance: Connector Hub LST proof-digest typed header fields drift")
	}
	if kat.TimestampNanos == assignment.InitialAssignment.Request.TimestampNanos ||
		binary.BigEndian.Uint64(prefix[16:24]) == binary.BigEndian.Uint64(initialPacket[16:24]) ||
		bytes.Equal(prefix[24:56], initialPacket[24:56]) {
		return errors.New("conformance: Connector Hub LST proof-digest header is not fresh")
	}
	if len(cookieKATs) == 0 || kat.RawCookieHex != cookieKATs[0].CookieHex {
		return errors.New("conformance: Connector Hub LST proof-digest cookie linkage drift")
	}
	if kat.ExpectedDigestHex != connectorHubLSTProofExpectedDigest {
		return errors.New("conformance: Connector Hub LST proof-digest output drift")
	}
	for name, check := range map[string]struct {
		value string
		bytes int
	}{
		"initial hash":    {kat.InitialHashHex, len(initialHash)},
		"cookie":          {kat.RawCookieHex, ConnectorHubLSTCookieBytes},
		"expected digest": {kat.ExpectedDigestHex, 32},
	} {
		decoded, err := hex.DecodeString(check.value)
		if err != nil || hex.EncodeToString(decoded) != check.value || len(decoded) != check.bytes {
			return fmt.Errorf("conformance: Connector Hub LST proof-digest %s is invalid", name)
		}
	}
	return nil
}

func validateConnectorHubLSTCookieFlows(flows []ConnectorHubLSTCookieFlow, kat ConnectorHubLSTCookieKAT, assignment *AgentAssignmentFile) error {
	if len(flows) != 2 {
		return fmt.Errorf("conformance: Connector Hub LST cookie flow count = %d, want 2", len(flows))
	}
	want := map[string]struct {
		exchange AgentAssignmentExchange
		nonce    string
	}{
		"initial_assignment": {assignment.InitialAssignment, AgentAssignmentInitialRequestNonceFixture},
		"refresh_assignment": {assignment.RefreshAssignment, AgentAssignmentRefreshRequestNonceFixture},
	}
	cookie, _ := base64.StdEncoding.Strict().DecodeString(kat.CookieB64)
	seen := make(map[string]struct{}, len(flows))
	for _, flow := range flows {
		expected, ok := want[flow.Phase]
		if !ok {
			return fmt.Errorf("conformance: Connector Hub LST cookie unknown flow phase %q", flow.Phase)
		}
		if _, duplicate := seen[flow.Phase]; duplicate {
			return fmt.Errorf("conformance: Connector Hub LST cookie duplicate flow phase %q", flow.Phase)
		}
		seen[flow.Phase] = struct{}{}
		unprovenCounter, err := strconv.ParseUint(flow.UnprovenCounter, 10, 64)
		if err != nil || strconv.FormatUint(unprovenCounter, 10) != flow.UnprovenCounter || flow.UnprovenCounter != expected.exchange.Request.Counter {
			return fmt.Errorf("conformance: Connector Hub LST cookie %s unproven counter drift", flow.Phase)
		}
		proofCounter, err := strconv.ParseUint(flow.ProofCounter, 10, 64)
		if err != nil || proofCounter == unprovenCounter || strconv.FormatUint(proofCounter, 10) != flow.ProofCounter {
			return fmt.Errorf("conformance: Connector Hub LST cookie %s proof counter is not fresh", flow.Phase)
		}
		challengeBody, _ := ConnectorHubLSTChallengeBody(unprovenCounter, cookie)
		requestPacketBytes := len(expected.exchange.Request.PacketHex) / 2
		legacyResultPacketBytes := len(expected.exchange.Result.PacketHex) / 2
		if flow.UnprovenBodyJSON != expected.exchange.Request.BodyJSON || flow.ProofBodyJSON != flow.UnprovenBodyJSON ||
			flow.RequestNonce != expected.nonce || flow.UnprovenHeaderFlagsHex != "0000" ||
			flow.ProofHeaderFlagsHex != ConnectorHubLSTCookieProofFlagHex || flow.UnprovenRequestPacketBytes != requestPacketBytes ||
			flow.ProofRequestPacketBytes != requestPacketBytes || flow.LegacyAssignmentFixtureResultPacketBytes != legacyResultPacketBytes ||
			flow.ChallengeBodyJSON != challengeBody || flow.ChallengeBodyBytes != len(challengeBody) ||
			flow.ChallengePacketBytes != len(challengeBody)+ConnectorHubLSTCookiePacketOverhead ||
			flow.ChallengePacketBytes >= flow.UnprovenRequestPacketBytes ||
			flow.AuthorityInvocationsBeforeProof != 0 || flow.AuthorityInvocationsAfterProof != 1 {
			return fmt.Errorf("conformance: Connector Hub LST cookie %s flow drift", flow.Phase)
		}
	}
	return nil
}

func validateConnectorHubLSTCookieSizes(cases []ConnectorHubLSTCookieSizeCase, contract ConnectorHubLSTCookieContract) error {
	want := map[string]struct {
		bodyClass     string
		body, request int
		action        string
	}{
		"drop_crypto_valid_empty_body":                  {"empty", 0, ConnectorHubLSTCookieHeaderBytes, ConnectorHubLSTCookieActionDrop},
		"drop_crypto_valid_smaller_request":             {"opaque_fill_85", 85, ConnectorHubLSTCookiePacketOverhead + 85, ConnectorHubLSTCookieActionDrop},
		"drop_crypto_valid_equal_size":                  {"opaque_fill_86", 86, ConnectorHubLSTCookiePacketOverhead + 86, ConnectorHubLSTCookieActionDrop},
		"allow_crypto_valid_malformed_application_size": {"malformed_json_87", 87, ConnectorHubLSTCookiePacketOverhead + 87, ConnectorHubLSTCookieActionSizeSafe},
		"allow_real_refresh_size":                       {"refresh_assignment", 181, ConnectorHubLSTCookiePacketOverhead + 181, ConnectorHubLSTCookieActionSizeSafe},
		"allow_real_initial_size":                       {"initial_assignment", 237, ConnectorHubLSTCookiePacketOverhead + 237, ConnectorHubLSTCookieActionSizeSafe},
	}
	if len(cases) != len(want) {
		return fmt.Errorf("conformance: Connector Hub LST cookie size count = %d, want %d", len(cases), len(want))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		expected, ok := want[c.Name]
		transactionID, err := strconv.ParseUint(c.ChallengeTransactionID, 10, 64)
		challengeBody, challengeErr := ConnectorHubLSTChallengeBody(transactionID, make([]byte, ConnectorHubLSTCookieBytes))
		if !ok || err != nil || strconv.FormatUint(transactionID, 10) != c.ChallengeTransactionID ||
			c.ChallengeTransactionID != contract.ChallengeMaxTransactionID || challengeErr != nil ||
			!c.CryptoValidNHPFraming || c.ApplicationBodyClass != expected.bodyClass || c.RequestPlaintextBodyBytes != expected.body ||
			c.ReceivedLSTPacketBytes != expected.request || c.CandidateCOKPacketBytes != contract.ChallengeMaxPacketBytes ||
			c.CandidateCOKPacketBytes != len(challengeBody)+ConnectorHubLSTCookiePacketOverhead || c.SizeGateAction != expected.action {
			return fmt.Errorf("conformance: Connector Hub LST cookie size case %q drift", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector Hub LST cookie size case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		allowed := c.CandidateCOKPacketBytes < c.ReceivedLSTPacketBytes
		if allowed != (c.SizeGateAction == ConnectorHubLSTCookieActionSizeSafe) {
			return fmt.Errorf("conformance: Connector Hub LST cookie size case %q violates strict-less-than rule", c.Name)
		}
	}
	return nil
}

func validateConnectorHubAssignmentSuccessSizes(cases []ConnectorHubAssignmentSuccessSize, assignment *AgentAssignmentFile, ticket *AssignmentTicketFile) error {
	initialRequestBytes := len(assignment.InitialAssignment.Request.PacketHex) / 2
	refreshRequestBytes := len(assignment.RefreshAssignment.Request.PacketHex) / 2
	refreshBodyBytes := len(assignment.RefreshAssignment.Result.BodyJSON)
	refreshPacketBytes := len(assignment.RefreshAssignment.Result.PacketHex) / 2
	envelopeWithoutTicket := len(ticket.Golden.LRTBodyTemplate) - len(ticket.Golden.TicketMarker)
	maxTicketBodyBytes := envelopeWithoutTicket + ticket.Contract.MaxTicketASCIIBytes
	maxTicketPacketBytes := maxTicketBodyBytes + ticket.Golden.NHPPacketOverheadBytes
	want := map[string]ConnectorHubAssignmentSuccessSize{
		"initial_real_qat1_golden": {
			Name: "initial_real_qat1_golden", Phase: "initial_assignment", Basis: "assignment_ticket_v1.golden_lrt_envelope",
			RequestPacketBytes: initialRequestBytes, ResultBodyBytes: ticket.Golden.LRTBodyBytes,
			ResultPacketBytes:           ticket.Golden.CompleteNHPPacketBytes,
			AmplificationNumeratorBytes: ticket.Golden.CompleteNHPPacketBytes, AmplificationDenominatorBytes: initialRequestBytes,
			LegacyAssignmentFixturePacketBytes: len(assignment.InitialAssignment.Result.PacketHex) / 2,
		},
		"initial_max_ticket_envelope": {
			Name: "initial_max_ticket_envelope", Phase: "initial_assignment", Basis: "assignment_ticket_v1.template_plus_max_ticket",
			RequestPacketBytes: initialRequestBytes, ResultBodyBytes: maxTicketBodyBytes, ResultPacketBytes: maxTicketPacketBytes,
			AmplificationNumeratorBytes: maxTicketPacketBytes, AmplificationDenominatorBytes: initialRequestBytes,
		},
		"refresh_assignment_golden": {
			Name: "refresh_assignment_golden", Phase: "refresh_assignment", Basis: "agent_assignment_golden.refresh_result",
			RequestPacketBytes: refreshRequestBytes, ResultBodyBytes: refreshBodyBytes, ResultPacketBytes: refreshPacketBytes,
			AmplificationNumeratorBytes: refreshPacketBytes, AmplificationDenominatorBytes: refreshRequestBytes,
			LegacyAssignmentFixturePacketBytes: refreshPacketBytes,
		},
	}
	if len(cases) != len(want) {
		return fmt.Errorf("conformance: Connector Hub assignment success-size count = %d, want %d", len(cases), len(want))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		expected, ok := want[c.Name]
		if !ok || !reflect.DeepEqual(c, expected) {
			return fmt.Errorf("conformance: Connector Hub assignment success-size %q drift", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector Hub assignment success-size %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.ResultPacketBytes != c.ResultBodyBytes+ConnectorHubLSTCookiePacketOverhead ||
			c.AmplificationNumeratorBytes != c.ResultPacketBytes || c.AmplificationDenominatorBytes != c.RequestPacketBytes {
			return fmt.Errorf("conformance: Connector Hub assignment success-size %q arithmetic drift", c.Name)
		}
	}
	return nil
}

func validateConnectorHubLSTCookieKeyCases(cases []ConnectorHubLSTCookieKeyCase) error {
	want := map[string]ConnectorHubLSTCookieKeyCase{
		"accept_active_current": {
			Name: "accept_active_current", ActiveKeyPresent: true, CookieKeySlot: "active", WindowOffset: 0,
			Outcome: ConnectorHubLSTCookieOutcomeAccept, ServerAction: ConnectorHubLSTCookieActionContinue,
		},
		"accept_active_previous_window": {
			Name: "accept_active_previous_window", ActiveKeyPresent: true, CookieKeySlot: "active", WindowOffset: -1,
			Outcome: ConnectorHubLSTCookieOutcomeAccept, ServerAction: ConnectorHubLSTCookieActionContinue,
		},
		"accept_previous_current": {
			Name: "accept_previous_current", ActiveKeyPresent: true, PreviousKeyPresent: true, CookieKeySlot: "previous", WindowOffset: 0,
			Outcome: ConnectorHubLSTCookieOutcomeAccept, ServerAction: ConnectorHubLSTCookieActionContinue,
		},
		"accept_previous_previous_window": {
			Name: "accept_previous_previous_window", ActiveKeyPresent: true, PreviousKeyPresent: true, CookieKeySlot: "previous", WindowOffset: -1,
			Outcome: ConnectorHubLSTCookieOutcomeAccept, ServerAction: ConnectorHubLSTCookieActionContinue,
		},
		"reject_previous_without_active": {
			Name: "reject_previous_without_active", PreviousKeyPresent: true, CookieKeySlot: "previous", WindowOffset: 0,
			Outcome: ConnectorHubLSTCookieOutcomeReject, ServerAction: ConnectorHubLSTCookieActionDrop,
		},
	}
	if len(cases) != len(want) {
		return fmt.Errorf("conformance: Connector Hub LST cookie key-case count = %d, want %d", len(cases), len(want))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		expected, ok := want[c.Name]
		if !ok || !reflect.DeepEqual(c, expected) {
			return fmt.Errorf("conformance: Connector Hub LST cookie key case %q drift", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector Hub LST cookie key case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
	}
	return nil
}

func validateConnectorHubLSTCookieRejects(cases []ConnectorHubLSTCookieRejectCase) error {
	if len(cases) != len(connectorHubLSTCookieRejects) {
		return fmt.Errorf("conformance: Connector Hub LST cookie reject count = %d, want %d", len(cases), len(connectorHubLSTCookieRejects))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		want, ok := connectorHubLSTCookieRejects[c.Name]
		if !ok || c.Stage != want.stage || c.Mutation != want.mutation || c.Outcome != ConnectorHubLSTCookieOutcomeReject ||
			c.ServerAction != ConnectorHubLSTCookieActionDrop || c.AuthorityInvocations != 0 {
			return fmt.Errorf("conformance: Connector Hub LST cookie reject %q drift", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector Hub LST cookie reject %q", c.Name)
		}
		seen[c.Name] = struct{}{}
	}
	return nil
}

func validateConnectorHubLSTCookieChallenges(cases []ConnectorHubLSTChallengeBodyCase, flows []ConnectorHubLSTCookieFlow) error {
	if len(cases) != len(connectorHubLSTCookieChallengeCases) {
		return fmt.Errorf("conformance: Connector Hub LST challenge count = %d, want %d", len(cases), len(connectorHubLSTCookieChallengeCases))
	}
	flowByPhase := make(map[string]ConnectorHubLSTCookieFlow, len(flows))
	for _, flow := range flows {
		flowByPhase[flow.Phase] = flow
	}
	initial := flowByPhase["initial_assignment"]
	refresh := flowByPhase["refresh_assignment"]
	var initialBody connectorHubLSTChallengeBody
	if err := strictDecodeArtifact([]byte(initial.ChallengeBodyJSON), &initialBody); err != nil {
		return fmt.Errorf("conformance: Connector Hub LST initial challenge linkage: %w", err)
	}
	validCookie := initialBody.Cookie
	shortCookie := base64.StdEncoding.EncodeToString(make([]byte, ConnectorHubLSTCookieBytes-1))
	expectedBodies := map[string]string{
		"accept_initial_challenge":      initial.ChallengeBodyJSON,
		"accept_refresh_challenge":      refresh.ChallengeBodyJSON,
		"reject_malformed_body":         `{"trxId":21`,
		"reject_unknown_field":          `{"trxId":21,"cookie":"` + validCookie + `","future":true}`,
		"reject_duplicate_field":        `{"trxId":21,"trxId":21,"cookie":"` + validCookie + `"}`,
		"reject_wrong_transaction":      refresh.ChallengeBodyJSON,
		"reject_cookie_encoding":        `{"trxId":21,"cookie":"***"}`,
		"reject_cookie_length":          `{"trxId":21,"cookie":"` + shortCookie + `"}`,
		"reject_untrusted_server":       initial.ChallengeBodyJSON,
		"reject_compressed_challenge":   initial.ChallengeBodyJSON,
		"reject_unknown_flag_challenge": initial.ChallengeBodyJSON,
		"reject_second_challenge":       `{"trxId":` + initial.ProofCounter + `,"cookie":"` + validCookie + `"}`,
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		want, ok := connectorHubLSTCookieChallengeCases[c.Name]
		if !ok || c.Stage != want.stage || c.Mutation != want.mutation || c.HeaderFlagsHex != want.flags ||
			c.Outcome != want.outcome || c.ClientAction != want.action {
			return fmt.Errorf("conformance: Connector Hub LST challenge %q drift", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector Hub LST challenge %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.BodyJSON != expectedBodies[c.Name] {
			return fmt.Errorf("conformance: Connector Hub LST challenge %q body drift", c.Name)
		}
		bodyErr := validateConnectorHubLSTChallengeBody(c.BodyJSON)
		bodyMustReject := c.Name == "reject_malformed_body" || c.Name == "reject_unknown_field" ||
			c.Name == "reject_duplicate_field" || c.Name == "reject_cookie_encoding" || c.Name == "reject_cookie_length"
		if (bodyErr != nil) != bodyMustReject {
			return fmt.Errorf("conformance: Connector Hub LST challenge %q parser outcome drift: %v", c.Name, bodyErr)
		}
	}
	return nil
}

func validateConnectorHubLSTChallengeBody(body string) error {
	var parsed connectorHubLSTChallengeBody
	if err := strictDecodeArtifact([]byte(body), &parsed); err != nil {
		return err
	}
	cookie, err := base64.StdEncoding.Strict().DecodeString(parsed.Cookie)
	if err != nil || base64.StdEncoding.EncodeToString(cookie) != parsed.Cookie || len(cookie) != ConnectorHubLSTCookieBytes {
		return errors.New("invalid Connector Hub LST challenge cookie")
	}
	return nil
}
