package conformance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// ConnectorResourceLSTV1ArtifactID identifies the registered-agent
	// NHP_LST/NHP_LRT Connector resource-discovery contract.
	ConnectorResourceLSTV1ArtifactID = "qurl-connector-resource-lst-v1-vectors"
	// ConnectorResourceLSTV1SchemaVersion is the only artifact schema accepted
	// by this release.
	ConnectorResourceLSTV1SchemaVersion = 1

	ConnectorResourceLSTV1Query   = "connector_resource"
	ConnectorResourceLSTV1Version = 1
	ConnectorResourceLSTV1AspID   = "agent"

	ConnectorResourceLSTV1RequestHeaderName = "NHP_LST"
	ConnectorResourceLSTV1RequestHeaderType = 5
	ConnectorResourceLSTV1ResultHeaderName  = "NHP_LRT"
	ConnectorResourceLSTV1ResultHeaderType  = 6

	ConnectorResourceLSTV1NonceBytes         = 32
	ConnectorResourceLSTV1ResourceIDBytes    = 91
	ConnectorResourceLSTV1ResourceIDChars    = 122
	ConnectorResourceLSTV1RoutingDigestBytes = 32
	ConnectorResourceLSTV1RoutingIDPrefix    = "c-"
	ConnectorResourceLSTV1RoutingIDChars     = 54
	// ConnectorResourceLSTV1KnockResourceIDMax is deliberately 64 bytes: even
	// when every byte expands to a six-byte JSON escape, the maximal success
	// object remains inside ConnectorResourceLSTV1MaxPlaintextBodyBytes.
	ConnectorResourceLSTV1KnockResourceIDMax          = 64
	ConnectorResourceLSTV1ConservativeSealBudgetBytes = 256
	ConnectorResourceLSTV1MaxPacketBytes              = 1232
	ConnectorResourceLSTV1MaxPlaintextBodyBytes       = ConnectorResourceLSTV1MaxPacketBytes - ConnectorResourceLSTV1ConservativeSealBudgetBytes
	ConnectorResourceLSTV1MaxRetryAfterSeconds        = 3600

	ConnectorResourceLSTV1OutcomeAccept = "accept"
	ConnectorResourceLSTV1OutcomeReject = "reject"
	ConnectorResourceLSTV1OutcomeError  = "error"

	ConnectorResourceLSTV1RejectBodyParse       = "body_parse"
	ConnectorResourceLSTV1RejectUnknownField    = "unknown_field"
	ConnectorResourceLSTV1RejectMissingField    = "missing_field"
	ConnectorResourceLSTV1RejectWrongType       = "wrong_type"
	ConnectorResourceLSTV1RejectSemantic        = "semantic"
	ConnectorResourceLSTV1RejectAgentBinding    = "agent_binding"
	ConnectorResourceLSTV1RejectRequestBinding  = "request_binding"
	ConnectorResourceLSTV1RejectResourceBinding = "resource_binding"
	ConnectorResourceLSTV1RejectCRIDBinding     = "crid_binding"
	ConnectorResourceLSTV1RejectListOnError     = "list_on_error"
	ConnectorResourceLSTV1RejectRetryMissing    = "retry_after_missing"
	ConnectorResourceLSTV1RejectRetryInvalid    = "retry_after_invalid"
	ConnectorResourceLSTV1RejectRetryUnexpected = "retry_after_unexpected"
	ConnectorResourceLSTV1RejectUnknownError    = "unknown_error_code"
	ConnectorResourceLSTV1RejectPacketSize      = "packet_size"

	ConnectorResourceLSTV1ErrorUnavailable      = "52500"
	ConnectorResourceLSTV1ErrorIdentityRejected = "52501"
	ConnectorResourceLSTV1ErrorEntitlement      = "52502"
	ConnectorResourceLSTV1ErrorIdentityConflict = "52503"
	ConnectorResourceLSTV1ErrorQuota            = "52504"
	ConnectorResourceLSTV1ErrorRateLimited      = "52505"
	ConnectorResourceLSTV1ErrorInvalidRequest   = "52506"

	ConnectorResourceLSTV1AuthorityOperation  = "ResolveConnectorResource"
	ConnectorResourceLSTV1CellRequestIDDomain = "layerv:qurl:connector-resource-request-id:v1"
	ConnectorResourceLSTV1CellRequestIDChars  = 64
)

const connectorResourceLSTV1Description = "Byte-exact registered-agent NHP_LST/NHP_LRT application contract for resolving or idempotently creating one qURL Connector resource without customer-runtime HTTP."

var (
	connectorResourceLSTV1AgentIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
	connectorResourceLSTV1ConnectorIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}[a-z0-9]$`)
	connectorResourceLSTV1EnvironmentPattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
	connectorResourceLSTV1RoutingEncoding    = base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)

	connectorResourceLSTV1ErrorSpecs = map[string]connectorResourceLSTV1ErrorSpec{
		ConnectorResourceLSTV1ErrorUnavailable:      {message: "connector resource temporarily unavailable", retry: connectorResourceRetryOptional},
		ConnectorResourceLSTV1ErrorIdentityRejected: {message: "connector resource identity rejected", retry: connectorResourceRetryForbidden},
		ConnectorResourceLSTV1ErrorEntitlement:      {message: "connector resource entitlement denied", retry: connectorResourceRetryForbidden},
		ConnectorResourceLSTV1ErrorIdentityConflict: {message: "connector resource identity conflict", retry: connectorResourceRetryForbidden},
		ConnectorResourceLSTV1ErrorQuota:            {message: "connector resource quota exceeded", retry: connectorResourceRetryForbidden},
		ConnectorResourceLSTV1ErrorRateLimited:      {message: "connector resource rate limited", retry: connectorResourceRetryRequired},
		ConnectorResourceLSTV1ErrorInvalidRequest:   {message: "invalid connector resource request", retry: connectorResourceRetryForbidden},
	}
)

type connectorResourceRetryPolicy int

const (
	connectorResourceRetryForbidden connectorResourceRetryPolicy = iota
	connectorResourceRetryOptional
	connectorResourceRetryRequired
)

type connectorResourceLSTV1ErrorSpec struct {
	message string
	retry   connectorResourceRetryPolicy
}

// ConnectorResourceLSTV1File freezes the public application bodies, replay
// behavior, closed error grammar, and operational unfragmented size bound. It
// deliberately contains no encrypted packets: consumers compose these exact
// bodies with their own NHP 2.0 codec and pinned assigned-cell key.
type ConnectorResourceLSTV1File struct {
	Artifact          string                             `json:"artifact"`
	SchemaVersion     int                                `json:"schema_version"`
	Description       string                             `json:"description"`
	Notes             []string                           `json:"notes"`
	Contract          ConnectorResourceLSTV1Contract     `json:"contract"`
	Fixtures          ConnectorResourceLSTV1Fixtures     `json:"fixtures"`
	SuccessExchanges  []ConnectorResourceLSTV1Exchange   `json:"success_exchanges"`
	ReplayCases       []ConnectorResourceLSTV1ReplayCase `json:"replay_cases"`
	RequestCases      []ConnectorResourceLSTV1BodyCase   `json:"request_cases"`
	ResultRejectCases []ConnectorResourceLSTV1BodyCase   `json:"result_reject_cases"`
	ErrorCases        []ConnectorResourceLSTV1ErrorCase  `json:"error_cases"`
	ErrorRejectCases  []ConnectorResourceLSTV1BodyCase   `json:"error_reject_cases"`
	SizeCases         []ConnectorResourceLSTV1SizeCase   `json:"size_cases"`
}

// ConnectorResourceLSTV1Contract is the complete consumer-neutral wire and
// trust-boundary profile.
type ConnectorResourceLSTV1Contract struct {
	Query                         string   `json:"query"`
	Version                       int      `json:"version"`
	RequestHeaderName             string   `json:"request_header_name"`
	RequestHeaderType             int      `json:"request_header_type"`
	ResultHeaderName              string   `json:"result_header_name"`
	ResultHeaderType              int      `json:"result_header_type"`
	AspID                         string   `json:"asp_id"`
	RequestOuterFields            []string `json:"request_outer_fields"`
	RequestUserDataRequiredFields []string `json:"request_user_data_required_fields"`
	RequestUserDataOptionalFields []string `json:"request_user_data_optional_fields"`
	SuccessOuterFields            []string `json:"success_outer_fields"`
	SuccessListRequiredFields     []string `json:"success_list_required_fields"`
	SuccessListOptionalFields     []string `json:"success_list_optional_fields"`
	ErrorRequiredFields           []string `json:"error_required_fields"`
	ErrorOptionalFields           []string `json:"error_optional_fields"`
	NonceEncoding                 string   `json:"nonce_encoding"`
	NonceDecodedBytes             int      `json:"nonce_decoded_bytes"`
	AgentIDPattern                string   `json:"agent_id_pattern"`
	ConnectorIDPattern            string   `json:"connector_id_pattern"`
	ResourceIDEncoding            string   `json:"resource_id_encoding"`
	ResourceIDDecodedBytes        int      `json:"resource_id_decoded_bytes"`
	ResourceIDEncodedChars        int      `json:"resource_id_encoded_chars"`
	ConnectorRoutingIDPattern     string   `json:"connector_routing_id_pattern"`
	KnockResourceIDMaxBytes       int      `json:"knock_resource_id_max_bytes"`
	CRIDProfile                   string   `json:"crid_profile"`
	IdentitySource                string   `json:"identity_source"`
	EntitlementSource             string   `json:"entitlement_source"`
	OneResourcePerExchange        bool     `json:"one_resource_per_exchange"`
	HTTPFallbackAllowed           bool     `json:"http_fallback_allowed"`
	ExpectedResourceIDRule        string   `json:"expected_resource_id_rule"`
	ExactReplayRule               string   `json:"exact_replay_rule"`
	ChangedReplayRule             string   `json:"changed_replay_rule"`
	LaterRequestRule              string   `json:"later_request_rule"`
	FoundExistingRule             string   `json:"found_existing_rule"`
	AuthorizationFreshnessRule    string   `json:"authorization_freshness_rule"`
	ConservativeOverheadBytes     int      `json:"conservative_overhead_bytes"`
	SizeAccountingRule            string   `json:"size_accounting_rule"`
	RealSealProofOwner            string   `json:"real_seal_proof_owner"`
	MaxPlaintextBodyBytes         int      `json:"max_plaintext_body_bytes"`
	MaxPacketBytes                int      `json:"max_packet_bytes"`
	MaxRetryAfterSeconds          int      `json:"max_retry_after_seconds"`
	RejectClasses                 []string `json:"reject_classes"`
	ErrorCodes                    []string `json:"error_codes"`
}

// UnmarshalJSON requires security-sensitive false decisions to be explicit.
func (contract *ConnectorResourceLSTV1Contract) UnmarshalJSON(data []byte) error {
	type plain ConnectorResourceLSTV1Contract
	var decoded plain
	if err := strictDecodeArtifact(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, required := range []string{"one_resource_per_exchange", "http_fallback_allowed"} {
		if _, ok := fields[required]; !ok {
			return fmt.Errorf("conformance: Connector resource LST contract missing %s", required)
		}
	}
	*contract = ConnectorResourceLSTV1Contract(decoded)
	return nil
}

type ConnectorResourceLSTV1Fixtures struct {
	AgentID                       string `json:"agent_id"`
	AuthenticatedPeerPublicKeyB64 string `json:"authenticated_peer_public_key_b64"`
	ConnectorID                   string `json:"connector_id"`
	ResourceID                    string `json:"resource_id"`
	ConnectorRoutingID            string `json:"connector_routing_id"`
	KnockResourceID               string `json:"knock_resource_id"`
	CRID                          string `json:"crid"`
	CreateRequestNonce            string `json:"create_request_nonce"`
	ExistingRequestNonce          string `json:"existing_request_nonce"`
	NoCRIDRequestNonce            string `json:"no_crid_request_nonce"`
}

type ConnectorResourceLSTV1Body struct {
	HeaderName      string `json:"header_name"`
	HeaderType      int    `json:"header_type"`
	BodyJSON        string `json:"body_json"`
	BodyBytes       int    `json:"body_bytes"`
	SizeBudgetBytes int    `json:"size_budget_bytes"`
}

type ConnectorResourceLSTV1Exchange struct {
	Name                  string                     `json:"name"`
	Request               ConnectorResourceLSTV1Body `json:"request"`
	Result                ConnectorResourceLSTV1Body `json:"result"`
	ExpectedFoundExisting bool                       `json:"expected_found_existing"`
}

type ConnectorResourceLSTV1ReplayCase struct {
	Name                    string `json:"name"`
	FirstExchange           string `json:"first_exchange"`
	ReplayRequestBodyJSON   string `json:"replay_request_body_json"`
	ChangedRequestBodyJSON  string `json:"changed_request_body_json,omitempty"`
	ExpectedOutcome         string `json:"expected_outcome"`
	ExpectedResultBodyJSON  string `json:"expected_result_body_json,omitempty"`
	ExpectedErrorCode       string `json:"expected_error_code,omitempty"`
	MutationAllowed         bool   `json:"mutation_allowed"`
	FoundExistingOnResponse *bool  `json:"found_existing_on_response,omitempty"`
}

type ConnectorResourceLSTV1BodyCase struct {
	Name        string `json:"name"`
	BodyJSON    string `json:"body_json"`
	Outcome     string `json:"outcome"`
	RejectClass string `json:"reject_class"`
}

type ConnectorResourceLSTV1ErrorCase struct {
	Name              string `json:"name"`
	BodyJSON          string `json:"body_json"`
	ErrorCode         string `json:"error_code"`
	Retryable         bool   `json:"retryable"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

type ConnectorResourceLSTV1SizeCase struct {
	Name            string `json:"name"`
	Direction       string `json:"direction"`
	BodyJSON        string `json:"body_json,omitempty"`
	BodyFillByteHex string `json:"body_fill_byte_hex,omitempty"`
	BodyBytes       int    `json:"body_bytes"`
	SizeBudgetBytes int    `json:"size_budget_bytes"`
	Outcome         string `json:"outcome"`
}

type connectorResourceLSTV1RequestWire struct {
	UsrID   string                                    `json:"usrId"`
	DevID   string                                    `json:"devId"`
	AspID   string                                    `json:"aspId"`
	UsrData connectorResourceLSTV1RequestUserDataWire `json:"usrData"`
}

type connectorResourceLSTV1RequestUserDataWire struct {
	Query              string  `json:"query"`
	Version            int     `json:"version"`
	RequestNonce       string  `json:"request_nonce"`
	ConnectorID        string  `json:"connector_id"`
	ExpectedResourceID *string `json:"expected_resource_id,omitempty"`
}

type connectorResourceLSTV1ResultWire struct {
	ErrCode           string                                 `json:"errCode"`
	ErrMsg            string                                 `json:"errMsg,omitempty"`
	List              *connectorResourceLSTV1SuccessListWire `json:"list,omitempty"`
	RetryAfterSeconds *int                                   `json:"retryAfterSeconds,omitempty"`
}

type connectorResourceLSTV1SuccessListWire struct {
	Query              string  `json:"query"`
	Version            int     `json:"version"`
	AgentID            string  `json:"agent_id"`
	ConnectorID        string  `json:"connector_id"`
	ResourceID         string  `json:"resource_id"`
	ConnectorRoutingID string  `json:"connector_routing_id"`
	KnockResourceID    string  `json:"knock_resource_id"`
	CRID               *string `json:"crid,omitempty"`
	FoundExisting      bool    `json:"found_existing"`
}

// Exported aliases are the exact public application-body types. Callers should
// use the parsing functions below so duplicate keys, null optionals, request
// binding, CRID binding, and closed error grammar remain enforced.
type ConnectorResourceLSTV1Request = connectorResourceLSTV1RequestWire
type ConnectorResourceLSTV1RequestUserData = connectorResourceLSTV1RequestUserDataWire
type ConnectorResourceLSTV1Result = connectorResourceLSTV1ResultWire
type ConnectorResourceLSTV1Resource = connectorResourceLSTV1SuccessListWire

// ConnectorResourceLSTV1ValidationError carries the stable consumer-neutral
// reject class without exposing rejected values in a sentinel error.
type ConnectorResourceLSTV1ValidationError struct {
	RejectClass string
	err         error
}

func (e *ConnectorResourceLSTV1ValidationError) Error() string { return e.err.Error() }
func (e *ConnectorResourceLSTV1ValidationError) Unwrap() error { return e.err }

// ParseConnectorResourceLSTV1RequestBody validates one already-decrypted LST
// body against the agent id independently established by the authenticated NHP
// peer mapping.
func ParseConnectorResourceLSTV1RequestBody(body []byte, authenticatedAgentID string) (*ConnectorResourceLSTV1Request, error) {
	request, class, err := parseConnectorResourceLSTV1Request(body, authenticatedAgentID)
	if err != nil {
		return nil, &ConnectorResourceLSTV1ValidationError{RejectClass: class, err: err}
	}
	return request, nil
}

// ParseConnectorResourceLSTV1ResultBody validates an already-decrypted LRT
// body. request may be nil only when parsing an error result; a success without
// its originating request is rejected by higher-level transaction correlation.
func ParseConnectorResourceLSTV1ResultBody(body []byte, request *ConnectorResourceLSTV1Request) (*ConnectorResourceLSTV1Result, error) {
	result, class, err := parseConnectorResourceLSTV1Result(body, request)
	if err != nil {
		return nil, &ConnectorResourceLSTV1ValidationError{RejectClass: class, err: err}
	}
	if result.List != nil && request == nil {
		return nil, &ConnectorResourceLSTV1ValidationError{
			RejectClass: ConnectorResourceLSTV1RejectRequestBinding,
			err:         errors.New("success result requires its authenticated originating request"),
		}
	}
	return result, nil
}

func ValidateConnectorResourceLSTV1AgentID(value string) bool {
	return connectorResourceLSTV1AgentIDPattern.MatchString(value)
}

func ValidateConnectorResourceLSTV1ConnectorID(value string) bool {
	return connectorResourceLSTV1ConnectorIDPattern.MatchString(value)
}

// DeriveConnectorResourceLSTV1CellRequestID derives the private Authority
// replay key from server-owned environment scope and authenticated public inputs.
// The public nonce itself never becomes an Authority persistence key.
func DeriveConnectorResourceLSTV1CellRequestID(environment string, authenticatedPeerPublicKey, requestNonce []byte) (string, error) {
	if !connectorResourceLSTV1EnvironmentPattern.MatchString(environment) {
		return "", errors.New("conformance: invalid Connector resource environment")
	}
	if len(authenticatedPeerPublicKey) != 32 {
		return "", errors.New("conformance: invalid Connector resource authenticated peer key")
	}
	if len(requestNonce) != ConnectorResourceLSTV1NonceBytes {
		return "", errors.New("conformance: invalid Connector resource request nonce")
	}
	preimage := make([]byte, 0, len(ConnectorResourceLSTV1CellRequestIDDomain)+1+3*3+len(environment)+len(authenticatedPeerPublicKey)+len(requestNonce))
	preimage = append(preimage, ConnectorResourceLSTV1CellRequestIDDomain...)
	preimage = append(preimage, 0)
	preimage = appendConnectorResourceLSTV1RequestIDFrame(preimage, 0x01, []byte(environment))
	preimage = appendConnectorResourceLSTV1RequestIDFrame(preimage, 0x02, authenticatedPeerPublicKey)
	preimage = appendConnectorResourceLSTV1RequestIDFrame(preimage, 0x03, requestNonce)
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:]), nil
}

func appendConnectorResourceLSTV1RequestIDFrame(dst []byte, tag byte, value []byte) []byte {
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(value)))
	dst = append(dst, tag)
	dst = append(dst, size[:]...)
	return append(dst, value...)
}

func ValidateConnectorResourceLSTV1CellRequestID(value string) error {
	if len(value) != ConnectorResourceLSTV1CellRequestIDChars {
		return errors.New("conformance: invalid Connector resource cell_request_id")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return errors.New("conformance: invalid Connector resource cell_request_id")
	}
	return nil
}

// ParseConnectorResourceLSTV1File strictly parses the embedded Connector
// resource discovery artifact and reclassifies every body through the reference
// application parser.
func ParseConnectorResourceLSTV1File(data []byte) (*ConnectorResourceLSTV1File, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("conformance: Connector resource LST file is not valid UTF-8")
	}
	var file ConnectorResourceLSTV1File
	if err := strictDecodeArtifact(data, &file); err != nil {
		return nil, fmt.Errorf("conformance: parse Connector resource LST file: %w", err)
	}
	if file.Artifact != ConnectorResourceLSTV1ArtifactID || file.SchemaVersion != ConnectorResourceLSTV1SchemaVersion || file.Description != connectorResourceLSTV1Description {
		return nil, errors.New("conformance: Connector resource LST artifact identity is invalid")
	}
	if len(file.Notes) != 8 {
		return nil, fmt.Errorf("conformance: Connector resource LST notes count = %d, want 8", len(file.Notes))
	}
	if err := validateConnectorResourceLSTV1Contract(file.Contract); err != nil {
		return nil, err
	}
	if err := validateConnectorResourceLSTV1Fixtures(file.Fixtures); err != nil {
		return nil, err
	}
	if err := validateConnectorResourceLSTV1SuccessExchanges(file.SuccessExchanges, file.Fixtures); err != nil {
		return nil, err
	}
	if err := validateConnectorResourceLSTV1ReplayCases(file.ReplayCases, file.SuccessExchanges, file.Fixtures); err != nil {
		return nil, err
	}
	if err := validateConnectorResourceLSTV1RequestCases(file.RequestCases, file.Fixtures); err != nil {
		return nil, err
	}
	if err := validateConnectorResourceLSTV1ResultRejectCases(file.ResultRejectCases, file.Fixtures); err != nil {
		return nil, err
	}
	if err := validateConnectorResourceLSTV1ErrorCases(file.ErrorCases); err != nil {
		return nil, err
	}
	if err := validateConnectorResourceLSTV1ErrorRejectCases(file.ErrorRejectCases); err != nil {
		return nil, err
	}
	if err := validateConnectorResourceLSTV1SizeCases(file.SizeCases, file.Fixtures); err != nil {
		return nil, err
	}
	return &file, nil
}

func validateConnectorResourceLSTV1Contract(contract ConnectorResourceLSTV1Contract) error {
	want := ConnectorResourceLSTV1Contract{
		Query: ConnectorResourceLSTV1Query, Version: ConnectorResourceLSTV1Version,
		RequestHeaderName: ConnectorResourceLSTV1RequestHeaderName, RequestHeaderType: ConnectorResourceLSTV1RequestHeaderType,
		ResultHeaderName: ConnectorResourceLSTV1ResultHeaderName, ResultHeaderType: ConnectorResourceLSTV1ResultHeaderType,
		AspID:                         ConnectorResourceLSTV1AspID,
		RequestOuterFields:            []string{"usrId", "devId", "aspId", "usrData"},
		RequestUserDataRequiredFields: []string{"query", "version", "request_nonce", "connector_id"},
		RequestUserDataOptionalFields: []string{"expected_resource_id"},
		SuccessOuterFields:            []string{"errCode", "list"},
		SuccessListRequiredFields:     []string{"query", "version", "agent_id", "connector_id", "resource_id", "connector_routing_id", "knock_resource_id", "found_existing"},
		SuccessListOptionalFields:     []string{"crid"},
		ErrorRequiredFields:           []string{"errCode", "errMsg"},
		ErrorOptionalFields:           []string{"retryAfterSeconds"},
		NonceEncoding:                 "canonical_base64url_unpadded", NonceDecodedBytes: ConnectorResourceLSTV1NonceBytes,
		AgentIDPattern: connectorResourceLSTV1AgentIDPattern.String(), ConnectorIDPattern: connectorResourceLSTV1ConnectorIDPattern.String(),
		ResourceIDEncoding: "canonical_base64url_unpadded_p256_der_spki", ResourceIDDecodedBytes: ConnectorResourceLSTV1ResourceIDBytes, ResourceIDEncodedChars: ConnectorResourceLSTV1ResourceIDChars,
		ConnectorRoutingIDPattern: `^c-[a-z2-7]{52}$`, KnockResourceIDMaxBytes: ConnectorResourceLSTV1KnockResourceIDMax,
		CRIDProfile:            "qurl-crid-v1-vectors_optional_but_if_present_must_match_resource_id",
		IdentitySource:         "noise_authenticated_registered_agent_key_mapped_to_exact_usrId_and_devId",
		EntitlementSource:      "server_side_owner_and_enrollment_connector_claim_never_client_supplied",
		OneResourcePerExchange: true, HTTPFallbackAllowed: false,
		ExpectedResourceIDRule:     "optional_read_only_continuity_assertion_exact_active_match_only_else_terminal_52503_for_absent_revoked_tombstoned_or_different_resource_never_create_or_reclaim",
		ExactReplayRule:            "same_authenticated_peer_query_request_nonce_and_exact_semantic_body_returns_byte_identical_result",
		ChangedReplayRule:          "same_replay_key_changed_semantics_returns_52506_before_authority_or_mutation",
		LaterRequestRule:           "fresh_nonce_reexecutes_authoritative_resolve_and_reports_current_found_existing",
		FoundExistingRule:          "fresh_create_false_exact_replay_preserves_false_later_fresh_nonce_for_same_active_resource_true",
		AuthorizationFreshnessRule: "persisted_binding_never_bypasses_each_knock_authorization_or_resource_lifecycle_check",
		ConservativeOverheadBytes:  ConnectorResourceLSTV1ConservativeSealBudgetBytes,
		SizeAccountingRule:         "plaintext_body_bytes_plus_256_conservative_preseal_budget_not_packet_golden",
		RealSealProofOwner:         "NHP_reference_codec_integration_test",
		MaxPlaintextBodyBytes:      ConnectorResourceLSTV1MaxPlaintextBodyBytes, MaxPacketBytes: ConnectorResourceLSTV1MaxPacketBytes,
		MaxRetryAfterSeconds: ConnectorResourceLSTV1MaxRetryAfterSeconds,
		RejectClasses: []string{
			ConnectorResourceLSTV1RejectBodyParse, ConnectorResourceLSTV1RejectUnknownField, ConnectorResourceLSTV1RejectMissingField,
			ConnectorResourceLSTV1RejectWrongType, ConnectorResourceLSTV1RejectSemantic, ConnectorResourceLSTV1RejectAgentBinding,
			ConnectorResourceLSTV1RejectRequestBinding, ConnectorResourceLSTV1RejectResourceBinding, ConnectorResourceLSTV1RejectCRIDBinding,
			ConnectorResourceLSTV1RejectListOnError, ConnectorResourceLSTV1RejectRetryMissing, ConnectorResourceLSTV1RejectRetryInvalid,
			ConnectorResourceLSTV1RejectRetryUnexpected, ConnectorResourceLSTV1RejectUnknownError, ConnectorResourceLSTV1RejectPacketSize,
		},
		ErrorCodes: []string{
			ConnectorResourceLSTV1ErrorUnavailable, ConnectorResourceLSTV1ErrorIdentityRejected, ConnectorResourceLSTV1ErrorEntitlement,
			ConnectorResourceLSTV1ErrorIdentityConflict, ConnectorResourceLSTV1ErrorQuota, ConnectorResourceLSTV1ErrorRateLimited,
			ConnectorResourceLSTV1ErrorInvalidRequest,
		},
	}
	if !reflect.DeepEqual(contract, want) {
		return errors.New("conformance: Connector resource LST contract drift")
	}
	return nil
}

func validateConnectorResourceLSTV1Fixtures(fixtures ConnectorResourceLSTV1Fixtures) error {
	if !connectorResourceLSTV1AgentIDPattern.MatchString(fixtures.AgentID) || !connectorResourceLSTV1ConnectorIDPattern.MatchString(fixtures.ConnectorID) {
		return errors.New("conformance: Connector resource LST fixture identity is invalid")
	}
	peer, err := base64.StdEncoding.Strict().DecodeString(fixtures.AuthenticatedPeerPublicKeyB64)
	if err != nil || len(peer) != 32 || base64.StdEncoding.EncodeToString(peer) != fixtures.AuthenticatedPeerPublicKeyB64 {
		return errors.New("conformance: Connector resource LST fixture peer key is not canonical padded base64 X25519")
	}
	if err := ValidateConnectorResourceLSTV1ResourceID(fixtures.ResourceID); err != nil {
		return fmt.Errorf("conformance: Connector resource LST fixture resource_id: %w", err)
	}
	if err := ValidateConnectorResourceLSTV1RoutingID(fixtures.ConnectorRoutingID); err != nil {
		return fmt.Errorf("conformance: Connector resource LST fixture connector_routing_id: %w", err)
	}
	if err := ValidateConnectorResourceLSTV1KnockResourceID(fixtures.KnockResourceID); err != nil {
		return fmt.Errorf("conformance: Connector resource LST fixture knock_resource_id: %w", err)
	}
	if fixtures.ResourceID == fixtures.KnockResourceID || fixtures.ConnectorRoutingID == fixtures.KnockResourceID {
		return errors.New("conformance: Connector resource LST fixture identity/routing/admission values are cross-wired")
	}
	if outcome, err := deriveCRIDV1KeyMatchExpectation(fixtures.CRID, fixtures.ResourceID); err != nil || outcome != CRIDV1OutcomeMatch {
		return errors.New("conformance: Connector resource LST fixture CRID does not match resource_id")
	}
	for _, nonce := range []string{fixtures.CreateRequestNonce, fixtures.ExistingRequestNonce, fixtures.NoCRIDRequestNonce} {
		if err := ValidateConnectorResourceLSTV1Nonce(nonce); err != nil {
			return fmt.Errorf("conformance: Connector resource LST fixture nonce: %w", err)
		}
	}
	if fixtures.CreateRequestNonce == fixtures.ExistingRequestNonce || fixtures.CreateRequestNonce == fixtures.NoCRIDRequestNonce || fixtures.ExistingRequestNonce == fixtures.NoCRIDRequestNonce {
		return errors.New("conformance: Connector resource LST fixture nonces must be distinct")
	}
	return nil
}

func validateConnectorResourceLSTV1SuccessExchanges(exchanges []ConnectorResourceLSTV1Exchange, fixtures ConnectorResourceLSTV1Fixtures) error {
	required := []string{"fresh_create", "existing_with_continuity", "existing_without_crid"}
	if len(exchanges) != len(required) {
		return fmt.Errorf("conformance: Connector resource LST success exchange count = %d, want %d", len(exchanges), len(required))
	}
	seen := make(map[string]struct{}, len(exchanges))
	for _, exchange := range exchanges {
		if _, duplicate := seen[exchange.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector resource LST exchange %q", exchange.Name)
		}
		seen[exchange.Name] = struct{}{}
		if !slices.Contains(required, exchange.Name) {
			return fmt.Errorf("conformance: unknown Connector resource LST exchange %q", exchange.Name)
		}
		if err := validateConnectorResourceLSTV1BodySize(exchange.Name+" request", exchange.Request, ConnectorResourceLSTV1RequestHeaderName, ConnectorResourceLSTV1RequestHeaderType); err != nil {
			return err
		}
		request, class, err := parseConnectorResourceLSTV1Request([]byte(exchange.Request.BodyJSON), fixtures.AgentID)
		if err != nil || class != "" {
			return fmt.Errorf("conformance: Connector resource LST exchange %q request rejected as %q: %v", exchange.Name, class, err)
		}
		if request.UsrData.ConnectorID != fixtures.ConnectorID {
			return fmt.Errorf("conformance: Connector resource LST exchange %q connector_id drift", exchange.Name)
		}
		if err := validateConnectorResourceLSTV1BodySize(exchange.Name+" result", exchange.Result, ConnectorResourceLSTV1ResultHeaderName, ConnectorResourceLSTV1ResultHeaderType); err != nil {
			return err
		}
		parsed, class, err := parseConnectorResourceLSTV1Result([]byte(exchange.Result.BodyJSON), request)
		if err != nil || class != "" || parsed.List == nil {
			return fmt.Errorf("conformance: Connector resource LST exchange %q result rejected as %q: %v", exchange.Name, class, err)
		}
		if parsed.List.ResourceID != fixtures.ResourceID || parsed.List.ConnectorRoutingID != fixtures.ConnectorRoutingID || parsed.List.KnockResourceID != fixtures.KnockResourceID || parsed.List.FoundExisting != exchange.ExpectedFoundExisting {
			return fmt.Errorf("conformance: Connector resource LST exchange %q success binding drift", exchange.Name)
		}
		if exchange.Name == "existing_without_crid" {
			if parsed.List.CRID != nil {
				return errors.New("conformance: existing_without_crid unexpectedly carries crid")
			}
		} else if parsed.List.CRID == nil || *parsed.List.CRID != fixtures.CRID {
			return fmt.Errorf("conformance: Connector resource LST exchange %q CRID drift", exchange.Name)
		}
		if exchange.Name == "fresh_create" && request.UsrData.ExpectedResourceID != nil {
			return errors.New("conformance: fresh_create must not carry expected_resource_id")
		}
		if exchange.Name == "existing_with_continuity" && (request.UsrData.ExpectedResourceID == nil || *request.UsrData.ExpectedResourceID != fixtures.ResourceID) {
			return errors.New("conformance: existing_with_continuity must carry the exact fixture expected_resource_id")
		}
	}
	for _, name := range required {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("conformance: missing Connector resource LST exchange %q", name)
		}
	}
	return nil
}

func validateConnectorResourceLSTV1ReplayCases(cases []ConnectorResourceLSTV1ReplayCase, exchanges []ConnectorResourceLSTV1Exchange, fixtures ConnectorResourceLSTV1Fixtures) error {
	required := map[string]struct {
		outcome, errorCode string
		mutation           bool
	}{
		"exact_create_replay":          {ConnectorResourceLSTV1OutcomeAccept, "", false},
		"same_nonce_changed_semantics": {ConnectorResourceLSTV1OutcomeError, ConnectorResourceLSTV1ErrorInvalidRequest, false},
		"fresh_nonce_after_create":     {ConnectorResourceLSTV1OutcomeAccept, "", false},
	}
	if len(cases) != len(required) {
		return fmt.Errorf("conformance: Connector resource LST replay case count = %d, want %d", len(cases), len(required))
	}
	exchangeByName := make(map[string]ConnectorResourceLSTV1Exchange, len(exchanges))
	for _, exchange := range exchanges {
		exchangeByName[exchange.Name] = exchange
	}
	seen := make(map[string]struct{}, len(cases))
	for _, test := range cases {
		want, ok := required[test.Name]
		if !ok {
			return fmt.Errorf("conformance: unknown Connector resource LST replay case %q", test.Name)
		}
		if _, duplicate := seen[test.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector resource LST replay case %q", test.Name)
		}
		seen[test.Name] = struct{}{}
		first, ok := exchangeByName[test.FirstExchange]
		if !ok || test.ReplayRequestBodyJSON != first.Request.BodyJSON {
			return fmt.Errorf("conformance: Connector resource LST replay case %q does not replay its named exchange exactly", test.Name)
		}
		if test.ExpectedOutcome != want.outcome || test.ExpectedErrorCode != want.errorCode || test.MutationAllowed != want.mutation {
			return fmt.Errorf("conformance: Connector resource LST replay case %q expectation drift", test.Name)
		}
		switch test.Name {
		case "exact_create_replay":
			if test.ExpectedResultBodyJSON != first.Result.BodyJSON || test.FoundExistingOnResponse == nil || *test.FoundExistingOnResponse {
				return errors.New("conformance: exact_create_replay must preserve byte-identical found_existing=false")
			}
		case "same_nonce_changed_semantics":
			if test.ChangedRequestBodyJSON == "" || test.ChangedRequestBodyJSON == test.ReplayRequestBodyJSON || test.ExpectedResultBodyJSON != "" || test.FoundExistingOnResponse != nil {
				return errors.New("conformance: same_nonce_changed_semantics shape drift")
			}
			request, class, err := parseConnectorResourceLSTV1Request([]byte(test.ChangedRequestBodyJSON), fixtures.AgentID)
			if err != nil || class != "" || request.UsrData.RequestNonce != fixtures.CreateRequestNonce {
				return errors.New("conformance: same_nonce_changed_semantics must remain a separately valid request sharing the create nonce")
			}
		case "fresh_nonce_after_create":
			if first.Name != "existing_with_continuity" || test.ExpectedResultBodyJSON != first.Result.BodyJSON || test.FoundExistingOnResponse == nil || !*test.FoundExistingOnResponse {
				return errors.New("conformance: fresh_nonce_after_create must report the authoritative existing result")
			}
		}
	}
	return nil
}

func validateConnectorResourceLSTV1RequestCases(cases []ConnectorResourceLSTV1BodyCase, fixtures ConnectorResourceLSTV1Fixtures) error {
	required := map[string]string{
		"reject_duplicate_outer_dev_id":       ConnectorResourceLSTV1RejectBodyParse,
		"reject_unknown_outer_field":          ConnectorResourceLSTV1RejectUnknownField,
		"reject_missing_usr_id":               ConnectorResourceLSTV1RejectMissingField,
		"reject_null_usr_data":                ConnectorResourceLSTV1RejectWrongType,
		"reject_usr_id_agent_mismatch":        ConnectorResourceLSTV1RejectAgentBinding,
		"reject_dev_id_agent_mismatch":        ConnectorResourceLSTV1RejectAgentBinding,
		"reject_wrong_asp_id":                 ConnectorResourceLSTV1RejectSemantic,
		"reject_wrong_query":                  ConnectorResourceLSTV1RejectSemantic,
		"reject_wrong_version":                ConnectorResourceLSTV1RejectSemantic,
		"reject_missing_request_nonce":        ConnectorResourceLSTV1RejectMissingField,
		"reject_null_request_nonce":           ConnectorResourceLSTV1RejectWrongType,
		"reject_padded_request_nonce":         ConnectorResourceLSTV1RejectSemantic,
		"reject_short_request_nonce":          ConnectorResourceLSTV1RejectSemantic,
		"reject_missing_connector_id":         ConnectorResourceLSTV1RejectMissingField,
		"reject_invalid_connector_id":         ConnectorResourceLSTV1RejectSemantic,
		"reject_null_expected_resource_id":    ConnectorResourceLSTV1RejectWrongType,
		"reject_invalid_expected_resource_id": ConnectorResourceLSTV1RejectSemantic,
		"reject_unknown_user_data_field":      ConnectorResourceLSTV1RejectUnknownField,
		"reject_trailing_value":               ConnectorResourceLSTV1RejectBodyParse,
	}
	return validateConnectorResourceLSTV1BodyCases("request", cases, required, func(body []byte) string {
		_, class, _ := parseConnectorResourceLSTV1Request(body, fixtures.AgentID)
		return class
	})
}

func validateConnectorResourceLSTV1ResultRejectCases(cases []ConnectorResourceLSTV1BodyCase, fixtures ConnectorResourceLSTV1Fixtures) error {
	baseline := &connectorResourceLSTV1RequestWire{UsrID: fixtures.AgentID, DevID: fixtures.AgentID, AspID: ConnectorResourceLSTV1AspID,
		UsrData: connectorResourceLSTV1RequestUserDataWire{Query: ConnectorResourceLSTV1Query, Version: 1, RequestNonce: fixtures.ExistingRequestNonce, ConnectorID: fixtures.ConnectorID, ExpectedResourceID: &fixtures.ResourceID}}
	required := map[string]string{
		"reject_success_missing_list":               ConnectorResourceLSTV1RejectMissingField,
		"reject_success_null_list":                  ConnectorResourceLSTV1RejectWrongType,
		"reject_success_err_msg":                    ConnectorResourceLSTV1RejectUnknownField,
		"reject_success_retry_after":                ConnectorResourceLSTV1RejectUnknownField,
		"reject_success_unknown_field":              ConnectorResourceLSTV1RejectUnknownField,
		"reject_success_wrong_query":                ConnectorResourceLSTV1RejectSemantic,
		"reject_success_wrong_version":              ConnectorResourceLSTV1RejectSemantic,
		"reject_success_agent_mismatch":             ConnectorResourceLSTV1RejectRequestBinding,
		"reject_success_connector_mismatch":         ConnectorResourceLSTV1RejectRequestBinding,
		"reject_success_expected_resource_mismatch": ConnectorResourceLSTV1RejectResourceBinding,
		"reject_success_invalid_resource_id":        ConnectorResourceLSTV1RejectSemantic,
		"reject_success_invalid_routing_id":         ConnectorResourceLSTV1RejectSemantic,
		"reject_success_blank_knock_id":             ConnectorResourceLSTV1RejectSemantic,
		"reject_success_oversize_knock_id":          ConnectorResourceLSTV1RejectSemantic,
		"reject_success_crosswired_knock_id":        ConnectorResourceLSTV1RejectResourceBinding,
		"reject_success_invalid_crid":               ConnectorResourceLSTV1RejectSemantic,
		"reject_success_crid_mismatch":              ConnectorResourceLSTV1RejectCRIDBinding,
		"reject_success_missing_found_existing":     ConnectorResourceLSTV1RejectMissingField,
		"reject_success_string_found_existing":      ConnectorResourceLSTV1RejectWrongType,
		"reject_success_unknown_list_field":         ConnectorResourceLSTV1RejectUnknownField,
	}
	return validateConnectorResourceLSTV1BodyCases("result", cases, required, func(body []byte) string {
		_, class, _ := parseConnectorResourceLSTV1Result(body, baseline)
		return class
	})
}

func validateConnectorResourceLSTV1ErrorCases(cases []ConnectorResourceLSTV1ErrorCase) error {
	required := []string{"unavailable", "unavailable_with_retry", "identity_rejected", "entitlement_denied", "identity_conflict", "quota_exceeded", "rate_limited", "invalid_request"}
	if len(cases) != len(required) {
		return fmt.Errorf("conformance: Connector resource LST error case count = %d, want %d", len(cases), len(required))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, test := range cases {
		if !slices.Contains(required, test.Name) {
			return fmt.Errorf("conformance: unknown Connector resource LST error case %q", test.Name)
		}
		if _, duplicate := seen[test.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector resource LST error case %q", test.Name)
		}
		seen[test.Name] = struct{}{}
		if len([]byte(test.BodyJSON)) > ConnectorResourceLSTV1MaxPlaintextBodyBytes {
			return fmt.Errorf("conformance: Connector resource LST error case %q size drift", test.Name)
		}
		parsed, class, err := parseConnectorResourceLSTV1Result([]byte(test.BodyJSON), nil)
		if err != nil || class != "" || parsed.List != nil || parsed.ErrCode != test.ErrorCode {
			return fmt.Errorf("conformance: Connector resource LST error case %q rejected as %q: %v", test.Name, class, err)
		}
		spec := connectorResourceLSTV1ErrorSpecs[test.ErrorCode]
		wantRetryable := spec.retry == connectorResourceRetryOptional || spec.retry == connectorResourceRetryRequired
		if test.Retryable != wantRetryable {
			return fmt.Errorf("conformance: Connector resource LST error case %q retryable drift", test.Name)
		}
		gotRetry := 0
		if parsed.RetryAfterSeconds != nil {
			gotRetry = *parsed.RetryAfterSeconds
		}
		if gotRetry != test.RetryAfterSeconds {
			return fmt.Errorf("conformance: Connector resource LST error case %q retry delay drift", test.Name)
		}
	}
	return nil
}

func validateConnectorResourceLSTV1ErrorRejectCases(cases []ConnectorResourceLSTV1BodyCase) error {
	required := map[string]string{
		"reject_error_with_list":                ConnectorResourceLSTV1RejectListOnError,
		"reject_rate_limit_missing_retry_after": ConnectorResourceLSTV1RejectRetryMissing,
		"reject_zero_retry_after":               ConnectorResourceLSTV1RejectRetryInvalid,
		"reject_negative_retry_after":           ConnectorResourceLSTV1RejectRetryInvalid,
		"reject_fractional_retry_after":         ConnectorResourceLSTV1RejectRetryInvalid,
		"reject_null_retry_after":               ConnectorResourceLSTV1RejectRetryInvalid,
		"reject_retry_after_above_max":          ConnectorResourceLSTV1RejectRetryInvalid,
		"reject_string_retry_after":             ConnectorResourceLSTV1RejectRetryInvalid,
		"reject_unexpected_retry_after":         ConnectorResourceLSTV1RejectRetryUnexpected,
		"reject_unknown_error_code":             ConnectorResourceLSTV1RejectUnknownError,
		"reject_wrong_error_message":            ConnectorResourceLSTV1RejectSemantic,
		"reject_missing_error_message":          ConnectorResourceLSTV1RejectMissingField,
		"reject_unknown_error_field":            ConnectorResourceLSTV1RejectUnknownField,
		"reject_duplicate_error_code":           ConnectorResourceLSTV1RejectBodyParse,
	}
	return validateConnectorResourceLSTV1BodyCases("error", cases, required, func(body []byte) string {
		_, class, _ := parseConnectorResourceLSTV1Result(body, nil)
		return class
	})
}

func validateConnectorResourceLSTV1BodyCases(group string, cases []ConnectorResourceLSTV1BodyCase, required map[string]string, classify func([]byte) string) error {
	if len(cases) != len(required) {
		return fmt.Errorf("conformance: Connector resource LST %s case count = %d, want %d", group, len(cases), len(required))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, test := range cases {
		wantClass, ok := required[test.Name]
		if !ok {
			return fmt.Errorf("conformance: unknown Connector resource LST %s case %q", group, test.Name)
		}
		if _, duplicate := seen[test.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector resource LST %s case %q", group, test.Name)
		}
		seen[test.Name] = struct{}{}
		if test.Outcome != ConnectorResourceLSTV1OutcomeReject || test.RejectClass != wantClass {
			return fmt.Errorf("conformance: Connector resource LST %s case %q declared expectation drift", group, test.Name)
		}
		if gotClass := classify([]byte(test.BodyJSON)); gotClass != wantClass {
			return fmt.Errorf("conformance: Connector resource LST %s case %q classifies as %q, want %q", group, test.Name, gotClass, wantClass)
		}
	}
	return nil
}

func validateConnectorResourceLSTV1SizeCases(cases []ConnectorResourceLSTV1SizeCase, fixtures ConnectorResourceLSTV1Fixtures) error {
	required := []string{"max_fields_request", "max_fields_success", "max_json_escaped_knock_id_success", "reject_plaintext_body_over_max"}
	if len(cases) != len(required) {
		return fmt.Errorf("conformance: Connector resource LST size case count = %d, want %d", len(cases), len(required))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, test := range cases {
		if !slices.Contains(required, test.Name) {
			return fmt.Errorf("conformance: unknown Connector resource LST size case %q", test.Name)
		}
		if _, duplicate := seen[test.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate Connector resource LST size case %q", test.Name)
		}
		seen[test.Name] = struct{}{}
		var body []byte
		if test.BodyFillByteHex != "" {
			fill, err := hex.DecodeString(test.BodyFillByteHex)
			if err != nil || len(fill) != 1 || test.BodyJSON != "" {
				return fmt.Errorf("conformance: Connector resource LST size case %q fill recipe drift", test.Name)
			}
			body = bytes.Repeat(fill, test.BodyBytes)
		} else {
			body = []byte(test.BodyJSON)
		}
		if test.BodyBytes != len(body) || test.SizeBudgetBytes != test.BodyBytes+ConnectorResourceLSTV1ConservativeSealBudgetBytes {
			return fmt.Errorf("conformance: Connector resource LST size case %q size/outcome drift", test.Name)
		}
		if test.Name == "reject_plaintext_body_over_max" {
			if test.Direction != "request" || test.Outcome != ConnectorResourceLSTV1OutcomeReject || test.BodyBytes != ConnectorResourceLSTV1MaxPlaintextBodyBytes+1 || test.SizeBudgetBytes != ConnectorResourceLSTV1MaxPacketBytes+1 {
				return fmt.Errorf("conformance: Connector resource LST oversize case %q expectation drift", test.Name)
			}
			if _, class, err := parseConnectorResourceLSTV1Request(body, fixtures.AgentID); err == nil || class != ConnectorResourceLSTV1RejectPacketSize {
				return fmt.Errorf("conformance: Connector resource LST oversize case class = %q, err=%v", class, err)
			}
			continue
		}
		if test.Outcome != ConnectorResourceLSTV1OutcomeAccept || test.SizeBudgetBytes > ConnectorResourceLSTV1MaxPacketBytes || test.BodyFillByteHex != "" {
			return fmt.Errorf("conformance: Connector resource LST size case %q size/outcome drift", test.Name)
		}
		switch test.Direction {
		case "request":
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(body, &envelope); err != nil {
				return err
			}
			var agent string
			if err := json.Unmarshal(envelope["usrId"], &agent); err != nil {
				return err
			}
			if _, class, err := parseConnectorResourceLSTV1Request(body, agent); err != nil || class != "" {
				return fmt.Errorf("conformance: Connector resource LST max request rejected as %q: %v", class, err)
			}
		case "result":
			var result connectorResourceLSTV1ResultWire
			if err := strictDecodeArtifact(body, &result); err != nil || result.List == nil {
				return fmt.Errorf("conformance: Connector resource LST max result decode: %v", err)
			}
			expected := result.List.ResourceID
			request := &connectorResourceLSTV1RequestWire{UsrID: result.List.AgentID, DevID: result.List.AgentID, AspID: ConnectorResourceLSTV1AspID,
				UsrData: connectorResourceLSTV1RequestUserDataWire{Query: ConnectorResourceLSTV1Query, Version: 1, RequestNonce: fixtures.ExistingRequestNonce, ConnectorID: result.List.ConnectorID, ExpectedResourceID: &expected}}
			if _, class, err := parseConnectorResourceLSTV1Result(body, request); err != nil || class != "" {
				return fmt.Errorf("conformance: Connector resource LST max result rejected as %q: %v", class, err)
			}
		default:
			return fmt.Errorf("conformance: Connector resource LST size case %q direction = %q", test.Name, test.Direction)
		}
	}
	return nil
}

func validateConnectorResourceLSTV1BodySize(name string, body ConnectorResourceLSTV1Body, wantName string, wantType int) error {
	if body.HeaderName != wantName || body.HeaderType != wantType {
		return fmt.Errorf("conformance: Connector resource LST %s header = %q/%d, want %q/%d", name, body.HeaderName, body.HeaderType, wantName, wantType)
	}
	if body.BodyBytes != len([]byte(body.BodyJSON)) || body.SizeBudgetBytes != body.BodyBytes+ConnectorResourceLSTV1ConservativeSealBudgetBytes {
		return fmt.Errorf("conformance: Connector resource LST %s size drift", name)
	}
	if body.BodyBytes > ConnectorResourceLSTV1MaxPlaintextBodyBytes || body.SizeBudgetBytes > ConnectorResourceLSTV1MaxPacketBytes {
		return fmt.Errorf("conformance: Connector resource LST %s exceeds unfragmented packet bound", name)
	}
	return nil
}

func parseConnectorResourceLSTV1Request(body []byte, authoritativeAgentID string) (*connectorResourceLSTV1RequestWire, string, error) {
	outer, class, err := connectorResourceLSTV1ExactObject(body, []string{"usrId", "devId", "aspId", "usrData"}, []string{"usrId", "devId", "aspId", "usrData"})
	if err != nil {
		return nil, class, err
	}
	for _, key := range []string{"usrId", "devId", "aspId"} {
		if string(outer[key]) == "null" || len(outer[key]) == 0 || outer[key][0] != '"' {
			return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("identity field must be a string")
		}
	}
	if string(outer["usrData"]) == "null" || len(outer["usrData"]) == 0 || outer["usrData"][0] != '{' {
		return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("usrData must be an object")
	}
	userData, class, err := connectorResourceLSTV1ExactObject(outer["usrData"],
		[]string{"query", "version", "request_nonce", "connector_id"},
		[]string{"query", "version", "request_nonce", "connector_id", "expected_resource_id"})
	if err != nil {
		return nil, class, err
	}
	for _, key := range []string{"query", "request_nonce", "connector_id"} {
		if string(userData[key]) == "null" || len(userData[key]) == 0 || userData[key][0] != '"' {
			return nil, ConnectorResourceLSTV1RejectWrongType, fmt.Errorf("%s must be a string", key)
		}
	}
	if expected, ok := userData["expected_resource_id"]; ok && (string(expected) == "null" || len(expected) == 0 || expected[0] != '"') {
		return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("expected_resource_id must be a string when present")
	}
	if string(userData["version"]) != "1" {
		if len(userData["version"]) == 0 || (userData["version"][0] != '-' && (userData["version"][0] < '0' || userData["version"][0] > '9')) {
			return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("version must be integer 1")
		}
		return nil, ConnectorResourceLSTV1RejectSemantic, errors.New("version must be integer 1")
	}
	var request connectorResourceLSTV1RequestWire
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, ConnectorResourceLSTV1RejectBodyParse, err
	}
	if request.UsrID != authoritativeAgentID || request.DevID != authoritativeAgentID || !connectorResourceLSTV1AgentIDPattern.MatchString(authoritativeAgentID) {
		return nil, ConnectorResourceLSTV1RejectAgentBinding, errors.New("usrId and devId must equal the authenticated registered agent")
	}
	if request.AspID != ConnectorResourceLSTV1AspID || request.UsrData.Query != ConnectorResourceLSTV1Query || request.UsrData.Version != ConnectorResourceLSTV1Version {
		return nil, ConnectorResourceLSTV1RejectSemantic, errors.New("request discriminator is invalid")
	}
	if err := ValidateConnectorResourceLSTV1Nonce(request.UsrData.RequestNonce); err != nil {
		return nil, ConnectorResourceLSTV1RejectSemantic, err
	}
	if !connectorResourceLSTV1ConnectorIDPattern.MatchString(request.UsrData.ConnectorID) {
		return nil, ConnectorResourceLSTV1RejectSemantic, errors.New("connector_id is invalid")
	}
	if request.UsrData.ExpectedResourceID != nil {
		if err := ValidateConnectorResourceLSTV1ResourceID(*request.UsrData.ExpectedResourceID); err != nil {
			return nil, ConnectorResourceLSTV1RejectSemantic, err
		}
	}
	return &request, "", nil
}

func parseConnectorResourceLSTV1Result(body []byte, request *connectorResourceLSTV1RequestWire) (*connectorResourceLSTV1ResultWire, string, error) {
	outer, class, err := connectorResourceLSTV1RawObject(body)
	if err != nil {
		return nil, class, err
	}
	errCodeRaw, ok := outer["errCode"]
	if !ok {
		return nil, ConnectorResourceLSTV1RejectMissingField, errors.New("missing errCode")
	}
	if string(errCodeRaw) == "null" || len(errCodeRaw) == 0 || errCodeRaw[0] != '"' {
		return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("errCode must be a string")
	}
	var errCode string
	if err := json.Unmarshal(errCodeRaw, &errCode); err != nil {
		return nil, ConnectorResourceLSTV1RejectWrongType, err
	}
	if errCode == "0" {
		outer, class, err = connectorResourceLSTV1ExactObject(body, []string{"errCode", "list"}, []string{"errCode", "list"})
		if err != nil {
			return nil, class, err
		}
		if string(outer["list"]) == "null" || len(outer["list"]) == 0 || outer["list"][0] != '{' {
			return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("list must be an object")
		}
		list, class, err := connectorResourceLSTV1ExactObject(outer["list"],
			[]string{"query", "version", "agent_id", "connector_id", "resource_id", "connector_routing_id", "knock_resource_id", "found_existing"},
			[]string{"query", "version", "agent_id", "connector_id", "resource_id", "connector_routing_id", "knock_resource_id", "crid", "found_existing"})
		if err != nil {
			return nil, class, err
		}
		for _, key := range []string{"query", "agent_id", "connector_id", "resource_id", "connector_routing_id", "knock_resource_id"} {
			if string(list[key]) == "null" || len(list[key]) == 0 || list[key][0] != '"' {
				return nil, ConnectorResourceLSTV1RejectWrongType, fmt.Errorf("%s must be a string", key)
			}
		}
		if string(list["version"]) != "1" {
			if len(list["version"]) == 0 || (list["version"][0] < '0' || list["version"][0] > '9') {
				return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("version must be integer 1")
			}
			return nil, ConnectorResourceLSTV1RejectSemantic, errors.New("version must be integer 1")
		}
		if string(list["found_existing"]) != "true" && string(list["found_existing"]) != "false" {
			return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("found_existing must be boolean")
		}
		if rawCRID, ok := list["crid"]; ok && (string(rawCRID) == "null" || len(rawCRID) == 0 || rawCRID[0] != '"') {
			return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("crid must be a string when present")
		}
		var result connectorResourceLSTV1ResultWire
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, ConnectorResourceLSTV1RejectBodyParse, err
		}
		if result.List == nil {
			return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("list must be present")
		}
		if result.List.Query != ConnectorResourceLSTV1Query || result.List.Version != ConnectorResourceLSTV1Version {
			return nil, ConnectorResourceLSTV1RejectSemantic, errors.New("success discriminator is invalid")
		}
		if request != nil {
			if result.List.AgentID != request.DevID || result.List.ConnectorID != request.UsrData.ConnectorID {
				return nil, ConnectorResourceLSTV1RejectRequestBinding, errors.New("success does not echo the exact request identity")
			}
		}
		if !connectorResourceLSTV1AgentIDPattern.MatchString(result.List.AgentID) || !connectorResourceLSTV1ConnectorIDPattern.MatchString(result.List.ConnectorID) {
			return nil, ConnectorResourceLSTV1RejectSemantic, errors.New("success identity is invalid")
		}
		if err := ValidateConnectorResourceLSTV1ResourceID(result.List.ResourceID); err != nil {
			return nil, ConnectorResourceLSTV1RejectSemantic, err
		}
		if err := ValidateConnectorResourceLSTV1RoutingID(result.List.ConnectorRoutingID); err != nil {
			return nil, ConnectorResourceLSTV1RejectSemantic, err
		}
		if err := ValidateConnectorResourceLSTV1KnockResourceID(result.List.KnockResourceID); err != nil {
			return nil, ConnectorResourceLSTV1RejectSemantic, err
		}
		if result.List.ResourceID == result.List.KnockResourceID || result.List.ConnectorRoutingID == result.List.KnockResourceID {
			return nil, ConnectorResourceLSTV1RejectResourceBinding, errors.New("success identity/routing/admission values are cross-wired")
		}
		if request != nil && request.UsrData.ExpectedResourceID != nil && result.List.ResourceID != *request.UsrData.ExpectedResourceID {
			return nil, ConnectorResourceLSTV1RejectResourceBinding, errors.New("success violates expected_resource_id continuity")
		}
		if result.List.CRID != nil {
			outcome, matchErr := deriveCRIDV1KeyMatchExpectation(*result.List.CRID, result.List.ResourceID)
			if matchErr != nil {
				return nil, ConnectorResourceLSTV1RejectSemantic, matchErr
			}
			if outcome != CRIDV1OutcomeMatch {
				return nil, ConnectorResourceLSTV1RejectCRIDBinding, errors.New("crid does not match resource_id")
			}
		}
		return &result, "", nil
	}

	if _, hasList := outer["list"]; hasList {
		return nil, ConnectorResourceLSTV1RejectListOnError, errors.New("error result must omit list")
	}
	outer, class, err = connectorResourceLSTV1ExactObject(body, []string{"errCode", "errMsg"}, []string{"errCode", "errMsg", "retryAfterSeconds"})
	if err != nil {
		return nil, class, err
	}
	if string(outer["errMsg"]) == "null" || len(outer["errMsg"]) == 0 || outer["errMsg"][0] != '"' {
		return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("errMsg must be a string")
	}
	spec, ok := connectorResourceLSTV1ErrorSpecs[errCode]
	if !ok {
		return nil, ConnectorResourceLSTV1RejectUnknownError, errors.New("unknown Connector resource error code")
	}
	var parsedRetry int64
	if raw, retryPresent := outer["retryAfterSeconds"]; retryPresent {
		if len(raw) == 0 {
			return nil, ConnectorResourceLSTV1RejectRetryInvalid, errors.New("retryAfterSeconds must be a positive integer")
		}
		for _, digit := range raw {
			if digit < '0' || digit > '9' {
				return nil, ConnectorResourceLSTV1RejectRetryInvalid, errors.New("retryAfterSeconds must use a positive integer lexeme")
			}
		}
		if err := json.Unmarshal(raw, &parsedRetry); err != nil || parsedRetry < 1 || parsedRetry > ConnectorResourceLSTV1MaxRetryAfterSeconds {
			return nil, ConnectorResourceLSTV1RejectRetryInvalid, errors.New("retryAfterSeconds is outside the permitted range")
		}
	}
	var result connectorResourceLSTV1ResultWire
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, ConnectorResourceLSTV1RejectBodyParse, err
	}
	if result.ErrMsg != spec.message {
		return nil, ConnectorResourceLSTV1RejectSemantic, errors.New("error message drift")
	}
	_, retryPresent := outer["retryAfterSeconds"]
	if spec.retry == connectorResourceRetryRequired && !retryPresent {
		return nil, ConnectorResourceLSTV1RejectRetryMissing, errors.New("retryAfterSeconds is required")
	}
	if spec.retry == connectorResourceRetryForbidden && retryPresent {
		return nil, ConnectorResourceLSTV1RejectRetryUnexpected, errors.New("retryAfterSeconds is forbidden")
	}
	if retryPresent {
		if result.RetryAfterSeconds == nil || int64(*result.RetryAfterSeconds) != parsedRetry {
			return nil, ConnectorResourceLSTV1RejectRetryInvalid, errors.New("retryAfterSeconds is outside the permitted range")
		}
	}
	return &result, "", nil
}

func connectorResourceLSTV1RawObject(body []byte) (map[string]json.RawMessage, string, error) {
	if len(body) > ConnectorResourceLSTV1MaxPlaintextBodyBytes {
		return nil, ConnectorResourceLSTV1RejectPacketSize, errors.New("body exceeds operational unfragmented limit")
	}
	if !utf8.Valid(body) {
		return nil, ConnectorResourceLSTV1RejectBodyParse, errors.New("body is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, ConnectorResourceLSTV1RejectBodyParse, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, ConnectorResourceLSTV1RejectBodyParse, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, ConnectorResourceLSTV1RejectBodyParse, err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("body must be an object")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil || object == nil {
		return nil, ConnectorResourceLSTV1RejectWrongType, errors.New("body must be an object")
	}
	return object, "", nil
}

func connectorResourceLSTV1ExactObject(body []byte, required, allowed []string) (map[string]json.RawMessage, string, error) {
	object, class, err := connectorResourceLSTV1RawObject(body)
	if err != nil {
		return nil, class, err
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowedSet[key]; !ok {
			return nil, ConnectorResourceLSTV1RejectUnknownField, fmt.Errorf("unknown field %q", key)
		}
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return nil, ConnectorResourceLSTV1RejectMissingField, fmt.Errorf("missing field %q", key)
		}
	}
	return object, "", nil
}

func ValidateConnectorResourceLSTV1Nonce(value string) error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != ConnectorResourceLSTV1NonceBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return errors.New("request_nonce must be canonical unpadded base64url for exactly 32 bytes")
	}
	return nil
}

func ValidateConnectorResourceLSTV1ResourceID(value string) error {
	if len(value) != ConnectorResourceLSTV1ResourceIDChars {
		return errors.New("resource_id has invalid encoded length")
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(der) != ConnectorResourceLSTV1ResourceIDBytes || base64.RawURLEncoding.EncodeToString(der) != value {
		return errors.New("resource_id is not canonical unpadded base64url")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return errors.New("resource_id is not DER SubjectPublicKeyInfo")
	}
	ecdsaKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || ecdsaKey.Curve != elliptic.P256() || ecdsaKey.X == nil || ecdsaKey.Y == nil || !ecdsaKey.Curve.IsOnCurve(ecdsaKey.X, ecdsaKey.Y) {
		return errors.New("resource_id must contain a P-256 public key")
	}
	canonical, err := x509.MarshalPKIXPublicKey(ecdsaKey)
	if err != nil || !bytes.Equal(canonical, der) {
		return errors.New("resource_id DER is not canonical")
	}
	return nil
}

func ValidateConnectorResourceLSTV1RoutingID(value string) error {
	if len(value) != ConnectorResourceLSTV1RoutingIDChars || !strings.HasPrefix(value, ConnectorResourceLSTV1RoutingIDPrefix) {
		return errors.New("connector_routing_id has invalid shape")
	}
	payload := strings.TrimPrefix(value, ConnectorResourceLSTV1RoutingIDPrefix)
	decoded, err := connectorResourceLSTV1RoutingEncoding.DecodeString(strings.ToUpper(payload))
	if err != nil || len(decoded) != ConnectorResourceLSTV1RoutingDigestBytes || strings.ToLower(connectorResourceLSTV1RoutingEncoding.EncodeToString(decoded)) != payload {
		return errors.New("connector_routing_id is not canonical lowercase unpadded base32")
	}
	return nil
}

func ValidateConnectorResourceLSTV1KnockResourceID(value string) error {
	if value == "" || len([]byte(value)) > ConnectorResourceLSTV1KnockResourceIDMax || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return errors.New("knock_resource_id is not a transport-safe opaque identifier")
	}
	return nil
}
