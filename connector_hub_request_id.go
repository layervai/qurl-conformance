package conformance

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"unicode/utf8"
)

const (
	// ConnectorHubRequestIDArtifactID identifies the byte-level private replay
	// key contract used by every Connector Hub worker.
	ConnectorHubRequestIDArtifactID = "qurl-connector-hub-request-id-v1-vectors"
	// ConnectorHubRequestIDSchemaVersion is the only artifact schema accepted by
	// this release.
	ConnectorHubRequestIDSchemaVersion = 1

	ConnectorHubRequestIDDigest          = "SHA-256"
	ConnectorHubRequestIDOutputEncoding  = "lowercase_hex"
	ConnectorHubRequestIDDomain          = "layerv:qurl:connector-hub-request-id:v1"
	ConnectorHubRequestIDDomainSuffixHex = "00"
	ConnectorHubRequestIDFrameEncoding   = "u8_field_tag_then_u16be_byte_length_then_value"

	ConnectorHubRequestIDEnvironmentTagHex = "01"
	ConnectorHubRequestIDOperationTagHex   = "02"
	ConnectorHubRequestIDPeerTagHex        = "03"
	ConnectorHubRequestIDNonceTagHex       = "04"

	ConnectorHubRequestIDOperationIssue   = "IssueAssignment"
	ConnectorHubRequestIDOperationRefresh = "RefreshAssignment"
	ConnectorHubRequestIDOperationRecover = "IssueCredentialRecovery"
	connectorHubRequestIDDescription      = "Byte-exact private replay-key derivation contract for authenticated assignment LST handled by Connector Hub workers. The SDK supplies only a per-logical-operation request_nonce; Hub derives hub_request_id after NHP authentication and sends it only to the separately permissioned Connector Authority IssueAssignment, RefreshAssignment, or IssueCredentialRecovery operation."

	ConnectorHubRequestIDEnvironmentNormalization = "none"
	ConnectorHubRequestIDPeerFixtureEncoding      = "canonical_base64_std_padded"
	ConnectorHubRequestIDPeerHashEncoding         = "raw_32_bytes"
	ConnectorHubRequestIDNonceFixtureEncoding     = "canonical_base64url_unpadded"
	ConnectorHubRequestIDNonceHashEncoding        = "raw_32_bytes"

	ConnectorHubRequestIDMinEnvironmentBytes = 1
	ConnectorHubRequestIDMaxEnvironmentBytes = 32
	ConnectorHubRequestIDPeerBytes           = 32
	ConnectorHubRequestIDNonceBytes          = 32
)

var (
	connectorHubRequestIDEnvironmentPattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
	connectorHubRequestIDHexPattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// ErrConnectorHubRequestIDEnvironment identifies an invalid immutable Hub
	// environment. It never includes the rejected value.
	ErrConnectorHubRequestIDEnvironment = errors.New("conformance: invalid Connector Hub request-ID environment")
	// ErrConnectorHubRequestIDOperation identifies a value outside the closed
	// separately permissioned Hub authority operations.
	ErrConnectorHubRequestIDOperation = errors.New("conformance: invalid Connector Hub request-ID operation")
	// ErrConnectorHubRequestIDPeer identifies a peer key that is not exactly one
	// raw X25519 public-key width.
	ErrConnectorHubRequestIDPeer = errors.New("conformance: invalid Connector Hub request-ID peer key")
	// ErrConnectorHubRequestIDNonce identifies a logical-request nonce that is
	// not exactly 32 decoded bytes.
	ErrConnectorHubRequestIDNonce = errors.New("conformance: invalid Connector Hub request-ID nonce")
)

var connectorHubRequestIDFieldOrder = []string{
	"environment",
	"operation",
	"authenticated_peer_public_key",
	"request_nonce",
}

// ConnectorHubRequestIDFile freezes the only request-ID preimage used by the
// public-UDP Connector Hub. It is separate from both the public LST and private
// Lambda schemas: the SDK supplies only request_nonce, and the authority treats
// the resulting hub_request_id as opaque.
type ConnectorHubRequestIDFile struct {
	Artifact      string                        `json:"artifact"`
	SchemaVersion int                           `json:"schema_version"`
	Description   string                        `json:"description"`
	Contract      ConnectorHubRequestIDContract `json:"contract"`
	Cases         []ConnectorHubRequestIDCase   `json:"cases"`
}

// ConnectorHubRequestIDContract is the complete consumer-neutral byte profile.
type ConnectorHubRequestIDContract struct {
	Digest                   string   `json:"digest"`
	OutputEncoding           string   `json:"output_encoding"`
	DomainASCII              string   `json:"domain_ascii"`
	DomainSuffixHex          string   `json:"domain_suffix_hex"`
	FrameEncoding            string   `json:"frame_encoding"`
	EnvironmentTagHex        string   `json:"environment_tag_hex"`
	OperationTagHex          string   `json:"operation_tag_hex"`
	PeerTagHex               string   `json:"peer_tag_hex"`
	NonceTagHex              string   `json:"nonce_tag_hex"`
	FieldOrder               []string `json:"field_order"`
	EnvironmentPattern       string   `json:"environment_pattern"`
	EnvironmentMinBytes      int      `json:"environment_min_bytes"`
	EnvironmentMaxBytes      int      `json:"environment_max_bytes"`
	EnvironmentNormalization string   `json:"environment_normalization"`
	Operations               []string `json:"operations"`
	PeerDecodedBytes         int      `json:"peer_decoded_bytes"`
	PeerFixtureEncoding      string   `json:"peer_fixture_encoding"`
	PeerHashEncoding         string   `json:"peer_hash_encoding"`
	NonceDecodedBytes        int      `json:"nonce_decoded_bytes"`
	NonceFixtureEncoding     string   `json:"nonce_fixture_encoding"`
	NonceHashEncoding        string   `json:"nonce_hash_encoding"`
	ExcludedInputs           []string `json:"excluded_inputs"`
}

// ConnectorHubRequestIDCase is one exact byte KAT. Substitution cases change
// exactly the named input from NotEqualTo and must derive a distinct ID.
type ConnectorHubRequestIDCase struct {
	Name                          string `json:"name"`
	Environment                   string `json:"environment"`
	Operation                     string `json:"operation"`
	AuthenticatedPeerPublicKeyB64 string `json:"authenticated_peer_public_key_b64"`
	RequestNonce                  string `json:"request_nonce"`
	PreimageHex                   string `json:"preimage_hex"`
	HubRequestID                  string `json:"hub_request_id"`
	MutatedField                  string `json:"mutated_field,omitempty"`
	NotEqualTo                    string `json:"not_equal_to,omitempty"`
}

// DeriveConnectorHubRequestID computes the canonical private replay identifier
// from immutable deployment scope and authenticated logical-request inputs.
// operation must be the Hub-selected authority operation after strict LST mode
// validation; authenticatedPeerPublicKey and requestNonce are raw decoded
// bytes. NHP timestamp and application-body bytes are deliberately absent: a
// fresh packet retry changes the timestamp, while Authority's existing
// operation-specific request fingerprint rejects nonce reuse with changed
// semantics.
func DeriveConnectorHubRequestID(environment, operation string, authenticatedPeerPublicKey, requestNonce []byte) (string, error) {
	preimage, err := connectorHubRequestIDPreimage(environment, operation, authenticatedPeerPublicKey, requestNonce)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:]), nil
}

func connectorHubRequestIDPreimage(environment, operation string, authenticatedPeerPublicKey, requestNonce []byte) ([]byte, error) {
	if !connectorHubRequestIDEnvironmentPattern.MatchString(environment) || len(environment) < ConnectorHubRequestIDMinEnvironmentBytes || len(environment) > ConnectorHubRequestIDMaxEnvironmentBytes {
		return nil, ErrConnectorHubRequestIDEnvironment
	}
	if operation != ConnectorHubRequestIDOperationIssue && operation != ConnectorHubRequestIDOperationRefresh && operation != ConnectorHubRequestIDOperationRecover {
		return nil, ErrConnectorHubRequestIDOperation
	}
	if len(authenticatedPeerPublicKey) != ConnectorHubRequestIDPeerBytes {
		return nil, ErrConnectorHubRequestIDPeer
	}
	if len(requestNonce) != ConnectorHubRequestIDNonceBytes {
		return nil, ErrConnectorHubRequestIDNonce
	}

	preimage := make([]byte, 0, len(ConnectorHubRequestIDDomain)+1+4*3+len(environment)+len(operation)+len(authenticatedPeerPublicKey)+len(requestNonce))
	preimage = append(preimage, ConnectorHubRequestIDDomain...)
	preimage = append(preimage, 0)
	preimage = appendConnectorHubRequestIDFrame(preimage, 0x01, []byte(environment))
	preimage = appendConnectorHubRequestIDFrame(preimage, 0x02, []byte(operation))
	preimage = appendConnectorHubRequestIDFrame(preimage, 0x03, authenticatedPeerPublicKey)
	preimage = appendConnectorHubRequestIDFrame(preimage, 0x04, requestNonce)
	return preimage, nil
}

func appendConnectorHubRequestIDFrame(dst []byte, tag byte, value []byte) []byte {
	// connectorHubRequestIDPreimage validates every field at 32 bytes or less
	// before framing, so the uint16 length conversion cannot truncate.
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	dst = append(dst, tag)
	dst = append(dst, length[:]...)
	return append(dst, value...)
}

// ParseConnectorHubRequestIDFile strictly parses and independently recomputes
// every embedded preimage and substitution result.
func ParseConnectorHubRequestIDFile(data []byte) (*ConnectorHubRequestIDFile, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("conformance: Connector Hub request-ID file is not valid UTF-8")
	}
	var file ConnectorHubRequestIDFile
	if err := strictDecodeArtifact(data, &file); err != nil {
		return nil, fmt.Errorf("conformance: parse Connector Hub request-ID file: %w", err)
	}
	if file.Artifact != ConnectorHubRequestIDArtifactID || file.SchemaVersion != ConnectorHubRequestIDSchemaVersion || file.Description != connectorHubRequestIDDescription {
		return nil, errors.New("conformance: Connector Hub request-ID artifact identity is invalid")
	}
	if err := validateConnectorHubRequestIDContract(file.Contract); err != nil {
		return nil, err
	}
	if err := validateConnectorHubRequestIDCases(file.Cases); err != nil {
		return nil, err
	}
	return &file, nil
}

func validateConnectorHubRequestIDContract(contract ConnectorHubRequestIDContract) error {
	want := ConnectorHubRequestIDContract{
		Digest: ConnectorHubRequestIDDigest, OutputEncoding: ConnectorHubRequestIDOutputEncoding,
		DomainASCII: ConnectorHubRequestIDDomain, DomainSuffixHex: ConnectorHubRequestIDDomainSuffixHex,
		FrameEncoding:     ConnectorHubRequestIDFrameEncoding,
		EnvironmentTagHex: ConnectorHubRequestIDEnvironmentTagHex, OperationTagHex: ConnectorHubRequestIDOperationTagHex,
		PeerTagHex: ConnectorHubRequestIDPeerTagHex, NonceTagHex: ConnectorHubRequestIDNonceTagHex,
		FieldOrder:          connectorHubRequestIDFieldOrder,
		EnvironmentPattern:  connectorHubRequestIDEnvironmentPattern.String(),
		EnvironmentMinBytes: ConnectorHubRequestIDMinEnvironmentBytes, EnvironmentMaxBytes: ConnectorHubRequestIDMaxEnvironmentBytes,
		EnvironmentNormalization: ConnectorHubRequestIDEnvironmentNormalization,
		Operations:               []string{ConnectorHubRequestIDOperationIssue, ConnectorHubRequestIDOperationRefresh, ConnectorHubRequestIDOperationRecover},
		PeerDecodedBytes:         ConnectorHubRequestIDPeerBytes, PeerFixtureEncoding: ConnectorHubRequestIDPeerFixtureEncoding,
		PeerHashEncoding:  ConnectorHubRequestIDPeerHashEncoding,
		NonceDecodedBytes: ConnectorHubRequestIDNonceBytes, NonceFixtureEncoding: ConnectorHubRequestIDNonceFixtureEncoding,
		NonceHashEncoding: ConnectorHubRequestIDNonceHashEncoding,
		ExcludedInputs:    []string{"nhp_send_timestamp", "nhp_transaction_id", "exact_body_digest", "source_address", "hub_request_id_in_public_body"},
	}
	if !reflect.DeepEqual(contract, want) {
		return errors.New("conformance: Connector Hub request-ID contract drift")
	}
	return nil
}

func validateConnectorHubRequestIDCases(cases []ConnectorHubRequestIDCase) error {
	required := []string{"baseline_refresh", "environment_substitution", "operation_substitution", "recovery_operation_substitution", "peer_substitution", "nonce_substitution"}
	if len(cases) != len(required) {
		return fmt.Errorf("conformance: Connector Hub request-ID case count = %d, want %d", len(cases), len(required))
	}
	byName := make(map[string]ConnectorHubRequestIDCase, len(cases))
	requestIDs := make(map[string]struct{}, len(cases))
	for _, test := range cases {
		if test.Name == "" {
			return errors.New("conformance: Connector Hub request-ID case name is empty")
		}
		if _, duplicate := byName[test.Name]; duplicate {
			return errors.New("conformance: duplicate Connector Hub request-ID case")
		}
		peer, err := decodeCanonicalConnectorHubRequestIDPeer(test.AuthenticatedPeerPublicKeyB64)
		if err != nil {
			return err
		}
		nonce, err := DecodeConnectorHubRequestNonce(test.RequestNonce)
		if err != nil {
			return err
		}
		preimage, err := connectorHubRequestIDPreimage(test.Environment, test.Operation, peer, nonce)
		if err != nil {
			return err
		}
		if test.PreimageHex != hex.EncodeToString(preimage) {
			return errors.New("conformance: Connector Hub request-ID preimage mismatch")
		}
		// Re-derive through the exported consumer path so every substitution KAT,
		// not only the baseline unit test, also guards its complete behavior.
		requestID, err := DeriveConnectorHubRequestID(test.Environment, test.Operation, peer, nonce)
		if err != nil || requestID != test.HubRequestID || !connectorHubRequestIDHexPattern.MatchString(test.HubRequestID) {
			return errors.New("conformance: Connector Hub request-ID KAT mismatch")
		}
		if _, duplicate := requestIDs[test.HubRequestID]; duplicate {
			return errors.New("conformance: Connector Hub request-ID cases are not unique")
		}
		requestIDs[test.HubRequestID] = struct{}{}
		byName[test.Name] = test
	}
	for _, name := range required {
		if _, ok := byName[name]; !ok {
			return errors.New("conformance: required Connector Hub request-ID case is missing")
		}
	}
	for _, test := range cases {
		if test.NotEqualTo == "" {
			if test.MutatedField != "" || test.Name != "baseline_refresh" {
				return errors.New("conformance: Connector Hub request-ID base case mutation metadata is invalid")
			}
			continue
		}
		base, ok := byName[test.NotEqualTo]
		if !ok || test.NotEqualTo != "baseline_refresh" || test.MutatedField == "" || test.HubRequestID == base.HubRequestID {
			return errors.New("conformance: Connector Hub request-ID substitution case did not separate")
		}
		if err := validateConnectorHubRequestIDSingleMutation(base, test); err != nil {
			return err
		}
	}
	return nil
}

func validateConnectorHubRequestIDSingleMutation(base, changed ConnectorHubRequestIDCase) error {
	differences := make([]string, 0, 4)
	if base.Environment != changed.Environment {
		differences = append(differences, "environment")
	}
	if base.Operation != changed.Operation {
		differences = append(differences, "operation")
	}
	if base.AuthenticatedPeerPublicKeyB64 != changed.AuthenticatedPeerPublicKeyB64 {
		differences = append(differences, "authenticated_peer_public_key")
	}
	if base.RequestNonce != changed.RequestNonce {
		differences = append(differences, "request_nonce")
	}
	if len(differences) != 1 || differences[0] != changed.MutatedField {
		return errors.New("conformance: Connector Hub request-ID substitution does not change exactly its named field")
	}
	return nil
}

func decodeCanonicalConnectorHubRequestIDPeer(value string) ([]byte, error) {
	return decodeCanonicalConnectorHubRequestIDField(base64.StdEncoding, value, ConnectorHubRequestIDPeerBytes, ErrConnectorHubRequestIDPeer)
}

// DecodeConnectorHubRequestNonce strictly decodes the public LST request_nonce
// grammar shared by SDKs and the Hub. The returned raw bytes are suitable for
// DeriveConnectorHubRequestID.
func DecodeConnectorHubRequestNonce(value string) ([]byte, error) {
	return decodeCanonicalConnectorHubRequestIDField(base64.RawURLEncoding, value, ConnectorHubRequestIDNonceBytes, ErrConnectorHubRequestIDNonce)
}

func decodeCanonicalConnectorHubRequestIDField(encoding *base64.Encoding, value string, wantBytes int, rejectErr error) ([]byte, error) {
	decoded, err := encoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != wantBytes || encoding.EncodeToString(decoded) != value {
		return nil, rejectErr
	}
	return decoded, nil
}
