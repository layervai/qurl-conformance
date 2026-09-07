package conformance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	PrivateUploadV1ArtifactID    = "qurl-private-upload-v1-vectors"
	PrivateUploadV1SchemaVersion = 1
	PrivateUploadV1Description   = "Byte-exact application signing contract for private upload and capability refresh through an authenticated NHP 1.1 session. It binds the exact protected authority, method, path, body, caller identity, audience, and request identity without an HTTP bearer credential."

	PrivateUploadV1NHPVersion           = "1.1"
	PrivateUploadV1Path                 = "/internal/v1/uploads"
	PrivateUploadV1UploadMethod         = "POST"
	PrivateUploadV1RefreshMethod        = "PATCH"
	PrivateUploadV1UploadAuthDomain     = "LV-QURL-UPLOAD-AUTH-V1"
	PrivateUploadV1UploadRequestDomain  = "LV-QURL-UPLOAD-REQUEST-V1"
	PrivateUploadV1RefreshAuthDomain    = "LV-QURL-UPLOAD-REFRESH-AUTH-V1"
	PrivateUploadV1RefreshRequestDomain = "LV-QURL-UPLOAD-REFRESH-REQUEST-V1"
	PrivateUploadV1FrameEncoding        = "u32be_byte_length_then_exact_utf8_bytes"
	PrivateUploadV1SignatureAlgorithm   = "ECDSA_P-256_SHA-256"
	PrivateUploadV1SignatureEncoding    = "canonical_der_base64url_unpadded_low_s"
	PrivateUploadV1PrivateKeyEncoding   = "pkcs8_der_base64url_unpadded"
	PrivateUploadV1PublicKeyEncoding    = "der_spki_base64url_unpadded"
	PrivateUploadV1ContentDigest        = "sha-256=:canonical_standard_base64_sha256:"
	PrivateUploadV1AudienceKeyIDRule    = "regex:^key_[A-Za-z0-9]{12}$"
	PrivateUploadV1ClientIDRule         = "regex:^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
	PrivateUploadV1KeyIDRule            = "regex:^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
	PrivateUploadV1UploadRequestIDRule  = "regex:^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
	PrivateUploadV1UploadHandleRule     = "regex:^upl_[A-Za-z0-9_-]{43}$"
	PrivateUploadV1AuthorityExpiryRule  = "rfc3339_utc_whole_seconds_uppercase_z"
	PrivateUploadV1BodyLengthRule       = "positive_canonical_decimal_equal_to_exact_body_byte_length"
	PrivateUploadV1MediaTypeRule        = "regex:^[!#$%&'*+.^_`|~0-9a-z-]+/[!#$%&'*+.^_`|~0-9a-z-]+$"
	PrivateUploadV1MediaTypeSubtypeRule = "not_exactly_star"
	PrivateUploadV1FilenameEncoding     = "utf8_then_base64url_unpadded"
	PrivateUploadV1DisplayFilenameRule  = "nfc_utf8_1_to_180_bytes_no_leading_or_trailing_unicode_whitespace_not_dot_or_dotdot_no_slash_or_backslash_no_unicode_control_cf_co_zl_or_zp"
	PrivateUploadV1AuthFailureStatus    = 401
	PrivateUploadV1AuthFailureCode      = "invalid_upload_auth"
)

var (
	privateUploadV1UploadFields = []string{
		"method", "authority", "path", "timestamp_unix_decimal", "nonce", "client_id", "key_id",
		"audience_key_id", "body_sha256_hex", "body_length_decimal", "media_type", "display_filename_utf8",
		"authority_expires_at", "upload_request_id",
	}
	privateUploadV1UploadStableFields = []string{
		"client_id", "audience_key_id", "body_sha256_hex", "body_length_decimal", "media_type",
		"display_filename_utf8", "authority_expires_at", "upload_request_id",
	}
	privateUploadV1RefreshFields = []string{
		"method", "authority", "path", "timestamp_unix_decimal", "nonce", "client_id", "key_id",
		"body_sha256_hex", "body_length_decimal", "upload_request_id",
	}
	privateUploadV1RefreshStableFields = []string{
		"client_id", "upload_handle", "max_batch_size_decimal", "max_link_ttl_seconds_decimal",
		"authority_expires_at", "upload_request_id",
	}
	privateUploadV1RefreshBodyFields = []string{
		"upload_handle", "upload_request_id", "max_batch_size", "max_link_ttl_seconds", "authority_expires_at",
	}
	privateUploadV1RequiredUploadHeaders = []string{
		"Content-Type", "Content-Length", "Content-Digest", "X-LayerV-Client-ID", "X-LayerV-Key-ID",
		"X-LayerV-Timestamp", "X-LayerV-Nonce", "X-LayerV-Audience-Key-ID", "X-LayerV-Authority-Expires-At",
		"X-LayerV-Upload-Request-ID", "X-LayerV-Filename-B64", "X-LayerV-Upload-Signature",
	}
	privateUploadV1RequiredRefreshHeaders = []string{
		"Content-Type", "Content-Length", "Content-Digest", "X-LayerV-Client-ID", "X-LayerV-Key-ID",
		"X-LayerV-Timestamp", "X-LayerV-Nonce", "X-LayerV-Upload-Request-ID", "X-LayerV-Upload-Signature",
	}
	privateUploadV1UploadForbiddenHeaders  = []string{"Authorization"}
	privateUploadV1RefreshForbiddenHeaders = []string{"Authorization", "X-LayerV-Audience-Key-ID", "X-LayerV-Filename-B64"}
	privateUploadV1AudiencePattern         = regexp.MustCompile(`^key_[A-Za-z0-9]{12}$`)
	privateUploadV1HexDigestPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	privateUploadV1IDPattern               = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	privateUploadV1UUIDV4Pattern           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	privateUploadV1UploadHandlePattern     = regexp.MustCompile(`^upl_[A-Za-z0-9_-]{43}$`)
	privateUploadV1MediaTypePattern        = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9a-z-]+/[!#$%&'*+.^_`|~0-9a-z-]+$")
)

type PrivateUploadV1File struct {
	Artifact                string                                  `json:"artifact"`
	SchemaVersion           int                                     `json:"schema_version"`
	Description             string                                  `json:"description"`
	Contract                PrivateUploadV1Contract                 `json:"contract"`
	FixtureKey              PrivateUploadV1FixtureKey               `json:"fixture_key"`
	UploadGolden            PrivateUploadV1UploadGolden             `json:"upload_golden"`
	RefreshGolden           PrivateUploadV1RefreshGolden            `json:"refresh_golden"`
	RejectCases             []PrivateUploadV1RejectCase             `json:"reject_cases"`
	ConstructionRejectCases []PrivateUploadV1ConstructionRejectCase `json:"construction_reject_cases"`
}

type PrivateUploadV1Contract struct {
	NHPProtocolVersion      string                           `json:"nhp_protocol_version"`
	TransportScope          string                           `json:"transport_scope"`
	FreshnessReplayScope    string                           `json:"freshness_replay_scope"`
	Path                    string                           `json:"path"`
	AuthorityRule           string                           `json:"authority_rule"`
	AudienceKeyIDRule       string                           `json:"audience_key_id_rule"`
	ClientIDRule            string                           `json:"client_id_rule"`
	KeyIDRule               string                           `json:"key_id_rule"`
	UploadRequestIDRule     string                           `json:"upload_request_id_rule"`
	UploadHandleRule        string                           `json:"upload_handle_rule"`
	AuthorityExpiresAtRule  string                           `json:"authority_expires_at_rule"`
	BodyLengthRule          string                           `json:"body_length_rule"`
	FrameEncoding           string                           `json:"frame_encoding"`
	SignatureAlgorithm      string                           `json:"signature_algorithm"`
	SignatureEncoding       string                           `json:"signature_encoding"`
	PrivateKeyEncoding      string                           `json:"private_key_encoding"`
	PublicKeyEncoding       string                           `json:"public_key_encoding"`
	ContentDigestEncoding   string                           `json:"content_digest_encoding"`
	NonceEncoding           string                           `json:"nonce_encoding"`
	NonceDecodedBytes       int                              `json:"nonce_decoded_bytes"`
	TimestampMaxSkewSeconds int                              `json:"timestamp_max_skew_seconds"`
	Upload                  PrivateUploadV1OperationContract `json:"upload"`
	Refresh                 PrivateUploadV1OperationContract `json:"refresh"`
	RejectClasses           []string                         `json:"reject_classes"`
	RejectClassPrecedence   []string                         `json:"reject_class_precedence"`
}

type PrivateUploadV1OperationContract struct {
	Method                   string   `json:"method"`
	SigningDomainASCII       string   `json:"signing_domain_ascii"`
	SigningDomainSeparator   string   `json:"signing_domain_separator_hex"`
	FieldOrder               []string `json:"field_order"`
	StableRequestDomainASCII string   `json:"stable_request_domain_ascii"`
	StableRequestFieldOrder  []string `json:"stable_request_field_order"`
	BodyEncoding             string   `json:"body_encoding"`
	BodyKeyOrder             []string `json:"body_key_order,omitempty"`
	BodyWhitespaceRule       string   `json:"body_whitespace_rule,omitempty"`
	BodyStringEscapingRule   string   `json:"body_string_escaping_rule,omitempty"`
	MediaTypeRule            string   `json:"media_type_rule,omitempty"`
	MediaTypeSubtypeRule     string   `json:"media_type_subtype_rule,omitempty"`
	FilenameEncoding         string   `json:"filename_encoding,omitempty"`
	DisplayFilenameRule      string   `json:"display_filename_rule,omitempty"`
	ContentTypeRule          string   `json:"content_type_rule"`
	RequiredHeaders          []string `json:"required_headers"`
	ForbiddenHeaders         []string `json:"forbidden_headers"`
}

type PrivateUploadV1FixtureKey struct {
	Warning                  string `json:"warning"`
	PrivateKeyPKCS8DERB64URL string `json:"private_key_pkcs8_der_b64url"`
	PublicKeyDERB64URL       string `json:"public_key_der_b64url"`
}

type PrivateUploadV1UploadGolden struct {
	Method                    string `json:"method"`
	Authority                 string `json:"authority"`
	Path                      string `json:"path"`
	TimestampUnixDecimal      string `json:"timestamp_unix_decimal"`
	Nonce                     string `json:"nonce"`
	ClientID                  string `json:"client_id"`
	KeyID                     string `json:"key_id"`
	AudienceKeyID             string `json:"audience_key_id"`
	BodyHex                   string `json:"body_hex"`
	BodySHA256Hex             string `json:"body_sha256_hex"`
	BodyLengthDecimal         string `json:"body_length_decimal"`
	ContentDigestHeader       string `json:"content_digest_header"`
	MediaType                 string `json:"media_type"`
	ContentType               string `json:"content_type"`
	DisplayFilenameUTF8       string `json:"display_filename_utf8"`
	FilenameB64URL            string `json:"filename_b64url"`
	AuthorityExpiresAt        string `json:"authority_expires_at"`
	UploadRequestID           string `json:"upload_request_id"`
	CanonicalHex              string `json:"canonical_hex"`
	SigningDigestHex          string `json:"signing_digest_hex"`
	SignatureDERB64URL        string `json:"signature_der_b64url"`
	StableRequestCanonicalHex string `json:"stable_request_canonical_hex"`
	StableRequestDigestHex    string `json:"stable_request_digest_hex"`
}

type PrivateUploadV1RefreshGolden struct {
	Method                    string `json:"method"`
	Authority                 string `json:"authority"`
	Path                      string `json:"path"`
	TimestampUnixDecimal      string `json:"timestamp_unix_decimal"`
	Nonce                     string `json:"nonce"`
	ClientID                  string `json:"client_id"`
	KeyID                     string `json:"key_id"`
	BodyHex                   string `json:"body_hex"`
	BodySHA256Hex             string `json:"body_sha256_hex"`
	BodyLengthDecimal         string `json:"body_length_decimal"`
	ContentDigestHeader       string `json:"content_digest_header"`
	ContentType               string `json:"content_type"`
	UploadHandle              string `json:"upload_handle"`
	MaxBatchSizeDecimal       string `json:"max_batch_size_decimal"`
	MaxLinkTTLSecondsDecimal  string `json:"max_link_ttl_seconds_decimal"`
	AuthorityExpiresAt        string `json:"authority_expires_at"`
	UploadRequestID           string `json:"upload_request_id"`
	CanonicalHex              string `json:"canonical_hex"`
	SigningDigestHex          string `json:"signing_digest_hex"`
	SignatureDERB64URL        string `json:"signature_der_b64url"`
	StableRequestCanonicalHex string `json:"stable_request_canonical_hex"`
	StableRequestDigestHex    string `json:"stable_request_digest_hex"`
}

type PrivateUploadV1RejectCase struct {
	Name        string                          `json:"name"`
	Base        string                          `json:"base"`
	Mutations   []PrivateUploadV1RejectMutation `json:"mutations"`
	Outcome     string                          `json:"outcome"`
	RejectClass string                          `json:"reject_class"`
	Status      int                             `json:"status"`
	ErrorCode   string                          `json:"error_code"`
}

type PrivateUploadV1RejectMutation struct {
	Target string `json:"target"`
	Field  string `json:"field"`
	Value  string `json:"value"`
}

type PrivateUploadV1ConstructionRejectCase struct {
	Name       string `json:"name"`
	Base       string `json:"base"`
	Field      string `json:"field"`
	Value      string `json:"value"`
	RejectRule string `json:"reject_rule"`
	Outcome    string `json:"outcome"`
}

func ParsePrivateUploadV1File(data []byte) (*PrivateUploadV1File, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("conformance: private-upload file is not valid UTF-8")
	}
	var file PrivateUploadV1File
	if err := strictDecodeArtifact(data, &file); err != nil {
		return nil, fmt.Errorf("conformance: parse private-upload file: %w", err)
	}
	if file.Artifact != PrivateUploadV1ArtifactID || file.SchemaVersion != PrivateUploadV1SchemaVersion || file.Description != PrivateUploadV1Description {
		return nil, errors.New("conformance: private-upload artifact identity is invalid")
	}
	if err := validatePrivateUploadV1Contract(file.Contract); err != nil {
		return nil, err
	}
	key, err := validatePrivateUploadV1FixtureKey(file.FixtureKey)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateUploadV1UploadGolden(file.UploadGolden, &key.PublicKey); err != nil {
		return nil, err
	}
	if err := validatePrivateUploadV1RefreshGolden(file.RefreshGolden, &key.PublicKey); err != nil {
		return nil, err
	}
	if err := validatePrivateUploadV1Rejects(&file, &key.PublicKey); err != nil {
		return nil, err
	}
	if err := validatePrivateUploadV1ConstructionRejects(&file); err != nil {
		return nil, err
	}
	return &file, nil
}

func validatePrivateUploadV1Contract(got PrivateUploadV1Contract) error {
	want := PrivateUploadV1Contract{
		NHPProtocolVersion:      PrivateUploadV1NHPVersion,
		TransportScope:          "application_request_after_authenticated_nhp_1_1_ack",
		FreshnessReplayScope:    "timestamp_freshness_and_nonce_replay_are_receiver_state_checks_not_stateless_signer_mutations",
		Path:                    PrivateUploadV1Path,
		AuthorityRule:           "sign_exact_protected_ack_url_authority_lowercase_dns_or_ipv4_labels_a-z0-9-hyphen_no_empty_or_edge_hyphen_max_63_per_label_and_253_host_bytes_optional_canonical_nonzero_decimal_port_colon_requires_port_ipv6_forbidden",
		AudienceKeyIDRule:       PrivateUploadV1AudienceKeyIDRule,
		ClientIDRule:            PrivateUploadV1ClientIDRule,
		KeyIDRule:               PrivateUploadV1KeyIDRule,
		UploadRequestIDRule:     PrivateUploadV1UploadRequestIDRule,
		UploadHandleRule:        PrivateUploadV1UploadHandleRule,
		AuthorityExpiresAtRule:  PrivateUploadV1AuthorityExpiryRule,
		BodyLengthRule:          PrivateUploadV1BodyLengthRule,
		FrameEncoding:           PrivateUploadV1FrameEncoding,
		SignatureAlgorithm:      PrivateUploadV1SignatureAlgorithm,
		SignatureEncoding:       PrivateUploadV1SignatureEncoding,
		PrivateKeyEncoding:      PrivateUploadV1PrivateKeyEncoding,
		PublicKeyEncoding:       PrivateUploadV1PublicKeyEncoding,
		ContentDigestEncoding:   PrivateUploadV1ContentDigest,
		NonceEncoding:           "base64url_unpadded",
		NonceDecodedBytes:       32,
		TimestampMaxSkewSeconds: 30,
		Upload: PrivateUploadV1OperationContract{
			Method: PrivateUploadV1UploadMethod, SigningDomainASCII: PrivateUploadV1UploadAuthDomain,
			SigningDomainSeparator: "00", FieldOrder: privateUploadV1UploadFields,
			StableRequestDomainASCII: PrivateUploadV1UploadRequestDomain,
			StableRequestFieldOrder:  privateUploadV1UploadStableFields,
			BodyEncoding:             "exact_bytes_no_multipart", RequiredHeaders: privateUploadV1RequiredUploadHeaders,
			MediaTypeRule:        PrivateUploadV1MediaTypeRule,
			MediaTypeSubtypeRule: PrivateUploadV1MediaTypeSubtypeRule,
			FilenameEncoding:     PrivateUploadV1FilenameEncoding,
			DisplayFilenameRule:  PrivateUploadV1DisplayFilenameRule,
			ContentTypeRule:      "exactly_equal_to_signed_media_type",
			ForbiddenHeaders:     privateUploadV1UploadForbiddenHeaders,
		},
		Refresh: PrivateUploadV1OperationContract{
			Method: PrivateUploadV1RefreshMethod, SigningDomainASCII: PrivateUploadV1RefreshAuthDomain,
			SigningDomainSeparator: "00", FieldOrder: privateUploadV1RefreshFields,
			StableRequestDomainASCII: PrivateUploadV1RefreshRequestDomain,
			StableRequestFieldOrder:  privateUploadV1RefreshStableFields,
			BodyEncoding:             "canonical_json_exact_bytes", RequiredHeaders: privateUploadV1RequiredRefreshHeaders,
			BodyKeyOrder:           privateUploadV1RefreshBodyFields,
			BodyWhitespaceRule:     "none_between_tokens",
			BodyStringEscapingRule: "rfc8259_utf8_short_escapes_for_quote_backslash_backspace_tab_newline_formfeed_carriage_return_u00xx_for_other_u0000_to_u001f_controls_plus_lowercase_u003c_u003e_u0026_u2028_u2029",
			ContentTypeRule:        "exactly_application/json",
			ForbiddenHeaders:       privateUploadV1RefreshForbiddenHeaders,
		},
		RejectClasses:         []string{"authority", "audience_key_id", "body_digest", "forbidden_header", "method_path", "nonce", "signature_encoding", "signature_malleability", "signature_mismatch", "signature_scalar"},
		RejectClassPrecedence: []string{"method_path", "forbidden_header", "authority", "nonce", "audience_key_id", "signature_encoding", "signature_scalar", "signature_malleability", "signature_mismatch", "body_digest"},
	}
	if !reflect.DeepEqual(got, want) {
		return errors.New("conformance: private-upload contract drift")
	}
	return nil
}

func privateUploadV1Frame(domain string, fields ...string) ([]byte, error) {
	result := append([]byte(domain), 0)
	for _, field := range fields {
		if uint64(len(field)) > uint64(^uint32(0)) {
			return nil, errors.New("conformance: private-upload canonical field is too large")
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		result = append(result, length[:]...)
		result = append(result, field...)
	}
	return result, nil
}

func PrivateUploadV1UploadCanonicalBytes(g PrivateUploadV1UploadGolden) ([]byte, error) {
	return privateUploadV1Frame(PrivateUploadV1UploadAuthDomain,
		g.Method, g.Authority, g.Path, g.TimestampUnixDecimal, g.Nonce, g.ClientID, g.KeyID,
		g.AudienceKeyID, g.BodySHA256Hex, g.BodyLengthDecimal, g.MediaType, g.DisplayFilenameUTF8,
		g.AuthorityExpiresAt, g.UploadRequestID,
	)
}

func PrivateUploadV1RefreshCanonicalBytes(g PrivateUploadV1RefreshGolden) ([]byte, error) {
	return privateUploadV1Frame(PrivateUploadV1RefreshAuthDomain,
		g.Method, g.Authority, g.Path, g.TimestampUnixDecimal, g.Nonce, g.ClientID, g.KeyID,
		g.BodySHA256Hex, g.BodyLengthDecimal, g.UploadRequestID,
	)
}

func privateUploadV1StableUploadBytes(g PrivateUploadV1UploadGolden) ([]byte, error) {
	return privateUploadV1Frame(PrivateUploadV1UploadRequestDomain,
		g.ClientID, g.AudienceKeyID, g.BodySHA256Hex, g.BodyLengthDecimal, g.MediaType,
		g.DisplayFilenameUTF8, g.AuthorityExpiresAt, g.UploadRequestID,
	)
}

type privateUploadV1RefreshBody struct {
	UploadHandle       string `json:"upload_handle"`
	UploadRequestID    string `json:"upload_request_id"`
	MaxBatchSize       int64  `json:"max_batch_size"`
	MaxLinkTTLSeconds  int64  `json:"max_link_ttl_seconds"`
	AuthorityExpiresAt string `json:"authority_expires_at"`
}

func privateUploadV1StableRefreshBytes(g PrivateUploadV1RefreshGolden) ([]byte, error) {
	return privateUploadV1Frame(PrivateUploadV1RefreshRequestDomain,
		g.ClientID, g.UploadHandle, g.MaxBatchSizeDecimal,
		g.MaxLinkTTLSecondsDecimal, g.AuthorityExpiresAt, g.UploadRequestID,
	)
}

func validatePrivateUploadV1FixtureKey(fixture PrivateUploadV1FixtureKey) (*ecdsa.PrivateKey, error) {
	if fixture.Warning != "Synthetic conformance private key with scalar d=1. Never admit it to a production trust store." {
		return nil, errors.New("conformance: private-upload fixture warning drift")
	}
	privateDER, err := strictRawBase64URL(fixture.PrivateKeyPKCS8DERB64URL)
	if err != nil {
		return nil, errors.New("conformance: private-upload fixture private key is not canonical base64url")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, fmt.Errorf("conformance: parse private-upload fixture private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() || key.D.Sign() <= 0 {
		return nil, errors.New("conformance: private-upload fixture key is not P-256")
	}
	publicDER, err := strictRawBase64URL(fixture.PublicKeyDERB64URL)
	if err != nil {
		return nil, errors.New("conformance: private-upload fixture public key is not canonical base64url")
	}
	parsedPublic, err := x509.ParsePKIXPublicKey(publicDER)
	public, ok := parsedPublic.(*ecdsa.PublicKey)
	if err != nil || !ok || public.Curve != elliptic.P256() || public.X.Cmp(key.X) != 0 || public.Y.Cmp(key.Y) != 0 {
		return nil, errors.New("conformance: private-upload fixture public key does not match its private key")
	}
	return key, nil
}

func strictRawBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("noncanonical base64url")
	}
	return decoded, nil
}

func validatePrivateUploadV1Common(method, authority, path, timestamp, nonce, clientID, keyID, bodyHex, bodyDigest, bodyLength, contentDigest, requestID string) ([]byte, error) {
	if method == "" || !privateUploadV1CanonicalAuthority(authority) || path != PrivateUploadV1Path ||
		!privateUploadV1IDPattern.MatchString(clientID) || !privateUploadV1IDPattern.MatchString(keyID) ||
		!privateUploadV1UUIDV4Pattern.MatchString(requestID) || !privateUploadV1HexDigestPattern.MatchString(bodyDigest) {
		return nil, errors.New("conformance: private-upload golden shape is invalid")
	}
	parsedTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || strconv.FormatInt(parsedTimestamp, 10) != timestamp {
		return nil, errors.New("conformance: private-upload timestamp is not canonical decimal")
	}
	nonceBytes, err := strictRawBase64URL(nonce)
	if err != nil || len(nonceBytes) != 32 {
		return nil, errors.New("conformance: private-upload nonce is invalid")
	}
	body, err := hex.DecodeString(bodyHex)
	if err != nil || hex.EncodeToString(body) != bodyHex || len(body) == 0 || strconv.Itoa(len(body)) != bodyLength {
		return nil, errors.New("conformance: private-upload body bytes or length are invalid")
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != bodyDigest || contentDigest != "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":" {
		return nil, errors.New("conformance: private-upload body digest is invalid")
	}
	return body, nil
}

func validatePrivateUploadV1UploadGolden(g PrivateUploadV1UploadGolden, public *ecdsa.PublicKey) error {
	if g.Method != PrivateUploadV1UploadMethod || !privateUploadV1AudiencePattern.MatchString(g.AudienceKeyID) ||
		!privateUploadV1MediaTypeValid(g.MediaType) || !privateUploadV1DisplayFilenameContained(g.DisplayFilenameUTF8) ||
		g.ContentType != g.MediaType || g.DisplayFilenameUTF8 != "report.txt" || g.FilenameB64URL != base64.RawURLEncoding.EncodeToString([]byte(g.DisplayFilenameUTF8)) {
		return errors.New("conformance: private-upload upload golden fields are invalid")
	}
	authorityExpiry, err := time.Parse(time.RFC3339, g.AuthorityExpiresAt)
	if err != nil || authorityExpiry.UTC().Format(time.RFC3339) != g.AuthorityExpiresAt {
		return errors.New("conformance: private-upload authority expiry is invalid")
	}
	if _, err := validatePrivateUploadV1Common(g.Method, g.Authority, g.Path, g.TimestampUnixDecimal, g.Nonce, g.ClientID, g.KeyID,
		g.BodyHex, g.BodySHA256Hex, g.BodyLengthDecimal, g.ContentDigestHeader, g.UploadRequestID); err != nil {
		return err
	}
	canonical, err := PrivateUploadV1UploadCanonicalBytes(g)
	if err != nil {
		return err
	}
	if err := validatePrivateUploadV1CanonicalAndSignature(canonical, g.CanonicalHex, g.SigningDigestHex, g.SignatureDERB64URL, public); err != nil {
		return err
	}
	stable, err := privateUploadV1StableUploadBytes(g)
	if err != nil {
		return err
	}
	return validatePrivateUploadV1DigestPair(stable, g.StableRequestCanonicalHex, g.StableRequestDigestHex)
}

func validatePrivateUploadV1RefreshGolden(g PrivateUploadV1RefreshGolden, public *ecdsa.PublicKey) error {
	if g.Method != PrivateUploadV1RefreshMethod || g.ContentType != "application/json" || !privateUploadV1UploadHandlePattern.MatchString(g.UploadHandle) {
		return errors.New("conformance: private-upload refresh method is invalid")
	}
	body, err := validatePrivateUploadV1Common(g.Method, g.Authority, g.Path, g.TimestampUnixDecimal, g.Nonce, g.ClientID, g.KeyID,
		g.BodyHex, g.BodySHA256Hex, g.BodyLengthDecimal, g.ContentDigestHeader, g.UploadRequestID)
	if err != nil {
		return err
	}
	var request privateUploadV1RefreshBody
	if err := strictDecodeArtifact(body, &request); err != nil || request.UploadHandle != g.UploadHandle || request.UploadRequestID != g.UploadRequestID ||
		strconv.FormatInt(request.MaxBatchSize, 10) != g.MaxBatchSizeDecimal || strconv.FormatInt(request.MaxLinkTTLSeconds, 10) != g.MaxLinkTTLSecondsDecimal ||
		request.AuthorityExpiresAt != g.AuthorityExpiresAt || request.MaxBatchSize < 1 || request.MaxLinkTTLSeconds < 1 {
		return errors.New("conformance: private-upload refresh body is invalid")
	}
	canonicalBody, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonicalBody, body) {
		return errors.New("conformance: private-upload refresh body is not canonical JSON")
	}
	authorityExpiry, err := time.Parse(time.RFC3339, request.AuthorityExpiresAt)
	if err != nil || authorityExpiry.UTC().Format(time.RFC3339) != request.AuthorityExpiresAt {
		return errors.New("conformance: private-upload refresh authority expiry is invalid")
	}
	canonical, err := PrivateUploadV1RefreshCanonicalBytes(g)
	if err != nil {
		return err
	}
	if err := validatePrivateUploadV1CanonicalAndSignature(canonical, g.CanonicalHex, g.SigningDigestHex, g.SignatureDERB64URL, public); err != nil {
		return err
	}
	stable, err := privateUploadV1StableRefreshBytes(g)
	if err != nil {
		return err
	}
	return validatePrivateUploadV1DigestPair(stable, g.StableRequestCanonicalHex, g.StableRequestDigestHex)
}

func validatePrivateUploadV1CanonicalAndSignature(canonical []byte, canonicalHex, digestHex, signature string, public *ecdsa.PublicKey) error {
	if hex.EncodeToString(canonical) != canonicalHex {
		return errors.New("conformance: private-upload canonical bytes drift")
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != digestHex {
		return errors.New("conformance: private-upload signing digest drift")
	}
	class := privateUploadV1VerifySignature(public, canonical, signature)
	if class != "" {
		return fmt.Errorf("conformance: private-upload golden signature rejected as %s", class)
	}
	return nil
}

func validatePrivateUploadV1DigestPair(canonical []byte, canonicalHex, digestHex string) error {
	if hex.EncodeToString(canonical) != canonicalHex {
		return errors.New("conformance: private-upload stable request bytes drift")
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != digestHex {
		return errors.New("conformance: private-upload stable request digest drift")
	}
	return nil
}

func privateUploadV1VerifySignature(public *ecdsa.PublicKey, canonical []byte, encoded string) string {
	der, err := strictRawBase64URL(encoded)
	if err != nil {
		return "signature_encoding"
	}
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		return "signature_encoding"
	}
	remarshaled, err := asn1.Marshal(signature)
	if err != nil || !bytes.Equal(remarshaled, der) {
		return "signature_encoding"
	}
	order := elliptic.P256().Params().N
	if signature.R.Sign() <= 0 || signature.S.Sign() <= 0 || signature.R.Cmp(order) >= 0 || signature.S.Cmp(order) >= 0 {
		return "signature_scalar"
	}
	if signature.S.Cmp(new(big.Int).Rsh(new(big.Int).Set(order), 1)) > 0 {
		return "signature_malleability"
	}
	digest := sha256.Sum256(canonical)
	if !ecdsa.Verify(public, digest[:], signature.R, signature.S) {
		return "signature_mismatch"
	}
	return ""
}

func privateUploadV1CanonicalAuthority(value string) bool {
	if value == "" || value != strings.ToLower(value) || strings.HasSuffix(value, ":") || strings.ContainsAny(value, " /\\\t\r\n") {
		return false
	}
	parsed, err := url.Parse("https://" + value)
	if err != nil || parsed.Host != value || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := parsed.Hostname()
	if host == "" || strings.HasSuffix(host, ".") || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	if port := parsed.Port(); port != "" {
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 || strconv.FormatUint(portNumber, 10) != port {
			return false
		}
	}
	return true
}

type privateUploadV1Candidate struct {
	base                   string
	method                 string
	authority              string
	path                   string
	audience               string
	forbiddenHeaderPresent bool
	nonce                  string
	bodyHex                string
	bodySHA256             string
	signature              string
}

func privateUploadV1ForbiddenHeader(base, name string) bool {
	headers := privateUploadV1UploadForbiddenHeaders
	if base == "refresh_golden" {
		headers = privateUploadV1RefreshForbiddenHeaders
	}
	for _, header := range headers {
		if header == name {
			return true
		}
	}
	return false
}

func privateUploadV1ApplyReject(file *PrivateUploadV1File, reject PrivateUploadV1RejectCase) (privateUploadV1Candidate, error) {
	var candidate privateUploadV1Candidate
	switch reject.Base {
	case "upload_golden":
		g := file.UploadGolden
		candidate = privateUploadV1Candidate{base: reject.Base, method: g.Method, authority: g.Authority, path: g.Path, audience: g.AudienceKeyID, nonce: g.Nonce, bodyHex: g.BodyHex, bodySHA256: g.BodySHA256Hex, signature: g.SignatureDERB64URL}
	case "refresh_golden":
		g := file.RefreshGolden
		candidate = privateUploadV1Candidate{base: reject.Base, method: g.Method, authority: g.Authority, path: g.Path, nonce: g.Nonce, bodyHex: g.BodyHex, bodySHA256: g.BodySHA256Hex, signature: g.SignatureDERB64URL}
	default:
		return candidate, errors.New("conformance: private-upload reject has unknown base")
	}
	for _, mutation := range reject.Mutations {
		switch {
		case mutation.Target == "request_field" && mutation.Field == "method":
			candidate.method = mutation.Value
		case mutation.Target == "request_field" && mutation.Field == "authority":
			candidate.authority = mutation.Value
		case mutation.Target == "request_field" && mutation.Field == "path":
			candidate.path = mutation.Value
		case mutation.Target == "request_field" && mutation.Field == "audience_key_id" && reject.Base == "upload_golden":
			candidate.audience = mutation.Value
		case mutation.Target == "request_header" && privateUploadV1ForbiddenHeader(reject.Base, mutation.Field):
			candidate.forbiddenHeaderPresent = true
		case mutation.Target == "request_field" && mutation.Field == "nonce":
			candidate.nonce = mutation.Value
		case mutation.Target == "body" && mutation.Field == "body_hex":
			candidate.bodyHex = mutation.Value
		case mutation.Target == "request_field" && mutation.Field == "body_sha256_hex":
			candidate.bodySHA256 = mutation.Value
		case mutation.Target == "request_field" && mutation.Field == "signature_der_b64url":
			candidate.signature = mutation.Value
		default:
			return candidate, errors.New("conformance: private-upload reject has unknown mutation")
		}
	}
	return candidate, nil
}

func privateUploadV1RejectClass(file *PrivateUploadV1File, candidate privateUploadV1Candidate, public *ecdsa.PublicKey) string {
	var canonical []byte
	var err error
	switch candidate.base {
	case "upload_golden":
		if candidate.method != PrivateUploadV1UploadMethod || candidate.path != PrivateUploadV1Path {
			return "method_path"
		}
		if candidate.forbiddenHeaderPresent {
			return "forbidden_header"
		}
		if !privateUploadV1CanonicalAuthority(candidate.authority) {
			return "authority"
		}
		if nonce, err := strictRawBase64URL(candidate.nonce); err != nil || len(nonce) != 32 {
			return "nonce"
		}
		if !privateUploadV1AudiencePattern.MatchString(candidate.audience) {
			return "audience_key_id"
		}
		g := file.UploadGolden
		g.Method, g.Authority, g.Path, g.Nonce, g.AudienceKeyID, g.BodySHA256Hex = candidate.method, candidate.authority, candidate.path, candidate.nonce, candidate.audience, candidate.bodySHA256
		canonical, err = PrivateUploadV1UploadCanonicalBytes(g)
	case "refresh_golden":
		if candidate.method != PrivateUploadV1RefreshMethod || candidate.path != PrivateUploadV1Path {
			return "method_path"
		}
		if candidate.forbiddenHeaderPresent {
			return "forbidden_header"
		}
		if !privateUploadV1CanonicalAuthority(candidate.authority) {
			return "authority"
		}
		if nonce, err := strictRawBase64URL(candidate.nonce); err != nil || len(nonce) != 32 {
			return "nonce"
		}
		g := file.RefreshGolden
		g.Method, g.Authority, g.Path, g.Nonce, g.BodySHA256Hex = candidate.method, candidate.authority, candidate.path, candidate.nonce, candidate.bodySHA256
		canonical, err = PrivateUploadV1RefreshCanonicalBytes(g)
	default:
		return "method_path"
	}
	if err != nil {
		return "signature_mismatch"
	}
	if class := privateUploadV1VerifySignature(public, canonical, candidate.signature); class != "" {
		return class
	}
	body, err := hex.DecodeString(candidate.bodyHex)
	if err != nil {
		return "body_digest"
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != candidate.bodySHA256 {
		return "body_digest"
	}
	return ""
}

func validatePrivateUploadV1Rejects(file *PrivateUploadV1File, public *ecdsa.PublicKey) error {
	type mutationContract struct{ target, field string }
	type rejectContract struct {
		base      string
		mutations []mutationContract
		class     string
	}
	mutation := func(target, field string) mutationContract {
		return mutationContract{target: target, field: field}
	}
	one := func(target, field string) []mutationContract {
		return []mutationContract{mutation(target, field)}
	}
	want := map[string]rejectContract{
		"reject_upload_high_s_signature":                     {"upload_golden", one("request_field", "signature_der_b64url"), "signature_malleability"},
		"reject_refresh_high_s_signature":                    {"refresh_golden", one("request_field", "signature_der_b64url"), "signature_malleability"},
		"reject_padded_signature_base64url":                  {"upload_golden", one("request_field", "signature_der_b64url"), "signature_encoding"},
		"reject_nonminimal_signature_der":                    {"upload_golden", one("request_field", "signature_der_b64url"), "signature_encoding"},
		"reject_trailing_signature_der_bytes":                {"upload_golden", one("request_field", "signature_der_b64url"), "signature_encoding"},
		"reject_zero_signature_scalar":                       {"upload_golden", one("request_field", "signature_der_b64url"), "signature_scalar"},
		"reject_negative_signature_scalar":                   {"upload_golden", one("request_field", "signature_der_b64url"), "signature_scalar"},
		"reject_uppercase_authority":                         {"upload_golden", one("request_field", "authority"), "authority"},
		"reject_trailing_colon_authority":                    {"upload_golden", one("request_field", "authority"), "authority"},
		"reject_changed_canonical_authority_stale_signature": {"upload_golden", one("request_field", "authority"), "signature_mismatch"},
		"reject_short_nonce":                                 {"upload_golden", one("request_field", "nonce"), "nonce"},
		"reject_invalid_audience_key_id":                     {"upload_golden", one("request_field", "audience_key_id"), "audience_key_id"},
		"reject_changed_audience_key_stale_signature":        {"upload_golden", one("request_field", "audience_key_id"), "signature_mismatch"},
		"reject_refresh_audience_header":                     {"refresh_golden", one("request_header", "X-LayerV-Audience-Key-ID"), "forbidden_header"},
		"reject_upload_authorization_header":                 {"upload_golden", one("request_header", "Authorization"), "forbidden_header"},
		"reject_refresh_authorization_header":                {"refresh_golden", one("request_header", "Authorization"), "forbidden_header"},
		"reject_refresh_filename_header":                     {"refresh_golden", one("request_header", "X-LayerV-Filename-B64"), "forbidden_header"},
		"reject_changed_upload_body":                         {"upload_golden", one("body", "body_hex"), "body_digest"},
		"reject_changed_refresh_body":                        {"refresh_golden", one("body", "body_hex"), "body_digest"},
		"reject_changed_body_digest_stale_signature":         {"upload_golden", one("request_field", "body_sha256_hex"), "signature_mismatch"},
		"reject_upload_method":                               {"upload_golden", one("request_field", "method"), "method_path"},
		"reject_upload_path":                                 {"upload_golden", one("request_field", "path"), "method_path"},
		"reject_refresh_method":                              {"refresh_golden", one("request_field", "method"), "method_path"},
		"reject_refresh_path":                                {"refresh_golden", one("request_field", "path"), "method_path"},
		"reject_method_before_authority":                     {"upload_golden", []mutationContract{mutation("request_field", "method"), mutation("request_field", "authority")}, "method_path"},
	}
	if len(file.RejectCases) != len(want) {
		return fmt.Errorf("conformance: private-upload reject count = %d, want %d", len(file.RejectCases), len(want))
	}
	seen := make(map[string]bool, len(want))
	for _, reject := range file.RejectCases {
		expected, ok := want[reject.Name]
		actualMutations := make([]mutationContract, len(reject.Mutations))
		for index, mutation := range reject.Mutations {
			actualMutations[index] = mutationContract{target: mutation.Target, field: mutation.Field}
		}
		if !ok || seen[reject.Name] || reject.Base != expected.base || !reflect.DeepEqual(actualMutations, expected.mutations) || reject.RejectClass != expected.class ||
			reject.Outcome != ExpectReject || reject.Status != PrivateUploadV1AuthFailureStatus || reject.ErrorCode != PrivateUploadV1AuthFailureCode || len(reject.Mutations) == 0 {
			return fmt.Errorf("conformance: private-upload reject %q is invalid", reject.Name)
		}
		for _, mutation := range reject.Mutations {
			if mutation.Value == "" {
				return fmt.Errorf("conformance: private-upload reject %q has an empty mutation", reject.Name)
			}
			if mutation.Target == "body" {
				mutated, err := hex.DecodeString(mutation.Value)
				if err != nil || hex.EncodeToString(mutated) != mutation.Value {
					return fmt.Errorf("conformance: private-upload reject %q body is not canonical hex", reject.Name)
				}
				originalHex := file.RefreshGolden.BodyHex
				if reject.Base == "upload_golden" {
					originalHex = file.UploadGolden.BodyHex
				}
				if len(mutation.Value) != len(originalHex) {
					return fmt.Errorf("conformance: private-upload reject %q changes body length", reject.Name)
				}
			}
		}
		seen[reject.Name] = true
		candidate, err := privateUploadV1ApplyReject(file, reject)
		if err != nil {
			return err
		}
		if class := privateUploadV1RejectClass(file, candidate, public); class != reject.RejectClass {
			return fmt.Errorf("conformance: private-upload reject %q classified as %q, want %q", reject.Name, class, reject.RejectClass)
		}
	}
	return nil
}

func privateUploadV1DisplayFilenameContained(value string) bool {
	if len(value) == 0 || len(value) > 180 || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
		value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return false
		}
	}
	return true
}

func privateUploadV1MediaTypeValid(value string) bool {
	if !privateUploadV1MediaTypePattern.MatchString(value) {
		return false
	}
	_, subtype, ok := strings.Cut(value, "/")
	return ok && subtype != "*"
}

func validatePrivateUploadV1ConstructionRejects(file *PrivateUploadV1File) error {
	want := []PrivateUploadV1ConstructionRejectCase{
		{Name: "reject_upload_content_type_mismatch", Base: "upload_golden", Field: "content_type", Value: "application/octet-stream", RejectRule: "upload.content_type_rule", Outcome: ExpectReject},
		{Name: "reject_display_filename_dotdot", Base: "upload_golden", Field: "display_filename_utf8", Value: "..", RejectRule: "upload.display_filename_rule", Outcome: ExpectReject},
		{Name: "reject_display_filename_forward_slash", Base: "upload_golden", Field: "display_filename_utf8", Value: "folder/report.txt", RejectRule: "upload.display_filename_rule", Outcome: ExpectReject},
		{Name: "reject_display_filename_backslash", Base: "upload_golden", Field: "display_filename_utf8", Value: `folder\report.txt`, RejectRule: "upload.display_filename_rule", Outcome: ExpectReject},
		{Name: "reject_display_filename_control", Base: "upload_golden", Field: "display_filename_utf8", Value: "report\n.txt", RejectRule: "upload.display_filename_rule", Outcome: ExpectReject},
		{Name: "reject_display_filename_not_nfc", Base: "upload_golden", Field: "display_filename_utf8", Value: "cafe\u0301.txt", RejectRule: "upload.display_filename_rule", Outcome: ExpectReject},
		{Name: "reject_media_type_uppercase", Base: "upload_golden", Field: "media_type", Value: "TEXT/plain", RejectRule: "upload.media_type_rule", Outcome: ExpectReject},
		{Name: "reject_media_type_wildcard_subtype", Base: "upload_golden", Field: "media_type", Value: "text/*", RejectRule: "upload.media_type_subtype_rule", Outcome: ExpectReject},
	}
	if !reflect.DeepEqual(file.ConstructionRejectCases, want) {
		return errors.New("conformance: private-upload construction rejects drift")
	}
	for _, reject := range file.ConstructionRejectCases {
		switch reject.Field {
		case "content_type":
			if reject.Value == file.UploadGolden.MediaType {
				return fmt.Errorf("conformance: private-upload construction reject %q does not violate Content-Type binding", reject.Name)
			}
		case "display_filename_utf8":
			if reject.Name == "reject_display_filename_not_nfc" {
				// The public Go module stays stdlib-only, and the standard library has
				// no Unicode normalization primitive. Pin the exact decomposed KAT
				// here; Node and Python execute NFC normalization in CI.
				if reject.Value != "cafe\u0301.txt" {
					return fmt.Errorf("conformance: private-upload construction reject %q is not the NFC KAT", reject.Name)
				}
				continue
			}
			if privateUploadV1DisplayFilenameContained(reject.Value) {
				return fmt.Errorf("conformance: private-upload construction reject %q has a contained filename", reject.Name)
			}
		case "media_type":
			if privateUploadV1MediaTypeValid(reject.Value) {
				return fmt.Errorf("conformance: private-upload construction reject %q has a valid media type", reject.Name)
			}
		default:
			return fmt.Errorf("conformance: private-upload construction reject %q has an unknown field", reject.Name)
		}
	}
	return nil
}
