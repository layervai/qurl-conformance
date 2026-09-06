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
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DelegatedMintIssueV1ArtifactID    = "qurl-delegated-mint-issue-v1-vectors"
	DelegatedMintIssueV1SchemaVersion = 1
	DelegatedMintIssueV1Description   = "Byte-exact private Connector-to-issuer-service authentication contract for delegated-mint capability issuance. The signature binds the configured issuer identity, exact request body, route, authority, replay nonce, and idempotency key. Capability claims and public redemption remain separate service-owned contracts."

	DelegatedMintIssueV1Method                      = "POST"
	DelegatedMintIssueV1Route                       = "/internal/v1/delegated-mint-capabilities"
	DelegatedMintIssueV1SigningDomain               = "LV-QURL-CAPABILITY-ISSUE-V1"
	DelegatedMintIssueV1SigningDomainSeparator      = "00"
	DelegatedMintIssueV1FrameEncoding               = "u32be_byte_length_then_exact_utf8_bytes"
	DelegatedMintIssueV1BodyDigest                  = "SHA-256"
	DelegatedMintIssueV1BodyDigestEncoding          = "lowercase_hex"
	DelegatedMintIssueV1SignatureAlgorithm          = "ECDSA_P-256_SHA-256"
	DelegatedMintIssueV1SignatureEncoding           = "canonical_der_base64url_unpadded_low_s"
	DelegatedMintIssueV1SignatureDERMaxBytes        = 72
	DelegatedMintIssueV1PublicKeyEncoding           = "der_spki_base64url_unpadded"
	DelegatedMintIssueV1NonceEncoding               = "base64url_unpadded"
	DelegatedMintIssueV1NonceBytes                  = 16
	DelegatedMintIssueV1IdempotencyKeyMinBytes      = 1
	DelegatedMintIssueV1IdempotencyKeyMaxBytes      = 128
	DelegatedMintIssueV1AuthorityNormalization      = "lowercase_dns_name_no_port"
	DelegatedMintIssueV1AuthorityBindingRule        = "receiver_requires_method_route_and_authority_to_equal_its_configured_endpoint"
	DelegatedMintIssueV1AuthorityMaxBytes           = 253
	DelegatedMintIssueV1ExpiryEncoding              = "rfc3339_utc_second_precision_literal_Z"
	DelegatedMintIssueV1BodyMaxBytes                = 8192
	DelegatedMintIssueV1SuccessStatus               = 200
	DelegatedMintIssueV1SuccessContentType          = "application/json"
	DelegatedMintIssueV1ErrorContentType            = "application/problem+json"
	DelegatedMintIssueV1AuthFailureStatus           = 403
	DelegatedMintIssueV1AuthFailureCode             = "invalid_capability_issue"
	DelegatedMintIssueV1StaleMissStatus             = 404
	DelegatedMintIssueV1StaleMissCode               = "issue_operation_not_found"
	DelegatedMintIssueV1RetryAfterAbsent            = "absent"
	DelegatedMintIssueV1RetryAfterExactSeconds      = "exact_seconds"
	DelegatedMintIssueV1RetryAfterPositiveSeconds   = "positive_integer_seconds"
	DelegatedMintIssueV1CapabilityTTLSeconds        = 15 * 60
	DelegatedMintIssueV1AuthorityMaxTTLSeconds      = 24 * 60 * 60
	DelegatedMintIssueV1TimestampMaxSkewSeconds     = 5 * 60
	DelegatedMintIssueV1NonceReplayRetentionSeconds = 15 * 60
	DelegatedMintIssueV1IdempotencyDomain           = "LV-QURL-CAPABILITY-ISSUE-IDEMPOTENCY-V1"
	DelegatedMintIssueV1IdempotencyKeyPrefix        = "uci_"
	DelegatedMintIssueV1IdempotencyDerivation       = "domain_then_zero_then_u32be_length_prefixed_issuer_id_upload_handle_generation_decimal_sha256_base64url_unpadded"

	DelegatedMintIssueV1IdempotencyKeyHeader = "Idempotency-Key"
	DelegatedMintIssueV1IssuerIDHeader       = "X-LayerV-Issuer-ID"
	DelegatedMintIssueV1KIDHeader            = "X-LayerV-Issuer-KID"
	DelegatedMintIssueV1TimestampHeader      = "X-LayerV-Timestamp"
	DelegatedMintIssueV1NonceHeader          = "X-LayerV-Nonce"
	DelegatedMintIssueV1SignatureHeader      = "X-LayerV-Signature"
)

var (
	delegatedMintIssueV1IdempotencyPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
	delegatedMintIssueV1IssuerFieldPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	delegatedMintIssueV1UploadHandlePattern = regexp.MustCompile(`^upl_[A-Za-z0-9_-]{43}$`)
	delegatedMintIssueV1HexDigestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	delegatedMintIssueV1FieldOrder          = []string{"method", "authority", "route", "issuer_id", "kid", "idempotency_key", "timestamp_unix_decimal", "nonce", "body_sha256"}
	delegatedMintIssueV1SuccessDataFields   = []string{"capability", "capability_expires_at", "authority_expires_at"}
	delegatedMintIssueV1BodyAuthorityFields = []string{"upload_handle", "issue_generation", "upload_request_digest", "content_sha256", "byte_size", "media_type", "display_filename", "audience_key_id", "target_path", "max_batch_size", "max_link_ttl_seconds", "capability_expires_at", "authority_expires_at"}
)

type DelegatedMintIssueV1File struct {
	Artifact                string                             `json:"artifact"`
	SchemaVersion           int                                `json:"schema_version"`
	Description             string                             `json:"description"`
	Contract                DelegatedMintIssueV1Contract       `json:"contract"`
	Golden                  DelegatedMintIssueV1Golden         `json:"golden"`
	RetryGolden             DelegatedMintIssueV1Golden         `json:"retry_golden"`
	RefreshGolden           DelegatedMintIssueV1Golden         `json:"refresh_golden"`
	WrongEndpointSigned     DelegatedMintIssueV1Golden         `json:"wrong_endpoint_signed"`
	NonceReuseSigned        DelegatedMintIssueV1Golden         `json:"nonce_reuse_signed"`
	AuthorityConflictSigned DelegatedMintIssueV1Golden         `json:"authority_conflict_signed"`
	RejectCases             []DelegatedMintIssueV1Reject       `json:"reject_cases"`
	StateCases              []DelegatedMintIssueV1StateCase    `json:"state_cases"`
	ResponseCases           []DelegatedMintIssueV1ResponseCase `json:"response_cases"`
}

type DelegatedMintIssueV1Contract struct {
	Method                      string   `json:"method"`
	Route                       string   `json:"route"`
	SigningDomainASCII          string   `json:"signing_domain_ascii"`
	SigningDomainSeparator      string   `json:"signing_domain_separator_hex"`
	FrameEncoding               string   `json:"frame_encoding"`
	FieldOrder                  []string `json:"field_order"`
	BodyDigest                  string   `json:"body_digest"`
	BodyDigestEncoding          string   `json:"body_digest_encoding"`
	BodyMaxBytes                int      `json:"body_max_bytes"`
	SignatureAlgorithm          string   `json:"signature_algorithm"`
	SignatureEncoding           string   `json:"signature_encoding"`
	PublicKeyEncoding           string   `json:"public_key_encoding"`
	NonceEncoding               string   `json:"nonce_encoding"`
	NonceDecodedBytes           int      `json:"nonce_decoded_bytes"`
	IdempotencyKeyPattern       string   `json:"idempotency_key_pattern"`
	IdempotencyDomain           string   `json:"idempotency_derivation_domain_ascii"`
	IdempotencyDerivation       string   `json:"idempotency_derivation"`
	IdempotencyKeyPrefix        string   `json:"idempotency_key_prefix"`
	IdempotencyKeyMinBytes      int      `json:"idempotency_key_min_bytes"`
	IdempotencyKeyMaxBytes      int      `json:"idempotency_key_max_bytes"`
	IdempotencyKeyHeader        string   `json:"idempotency_key_header"`
	IssuerFieldPattern          string   `json:"issuer_field_pattern"`
	IssuerIDHeader              string   `json:"issuer_id_header"`
	KIDHeader                   string   `json:"kid_header"`
	TimestampHeader             string   `json:"timestamp_header"`
	NonceHeader                 string   `json:"nonce_header"`
	SignatureHeader             string   `json:"signature_header"`
	AuthorityNormalization      string   `json:"authority_normalization"`
	AuthorityBindingRule        string   `json:"authority_binding_rule"`
	AuthorityMaxBytes           int      `json:"authority_max_bytes"`
	SuccessStatus               int      `json:"success_status"`
	SuccessContentType          string   `json:"success_content_type"`
	SuccessEnvelope             string   `json:"success_envelope"`
	SuccessDataFields           []string `json:"success_data_fields"`
	SuccessReconciliationRule   string   `json:"success_reconciliation_rule"`
	ErrorContentType            string   `json:"error_content_type"`
	ErrorEnvelope               string   `json:"error_envelope"`
	BodyAuthorityFields         []string `json:"body_authority_fields"`
	BodySemanticValidationRule  string   `json:"body_semantic_validation_rule"`
	ExternalOperationCommitRule string   `json:"external_operation_commit_rule"`
	CapabilityTTLSeconds        int      `json:"capability_ttl_seconds"`
	AuthorityMaxTTLSeconds      int      `json:"authority_max_ttl_seconds"`
	TimestampMaxSkewSeconds     int      `json:"timestamp_max_skew_seconds"`
	NonceReplayRetentionSeconds int      `json:"nonce_replay_retention_seconds"`
	ExpiryAuthorityRule         string   `json:"expiry_authority_rule"`
	ExactReplayFreshnessRule    string   `json:"exact_replay_freshness_rule"`
	OperationIdentityFields     []string `json:"operation_identity_fields"`
	AuthorityFingerprintFields  []string `json:"authority_fingerprint_fields"`
	EnvelopeFingerprintFields   []string `json:"envelope_fingerprint_fields"`
	TransportReplayRule         string   `json:"transport_replay_rule"`
	StaleOperationMissRule      string   `json:"stale_operation_miss_rule"`
	StaleOperationMissStatus    int      `json:"stale_operation_miss_status"`
	StaleOperationMissCode      string   `json:"stale_operation_miss_code"`
	IssuerKeyRetentionRule      string   `json:"issuer_key_retention_rule"`
	ExpiryEncoding              string   `json:"expiry_encoding"`
	RejectClasses               []string `json:"reject_classes"`
	StateOutcomes               []string `json:"state_outcomes"`
	StateMutations              []string `json:"state_mutations"`
	RetryAfterModes             []string `json:"retry_after_modes"`
}

type DelegatedMintIssueV1Golden struct {
	Method                 string `json:"method"`
	Authority              string `json:"authority"`
	Route                  string `json:"route"`
	IssuerID               string `json:"issuer_id"`
	KID                    string `json:"kid"`
	IdempotencyKey         string `json:"idempotency_key"`
	IdempotencyPreimageHex string `json:"idempotency_preimage_hex"`
	TimestampUnix          int64  `json:"timestamp_unix"`
	Nonce                  string `json:"nonce"`
	BodyUTF8               string `json:"body_utf8"`
	BodySHA256             string `json:"body_sha256"`
	CanonicalHex           string `json:"canonical_hex"`
	SigningDigestHex       string `json:"signing_digest_hex"`
	PublicKeyDERB64URL     string `json:"public_key_der_b64url"`
	SignatureDERB64URL     string `json:"signature_der_b64url"`
}

type DelegatedMintIssueV1Reject struct {
	Name        string `json:"name"`
	Base        string `json:"base"`
	Field       string `json:"field"`
	Operation   string `json:"operation"`
	Value       string `json:"value,omitempty"`
	Repeat      int    `json:"repeat,omitempty"`
	Outcome     string `json:"outcome"`
	RejectClass string `json:"reject_class"`
	Status      int    `json:"status"`
	ErrorCode   string `json:"error_code"`
}

type DelegatedMintIssueV1StateCase struct {
	Name                  string `json:"name"`
	Input                 string `json:"input"`
	NowUnix               int64  `json:"now_unix"`
	PriorOperation        string `json:"prior_operation"`
	PriorNonce            string `json:"prior_nonce"`
	Outcome               string `json:"outcome"`
	Status                int    `json:"status"`
	ErrorCode             string `json:"error_code"`
	Mutation              string `json:"mutation"`
	ResponseSource        string `json:"response_source"`
	StrongOperationLookup bool   `json:"strong_operation_lookup"`
}

// DelegatedMintIssueV1ResponseCase freezes the public receiver response that a
// producer can use for retry and mutation-recovery decisions.
type DelegatedMintIssueV1ResponseCase struct {
	Name                  string                         `json:"name"`
	Trigger               string                         `json:"trigger"`
	Status                int                            `json:"status"`
	ContentType           string                         `json:"content_type"`
	ErrorCode             string                         `json:"error_code"`
	RetryAfter            DelegatedMintIssueV1RetryAfter `json:"retry_after"`
	ProvesOperationAbsent bool                           `json:"proves_operation_absent"`
}

// DelegatedMintIssueV1RetryAfter separates an absent header, an exact value,
// and the positive-integer rule used for receiver admission control.
type DelegatedMintIssueV1RetryAfter struct {
	Mode    string `json:"mode"`
	Seconds int    `json:"seconds,omitempty"`
}

func ParseDelegatedMintIssueV1File(data []byte) (*DelegatedMintIssueV1File, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("conformance: delegated-mint issue file is not valid UTF-8")
	}
	var file DelegatedMintIssueV1File
	if err := strictDecodeArtifact(data, &file); err != nil {
		return nil, fmt.Errorf("conformance: parse delegated-mint issue file: %w", err)
	}
	if file.Artifact != DelegatedMintIssueV1ArtifactID || file.SchemaVersion != DelegatedMintIssueV1SchemaVersion || file.Description != DelegatedMintIssueV1Description {
		return nil, errors.New("conformance: delegated-mint issue artifact identity is invalid")
	}
	if err := validateDelegatedMintIssueV1Contract(file.Contract); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1Golden(file.Golden); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1Golden(file.RetryGolden); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1Golden(file.RefreshGolden); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1Golden(file.WrongEndpointSigned); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1Golden(file.NonceReuseSigned); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1Golden(file.AuthorityConflictSigned); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1Relations(&file); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1StaleRetry(file.Golden, file.RetryGolden); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1Renewal(file.Golden, file.RefreshGolden); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1Rejects(file.Golden, file.RejectCases); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1StateCases(&file); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1ResponseCases(&file); err != nil {
		return nil, err
	}
	return &file, nil
}

func DelegatedMintIssueV1CanonicalBytes(golden DelegatedMintIssueV1Golden) ([]byte, error) {
	if golden.Method != DelegatedMintIssueV1Method || golden.Route != DelegatedMintIssueV1Route ||
		!validDelegatedMintIssueV1Authority(golden.Authority) ||
		!delegatedMintIssueV1IssuerFieldPattern.MatchString(golden.IssuerID) ||
		!delegatedMintIssueV1IssuerFieldPattern.MatchString(golden.KID) ||
		!delegatedMintIssueV1IdempotencyPattern.MatchString(golden.IdempotencyKey) ||
		len(golden.IdempotencyKey) < DelegatedMintIssueV1IdempotencyKeyMinBytes ||
		len(golden.IdempotencyKey) > DelegatedMintIssueV1IdempotencyKeyMaxBytes ||
		golden.TimestampUnix <= 0 || len(golden.BodyUTF8) > DelegatedMintIssueV1BodyMaxBytes || !utf8.ValidString(golden.BodyUTF8) {
		return nil, errors.New("conformance: invalid delegated-mint issue signature input")
	}
	nonce, err := decodeDelegatedMintIssueV1Base64URL(golden.Nonce)
	if err != nil || len(nonce) != DelegatedMintIssueV1NonceBytes {
		return nil, errors.New("conformance: invalid delegated-mint issue nonce")
	}
	bodyDigest := sha256.Sum256([]byte(golden.BodyUTF8))
	bodySHA256 := hex.EncodeToString(bodyDigest[:])
	if golden.BodySHA256 != bodySHA256 || !delegatedMintIssueV1HexDigestPattern.MatchString(golden.BodySHA256) {
		return nil, errors.New("conformance: delegated-mint issue body digest mismatch")
	}
	fields := []string{golden.Method, golden.Authority, golden.Route, golden.IssuerID, golden.KID, golden.IdempotencyKey, strconv.FormatInt(golden.TimestampUnix, 10), golden.Nonce, bodySHA256}
	total := len(DelegatedMintIssueV1SigningDomain) + 1
	for _, field := range fields {
		total += 4 + len(field)
	}
	out := make([]byte, 0, total)
	out = append(out, DelegatedMintIssueV1SigningDomain...)
	out = append(out, 0)
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		out = append(out, length[:]...)
		out = append(out, field...)
	}
	return out, nil
}

// DelegatedMintIssueV1ContractValue returns the exact v1 contract object used
// by the generator and strict loader.
func DelegatedMintIssueV1ContractValue() DelegatedMintIssueV1Contract {
	return DelegatedMintIssueV1Contract{
		Method: DelegatedMintIssueV1Method, Route: DelegatedMintIssueV1Route,
		SigningDomainASCII: DelegatedMintIssueV1SigningDomain, SigningDomainSeparator: DelegatedMintIssueV1SigningDomainSeparator,
		FrameEncoding: DelegatedMintIssueV1FrameEncoding, FieldOrder: delegatedMintIssueV1FieldOrder,
		BodyDigest: DelegatedMintIssueV1BodyDigest, BodyDigestEncoding: DelegatedMintIssueV1BodyDigestEncoding,
		BodyMaxBytes:       DelegatedMintIssueV1BodyMaxBytes,
		SignatureAlgorithm: DelegatedMintIssueV1SignatureAlgorithm, SignatureEncoding: DelegatedMintIssueV1SignatureEncoding,
		PublicKeyEncoding: DelegatedMintIssueV1PublicKeyEncoding, NonceEncoding: DelegatedMintIssueV1NonceEncoding,
		NonceDecodedBytes: DelegatedMintIssueV1NonceBytes, IdempotencyKeyPattern: delegatedMintIssueV1IdempotencyPattern.String(),
		IdempotencyDomain: DelegatedMintIssueV1IdempotencyDomain, IdempotencyDerivation: DelegatedMintIssueV1IdempotencyDerivation,
		IdempotencyKeyPrefix:   DelegatedMintIssueV1IdempotencyKeyPrefix,
		IdempotencyKeyMinBytes: DelegatedMintIssueV1IdempotencyKeyMinBytes, IdempotencyKeyMaxBytes: DelegatedMintIssueV1IdempotencyKeyMaxBytes,
		IdempotencyKeyHeader: DelegatedMintIssueV1IdempotencyKeyHeader,
		IssuerFieldPattern:   delegatedMintIssueV1IssuerFieldPattern.String(), IssuerIDHeader: DelegatedMintIssueV1IssuerIDHeader,
		KIDHeader: DelegatedMintIssueV1KIDHeader, TimestampHeader: DelegatedMintIssueV1TimestampHeader,
		NonceHeader: DelegatedMintIssueV1NonceHeader, SignatureHeader: DelegatedMintIssueV1SignatureHeader,
		AuthorityNormalization: DelegatedMintIssueV1AuthorityNormalization,
		AuthorityBindingRule:   DelegatedMintIssueV1AuthorityBindingRule,
		AuthorityMaxBytes:      DelegatedMintIssueV1AuthorityMaxBytes,
		SuccessStatus:          DelegatedMintIssueV1SuccessStatus, SuccessContentType: DelegatedMintIssueV1SuccessContentType,
		SuccessEnvelope: "data", SuccessDataFields: delegatedMintIssueV1SuccessDataFields,
		SuccessReconciliationRule:   "authority_expiry_equals_immutable_operation_authority_capability_expiry_is_canonical_and_not_after_authority_expired_capability_advances_generation",
		ErrorContentType:            DelegatedMintIssueV1ErrorContentType,
		ErrorEnvelope:               "rfc7807_error_object_plus_meta_request_id_no_unknown_fields",
		BodyAuthorityFields:         delegatedMintIssueV1BodyAuthorityFields,
		BodySemanticValidationRule:  "receiver_strictly_decodes_and_validates_every_body_authority_field_before_state_access_service_policy_owns_runtime_ceilings",
		ExternalOperationCommitRule: "uncommitted_external_operation_may_advance_internal_issue_generation_within_same_authority_committed_external_response_replays_byte_exact_new_outward_capability_requires_new_signed_external_request",
		CapabilityTTLSeconds:        DelegatedMintIssueV1CapabilityTTLSeconds, AuthorityMaxTTLSeconds: DelegatedMintIssueV1AuthorityMaxTTLSeconds,
		TimestampMaxSkewSeconds:     DelegatedMintIssueV1TimestampMaxSkewSeconds,
		NonceReplayRetentionSeconds: DelegatedMintIssueV1NonceReplayRetentionSeconds,
		ExpiryAuthorityRule:         "caller_supplies_signed_values_service_requires_capability_timestamp_plus_900_and_initial_authority_at_most_timestamp_plus_86400_refresh_preserves_authority",
		ExactReplayFreshnessRule:    "verify_shape_signature_then_operation_lookup_before_freshness_exact_accepted_envelope_returns_original_same_operation_authority_fresh_envelope_reconciles_changed_authority_conflicts_stale_nonexact_rejects_without_mutation",
		OperationIdentityFields:     []string{"issuer_id", "upload_handle", "issue_generation", "idempotency_key"},
		AuthorityFingerprintFields:  []string{"upload_request_digest", "content_sha256", "byte_size", "media_type", "display_filename", "audience_key_id", "target_path", "max_batch_size", "max_link_ttl_seconds", "authority_expires_at", "service_owned_issuer_policy_fingerprint"},
		EnvelopeFingerprintFields:   []string{"method", "authority", "route", "issuer_id", "kid", "idempotency_key", "timestamp_unix_decimal", "nonce", "exact_body_sha256", "signature_der_b64url"},
		TransportReplayRule:         "exact_accepted_envelope_may_bypass_freshness_same_operation_authority_different_envelope_requires_fresh_timestamp_and_nonce_binding_issuer_kid_may_rotate",
		StaleOperationMissRule:      "authenticated_strongly_consistent_absent_stale_operation_returns_no_mutation_connector_retries_fresh_same_generation",
		StaleOperationMissStatus:    DelegatedMintIssueV1StaleMissStatus,
		StaleOperationMissCode:      DelegatedMintIssueV1StaleMissCode,
		IssuerKeyRetentionRule:      "accepted_kid_verifier_retained_until_operation_authority_expires",
		ExpiryEncoding:              DelegatedMintIssueV1ExpiryEncoding,
		RejectClasses:               []string{"authority", "body_size", "idempotency_key", "nonce", "signature_encoding", "signature_malleability", "signature_scalar", "signature_mismatch"},
		StateOutcomes:               []string{"issue_new", "return_durable_result", "reject"},
		StateMutations:              []string{"store_operation_and_bind_nonce", "bind_nonce_to_existing_operation", "none"},
		RetryAfterModes:             []string{DelegatedMintIssueV1RetryAfterAbsent, DelegatedMintIssueV1RetryAfterExactSeconds, DelegatedMintIssueV1RetryAfterPositiveSeconds},
	}
}

func validateDelegatedMintIssueV1Contract(contract DelegatedMintIssueV1Contract) error {
	want := DelegatedMintIssueV1ContractValue()
	if !reflect.DeepEqual(contract, want) {
		return errors.New("conformance: delegated-mint issue contract drift")
	}
	if contract.NonceReplayRetentionSeconds <= 2*contract.TimestampMaxSkewSeconds {
		return errors.New("conformance: delegated-mint nonce retention must exceed twice the timestamp skew")
	}
	return nil
}

type delegatedMintIssueV1Body struct {
	UploadHandle        string `json:"upload_handle"`
	IssueGeneration     int    `json:"issue_generation"`
	UploadRequestDigest string `json:"upload_request_digest"`
	ContentSHA256       string `json:"content_sha256"`
	ByteSize            int64  `json:"byte_size"`
	MediaType           string `json:"media_type"`
	DisplayFilename     string `json:"display_filename"`
	AudienceKeyID       string `json:"audience_key_id"`
	TargetPath          string `json:"target_path"`
	MaxBatchSize        int    `json:"max_batch_size"`
	MaxLinkTTLSeconds   int    `json:"max_link_ttl_seconds"`
	CapabilityExpiresAt string `json:"capability_expires_at"`
	AuthorityExpiresAt  string `json:"authority_expires_at"`
}

// DelegatedMintIssueV1IdempotencyKey derives the stable request key used for
// one issuer upload generation. A later refresh increments generation and gets
// a different key without changing the upload authority.
func DelegatedMintIssueV1IdempotencyKey(issuerID, uploadHandle string, generation int) (string, error) {
	preimage, err := delegatedMintIssueV1IdempotencyPreimage(issuerID, uploadHandle, generation)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(preimage)
	return DelegatedMintIssueV1IdempotencyKeyPrefix + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func delegatedMintIssueV1IdempotencyPreimage(issuerID, uploadHandle string, generation int) ([]byte, error) {
	if !delegatedMintIssueV1IssuerFieldPattern.MatchString(issuerID) ||
		!delegatedMintIssueV1UploadHandlePattern.MatchString(uploadHandle) || generation <= 0 {
		return nil, errors.New("conformance: invalid delegated-mint issue idempotency input")
	}
	if decoded, err := decodeDelegatedMintIssueV1Base64URL(strings.TrimPrefix(uploadHandle, "upl_")); err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("conformance: invalid delegated-mint upload handle")
	}
	preimage := append([]byte(DelegatedMintIssueV1IdempotencyDomain), 0)
	for _, field := range []string{issuerID, uploadHandle, strconv.Itoa(generation)} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		preimage = append(preimage, length[:]...)
		preimage = append(preimage, field...)
	}
	return preimage, nil
}

func validateDelegatedMintIssueV1Golden(golden DelegatedMintIssueV1Golden) error {
	canonical, err := DelegatedMintIssueV1CanonicalBytes(golden)
	if err != nil {
		return err
	}
	if hex.EncodeToString(canonical) != golden.CanonicalHex {
		return errors.New("conformance: delegated-mint issue canonical bytes mismatch")
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != golden.SigningDigestHex {
		return errors.New("conformance: delegated-mint issue signing digest mismatch")
	}
	publicDER, err := decodeDelegatedMintIssueV1Base64URL(golden.PublicKeyDERB64URL)
	if err != nil {
		return errors.New("conformance: delegated-mint issue public key encoding is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return errors.New("conformance: delegated-mint issue public key is invalid")
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() || publicKey.X == nil || publicKey.Y == nil {
		return errors.New("conformance: delegated-mint issue public key is not P-256")
	}
	if len(golden.SignatureDERB64URL) > base64.RawURLEncoding.EncodedLen(DelegatedMintIssueV1SignatureDERMaxBytes) {
		return errors.New("conformance: delegated-mint issue signature encoding is too long")
	}
	signatureDER, err := decodeDelegatedMintIssueV1Base64URL(golden.SignatureDERB64URL)
	if err != nil {
		return errors.New("conformance: delegated-mint issue signature encoding is invalid")
	}
	if len(signatureDER) > DelegatedMintIssueV1SignatureDERMaxBytes {
		return errors.New("conformance: delegated-mint issue signature DER is too long")
	}
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(signatureDER, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		return errors.New("conformance: delegated-mint issue signature DER is invalid")
	}
	canonicalDER, err := asn1.Marshal(signature)
	if err != nil || !bytes.Equal(canonicalDER, signatureDER) {
		return errors.New("conformance: delegated-mint issue signature DER is not canonical")
	}
	n := elliptic.P256().Params().N
	halfN := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if signature.R.Sign() <= 0 || signature.R.Cmp(n) >= 0 || signature.S.Sign() <= 0 || signature.S.Cmp(halfN) > 0 {
		return errors.New("conformance: delegated-mint issue signature scalar is invalid or high-S")
	}
	if !ecdsa.Verify(publicKey, digest[:], signature.R, signature.S) {
		return errors.New("conformance: delegated-mint issue signature verification failed")
	}
	return nil
}

func validateDelegatedMintIssueV1Relations(file *DelegatedMintIssueV1File) error {
	for _, golden := range []DelegatedMintIssueV1Golden{file.Golden, file.RetryGolden, file.RefreshGolden, file.NonceReuseSigned, file.AuthorityConflictSigned} {
		if golden.Method != DelegatedMintIssueV1Method || golden.Authority != file.Golden.Authority ||
			golden.Route != DelegatedMintIssueV1Route || golden.IssuerID != file.Golden.IssuerID {
			return errors.New("conformance: delegated-mint configured endpoint relation is invalid")
		}
	}
	if file.WrongEndpointSigned.Method != DelegatedMintIssueV1Method ||
		file.WrongEndpointSigned.Route != DelegatedMintIssueV1Route ||
		file.WrongEndpointSigned.Authority == file.Golden.Authority {
		return errors.New("conformance: delegated-mint alternate endpoint relation is invalid")
	}
	if file.WrongEndpointSigned.KID != file.Golden.KID ||
		file.WrongEndpointSigned.PublicKeyDERB64URL != file.Golden.PublicKeyDERB64URL ||
		file.WrongEndpointSigned.IssuerID != file.Golden.IssuerID ||
		file.WrongEndpointSigned.BodyUTF8 != file.Golden.BodyUTF8 ||
		file.WrongEndpointSigned.IdempotencyKey != file.Golden.IdempotencyKey ||
		file.WrongEndpointSigned.IdempotencyPreimageHex != file.Golden.IdempotencyPreimageHex ||
		file.WrongEndpointSigned.TimestampUnix != file.Golden.TimestampUnix ||
		file.WrongEndpointSigned.Nonce == file.Golden.Nonce {
		return errors.New("conformance: delegated-mint alternate endpoint signed input drifted")
	}
	if file.Golden.KID == file.RetryGolden.KID ||
		file.Golden.PublicKeyDERB64URL == file.RetryGolden.PublicKeyDERB64URL ||
		file.RetryGolden.KID != file.RefreshGolden.KID ||
		file.RetryGolden.PublicKeyDERB64URL != file.RefreshGolden.PublicKeyDERB64URL ||
		file.NonceReuseSigned.KID != file.RefreshGolden.KID ||
		file.NonceReuseSigned.PublicKeyDERB64URL != file.RefreshGolden.PublicKeyDERB64URL {
		return errors.New("conformance: delegated-mint issuer key rotation relation is invalid")
	}
	if file.NonceReuseSigned.Nonce != file.Golden.Nonce ||
		file.NonceReuseSigned.Nonce == file.RefreshGolden.Nonce ||
		file.NonceReuseSigned.IdempotencyKey != file.RefreshGolden.IdempotencyKey ||
		file.NonceReuseSigned.IdempotencyPreimageHex != file.RefreshGolden.IdempotencyPreimageHex ||
		file.NonceReuseSigned.TimestampUnix <= file.Golden.TimestampUnix ||
		file.NonceReuseSigned.TimestampUnix-(file.Golden.TimestampUnix-int64(DelegatedMintIssueV1TimestampMaxSkewSeconds)) >= int64(DelegatedMintIssueV1NonceReplayRetentionSeconds) {
		return errors.New("conformance: delegated-mint signed nonce-reuse input drifted")
	}
	var nonceReuseBody, refreshBody delegatedMintIssueV1Body
	if err := strictDecodeArtifact([]byte(file.NonceReuseSigned.BodyUTF8), &nonceReuseBody); err != nil {
		return fmt.Errorf("conformance: parse delegated-mint nonce-reuse body: %w", err)
	}
	if err := strictDecodeArtifact([]byte(file.RefreshGolden.BodyUTF8), &refreshBody); err != nil {
		return fmt.Errorf("conformance: parse delegated-mint refresh body for nonce reuse: %w", err)
	}
	nonceReuseCapabilityExpiry, err := time.Parse(time.RFC3339, nonceReuseBody.CapabilityExpiresAt)
	if err != nil || nonceReuseCapabilityExpiry.Sub(time.Unix(file.NonceReuseSigned.TimestampUnix, 0)) != time.Duration(DelegatedMintIssueV1CapabilityTTLSeconds)*time.Second {
		return errors.New("conformance: delegated-mint nonce-reuse capability expiry is invalid")
	}
	nonceReuseBody.CapabilityExpiresAt = refreshBody.CapabilityExpiresAt
	if !reflect.DeepEqual(nonceReuseBody, refreshBody) {
		return errors.New("conformance: delegated-mint nonce-reuse input changed immutable generation authority")
	}
	var initialBody, conflictBody delegatedMintIssueV1Body
	if err := strictDecodeArtifact([]byte(file.Golden.BodyUTF8), &initialBody); err != nil {
		return fmt.Errorf("conformance: parse delegated-mint initial body for conflict: %w", err)
	}
	if err := strictDecodeArtifact([]byte(file.AuthorityConflictSigned.BodyUTF8), &conflictBody); err != nil {
		return fmt.Errorf("conformance: parse delegated-mint authority-conflict body: %w", err)
	}
	if file.AuthorityConflictSigned.KID != file.Golden.KID ||
		file.AuthorityConflictSigned.PublicKeyDERB64URL != file.Golden.PublicKeyDERB64URL ||
		file.AuthorityConflictSigned.IdempotencyKey != file.Golden.IdempotencyKey ||
		file.AuthorityConflictSigned.IdempotencyPreimageHex != file.Golden.IdempotencyPreimageHex ||
		file.AuthorityConflictSigned.TimestampUnix != file.Golden.TimestampUnix ||
		file.AuthorityConflictSigned.Nonce == file.Golden.Nonce ||
		conflictBody.DisplayFilename == initialBody.DisplayFilename {
		return errors.New("conformance: delegated-mint authority-conflict signed input drifted")
	}
	conflictBody.DisplayFilename = initialBody.DisplayFilename
	if !reflect.DeepEqual(initialBody, conflictBody) {
		return errors.New("conformance: delegated-mint authority-conflict input changed more than display_filename")
	}
	return nil
}

func validateDelegatedMintIssueV1Renewal(initial, refresh DelegatedMintIssueV1Golden) error {
	if initial.Method != refresh.Method || initial.Authority != refresh.Authority || initial.Route != refresh.Route ||
		initial.IssuerID != refresh.IssuerID || initial.Nonce == refresh.Nonce {
		return errors.New("conformance: delegated-mint refresh transport binding is invalid")
	}
	var initialBody, refreshBody delegatedMintIssueV1Body
	if err := strictDecodeArtifact([]byte(initial.BodyUTF8), &initialBody); err != nil {
		return fmt.Errorf("conformance: parse delegated-mint initial body: %w", err)
	}
	if err := strictDecodeArtifact([]byte(refresh.BodyUTF8), &refreshBody); err != nil {
		return fmt.Errorf("conformance: parse delegated-mint refresh body: %w", err)
	}
	if initialBody.IssueGeneration != 1 || refreshBody.IssueGeneration != 2 {
		return errors.New("conformance: delegated-mint golden generations are invalid")
	}
	wantInitialKey, err := DelegatedMintIssueV1IdempotencyKey(initial.IssuerID, initialBody.UploadHandle, initialBody.IssueGeneration)
	if err != nil || initial.IdempotencyKey != wantInitialKey {
		return errors.New("conformance: delegated-mint initial idempotency key is invalid")
	}
	initialPreimage, err := delegatedMintIssueV1IdempotencyPreimage(initial.IssuerID, initialBody.UploadHandle, initialBody.IssueGeneration)
	if err != nil || initial.IdempotencyPreimageHex != hex.EncodeToString(initialPreimage) {
		return errors.New("conformance: delegated-mint initial idempotency preimage is invalid")
	}
	wantRefreshKey, err := DelegatedMintIssueV1IdempotencyKey(refresh.IssuerID, refreshBody.UploadHandle, refreshBody.IssueGeneration)
	if err != nil || refresh.IdempotencyKey != wantRefreshKey {
		return errors.New("conformance: delegated-mint refresh idempotency key is invalid")
	}
	refreshPreimage, err := delegatedMintIssueV1IdempotencyPreimage(refresh.IssuerID, refreshBody.UploadHandle, refreshBody.IssueGeneration)
	if err != nil || refresh.IdempotencyPreimageHex != hex.EncodeToString(refreshPreimage) {
		return errors.New("conformance: delegated-mint refresh idempotency preimage is invalid")
	}
	initialCapabilityExpiry, err := time.Parse(time.RFC3339, initialBody.CapabilityExpiresAt)
	if err != nil {
		return errors.New("conformance: delegated-mint initial capability expiry is invalid")
	}
	refreshCapabilityExpiry, err := time.Parse(time.RFC3339, refreshBody.CapabilityExpiresAt)
	if err != nil {
		return errors.New("conformance: delegated-mint refresh capability expiry is invalid")
	}
	authorityExpiry, err := time.Parse(time.RFC3339, initialBody.AuthorityExpiresAt)
	if err != nil || refreshBody.AuthorityExpiresAt != initialBody.AuthorityExpiresAt {
		return errors.New("conformance: delegated-mint maximum authority expiry is invalid")
	}
	initialIssuedAt := time.Unix(initial.TimestampUnix, 0)
	refreshIssuedAt := time.Unix(refresh.TimestampUnix, 0)
	if !delegatedMintIssueV1CanonicalExpiry(initialBody.CapabilityExpiresAt, initialCapabilityExpiry) ||
		!delegatedMintIssueV1CanonicalExpiry(refreshBody.CapabilityExpiresAt, refreshCapabilityExpiry) ||
		!delegatedMintIssueV1CanonicalExpiry(initialBody.AuthorityExpiresAt, authorityExpiry) ||
		!initialCapabilityExpiry.After(initialIssuedAt) || !refreshCapabilityExpiry.After(refreshIssuedAt) ||
		!refreshIssuedAt.After(initialIssuedAt) || !refreshCapabilityExpiry.After(initialCapabilityExpiry) ||
		refreshCapabilityExpiry.After(authorityExpiry) ||
		initialCapabilityExpiry.Sub(initialIssuedAt) != time.Duration(DelegatedMintIssueV1CapabilityTTLSeconds)*time.Second ||
		refreshCapabilityExpiry.Sub(refreshIssuedAt) != time.Duration(DelegatedMintIssueV1CapabilityTTLSeconds)*time.Second ||
		authorityExpiry.Sub(initialIssuedAt) <= 0 ||
		authorityExpiry.Sub(initialIssuedAt) > time.Duration(DelegatedMintIssueV1AuthorityMaxTTLSeconds)*time.Second {
		return errors.New("conformance: delegated-mint capability expiry exceeds its renewal bounds")
	}
	initialBody.IssueGeneration = refreshBody.IssueGeneration
	initialBody.CapabilityExpiresAt = refreshBody.CapabilityExpiresAt
	if !reflect.DeepEqual(initialBody, refreshBody) {
		return errors.New("conformance: delegated-mint refresh widened immutable authority")
	}
	return nil
}

func validateDelegatedMintIssueV1StaleRetry(initial, retry DelegatedMintIssueV1Golden) error {
	if initial.Method != retry.Method || initial.Authority != retry.Authority || initial.Route != retry.Route ||
		initial.IssuerID != retry.IssuerID || initial.IdempotencyKey != retry.IdempotencyKey || initial.Nonce == retry.Nonce ||
		retry.TimestampUnix-initial.TimestampUnix <= int64(DelegatedMintIssueV1TimestampMaxSkewSeconds) {
		return errors.New("conformance: delegated-mint stale retry transport binding is invalid")
	}
	var initialBody, retryBody delegatedMintIssueV1Body
	if err := strictDecodeArtifact([]byte(initial.BodyUTF8), &initialBody); err != nil {
		return fmt.Errorf("conformance: parse delegated-mint stale-retry initial body: %w", err)
	}
	if err := strictDecodeArtifact([]byte(retry.BodyUTF8), &retryBody); err != nil {
		return fmt.Errorf("conformance: parse delegated-mint stale-retry body: %w", err)
	}
	if initialBody.IssueGeneration != 1 || retryBody.IssueGeneration != 1 ||
		initial.IdempotencyPreimageHex != retry.IdempotencyPreimageHex {
		return errors.New("conformance: delegated-mint stale retry changed operation identity")
	}
	retryCapabilityExpiry, err := time.Parse(time.RFC3339, retryBody.CapabilityExpiresAt)
	if err != nil || !delegatedMintIssueV1CanonicalExpiry(retryBody.CapabilityExpiresAt, retryCapabilityExpiry) ||
		retryCapabilityExpiry.Sub(time.Unix(retry.TimestampUnix, 0)) != time.Duration(DelegatedMintIssueV1CapabilityTTLSeconds)*time.Second {
		return errors.New("conformance: delegated-mint stale retry capability expiry is invalid")
	}
	authorityExpiry, err := time.Parse(time.RFC3339, retryBody.AuthorityExpiresAt)
	if err != nil || !delegatedMintIssueV1CanonicalExpiry(retryBody.AuthorityExpiresAt, authorityExpiry) ||
		retryCapabilityExpiry.After(authorityExpiry) {
		return errors.New("conformance: delegated-mint stale retry exceeds maximum authority")
	}
	if initialBody.CapabilityExpiresAt == retryBody.CapabilityExpiresAt {
		return errors.New("conformance: delegated-mint stale retry did not move capability expiry")
	}
	initialBody.CapabilityExpiresAt = retryBody.CapabilityExpiresAt
	if !reflect.DeepEqual(initialBody, retryBody) {
		return errors.New("conformance: delegated-mint stale retry changed immutable authority")
	}
	return nil
}

func validateDelegatedMintIssueV1Rejects(golden DelegatedMintIssueV1Golden, rejects []DelegatedMintIssueV1Reject) error {
	want, err := DelegatedMintIssueV1RejectCases(golden)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(rejects, want) {
		return errors.New("conformance: delegated-mint reject vectors drift")
	}
	for _, reject := range rejects {
		mutated, err := delegatedMintIssueV1ApplyReject(golden, reject)
		if err != nil {
			return err
		}
		if got := delegatedMintIssueV1RejectClass(mutated); got != reject.RejectClass {
			return fmt.Errorf("conformance: delegated-mint reject vector %q classified as %q, want %q", reject.Name, got, reject.RejectClass)
		}
	}
	return nil
}

func validateDelegatedMintIssueV1StateCases(file *DelegatedMintIssueV1File) error {
	want := DelegatedMintIssueV1StateCases(*file)
	if !reflect.DeepEqual(file.StateCases, want) {
		return errors.New("conformance: delegated-mint state vectors drift")
	}
	return nil
}

// DelegatedMintIssueV1StateCases derives the complete v1 receiver state table.
// The vector generator stores this result with each test-key rotation.
func DelegatedMintIssueV1StateCases(file DelegatedMintIssueV1File) []DelegatedMintIssueV1StateCase {
	return []DelegatedMintIssueV1StateCase{
		{
			Name: "first_issue", Input: "golden", NowUnix: file.Golden.TimestampUnix,
			PriorOperation: "absent", PriorNonce: "absent", Outcome: "issue_new",
			Status: DelegatedMintIssueV1SuccessStatus, Mutation: "store_operation_and_bind_nonce",
			ResponseSource: "new_durable_result", StrongOperationLookup: true,
		},
		{
			Name: "exact_stale_replay", Input: "golden",
			NowUnix:        file.Golden.TimestampUnix + int64(DelegatedMintIssueV1NonceReplayRetentionSeconds) + 1,
			PriorOperation: "golden_committed", PriorNonce: "expired", Outcome: "return_durable_result",
			Status: DelegatedMintIssueV1SuccessStatus, Mutation: "none",
			ResponseSource: "golden_durable_result", StrongOperationLookup: true,
		},
		{
			Name: "fresh_reconciliation", Input: "retry_golden", NowUnix: file.RetryGolden.TimestampUnix,
			PriorOperation: "golden_committed", PriorNonce: "absent", Outcome: "return_durable_result",
			Status: DelegatedMintIssueV1SuccessStatus, Mutation: "bind_nonce_to_existing_operation",
			ResponseSource: "golden_durable_result", StrongOperationLookup: true,
		},
		{
			Name: "generation_2_refresh", Input: "refresh_golden", NowUnix: file.RefreshGolden.TimestampUnix,
			PriorOperation: "generation_2_absent_generation_1_lineage_committed", PriorNonce: "absent", Outcome: "issue_new",
			Status: DelegatedMintIssueV1SuccessStatus, Mutation: "store_operation_and_bind_nonce",
			ResponseSource: "new_durable_result", StrongOperationLookup: true,
		},
		{
			Name: "stale_unseen", Input: "golden",
			NowUnix:        file.Golden.TimestampUnix + int64(DelegatedMintIssueV1TimestampMaxSkewSeconds) + 1,
			PriorOperation: "absent", PriorNonce: "absent", Outcome: "reject",
			Status: DelegatedMintIssueV1StaleMissStatus, ErrorCode: DelegatedMintIssueV1StaleMissCode,
			Mutation: "none", ResponseSource: "none", StrongOperationLookup: true,
		},
		{
			Name: "alternate_endpoint", Input: "wrong_endpoint_signed", NowUnix: file.WrongEndpointSigned.TimestampUnix,
			PriorOperation: "absent", PriorNonce: "absent", Outcome: "reject",
			Status: DelegatedMintIssueV1AuthFailureStatus, ErrorCode: DelegatedMintIssueV1AuthFailureCode,
			Mutation: "none", ResponseSource: "none", StrongOperationLookup: false,
		},
		{
			Name: "reused_nonce_across_operation", Input: "nonce_reuse_signed", NowUnix: file.NonceReuseSigned.TimestampUnix,
			PriorOperation: "absent", PriorNonce: "golden_bound_to_golden_operation", Outcome: "reject",
			Status: DelegatedMintIssueV1AuthFailureStatus, ErrorCode: DelegatedMintIssueV1AuthFailureCode,
			Mutation: "none", ResponseSource: "none", StrongOperationLookup: true,
		},
		{
			Name: "stale_non_exact_retry", Input: "retry_golden",
			NowUnix:        file.RetryGolden.TimestampUnix + int64(DelegatedMintIssueV1TimestampMaxSkewSeconds) + 1,
			PriorOperation: "golden_committed", PriorNonce: "absent", Outcome: "reject",
			Status: DelegatedMintIssueV1AuthFailureStatus, ErrorCode: DelegatedMintIssueV1AuthFailureCode,
			Mutation: "none", ResponseSource: "none", StrongOperationLookup: true,
		},
		{
			Name: "fresh_authority_conflict", Input: "authority_conflict_signed",
			NowUnix:        file.AuthorityConflictSigned.TimestampUnix,
			PriorOperation: "golden_committed", PriorNonce: "absent", Outcome: "reject",
			Status: 409, ErrorCode: "idempotency_conflict",
			Mutation: "none", ResponseSource: "none", StrongOperationLookup: true,
		},
	}
}

func validateDelegatedMintIssueV1ResponseCases(file *DelegatedMintIssueV1File) error {
	want := DelegatedMintIssueV1ResponseCases()
	if !reflect.DeepEqual(file.ResponseCases, want) {
		return errors.New("conformance: delegated-mint response vectors drift")
	}
	for _, response := range file.ResponseCases {
		switch response.RetryAfter.Mode {
		case DelegatedMintIssueV1RetryAfterAbsent, DelegatedMintIssueV1RetryAfterPositiveSeconds:
			if response.RetryAfter.Seconds != 0 {
				return fmt.Errorf("conformance: delegated-mint response %q has an unexpected exact Retry-After", response.Name)
			}
		case DelegatedMintIssueV1RetryAfterExactSeconds:
			if response.RetryAfter.Seconds <= 0 {
				return fmt.Errorf("conformance: delegated-mint response %q has an invalid exact Retry-After", response.Name)
			}
		default:
			return fmt.Errorf("conformance: delegated-mint response %q has an unknown Retry-After mode", response.Name)
		}
	}
	return nil
}

// DelegatedMintIssueV1ResponseCases freezes the receiver errors that affect
// producer retry, conflict, and mutation-recovery behavior.
func DelegatedMintIssueV1ResponseCases() []DelegatedMintIssueV1ResponseCase {
	return []DelegatedMintIssueV1ResponseCase{
		{Name: "invalid_request", Trigger: "strict_shape_or_semantic_body_rejection_before_state", Status: 400, ContentType: DelegatedMintIssueV1ErrorContentType, ErrorCode: "invalid_request", RetryAfter: DelegatedMintIssueV1RetryAfter{Mode: DelegatedMintIssueV1RetryAfterAbsent}},
		{Name: "invalid_capability_issue", Trigger: "signature_authority_freshness_or_nonce_rejection", Status: 403, ContentType: DelegatedMintIssueV1ErrorContentType, ErrorCode: DelegatedMintIssueV1AuthFailureCode, RetryAfter: DelegatedMintIssueV1RetryAfter{Mode: DelegatedMintIssueV1RetryAfterAbsent}},
		{Name: "issue_operation_not_found", Trigger: "authenticated_stale_strong_operation_miss", Status: DelegatedMintIssueV1StaleMissStatus, ContentType: DelegatedMintIssueV1ErrorContentType, ErrorCode: DelegatedMintIssueV1StaleMissCode, RetryAfter: DelegatedMintIssueV1RetryAfter{Mode: DelegatedMintIssueV1RetryAfterAbsent}, ProvesOperationAbsent: true},
		{Name: "idempotency_conflict", Trigger: "same_operation_different_immutable_authority", Status: 409, ContentType: DelegatedMintIssueV1ErrorContentType, ErrorCode: "idempotency_conflict", RetryAfter: DelegatedMintIssueV1RetryAfter{Mode: DelegatedMintIssueV1RetryAfterAbsent}},
		{Name: "payload_too_large", Trigger: "request_body_exceeds_8192_bytes_before_state", Status: 413, ContentType: DelegatedMintIssueV1ErrorContentType, ErrorCode: "payload_too_large", RetryAfter: DelegatedMintIssueV1RetryAfter{Mode: DelegatedMintIssueV1RetryAfterAbsent}},
		{Name: "rate_limit_exceeded", Trigger: "bounded_pre_auth_admission_rejection", Status: 429, ContentType: DelegatedMintIssueV1ErrorContentType, ErrorCode: "rate_limit_exceeded", RetryAfter: DelegatedMintIssueV1RetryAfter{Mode: DelegatedMintIssueV1RetryAfterPositiveSeconds}},
		{Name: "internal_error", Trigger: "receiver_configuration_or_internal_failure", Status: 500, ContentType: DelegatedMintIssueV1ErrorContentType, ErrorCode: "internal_error", RetryAfter: DelegatedMintIssueV1RetryAfter{Mode: DelegatedMintIssueV1RetryAfterAbsent}},
		{Name: "mutation_outcome_unknown", Trigger: "durable_write_outcome_cannot_be_reconciled", Status: 503, ContentType: DelegatedMintIssueV1ErrorContentType, ErrorCode: "mutation_outcome_unknown", RetryAfter: DelegatedMintIssueV1RetryAfter{Mode: DelegatedMintIssueV1RetryAfterExactSeconds, Seconds: 1}},
	}
}

// DelegatedMintIssueV1RejectCases derives the frozen negative vectors from an
// initial golden. The vector generator uses this after it rotates the test key.
func DelegatedMintIssueV1RejectCases(golden DelegatedMintIssueV1Golden) ([]DelegatedMintIssueV1Reject, error) {
	if len(golden.SignatureDERB64URL) > base64.RawURLEncoding.EncodedLen(DelegatedMintIssueV1SignatureDERMaxBytes) {
		return nil, errors.New("conformance: cannot derive delegated-mint reject vectors from oversized signature")
	}
	signatureDER, err := decodeDelegatedMintIssueV1Base64URL(golden.SignatureDERB64URL)
	if err != nil {
		return nil, errors.New("conformance: cannot derive delegated-mint reject vectors from invalid signature")
	}
	if len(signatureDER) > DelegatedMintIssueV1SignatureDERMaxBytes {
		return nil, errors.New("conformance: cannot derive delegated-mint reject vectors from oversized DER")
	}
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(signatureDER, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		return nil, errors.New("conformance: cannot derive delegated-mint reject vectors from invalid DER")
	}
	highS := new(big.Int).Sub(elliptic.P256().Params().N, signature.S)
	highDER, err := asn1.Marshal(struct{ R, S *big.Int }{signature.R, highS})
	if err != nil {
		return nil, fmt.Errorf("conformance: derive high-S delegated-mint reject: %w", err)
	}
	zeroRDER, err := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(0), signature.S})
	if err != nil {
		return nil, fmt.Errorf("conformance: derive zero-R delegated-mint reject: %w", err)
	}
	if len(signatureDER) < 6 || signatureDER[0] != 0x30 || signatureDER[1] >= 0x80 ||
		signatureDER[2] != 0x02 || signatureDER[3] >= 0x80 || int(signatureDER[1])+2 != len(signatureDER) ||
		int(signatureDER[3])+4 >= len(signatureDER) {
		return nil, errors.New("conformance: delegated-mint golden DER cannot produce the non-canonical reject")
	}
	nonCanonicalDER := make([]byte, 0, len(signatureDER)+1)
	nonCanonicalDER = append(nonCanonicalDER, 0x30, signatureDER[1]+1, 0x02, signatureDER[3]+1, 0)
	nonCanonicalDER = append(nonCanonicalDER, signatureDER[4:]...)
	encode := base64.RawURLEncoding.EncodeToString
	return []DelegatedMintIssueV1Reject{
		{Name: "reject_padded_signature", Base: "golden", Field: "signature_der_b64url", Operation: "replace", Value: golden.SignatureDERB64URL + "=", Outcome: "reject", RejectClass: "signature_encoding", Status: 403, ErrorCode: DelegatedMintIssueV1AuthFailureCode},
		{Name: "reject_noncanonical_signature_der", Base: "golden", Field: "signature_der_b64url", Operation: "replace", Value: encode(nonCanonicalDER), Outcome: "reject", RejectClass: "signature_encoding", Status: 403, ErrorCode: DelegatedMintIssueV1AuthFailureCode},
		{Name: "reject_high_s_signature", Base: "golden", Field: "signature_der_b64url", Operation: "replace", Value: encode(highDER), Outcome: "reject", RejectClass: "signature_malleability", Status: 403, ErrorCode: DelegatedMintIssueV1AuthFailureCode},
		{Name: "reject_zero_r_signature", Base: "golden", Field: "signature_der_b64url", Operation: "replace", Value: encode(zeroRDER), Outcome: "reject", RejectClass: "signature_scalar", Status: 403, ErrorCode: DelegatedMintIssueV1AuthFailureCode},
		{Name: "reject_oversize_body", Base: "golden", Field: "body_utf8", Operation: "ascii_repeat", Value: "a", Repeat: DelegatedMintIssueV1BodyMaxBytes + 1, Outcome: "reject", RejectClass: "body_size", Status: 413, ErrorCode: "payload_too_large"},
		{Name: "reject_bad_idempotency_key", Base: "golden", Field: "idempotency_key", Operation: "replace", Value: "bad key", Outcome: "reject", RejectClass: "idempotency_key", Status: 403, ErrorCode: DelegatedMintIssueV1AuthFailureCode},
		{Name: "reject_uppercase_authority", Base: "golden", Field: "authority", Operation: "replace", Value: strings.ToUpper(golden.Authority), Outcome: "reject", RejectClass: "authority", Status: 403, ErrorCode: DelegatedMintIssueV1AuthFailureCode},
		{Name: "reject_short_nonce", Base: "golden", Field: "nonce", Operation: "replace", Value: "AA", Outcome: "reject", RejectClass: "nonce", Status: 403, ErrorCode: DelegatedMintIssueV1AuthFailureCode},
		{Name: "reject_changed_body_stale_signature", Base: "golden", Field: "body_utf8", Operation: "append", Value: "\n", Outcome: "reject", RejectClass: "signature_mismatch", Status: 403, ErrorCode: DelegatedMintIssueV1AuthFailureCode},
	}, nil
}

func delegatedMintIssueV1ApplyReject(golden DelegatedMintIssueV1Golden, reject DelegatedMintIssueV1Reject) (DelegatedMintIssueV1Golden, error) {
	if reject.Base != "golden" || reject.Outcome != "reject" {
		return DelegatedMintIssueV1Golden{}, fmt.Errorf("conformance: delegated-mint reject %q has invalid base or outcome", reject.Name)
	}
	value := reject.Value
	switch reject.Operation {
	case "replace":
		if reject.Repeat != 0 {
			return DelegatedMintIssueV1Golden{}, fmt.Errorf("conformance: delegated-mint reject %q has an invalid repeat", reject.Name)
		}
	case "ascii_repeat":
		if len(reject.Value) != 1 || reject.Value[0] > 0x7f || reject.Repeat <= 0 ||
			reject.Repeat > DelegatedMintIssueV1BodyMaxBytes+1 {
			return DelegatedMintIssueV1Golden{}, fmt.Errorf("conformance: delegated-mint reject %q has an invalid repeat recipe", reject.Name)
		}
		value = strings.Repeat(reject.Value, reject.Repeat)
	case "append":
		if reject.Value == "" || reject.Repeat != 0 {
			return DelegatedMintIssueV1Golden{}, fmt.Errorf("conformance: delegated-mint reject %q has an invalid append recipe", reject.Name)
		}
	default:
		return DelegatedMintIssueV1Golden{}, fmt.Errorf("conformance: delegated-mint reject %q has an unknown operation", reject.Name)
	}
	switch reject.Field {
	case "signature_der_b64url":
		golden.SignatureDERB64URL = value
	case "body_utf8":
		golden.BodyUTF8 = value
	case "idempotency_key":
		golden.IdempotencyKey = value
	case "authority":
		golden.Authority = value
	case "nonce":
		golden.Nonce = value
	default:
		return DelegatedMintIssueV1Golden{}, fmt.Errorf("conformance: delegated-mint reject %q has an unknown field", reject.Name)
	}
	return golden, nil
}

func delegatedMintIssueV1RejectClass(golden DelegatedMintIssueV1Golden) string {
	if len(golden.BodyUTF8) > DelegatedMintIssueV1BodyMaxBytes || !utf8.ValidString(golden.BodyUTF8) {
		return "body_size"
	}
	if !validDelegatedMintIssueV1Authority(golden.Authority) {
		return "authority"
	}
	if !delegatedMintIssueV1IdempotencyPattern.MatchString(golden.IdempotencyKey) ||
		len(golden.IdempotencyKey) < DelegatedMintIssueV1IdempotencyKeyMinBytes ||
		len(golden.IdempotencyKey) > DelegatedMintIssueV1IdempotencyKeyMaxBytes {
		return "idempotency_key"
	}
	nonce, err := decodeDelegatedMintIssueV1Base64URL(golden.Nonce)
	if err != nil || len(nonce) != DelegatedMintIssueV1NonceBytes {
		return "nonce"
	}
	signatureDER, err := decodeDelegatedMintIssueV1Base64URL(golden.SignatureDERB64URL)
	if err != nil {
		return "signature_encoding"
	}
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(signatureDER, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		return "signature_encoding"
	}
	canonicalDER, err := asn1.Marshal(signature)
	if err != nil || !bytes.Equal(canonicalDER, signatureDER) {
		return "signature_encoding"
	}
	n := elliptic.P256().Params().N
	halfN := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if signature.R.Sign() <= 0 || signature.R.Cmp(n) >= 0 || signature.S.Sign() <= 0 || signature.S.Cmp(n) >= 0 {
		return "signature_scalar"
	}
	if signature.S.Cmp(halfN) > 0 {
		return "signature_malleability"
	}
	publicDER, err := decodeDelegatedMintIssueV1Base64URL(golden.PublicKeyDERB64URL)
	if err != nil {
		return "signature_mismatch"
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || publicKey.Curve != elliptic.P256() {
		return "signature_mismatch"
	}
	bodyDigest := sha256.Sum256([]byte(golden.BodyUTF8))
	golden.BodySHA256 = hex.EncodeToString(bodyDigest[:])
	canonical, err := DelegatedMintIssueV1CanonicalBytes(golden)
	if err != nil {
		return "signature_mismatch"
	}
	digest := sha256.Sum256(canonical)
	if !ecdsa.Verify(publicKey, digest[:], signature.R, signature.S) {
		return "signature_mismatch"
	}
	return ""
}

func delegatedMintIssueV1CanonicalExpiry(encoded string, parsed time.Time) bool {
	return parsed.Nanosecond() == 0 && parsed.Location() == time.UTC &&
		parsed.Format(time.RFC3339) == encoded
}

func decodeDelegatedMintIssueV1Base64URL(value string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("non-canonical base64url")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical base64url")
	}
	return decoded, nil
}

func validDelegatedMintIssueV1Authority(authority string) bool {
	if authority == "" || len(authority) > DelegatedMintIssueV1AuthorityMaxBytes || authority != strings.ToLower(authority) ||
		strings.Count(authority, ".") == 0 {
		return false
	}
	if _, err := netip.ParseAddr(authority); err == nil {
		return false
	}
	for _, label := range strings.Split(authority, ".") {
		if label == "" || len(label) > 63 || !delegatedMintIssueV1AuthorityAlphaNumeric(label[0]) ||
			!delegatedMintIssueV1AuthorityAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !delegatedMintIssueV1AuthorityAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func delegatedMintIssueV1AuthorityAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}
