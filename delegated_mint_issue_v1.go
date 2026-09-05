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
	DelegatedMintIssueV1Description   = "Byte-exact private Connector-to-qurl-service authentication contract for delegated-mint capability issuance. The signature binds the configured issuer identity, exact request body, route, authority, replay nonce, and idempotency key. Capability claims and public redemption remain separate service-owned contracts."

	DelegatedMintIssueV1Method                 = "POST"
	DelegatedMintIssueV1Route                  = "/internal/v1/delegated-mint-capabilities"
	DelegatedMintIssueV1SigningDomain          = "LV-QURL-CAPABILITY-ISSUE-V1"
	DelegatedMintIssueV1SigningDomainSeparator = "00"
	DelegatedMintIssueV1FrameEncoding          = "u32be_byte_length_then_exact_utf8_bytes"
	DelegatedMintIssueV1BodyDigest             = "SHA-256"
	DelegatedMintIssueV1BodyDigestEncoding     = "lowercase_hex"
	DelegatedMintIssueV1SignatureAlgorithm     = "ECDSA_P-256_SHA-256"
	DelegatedMintIssueV1SignatureEncoding      = "canonical_der_base64url_unpadded_low_s"
	DelegatedMintIssueV1PublicKeyEncoding      = "der_spki_base64url_unpadded"
	DelegatedMintIssueV1NonceEncoding          = "base64url_unpadded"
	DelegatedMintIssueV1NonceBytes             = 16
	DelegatedMintIssueV1IdempotencyKeyMinBytes = 1
	DelegatedMintIssueV1IdempotencyKeyMaxBytes = 128
	DelegatedMintIssueV1AuthorityNormalization = "lowercase_dns_name_no_port"
	DelegatedMintIssueV1AuthorityMaxBytes      = 253
	DelegatedMintIssueV1BodyMaxBytes           = 8192
	DelegatedMintIssueV1SuccessStatus          = 200
	DelegatedMintIssueV1SuccessContentType     = "application/json"
	DelegatedMintIssueV1CapabilityTTLSeconds   = 15 * 60
	DelegatedMintIssueV1AuthorityMaxTTLSeconds = 24 * 60 * 60
	DelegatedMintIssueV1IdempotencyDomain      = "LV-QURL-CAPABILITY-ISSUE-IDEMPOTENCY-V1"
	DelegatedMintIssueV1IdempotencyDerivation  = "domain_then_zero_then_u32be_length_prefixed_issuer_id_upload_handle_generation_decimal_sha256_base64url_unpadded"

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
)

type DelegatedMintIssueV1File struct {
	Artifact      string                       `json:"artifact"`
	SchemaVersion int                          `json:"schema_version"`
	Description   string                       `json:"description"`
	Contract      DelegatedMintIssueV1Contract `json:"contract"`
	Golden        DelegatedMintIssueV1Golden   `json:"golden"`
	RefreshGolden DelegatedMintIssueV1Golden   `json:"refresh_golden"`
}

type DelegatedMintIssueV1Contract struct {
	Method                 string   `json:"method"`
	Route                  string   `json:"route"`
	SigningDomainASCII     string   `json:"signing_domain_ascii"`
	SigningDomainSeparator string   `json:"signing_domain_separator_hex"`
	FrameEncoding          string   `json:"frame_encoding"`
	FieldOrder             []string `json:"field_order"`
	BodyDigest             string   `json:"body_digest"`
	BodyDigestEncoding     string   `json:"body_digest_encoding"`
	BodyMaxBytes           int      `json:"body_max_bytes"`
	SignatureAlgorithm     string   `json:"signature_algorithm"`
	SignatureEncoding      string   `json:"signature_encoding"`
	PublicKeyEncoding      string   `json:"public_key_encoding"`
	NonceEncoding          string   `json:"nonce_encoding"`
	NonceDecodedBytes      int      `json:"nonce_decoded_bytes"`
	IdempotencyKeyPattern  string   `json:"idempotency_key_pattern"`
	IdempotencyDomain      string   `json:"idempotency_derivation_domain_ascii"`
	IdempotencyDerivation  string   `json:"idempotency_derivation"`
	IdempotencyKeyMinBytes int      `json:"idempotency_key_min_bytes"`
	IdempotencyKeyMaxBytes int      `json:"idempotency_key_max_bytes"`
	IdempotencyKeyHeader   string   `json:"idempotency_key_header"`
	IssuerFieldPattern     string   `json:"issuer_field_pattern"`
	IssuerIDHeader         string   `json:"issuer_id_header"`
	KIDHeader              string   `json:"kid_header"`
	TimestampHeader        string   `json:"timestamp_header"`
	NonceHeader            string   `json:"nonce_header"`
	SignatureHeader        string   `json:"signature_header"`
	AuthorityNormalization string   `json:"authority_normalization"`
	AuthorityMaxBytes      int      `json:"authority_max_bytes"`
	SuccessStatus          int      `json:"success_status"`
	SuccessContentType     string   `json:"success_content_type"`
	SuccessEnvelope        string   `json:"success_envelope"`
	SuccessDataFields      []string `json:"success_data_fields"`
	CapabilityTTLSeconds   int      `json:"capability_ttl_seconds"`
	AuthorityMaxTTLSeconds int      `json:"authority_max_ttl_seconds"`
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
	if err := validateDelegatedMintIssueV1Golden(file.RefreshGolden); err != nil {
		return nil, err
	}
	if err := validateDelegatedMintIssueV1Renewal(file.Golden, file.RefreshGolden); err != nil {
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

func validateDelegatedMintIssueV1Contract(contract DelegatedMintIssueV1Contract) error {
	want := DelegatedMintIssueV1Contract{
		Method: DelegatedMintIssueV1Method, Route: DelegatedMintIssueV1Route,
		SigningDomainASCII: DelegatedMintIssueV1SigningDomain, SigningDomainSeparator: DelegatedMintIssueV1SigningDomainSeparator,
		FrameEncoding: DelegatedMintIssueV1FrameEncoding, FieldOrder: delegatedMintIssueV1FieldOrder,
		BodyDigest: DelegatedMintIssueV1BodyDigest, BodyDigestEncoding: DelegatedMintIssueV1BodyDigestEncoding,
		BodyMaxBytes:       DelegatedMintIssueV1BodyMaxBytes,
		SignatureAlgorithm: DelegatedMintIssueV1SignatureAlgorithm, SignatureEncoding: DelegatedMintIssueV1SignatureEncoding,
		PublicKeyEncoding: DelegatedMintIssueV1PublicKeyEncoding, NonceEncoding: DelegatedMintIssueV1NonceEncoding,
		NonceDecodedBytes: DelegatedMintIssueV1NonceBytes, IdempotencyKeyPattern: delegatedMintIssueV1IdempotencyPattern.String(),
		IdempotencyDomain: DelegatedMintIssueV1IdempotencyDomain, IdempotencyDerivation: DelegatedMintIssueV1IdempotencyDerivation,
		IdempotencyKeyMinBytes: DelegatedMintIssueV1IdempotencyKeyMinBytes, IdempotencyKeyMaxBytes: DelegatedMintIssueV1IdempotencyKeyMaxBytes,
		IdempotencyKeyHeader: DelegatedMintIssueV1IdempotencyKeyHeader,
		IssuerFieldPattern:   delegatedMintIssueV1IssuerFieldPattern.String(), IssuerIDHeader: DelegatedMintIssueV1IssuerIDHeader,
		KIDHeader: DelegatedMintIssueV1KIDHeader, TimestampHeader: DelegatedMintIssueV1TimestampHeader,
		NonceHeader: DelegatedMintIssueV1NonceHeader, SignatureHeader: DelegatedMintIssueV1SignatureHeader,
		AuthorityNormalization: DelegatedMintIssueV1AuthorityNormalization, AuthorityMaxBytes: DelegatedMintIssueV1AuthorityMaxBytes,
		SuccessStatus: DelegatedMintIssueV1SuccessStatus, SuccessContentType: DelegatedMintIssueV1SuccessContentType,
		SuccessEnvelope: "data", SuccessDataFields: delegatedMintIssueV1SuccessDataFields,
		CapabilityTTLSeconds: DelegatedMintIssueV1CapabilityTTLSeconds, AuthorityMaxTTLSeconds: DelegatedMintIssueV1AuthorityMaxTTLSeconds,
	}
	if !reflect.DeepEqual(contract, want) {
		return errors.New("conformance: delegated-mint issue contract drift")
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
	return "uci_" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
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
	if !ok || publicKey.Curve != elliptic.P256() || publicKey.X == nil || publicKey.Y == nil || !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return errors.New("conformance: delegated-mint issue public key is not P-256")
	}
	signatureDER, err := decodeDelegatedMintIssueV1Base64URL(golden.SignatureDERB64URL)
	if err != nil {
		return errors.New("conformance: delegated-mint issue signature encoding is invalid")
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

func validateDelegatedMintIssueV1Renewal(initial, refresh DelegatedMintIssueV1Golden) error {
	if initial.Method != refresh.Method || initial.Authority != refresh.Authority || initial.Route != refresh.Route ||
		initial.IssuerID != refresh.IssuerID || initial.KID != refresh.KID ||
		initial.PublicKeyDERB64URL != refresh.PublicKeyDERB64URL || initial.Nonce == refresh.Nonce {
		return errors.New("conformance: delegated-mint refresh signer binding is invalid")
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
	if !initialCapabilityExpiry.After(initialIssuedAt) || !refreshCapabilityExpiry.After(refreshIssuedAt) ||
		!refreshIssuedAt.After(initialIssuedAt) || !refreshCapabilityExpiry.After(initialCapabilityExpiry) ||
		refreshCapabilityExpiry.After(authorityExpiry) ||
		initialCapabilityExpiry.Sub(initialIssuedAt) != time.Duration(DelegatedMintIssueV1CapabilityTTLSeconds)*time.Second ||
		refreshCapabilityExpiry.Sub(refreshIssuedAt) != time.Duration(DelegatedMintIssueV1CapabilityTTLSeconds)*time.Second ||
		authorityExpiry.Sub(initialIssuedAt) != time.Duration(DelegatedMintIssueV1AuthorityMaxTTLSeconds)*time.Second {
		return errors.New("conformance: delegated-mint capability expiry exceeds its renewal bounds")
	}
	initialBody.IssueGeneration = refreshBody.IssueGeneration
	initialBody.CapabilityExpiresAt = refreshBody.CapabilityExpiresAt
	if !reflect.DeepEqual(initialBody, refreshBody) {
		return errors.New("conformance: delegated-mint refresh widened immutable authority")
	}
	return nil
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
