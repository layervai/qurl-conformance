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
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
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
	DelegatedMintIssueV1AuthorityNormalization = "lowercase_exact"
	DelegatedMintIssueV1AuthorityMaxBytes      = 253
	DelegatedMintIssueV1BodyMaxBytes           = 8192

	DelegatedMintIssueV1IdempotencyKeyHeader = "Idempotency-Key"
	DelegatedMintIssueV1IssuerIDHeader       = "X-LayerV-Issuer-ID"
	DelegatedMintIssueV1KIDHeader            = "X-LayerV-Issuer-KID"
	DelegatedMintIssueV1TimestampHeader      = "X-LayerV-Timestamp"
	DelegatedMintIssueV1NonceHeader          = "X-LayerV-Nonce"
	DelegatedMintIssueV1SignatureHeader      = "X-LayerV-Signature"
)

var (
	delegatedMintIssueV1IdempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
	delegatedMintIssueV1IssuerFieldPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	delegatedMintIssueV1HexDigestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	delegatedMintIssueV1FieldOrder         = []string{"method", "authority", "route", "issuer_id", "kid", "idempotency_key", "timestamp_unix_decimal", "nonce", "body_sha256"}
)

type DelegatedMintIssueV1File struct {
	Artifact      string                       `json:"artifact"`
	SchemaVersion int                          `json:"schema_version"`
	Description   string                       `json:"description"`
	Contract      DelegatedMintIssueV1Contract `json:"contract"`
	Golden        DelegatedMintIssueV1Golden   `json:"golden"`
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
}

type DelegatedMintIssueV1Golden struct {
	Method             string `json:"method"`
	Authority          string `json:"authority"`
	Route              string `json:"route"`
	IssuerID           string `json:"issuer_id"`
	KID                string `json:"kid"`
	IdempotencyKey     string `json:"idempotency_key"`
	TimestampUnix      int64  `json:"timestamp_unix"`
	Nonce              string `json:"nonce"`
	BodyUTF8           string `json:"body_utf8"`
	BodySHA256         string `json:"body_sha256"`
	CanonicalHex       string `json:"canonical_hex"`
	SigningDigestHex   string `json:"signing_digest_hex"`
	PublicKeyDERB64URL string `json:"public_key_der_b64url"`
	SignatureDERB64URL string `json:"signature_der_b64url"`
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
		IdempotencyKeyMinBytes: DelegatedMintIssueV1IdempotencyKeyMinBytes, IdempotencyKeyMaxBytes: DelegatedMintIssueV1IdempotencyKeyMaxBytes,
		IdempotencyKeyHeader: DelegatedMintIssueV1IdempotencyKeyHeader,
		IssuerFieldPattern:   delegatedMintIssueV1IssuerFieldPattern.String(), IssuerIDHeader: DelegatedMintIssueV1IssuerIDHeader,
		KIDHeader: DelegatedMintIssueV1KIDHeader, TimestampHeader: DelegatedMintIssueV1TimestampHeader,
		NonceHeader: DelegatedMintIssueV1NonceHeader, SignatureHeader: DelegatedMintIssueV1SignatureHeader,
		AuthorityNormalization: DelegatedMintIssueV1AuthorityNormalization, AuthorityMaxBytes: DelegatedMintIssueV1AuthorityMaxBytes,
	}
	if !reflect.DeepEqual(contract, want) {
		return errors.New("conformance: delegated-mint issue contract drift")
	}
	return nil
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
		strings.ContainsAny(authority, "\\/@?# ") {
		return false
	}
	parsed, err := url.Parse("https://" + authority)
	return err == nil && parsed.User == nil && parsed.Host == authority && parsed.Hostname() != "" &&
		parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}
