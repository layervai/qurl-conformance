package conformance

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
)

const (
	// CRIDV1ArtifactID identifies the CRID v1 derivation and validation artifact.
	CRIDV1ArtifactID = "qurl-crid-v1-vectors"
	// CRIDV1SchemaVersion is the only schema accepted by this release.
	CRIDV1SchemaVersion = 1

	// CRIDV1DomainSeparationPrefix starts every digest input, followed by one
	// 0x00 separator byte and the DER SubjectPublicKeyInfo bytes.
	CRIDV1DomainSeparationPrefix = "NHP-QURL-CRID-V1"
	// CRIDV1DomainSeparator is the single byte between the prefix and the key.
	CRIDV1DomainSeparator = byte(0x00)
	// CRIDV1ChecksumLength is the byte length of the big-endian CRC32C
	// (Castagnoli, polynomial 0x1edc6f41) appended after the payload.
	CRIDV1ChecksumLength = 4
	// CRIDV1ChecksumPolynomialHex is the Castagnoli polynomial in normal
	// (non-reflected) form; Go's crc32.Castagnoli table constant is its
	// bit-reversed representation.
	CRIDV1ChecksumPolynomialHex = "1edc6f41"
	// CRIDV1Alphabet is the RFC 4648 base32 alphabet in lowercase; encoding is
	// unpadded.
	CRIDV1Alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	// CRIDV1EnvironmentBit distinguishes non-production version bytes.
	CRIDV1EnvironmentBit = byte(0x80)
	// CRIDV1ForbiddenVersion is permanently invalid and must reject locally.
	CRIDV1ForbiddenVersion = byte(0x00)

	CRIDV1FullDigestLength      = 32
	CRIDV1FullCRIDLength        = 60
	CRIDV1TruncatedDigestLength = 24
	CRIDV1TruncatedCRIDLength   = 47

	CRIDV1EnvironmentProduction = "production"
	CRIDV1EnvironmentTest       = "test"
	// CRIDV1EnvironmentUnknown is reported for structurally valid CRIDs whose
	// version byte is not in the registry; such values are forwarded, not
	// rejected.
	CRIDV1EnvironmentUnknown = "unknown"

	CRIDV1StatusActive   = "active"
	CRIDV1StatusReserved = "reserved"

	CRIDV1OutcomeMatch    = "match"
	CRIDV1OutcomeMismatch = "mismatch"

	// The closed local reject_class vocabulary. Adding a class is a breaking
	// change that requires a schema_version bump.
	CRIDV1RejectLength       = "length"
	CRIDV1RejectCharset      = "charset"
	CRIDV1RejectChecksum     = "checksum"
	CRIDV1RejectNonCanonical = "non_canonical"
	CRIDV1RejectVersion      = "version"
)

// CRIDV1File freezes the CRID v1 derivation, the local validation gate, the
// version-byte registry, and the delivered-key match rule.
type CRIDV1File struct {
	Artifact           string               `json:"artifact"`
	SchemaVersion      int                  `json:"schema_version"`
	Description        string               `json:"description"`
	Contract           CRIDV1Contract       `json:"contract"`
	Versions           []CRIDV1Version      `json:"versions"`
	ProducerCases      []CRIDV1ProducerCase `json:"producer_cases"`
	ConsumerValueCases []CRIDV1ValueCase    `json:"consumer_value_cases"`
	VersionCases       []CRIDV1VersionCase  `json:"version_cases"`
	KeyMatchCases      []CRIDV1KeyMatchCase `json:"key_match_cases"`
}

// CRIDV1Contract is the language-neutral public derivation grammar.
type CRIDV1Contract struct {
	DomainSeparationPrefix string `json:"domain_separation_prefix"`
	DomainSeparatorHex     string `json:"domain_separator_hex"`
	Digest                 string `json:"digest"`
	Checksum               string `json:"checksum"`
	ChecksumPolynomialHex  string `json:"checksum_polynomial_hex"`
	ChecksumByteOrder      string `json:"checksum_byte_order"`
	ChecksumLength         int    `json:"checksum_length"`
	Encoding               string `json:"encoding"`
	Alphabet               string `json:"alphabet"`
	EnvironmentBitHex      string `json:"environment_bit_hex"`
	ForbiddenVersionHex    string `json:"forbidden_version_hex"`
	FullDigestLength       int    `json:"full_digest_length"`
	FullCRIDLength         int    `json:"full_crid_length"`
	TruncatedDigestLength  int    `json:"truncated_digest_length"`
	TruncatedCRIDLength    int    `json:"truncated_crid_length"`
}

// CRIDV1Version is one row of the closed version-byte registry.
type CRIDV1Version struct {
	VersionHex   string `json:"version_hex"`
	DigestLength int    `json:"digest_length"`
	Environment  string `json:"environment"`
	Status       string `json:"status"`
}

// CRIDV1ProducerCase lets a producer drive its real derivation with a frozen
// DER SubjectPublicKeyInfo and version byte and compare every intermediate.
// PayloadHex is the complete pre-encoding byte string
// version_byte || digest[:digest_length] || crc; CRCHex is its final four
// bytes, computed over everything before them.
type CRIDV1ProducerCase struct {
	Name          string `json:"name"`
	DERSPKIB64URL string `json:"der_spki_b64url"`
	VersionByte   string `json:"version_byte"`
	Environment   string `json:"environment"`
	DigestHex     string `json:"digest_hex"`
	PayloadHex    string `json:"payload_hex"`
	CRCHex        string `json:"crc_hex"`
	ExpectedCRID  string `json:"expected_crid"`
}

// CRIDV1ValueCase is one direct input to the local validation gate.
type CRIDV1ValueCase struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Outcome     string `json:"outcome"`
	RejectClass string `json:"reject_class,omitempty"`
}

// CRIDV1VersionCase pins what a consumer reports for the version byte of a
// locally valid CRID.
type CRIDV1VersionCase struct {
	Name         string `json:"name"`
	Value        string `json:"value"`
	VersionHex   string `json:"version_hex"`
	Known        bool   `json:"known"`
	Environment  string `json:"environment"`
	DigestLength int    `json:"digest_length"`
}

// CRIDV1KeyMatchCase pins the consumer rule that a delivered public key is
// used only when its derived CRID equals the CRID the consumer already holds.
type CRIDV1KeyMatchCase struct {
	Name          string `json:"name"`
	CRID          string `json:"crid"`
	DERSPKIB64URL string `json:"der_spki_b64url"`
	Outcome       string `json:"outcome"`
}

var (
	cridV1Base32   = base32.NewEncoding(CRIDV1Alphabet).WithPadding(base32.NoPadding)
	cridV1CRCTable = crc32.MakeTable(crc32.Castagnoli)
)

// Frozen golden inputs shared across the CRID v1 fixture maps.
const (
	cridV1ResourceKeyQV2B64URL    = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ"
	cridV1ResourceKeyIssuerB64URL = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpDu9mdM6E96ncBm5qjKn16Rjv6sWoHRQQz2ElwKSg5YQDLCvofuEb7gmId2YBKv3YXcrdc3tmBaiRzYCH9Hp6Q"
	cridV1ResourceKeyFreshB64URL  = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQO7AVyQoQU-XEjGE--rSv9AqTGb3yXpNZdisdp9e21hjPI4Mbg3DVMIqd-ElkdErdNFl56iiTNFg6FPTMsWv4Q"

	cridV1ProdCanonicalCRID       = "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha"
	cridV1TestCanonicalCRID       = "qe4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw742pueoujq"
	cridV1IssuerProdCRID          = "aeqq3ixwrzh6k32picwqxzdkc4dkzenxwozcpcw2fstb5uug22dn3akqpppq"
	cridV1UnknownVersionFullCRID  = "p44jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743out3lhq"
	cridV1UnknownVersionTruncCRID = "p44jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobin3qa7fei"
)

var cridV1VersionRegistry = []CRIDV1Version{
	{VersionHex: "01", DigestLength: CRIDV1FullDigestLength, Environment: CRIDV1EnvironmentProduction, Status: CRIDV1StatusActive},
	{VersionHex: "81", DigestLength: CRIDV1FullDigestLength, Environment: CRIDV1EnvironmentTest, Status: CRIDV1StatusActive},
	{VersionHex: "02", DigestLength: CRIDV1TruncatedDigestLength, Environment: CRIDV1EnvironmentProduction, Status: CRIDV1StatusReserved},
	{VersionHex: "82", DigestLength: CRIDV1TruncatedDigestLength, Environment: CRIDV1EnvironmentTest, Status: CRIDV1StatusReserved},
}

var cridV1ProducerFixtures = map[string]struct {
	derSPKIB64URL string
	version       byte
}{
	"resource_key_qv2_v01":    {cridV1ResourceKeyQV2B64URL, 0x01},
	"resource_key_qv2_v81":    {cridV1ResourceKeyQV2B64URL, 0x81},
	"resource_key_issuer_v01": {cridV1ResourceKeyIssuerB64URL, 0x01},
	"resource_key_issuer_v81": {cridV1ResourceKeyIssuerB64URL, 0x81},
	"resource_key_fresh_v01":  {cridV1ResourceKeyFreshB64URL, 0x01},
	"resource_key_fresh_v81":  {cridV1ResourceKeyFreshB64URL, 0x81},
}

var cridV1ValueFixtures = map[string]string{
	"accept_prod_canonical":            cridV1ProdCanonicalCRID,
	"accept_test_canonical":            cridV1TestCanonicalCRID,
	"accept_unknown_version_full":      cridV1UnknownVersionFullCRID,
	"accept_unknown_version_truncated": cridV1UnknownVersionTruncCRID,
	"reject_empty":                     "",
	"reject_len_59":                    "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyh",
	"reject_len_61":                    "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyhaa",
	"reject_uppercase":                 "Ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha",
	"reject_digit_zero":                "0e4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha",
	"reject_digit_one":                 "ae4jqpd7ea1slq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha",
	"reject_symbol":                    "ae4jqpd7ea!slq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha",
	"reject_leading_space":             " ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha",
	"reject_trailing_newline":          "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha\n",
	"reject_checksum":                  "ae4jqpd7eaoslq7jinmjb4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha",
	"reject_trailing_bits":             "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyhb",
	"reject_version_zero":              "aa4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw7436eybuqq",
}

var cridV1VersionCaseFixtures = map[string]string{
	"prod_full":         cridV1ProdCanonicalCRID,
	"test_full":         cridV1TestCanonicalCRID,
	"unknown_full":      cridV1UnknownVersionFullCRID,
	"unknown_truncated": cridV1UnknownVersionTruncCRID,
}

var cridV1KeyMatchFixtures = map[string]struct {
	crid          string
	derSPKIB64URL string
}{
	"match_production":           {cridV1ProdCanonicalCRID, cridV1ResourceKeyQV2B64URL},
	"match_test":                 {cridV1TestCanonicalCRID, cridV1ResourceKeyQV2B64URL},
	"mismatch_wrong_key":         {cridV1ProdCanonicalCRID, cridV1ResourceKeyIssuerB64URL},
	"mismatch_wrong_key_reverse": {cridV1IssuerProdCRID, cridV1ResourceKeyFreshB64URL},
}

// ParseCRIDV1File strictly parses the CRID v1 artifact and independently
// re-derives every declared expectation: producer digests, checksums and
// CRIDs from the DER key bytes, consumer outcomes from the reference local
// gate, version-case fields from the registry, and key-match outcomes from
// the derivation itself.
func ParseCRIDV1File(data []byte) (*CRIDV1File, error) {
	var cf CRIDV1File
	if err := strictDecodeArtifact(data, &cf); err != nil {
		return nil, fmt.Errorf("conformance: parse CRID v1 file: %w", err)
	}
	if cf.Artifact != CRIDV1ArtifactID {
		return nil, fmt.Errorf("conformance: CRID v1 file has artifact %q, want %q", cf.Artifact, CRIDV1ArtifactID)
	}
	if cf.SchemaVersion != CRIDV1SchemaVersion {
		return nil, fmt.Errorf("conformance: CRID v1 file has schema_version %d, want %d", cf.SchemaVersion, CRIDV1SchemaVersion)
	}
	if cf.Description == "" {
		return nil, errors.New("conformance: CRID v1 file has empty description")
	}
	wantContract := CRIDV1Contract{
		DomainSeparationPrefix: CRIDV1DomainSeparationPrefix,
		DomainSeparatorHex:     hex.EncodeToString([]byte{CRIDV1DomainSeparator}),
		Digest:                 "SHA-256",
		Checksum:               "CRC32C",
		ChecksumPolynomialHex:  CRIDV1ChecksumPolynomialHex,
		ChecksumByteOrder:      "big-endian",
		ChecksumLength:         CRIDV1ChecksumLength,
		Encoding:               "base32-rfc4648-lowercase-unpadded",
		Alphabet:               CRIDV1Alphabet,
		EnvironmentBitHex:      hex.EncodeToString([]byte{CRIDV1EnvironmentBit}),
		ForbiddenVersionHex:    hex.EncodeToString([]byte{CRIDV1ForbiddenVersion}),
		FullDigestLength:       CRIDV1FullDigestLength,
		FullCRIDLength:         CRIDV1FullCRIDLength,
		TruncatedDigestLength:  CRIDV1TruncatedDigestLength,
		TruncatedCRIDLength:    CRIDV1TruncatedCRIDLength,
	}
	if cf.Contract != wantContract {
		return nil, fmt.Errorf("conformance: CRID v1 contract = %+v, want %+v", cf.Contract, wantContract)
	}
	if err := validateCRIDV1Versions(cf.Versions); err != nil {
		return nil, err
	}
	if err := validateCRIDV1ProducerCases(cf.ProducerCases); err != nil {
		return nil, err
	}
	if err := validateCRIDV1ValueCases(cf.ConsumerValueCases); err != nil {
		return nil, err
	}
	if err := validateCRIDV1VersionCases(cf.VersionCases); err != nil {
		return nil, err
	}
	if err := validateCRIDV1KeyMatchCases(cf.KeyMatchCases); err != nil {
		return nil, err
	}
	return &cf, nil
}

func validateCRIDV1Versions(rows []CRIDV1Version) error {
	if len(rows) != len(cridV1VersionRegistry) {
		return fmt.Errorf("conformance: CRID v1 version registry count = %d, want %d", len(rows), len(cridV1VersionRegistry))
	}
	for i, row := range rows {
		if row != cridV1VersionRegistry[i] {
			return fmt.Errorf("conformance: CRID v1 version registry row %d = %+v, want %+v", i, row, cridV1VersionRegistry[i])
		}
		version, err := cridV1DecodeVersionHex(row.VersionHex)
		if err != nil {
			return fmt.Errorf("conformance: CRID v1 version registry row %d: %w", i, err)
		}
		if version == CRIDV1ForbiddenVersion {
			return fmt.Errorf("conformance: CRID v1 version registry row %d registers the forbidden version byte", i)
		}
		if row.Environment != cridV1EnvironmentForVersion(version) {
			return fmt.Errorf("conformance: CRID v1 version registry row %d environment %q disagrees with the %#02x bit", i, row.Environment, CRIDV1EnvironmentBit)
		}
		if row.DigestLength != CRIDV1FullDigestLength && row.DigestLength != CRIDV1TruncatedDigestLength {
			return fmt.Errorf("conformance: CRID v1 version registry row %d digest_length = %d", i, row.DigestLength)
		}
		if row.Status != CRIDV1StatusActive && row.Status != CRIDV1StatusReserved {
			return fmt.Errorf("conformance: CRID v1 version registry row %d status = %q", i, row.Status)
		}
	}
	return nil
}

func validateCRIDV1ProducerCases(cases []CRIDV1ProducerCase) error {
	if len(cases) != len(cridV1ProducerFixtures) {
		return fmt.Errorf("conformance: CRID v1 producer case count = %d, want %d", len(cases), len(cridV1ProducerFixtures))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		fixture, ok := cridV1ProducerFixtures[c.Name]
		if !ok {
			return fmt.Errorf("conformance: unknown CRID v1 producer case %q", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate CRID v1 producer case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.DERSPKIB64URL != fixture.derSPKIB64URL {
			return fmt.Errorf("conformance: CRID v1 producer case %q der_spki_b64url does not match its fixture", c.Name)
		}
		if c.VersionByte != hex.EncodeToString([]byte{fixture.version}) {
			return fmt.Errorf("conformance: CRID v1 producer case %q version_byte = %q, want %q", c.Name, c.VersionByte, hex.EncodeToString([]byte{fixture.version}))
		}
		if c.Environment != cridV1EnvironmentForVersion(fixture.version) {
			return fmt.Errorf("conformance: CRID v1 producer case %q environment = %q, want %q", c.Name, c.Environment, cridV1EnvironmentForVersion(fixture.version))
		}
		der, err := base64.RawURLEncoding.Strict().DecodeString(c.DERSPKIB64URL)
		if err != nil {
			return fmt.Errorf("conformance: CRID v1 producer case %q der_spki_b64url: %w", c.Name, err)
		}
		digestLength, ok := cridV1RegistryDigestLength(fixture.version)
		if !ok {
			return fmt.Errorf("conformance: CRID v1 producer case %q uses unregistered version %#02x", c.Name, fixture.version)
		}
		digest, encoded, crc, crid := deriveCRIDV1(fixture.version, der, digestLength)
		if c.DigestHex != hex.EncodeToString(digest[:]) {
			return fmt.Errorf("conformance: CRID v1 producer case %q digest_hex does not re-derive", c.Name)
		}
		if c.PayloadHex != hex.EncodeToString(encoded) {
			return fmt.Errorf("conformance: CRID v1 producer case %q payload_hex does not re-derive", c.Name)
		}
		if c.CRCHex != hex.EncodeToString(crc) {
			return fmt.Errorf("conformance: CRID v1 producer case %q crc_hex does not re-derive", c.Name)
		}
		if c.ExpectedCRID != crid {
			return fmt.Errorf("conformance: CRID v1 producer case %q expected_crid does not re-derive", c.Name)
		}
		if err := cridV1CheckShape(crid, fixture.version); err != nil {
			return fmt.Errorf("conformance: CRID v1 producer case %q: %w", c.Name, err)
		}
		if outcome, _ := deriveCRIDV1ValueExpectation(crid); outcome != ExpectAccept {
			return fmt.Errorf("conformance: CRID v1 producer case %q derives a CRID its own local gate rejects", c.Name)
		}
	}
	return nil
}

func validateCRIDV1ValueCases(cases []CRIDV1ValueCase) error {
	if len(cases) != len(cridV1ValueFixtures) {
		return fmt.Errorf("conformance: CRID v1 consumer value case count = %d, want %d", len(cases), len(cridV1ValueFixtures))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		value, ok := cridV1ValueFixtures[c.Name]
		if !ok {
			return fmt.Errorf("conformance: unknown CRID v1 consumer value case %q", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate CRID v1 consumer value case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.Value != value {
			return fmt.Errorf("conformance: CRID v1 consumer value case %q value = %q, want %q", c.Name, c.Value, value)
		}
		wantOutcome, wantRejectClass := deriveCRIDV1ValueExpectation(c.Value)
		if c.Outcome != wantOutcome || c.RejectClass != wantRejectClass {
			return fmt.Errorf("conformance: CRID v1 consumer value case %q expectation = %q/%q, want %q/%q", c.Name, c.Outcome, c.RejectClass, wantOutcome, wantRejectClass)
		}
	}
	return nil
}

func validateCRIDV1VersionCases(cases []CRIDV1VersionCase) error {
	if len(cases) != len(cridV1VersionCaseFixtures) {
		return fmt.Errorf("conformance: CRID v1 version case count = %d, want %d", len(cases), len(cridV1VersionCaseFixtures))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		value, ok := cridV1VersionCaseFixtures[c.Name]
		if !ok {
			return fmt.Errorf("conformance: unknown CRID v1 version case %q", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate CRID v1 version case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.Value != value {
			return fmt.Errorf("conformance: CRID v1 version case %q value = %q, want %q", c.Name, c.Value, value)
		}
		versionHex, known, environment, digestLength, err := deriveCRIDV1VersionExpectation(c.Value)
		if err != nil {
			return fmt.Errorf("conformance: CRID v1 version case %q: %w", c.Name, err)
		}
		if c.VersionHex != versionHex || c.Known != known || c.Environment != environment || c.DigestLength != digestLength {
			return fmt.Errorf("conformance: CRID v1 version case %q expectation = %q/%t/%q/%d, want %q/%t/%q/%d",
				c.Name, c.VersionHex, c.Known, c.Environment, c.DigestLength, versionHex, known, environment, digestLength)
		}
	}
	return nil
}

func validateCRIDV1KeyMatchCases(cases []CRIDV1KeyMatchCase) error {
	if len(cases) != len(cridV1KeyMatchFixtures) {
		return fmt.Errorf("conformance: CRID v1 key-match case count = %d, want %d", len(cases), len(cridV1KeyMatchFixtures))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		fixture, ok := cridV1KeyMatchFixtures[c.Name]
		if !ok {
			return fmt.Errorf("conformance: unknown CRID v1 key-match case %q", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate CRID v1 key-match case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.CRID != fixture.crid || c.DERSPKIB64URL != fixture.derSPKIB64URL {
			return fmt.Errorf("conformance: CRID v1 key-match case %q inputs do not match their fixtures", c.Name)
		}
		outcome, err := deriveCRIDV1KeyMatchExpectation(c.CRID, c.DERSPKIB64URL)
		if err != nil {
			return fmt.Errorf("conformance: CRID v1 key-match case %q: %w", c.Name, err)
		}
		if c.Outcome != outcome {
			return fmt.Errorf("conformance: CRID v1 key-match case %q expectation = %q, want %q", c.Name, c.Outcome, outcome)
		}
	}
	return nil
}

// cridV1RegistryDigestLength returns the digest width the version registry
// pins for a version byte, so producer validation derives at the registered
// width rather than assuming the full-digest shape — correct by construction
// if a reserved truncated version ever gains a producer fixture.
func cridV1RegistryDigestLength(version byte) (int, bool) {
	for _, row := range cridV1VersionRegistry {
		rowVersion, err := cridV1DecodeVersionHex(row.VersionHex)
		if err != nil {
			continue
		}
		if rowVersion == version {
			return row.DigestLength, true
		}
	}
	return 0, false
}

// deriveCRIDV1 derives a CRID from a version byte and DER SubjectPublicKeyInfo
// bytes. It returns the full SHA-256 digest, the complete pre-encoding byte
// string version || digest[:digestLength] || crc, the big-endian CRC32C bytes,
// and the encoded CRID.
func deriveCRIDV1(version byte, derSPKI []byte, digestLength int) (digest [sha256.Size]byte, encoded, crc []byte, crid string) {
	message := make([]byte, 0, len(CRIDV1DomainSeparationPrefix)+1+len(derSPKI))
	message = append(message, CRIDV1DomainSeparationPrefix...)
	message = append(message, CRIDV1DomainSeparator)
	message = append(message, derSPKI...)
	digest = sha256.Sum256(message)
	payload := append([]byte{version}, digest[:digestLength]...)
	crc = make([]byte, CRIDV1ChecksumLength)
	binary.BigEndian.PutUint32(crc, crc32.Checksum(payload, cridV1CRCTable))
	encoded = append(payload, crc...)
	return digest, encoded, crc, cridV1Base32.EncodeToString(encoded)
}

// deriveCRIDV1ValueExpectation is the reference local validation gate. Accept
// means only that every local check passed; the value must still be forwarded
// to the authoritative validator. Unknown version bytes are accepted here by
// design; only permanently invalid inputs reject.
func deriveCRIDV1ValueExpectation(value string) (outcome, rejectClass string) {
	for i := 0; i < len(value); i++ {
		if strings.IndexByte(CRIDV1Alphabet, value[i]) < 0 {
			return ExpectReject, CRIDV1RejectCharset
		}
	}
	if len(value) != CRIDV1FullCRIDLength && len(value) != CRIDV1TruncatedCRIDLength {
		return ExpectReject, CRIDV1RejectLength
	}
	decoded, err := cridV1Base32.DecodeString(value)
	if err != nil || cridV1Base32.EncodeToString(decoded) != value {
		// Go's decoder does not police the trailing pad bits, so canonicality
		// is enforced by round-tripping the decoded bytes.
		return ExpectReject, CRIDV1RejectNonCanonical
	}
	payload, crc := decoded[:len(decoded)-CRIDV1ChecksumLength], decoded[len(decoded)-CRIDV1ChecksumLength:]
	if binary.BigEndian.Uint32(crc) != crc32.Checksum(payload, cridV1CRCTable) {
		return ExpectReject, CRIDV1RejectChecksum
	}
	if payload[0] == CRIDV1ForbiddenVersion {
		return ExpectReject, CRIDV1RejectVersion
	}
	return ExpectAccept, ""
}

// deriveCRIDV1VersionExpectation reports the version fields a consumer must
// surface for a locally valid CRID.
func deriveCRIDV1VersionExpectation(value string) (versionHex string, known bool, environment string, digestLength int, err error) {
	if outcome, rejectClass := deriveCRIDV1ValueExpectation(value); outcome != ExpectAccept {
		return "", false, "", 0, fmt.Errorf("value fails the local gate with class %q", rejectClass)
	}
	decoded, err := cridV1Base32.DecodeString(value)
	if err != nil {
		return "", false, "", 0, err
	}
	version := decoded[0]
	versionHex = hex.EncodeToString([]byte{version})
	digestLength = len(decoded) - CRIDV1ChecksumLength - 1
	for _, row := range cridV1VersionRegistry {
		if row.VersionHex != versionHex {
			continue
		}
		if row.DigestLength != digestLength {
			return "", false, "", 0, fmt.Errorf("registered version %q pins digest length %d but the value carries %d", versionHex, row.DigestLength, digestLength)
		}
		return versionHex, true, row.Environment, row.DigestLength, nil
	}
	return versionHex, false, CRIDV1EnvironmentUnknown, digestLength, nil
}

// deriveCRIDV1KeyMatchExpectation re-derives a CRID from the delivered key
// under the held CRID's version byte and digest length and reports whether a
// consumer may use the key.
func deriveCRIDV1KeyMatchExpectation(crid, derSPKIB64URL string) (string, error) {
	if outcome, rejectClass := deriveCRIDV1ValueExpectation(crid); outcome != ExpectAccept {
		return "", fmt.Errorf("held CRID fails the local gate with class %q", rejectClass)
	}
	decoded, err := cridV1Base32.DecodeString(crid)
	if err != nil {
		return "", err
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(derSPKIB64URL)
	if err != nil {
		return "", fmt.Errorf("der_spki_b64url: %w", err)
	}
	_, _, _, derived := deriveCRIDV1(decoded[0], der, len(decoded)-CRIDV1ChecksumLength-1)
	if derived == crid {
		return CRIDV1OutcomeMatch, nil
	}
	return CRIDV1OutcomeMismatch, nil
}

func cridV1DecodeVersionHex(versionHex string) (byte, error) {
	decoded, err := hex.DecodeString(versionHex)
	if err != nil {
		return 0, fmt.Errorf("version_hex %q: %w", versionHex, err)
	}
	if len(decoded) != 1 {
		return 0, fmt.Errorf("version_hex %q is not one byte", versionHex)
	}
	return decoded[0], nil
}

func cridV1EnvironmentForVersion(version byte) string {
	if version&CRIDV1EnvironmentBit != 0 {
		return CRIDV1EnvironmentTest
	}
	return CRIDV1EnvironmentProduction
}

// cridV1CheckShape enforces the structural encoding facts: exact length, the
// zero-pad-bit final-character classes, and the version-derived first
// character (production full CRIDs start 'a', test 'q').
func cridV1CheckShape(crid string, version byte) error {
	switch len(crid) {
	case CRIDV1FullCRIDLength:
		if last := crid[len(crid)-1]; last != 'a' && last != 'q' {
			return fmt.Errorf("full CRID final char %q is not 'a' or 'q'", last)
		}
	case CRIDV1TruncatedCRIDLength:
		if last := crid[len(crid)-1]; last != 'a' && last != 'i' && last != 'q' && last != 'y' {
			return fmt.Errorf("truncated CRID final char %q is not one of 'a','i','q','y'", last)
		}
	default:
		return fmt.Errorf("CRID length %d is neither %d nor %d", len(crid), CRIDV1FullCRIDLength, CRIDV1TruncatedCRIDLength)
	}
	if want := CRIDV1Alphabet[version>>3]; crid[0] != want {
		return fmt.Errorf("CRID first char %q does not encode the top five bits of version %#02x (%q)", crid[0], version, want)
	}
	return nil
}
