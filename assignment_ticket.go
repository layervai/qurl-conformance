package conformance

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	// AssignmentTicketArtifactID identifies the standalone qat1 artifact.
	AssignmentTicketArtifactID = "qurl-assignment-ticket-v1-vectors"
	// AssignmentTicketSchemaVersion is the only schema accepted by this release.
	AssignmentTicketSchemaVersion = 1

	AssignmentTicketPrefix        = "qat1"
	AssignmentTicketSigningDomain = "qurl-agent-assignment-ticket-v1"

	// AssignmentTicketSyntheticCredentialBytes is the byte length of the fixed
	// ASCII test credential committed in the golden artifact.
	AssignmentTicketSyntheticCredentialBytes = 51
)

// AssignmentTicketFile freezes the byte-level qat1 signing profile, the three
// optimistic fences, and negative inputs for strict producer/verifier tests.
type AssignmentTicketFile struct {
	Artifact            string                         `json:"artifact"`
	SchemaVersion       int                            `json:"schema_version"`
	Description         string                         `json:"description"`
	Contract            AssignmentTicketContract       `json:"contract"`
	SyntheticSigningKey AssignmentTicketSyntheticKey   `json:"synthetic_signing_key"`
	FenceVectors        []AssignmentTicketFenceVector  `json:"fence_vectors"`
	Golden              AssignmentTicketGolden         `json:"golden"`
	VerifyRejects       []AssignmentTicketVerifyReject `json:"verify_rejects"`
	ClaimsRejects       []AssignmentTicketClaimsReject `json:"claims_rejects"`
	KMSDERCases         []AssignmentTicketDERCase      `json:"kms_der_cases"`
	FenceRejects        []AssignmentTicketFenceReject  `json:"fence_rejects"`
	TrustKeyRejects     []AssignmentTicketTrustReject  `json:"trust_key_rejects"`
}

// AssignmentTicketContract is the closed wire and size profile.
type AssignmentTicketContract struct {
	TokenPrefix              string   `json:"token_prefix"`
	SigningAlgorithm         string   `json:"signing_algorithm"`
	SigningDomain            string   `json:"signing_domain"`
	SigningSeparatorHex      string   `json:"signing_separator_hex"`
	SignatureEncoding        string   `json:"signature_encoding"`
	KMSMessageType           string   `json:"kms_message_type"`
	KMSOutputEncoding        string   `json:"kms_output_encoding"`
	MaxTicketASCIIBytes      int      `json:"max_ticket_ascii_bytes"`
	MaxClaimsPartCharacters  int      `json:"max_claims_part_characters"`
	MaxClaimsJSONBytes       int      `json:"max_claims_json_bytes"`
	RawSignatureBytes        int      `json:"raw_signature_bytes"`
	SignaturePartCharacters  int      `json:"signature_part_characters"`
	MaxKIDCharacters         int      `json:"max_kid_characters"`
	DigestCharacters         int      `json:"digest_characters"`
	AgentPublicKeyCharacters int      `json:"agent_public_key_characters"`
	MaxLifetimeSeconds       int      `json:"max_lifetime_seconds"`
	NotBeforeOffsetSeconds   int      `json:"not_before_offset_seconds"`
	NHPBodyMaxBytes          int      `json:"nhp_body_max_bytes"`
	NHPPacketMaxBytes        int      `json:"nhp_packet_max_bytes"`
	ClaimOrder               []string `json:"claim_order"`
	CredentialKinds          []string `json:"credential_kinds"`
	PlacementModes           []string `json:"placement_modes"`
}

// AssignmentTicketSyntheticKey is public test-only signing material. It must
// never be used outside conformance tests.
type AssignmentTicketSyntheticKey struct {
	KID                 string              `json:"kid"`
	Curve               string              `json:"curve"`
	PrivateScalarHex    string              `json:"private_scalar_hex"`
	PublicKeySPKIDERB64 string              `json:"public_key_spki_der_b64url"`
	JWK                 AssignmentTicketJWK `json:"jwk"`
}

// AssignmentTicketJWK is the public half of the synthetic P-256 key.
type AssignmentTicketJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// AssignmentTicketFenceVector freezes one exact length-framed fence preimage.
type AssignmentTicketFenceVector struct {
	Name         string                      `json:"name"`
	Kind         string                      `json:"kind"`
	Domain       string                      `json:"domain"`
	Parts        []AssignmentTicketFencePart `json:"parts"`
	PreimageHex  string                      `json:"preimage_hex"`
	DigestHex    string                      `json:"digest_hex"`
	DigestB64URL string                      `json:"digest_b64url"`
}

// AssignmentTicketFencePart exposes both the semantic input and its exact bytes.
// Value is always a string; Encoding determines how to interpret it.
type AssignmentTicketFencePart struct {
	Name     string `json:"name"`
	Encoding string `json:"encoding"`
	Value    string `json:"value"`
	BytesHex string `json:"bytes_hex"`
}

// AssignmentTicketGolden is the single complete positive cryptographic vector.
type AssignmentTicketGolden struct {
	EnvironmentID          string `json:"environment_id"`
	VerifyAtUnix           int64  `json:"verify_at_unix"`
	ClockUnix              int64  `json:"clock_unix"`
	JTIRandomHex           string `json:"jti_random_hex"`
	SyntheticECDSANonceHex string `json:"synthetic_ecdsa_nonce_hex"`
	SyntheticCredential    string `json:"synthetic_presented_credential"`
	ClaimsJSON             string `json:"claims_json"`
	ClaimsUTF8Hex          string `json:"claims_utf8_hex"`
	ClaimsB64URL           string `json:"claims_b64url"`
	SigningPreimageHex     string `json:"signing_preimage_hex"`
	SigningDigestHex       string `json:"signing_digest_hex"`
	KMSSignatureDERHex     string `json:"kms_signature_der_hex"`
	KMSSignatureDERB64     string `json:"kms_signature_der_b64"`
	RawLowSSignatureHex    string `json:"raw_low_s_signature_hex"`
	SignatureB64URL        string `json:"signature_b64url"`
	Token                  string `json:"token"`
	LRTBodyTemplate        string `json:"lrt_body_template"`
	TicketMarker           string `json:"ticket_marker"`
	NHPPacketOverheadBytes int    `json:"nhp_packet_overhead_bytes"`
	LRTBodyBytes           int    `json:"lrt_body_bytes"`
	CompleteNHPPacketBytes int    `json:"complete_nhp_packet_bytes"`
}

// AssignmentTicketVerifyReject drives the complete verifier. Empty source
// fields inherit the golden claims/signature; explicit fields are used verbatim.
type AssignmentTicketVerifyReject struct {
	Name                  string                            `json:"name"`
	RejectClass           string                            `json:"reject_class"`
	Reason                string                            `json:"reason"`
	ClaimsB64URL          string                            `json:"claims_b64url,omitempty"`
	SignatureB64URL       string                            `json:"signature_b64url,omitempty"`
	Token                 string                            `json:"token,omitempty"`
	ExpectedEnvironmentID string                            `json:"expected_environment_id"`
	TrustedKID            string                            `json:"trusted_kid"`
	VerifyAtUnix          int64                             `json:"verify_at_unix"`
	Derivation            *AssignmentTicketRepeatDerivation `json:"derivation,omitempty"`
}

// AssignmentTicketClaimsReject drives strict parsing before signing/verification.
type AssignmentTicketClaimsReject struct {
	Name        string                            `json:"name"`
	RejectClass string                            `json:"reject_class"`
	Reason      string                            `json:"reason"`
	ClaimsJSON  string                            `json:"claims_json,omitempty"`
	Derivation  *AssignmentTicketRepeatDerivation `json:"derivation,omitempty"`
}

// AssignmentTicketRepeatDerivation specifies an exact large ASCII input without
// inflating all three published package copies.
type AssignmentTicketRepeatDerivation struct {
	Target    string `json:"target"`
	ASCIIChar string `json:"ascii_char"`
	Count     int    `json:"count"`
}

// AssignmentTicketDERCase drives KMS DER-to-raw-low-S normalization.
type AssignmentTicketDERCase struct {
	Name           string `json:"name"`
	Outcome        string `json:"outcome"`
	RejectClass    string `json:"reject_class,omitempty"`
	Reason         string `json:"reason"`
	DERHex         string `json:"der_hex"`
	ExpectedRawHex string `json:"expected_raw_low_s_hex,omitempty"`
}

// AssignmentTicketFenceReject freezes invalid typed fence input classes.
type AssignmentTicketFenceReject struct {
	Name        string `json:"name"`
	FenceKind   string `json:"fence_kind"`
	RejectClass string `json:"reject_class"`
	Reason      string `json:"reason"`
	Mutation    string `json:"mutation"`
}

// AssignmentTicketTrustReject freezes invalid verifier-key inputs.
type AssignmentTicketTrustReject struct {
	Name                string `json:"name"`
	RejectClass         string `json:"reject_class"`
	Reason              string `json:"reason"`
	PublicKeySPKIDERB64 string `json:"public_key_spki_der_b64url"`
}

var assignmentTicketClaimOrder = []string{
	"v", "iss", "aud", "environment_id", "kid", "iat", "nbf", "exp", "jti",
	"agent_id", "agent_public_key_b64", "credential_key_hash_b64", "credential_key_id",
	"credential_kind", "credential_fence_b64", "placement_mode", "cell_id",
	"assignment_generation", "endpoint_revision", "cell_fence_b64", "assignment_fence_b64",
}

var assignmentTicketCredentialKinds = []string{"bootstrap", "connector_bootstrap", "account", "agent"}
var assignmentTicketPlacementModes = []string{"new", "existing"}

var assignmentTicketRejectClasses = map[string]struct{}{
	"claims": {}, "time": {}, "size": {}, "encoding": {},
	"signature": {}, "high_s": {}, "wrong_length": {},
	"unknown_kid": {}, "environment": {}, "key_length": {},
	"der": {}, "fence_input": {},
}

var assignmentTicketFenceProfiles = map[string]string{
	"credential": "qurl-agent-assignment-credential-fence-v1",
	"cell":       "qurl-agent-assignment-cell-fence-v1",
	"existing":   "qurl-agent-assignment-existing-fence-v1",
}

var assignmentTicketFenceEncodings = map[string]struct{}{
	"raw_bytes_b64url": {}, "utf8": {}, "uint64_be": {}, "bool_byte": {},
}

var assignmentTicketVerifyRejectClasses = map[string]string{
	"altered_claims":                      "signature",
	"reordered_claims_original_signature": "signature",
	"claims_padding":                      "encoding",
	"claims_noncanonical_base64url":       "encoding",
	"signature_padding":                   "encoding",
	"signature_noncanonical_base64url":    "encoding",
	"high_s_raw_signature":                "high_s",
	"malformed_raw_signature":             "wrong_length",
	"wrong_kid":                           "unknown_kid",
	"wrong_environment":                   "environment",
	"wrong_signing_domain":                "signature",
	"wrong_audience":                      "claims",
	"not_yet_valid":                       "time",
	"expired":                             "time",
	"ticket_too_large":                    "size",
	"claims_part_too_large":               "size",
}

var assignmentTicketClaimsRejectClasses = map[string]string{
	"duplicate_claim":                   "claims",
	"unknown_claim":                     "claims",
	"trailing_json":                     "claims",
	"null_claim":                        "claims",
	"invalid_nbf_relation":              "time",
	"exp_not_after_iat":                 "time",
	"lifetime_too_long":                 "time",
	"new_with_assignment_fence":         "claims",
	"existing_without_assignment_fence": "claims",
	"private_tunnel_bootstrap_kind":     "claims",
	"unknown_credential_kind":           "claims",
	"credential_hash_wrong_length":      "key_length",
	"credential_fence_wrong_length":     "key_length",
	"cell_fence_wrong_length":           "key_length",
	"assignment_fence_wrong_length":     "key_length",
	"agent_public_key_wrong_length":     "key_length",
	"kid_too_long":                      "claims",
	"invalid_environment":               "claims",
	"jti_wrong_length":                  "key_length",
	"claims_json_too_large":             "size",
}

var assignmentTicketDERCaseClasses = map[string]string{
	"kms_high_s_normalizes":            "",
	"malformed_truncated":              "der",
	"malformed_trailing_data":          "der",
	"malformed_extra_sequence_element": "der",
	"invalid_zero_r":                   "der",
	"invalid_out_of_range_s":           "der",
}

var assignmentTicketFenceRejectClasses = map[string]string{
	"credential_hash_wrong_length": "key_length",
	"credential_scopes_unsorted":   "fence_input",
	"credential_scopes_duplicate":  "fence_input",
	"uint64_negative_or_overflow":  "fence_input",
	"bool_not_single_byte":         "fence_input",
	"missing_required_cell_part":   "fence_input",
}

var assignmentTicketTrustRejectClasses = map[string]string{
	"wrong_curve":    "key_length",
	"malformed_spki": "der",
	"empty_spki":     "der",
}

var assignmentTicketFenceRejectKinds = map[string]struct{}{
	"credential": {}, "cell": {}, "existing": {}, "all": {},
}

// ParseAssignmentTicketFile strictly parses and structurally validates the qat1
// artifact. Cryptographic byte identity is checked independently by
// tools/verify-assignment-ticket.
func ParseAssignmentTicketFile(data []byte) (*AssignmentTicketFile, error) {
	var af AssignmentTicketFile
	if err := strictDecodeArtifact(data, &af); err != nil {
		return nil, fmt.Errorf("conformance: parse assignment-ticket file: %w", err)
	}
	if af.Artifact != AssignmentTicketArtifactID || af.SchemaVersion != AssignmentTicketSchemaVersion {
		return nil, fmt.Errorf("conformance: assignment-ticket identity = %q/v%d, want %q/v%d", af.Artifact, af.SchemaVersion, AssignmentTicketArtifactID, AssignmentTicketSchemaVersion)
	}
	if af.Description == "" {
		return nil, errors.New("conformance: assignment-ticket description is empty")
	}
	if err := validateAssignmentTicketContract(af.Contract); err != nil {
		return nil, err
	}
	if err := validateAssignmentTicketKey(af.SyntheticSigningKey); err != nil {
		return nil, err
	}
	if err := validateAssignmentTicketFences(af.FenceVectors); err != nil {
		return nil, err
	}
	if err := validateAssignmentTicketGolden(af.Golden, af.Contract); err != nil {
		return nil, err
	}
	if err := validateNamedAssignmentCases("verify reject", assignmentTicketVerifyRejectClasses, af.VerifyRejects, func(c AssignmentTicketVerifyReject) string { return c.Name }, func(c AssignmentTicketVerifyReject) string { return c.RejectClass }); err != nil {
		return nil, err
	}
	if err := validateNamedAssignmentCases("claims reject", assignmentTicketClaimsRejectClasses, af.ClaimsRejects, func(c AssignmentTicketClaimsReject) string { return c.Name }, func(c AssignmentTicketClaimsReject) string { return c.RejectClass }); err != nil {
		return nil, err
	}
	if err := validateNamedAssignmentCases("KMS DER", assignmentTicketDERCaseClasses, af.KMSDERCases, func(c AssignmentTicketDERCase) string { return c.Name }, func(c AssignmentTicketDERCase) string { return c.RejectClass }); err != nil {
		return nil, err
	}
	if err := validateNamedAssignmentCases("fence reject", assignmentTicketFenceRejectClasses, af.FenceRejects, func(c AssignmentTicketFenceReject) string { return c.Name }, func(c AssignmentTicketFenceReject) string { return c.RejectClass }); err != nil {
		return nil, err
	}
	if err := validateNamedAssignmentCases("trust-key reject", assignmentTicketTrustRejectClasses, af.TrustKeyRejects, func(c AssignmentTicketTrustReject) string { return c.Name }, func(c AssignmentTicketTrustReject) string { return c.RejectClass }); err != nil {
		return nil, err
	}
	if err := validateAssignmentTicketCaseInputs(&af); err != nil {
		return nil, err
	}
	return &af, nil
}

func validateAssignmentTicketContract(c AssignmentTicketContract) error {
	if c.TokenPrefix != AssignmentTicketPrefix || c.SigningAlgorithm != "ECDSA_P256_SHA256" ||
		c.SigningDomain != AssignmentTicketSigningDomain || c.SigningSeparatorHex != "00" ||
		c.SignatureEncoding != "raw_r_s_low_s" || c.KMSMessageType != "DIGEST" ||
		c.KMSOutputEncoding != "ASN.1_DER" || c.MaxTicketASCIIBytes != 2304 ||
		c.MaxClaimsPartCharacters != 2048 || c.MaxClaimsJSONBytes != 1536 ||
		c.RawSignatureBytes != 64 || c.SignaturePartCharacters != 86 || c.MaxKIDCharacters != 64 ||
		c.DigestCharacters != 43 || c.AgentPublicKeyCharacters != 44 ||
		c.MaxLifetimeSeconds != 900 || c.NotBeforeOffsetSeconds != -30 ||
		c.NHPBodyMaxBytes != 3856 || c.NHPPacketMaxBytes != 4096 ||
		!slices.Equal(c.ClaimOrder, assignmentTicketClaimOrder) ||
		!slices.Equal(c.CredentialKinds, assignmentTicketCredentialKinds) ||
		!slices.Equal(c.PlacementModes, assignmentTicketPlacementModes) {
		return errors.New("conformance: assignment-ticket contract drift")
	}
	return nil
}

func validateAssignmentTicketKey(key AssignmentTicketSyntheticKey) error {
	if key.KID != "assignment-2026-01" || key.Curve != "P-256" || len(key.PrivateScalarHex) != 64 ||
		key.PublicKeySPKIDERB64 == "" || key.JWK.Kty != "EC" || key.JWK.Crv != "P-256" ||
		key.JWK.X == "" || key.JWK.Y == "" {
		return errors.New("conformance: assignment-ticket synthetic key is incomplete")
	}
	if _, err := hex.DecodeString(key.PrivateScalarHex); err != nil {
		return fmt.Errorf("conformance: assignment-ticket private scalar: %w", err)
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(key.PublicKeySPKIDERB64); err != nil {
		return fmt.Errorf("conformance: assignment-ticket SPKI encoding: %w", err)
	}
	return nil
}

func validateAssignmentTicketFences(vectors []AssignmentTicketFenceVector) error {
	if len(vectors) != len(assignmentTicketFenceProfiles) {
		return fmt.Errorf("conformance: assignment-ticket fence count = %d, want %d", len(vectors), len(assignmentTicketFenceProfiles))
	}
	seen := make(map[string]struct{}, len(vectors))
	for _, vector := range vectors {
		domain, ok := assignmentTicketFenceProfiles[vector.Kind]
		if !ok || vector.Name == "" || vector.Domain != domain || len(vector.Parts) == 0 {
			return fmt.Errorf("conformance: invalid assignment-ticket fence %q/%q", vector.Name, vector.Kind)
		}
		if _, duplicate := seen[vector.Kind]; duplicate {
			return fmt.Errorf("conformance: duplicate assignment-ticket fence kind %q", vector.Kind)
		}
		seen[vector.Kind] = struct{}{}
		if _, err := hex.DecodeString(vector.PreimageHex); err != nil {
			return fmt.Errorf("conformance: fence %q preimage: %w", vector.Name, err)
		}
		if digest, err := hex.DecodeString(vector.DigestHex); err != nil || len(digest) != 32 {
			return fmt.Errorf("conformance: fence %q digest must be 32-byte hex", vector.Name)
		}
		if digest, err := base64.RawURLEncoding.Strict().DecodeString(vector.DigestB64URL); err != nil || len(digest) != 32 || len(vector.DigestB64URL) != 43 {
			return fmt.Errorf("conformance: fence %q digest_b64url is invalid", vector.Name)
		}
		for _, part := range vector.Parts {
			if part.Name == "" {
				return fmt.Errorf("conformance: fence %q has incomplete part", vector.Name)
			}
			if _, ok := assignmentTicketFenceEncodings[part.Encoding]; !ok {
				return fmt.Errorf("conformance: fence %q part %q has unknown encoding %q", vector.Name, part.Name, part.Encoding)
			}
			if _, err := hex.DecodeString(part.BytesHex); err != nil {
				return fmt.Errorf("conformance: fence %q part %q bytes: %w", vector.Name, part.Name, err)
			}
		}
	}
	return nil
}

func validateAssignmentTicketGolden(g AssignmentTicketGolden, contract AssignmentTicketContract) error {
	claims, err := base64.RawURLEncoding.Strict().DecodeString(g.ClaimsB64URL)
	if err != nil || string(claims) != g.ClaimsJSON || hex.EncodeToString(claims) != g.ClaimsUTF8Hex {
		return errors.New("conformance: assignment-ticket golden claims encodings disagree")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(g.SignatureB64URL)
	if err != nil || len(sig) != 64 || len(g.SignatureB64URL) != 86 {
		return errors.New("conformance: assignment-ticket golden signature is not canonical raw r||s")
	}
	if g.Token != AssignmentTicketPrefix+"."+g.ClaimsB64URL+"."+g.SignatureB64URL || len(g.Token) > contract.MaxTicketASCIIBytes ||
		g.EnvironmentID != "sandbox" || g.VerifyAtUnix < 1 || g.ClockUnix != 1784160000 ||
		g.JTIRandomHex != "000102030405060708090a0b0c0d0e0f" || len(g.SyntheticECDSANonceHex) != 64 ||
		len(g.SyntheticCredential) != AssignmentTicketSyntheticCredentialBytes ||
		g.TicketMarker != "${qat1_token}" || strings.Count(g.LRTBodyTemplate, g.TicketMarker) != 1 ||
		g.NHPPacketOverheadBytes != 256 || g.LRTBodyBytes < 1 || g.LRTBodyBytes > contract.NHPBodyMaxBytes ||
		g.CompleteNHPPacketBytes < 1 || g.CompleteNHPPacketBytes > contract.NHPPacketMaxBytes {
		return errors.New("conformance: assignment-ticket golden envelope or NHP budget is invalid")
	}
	lrtBody := strings.Replace(g.LRTBodyTemplate, g.TicketMarker, g.Token, 1)
	if len(lrtBody) != g.LRTBodyBytes || len(lrtBody)+g.NHPPacketOverheadBytes != g.CompleteNHPPacketBytes {
		return errors.New("conformance: assignment-ticket golden NHP budget derivation disagrees")
	}
	for _, value := range []string{g.SigningPreimageHex, g.SigningDigestHex, g.KMSSignatureDERHex, g.RawLowSSignatureHex} {
		if _, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("conformance: assignment-ticket golden hex: %w", err)
		}
	}
	if strings.Contains(g.ClaimsJSON, `"credential_kind":"tunnel_bootstrap"`) {
		return errors.New("conformance: private tunnel_bootstrap leaked into positive qat1 claims")
	}
	return nil
}

func validateNamedAssignmentCases[T any](kind string, want map[string]string, cases []T, name func(T) string, rejectClass func(T) string) error {
	if len(cases) != len(want) {
		return fmt.Errorf("conformance: assignment-ticket %s count = %d, want %d", kind, len(cases), len(want))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		value := name(c)
		expectedClass, ok := want[value]
		if !ok {
			return fmt.Errorf("conformance: unknown assignment-ticket %s case %q", kind, value)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("conformance: duplicate assignment-ticket %s case %q", kind, value)
		}
		seen[value] = struct{}{}
		actualClass := rejectClass(c)
		if actualClass != "" {
			if err := validateAssignmentTicketRejectClass(value, actualClass); err != nil {
				return err
			}
		}
		if actualClass != expectedClass {
			return fmt.Errorf("conformance: assignment-ticket %s case %q reject class = %q, want %q", kind, value, actualClass, expectedClass)
		}
	}
	return nil
}

func validateAssignmentTicketCaseInputs(af *AssignmentTicketFile) error {
	for _, c := range af.VerifyRejects {
		if c.RejectClass == "" || c.Reason == "" || c.ExpectedEnvironmentID == "" || c.TrustedKID == "" || c.VerifyAtUnix < 1 {
			return fmt.Errorf("conformance: assignment-ticket verify reject %q is incomplete", c.Name)
		}
		hasParts := c.ClaimsB64URL != "" || c.SignatureB64URL != ""
		if (c.Derivation != nil && (c.Token != "" || hasParts)) || (c.Token != "" && hasParts) {
			return fmt.Errorf("conformance: assignment-ticket verify reject %q has ambiguous input sources", c.Name)
		}
		if _, err := c.ResolveToken(af.Golden); err != nil {
			return fmt.Errorf("conformance: assignment-ticket verify reject %q: %w", c.Name, err)
		}
	}
	for _, c := range af.ClaimsRejects {
		if c.RejectClass == "" || c.Reason == "" || (c.ClaimsJSON == "") == (c.Derivation == nil) {
			return fmt.Errorf("conformance: assignment-ticket claims reject %q is incomplete or ambiguous", c.Name)
		}
		if _, err := c.ResolveClaims(); err != nil {
			return fmt.Errorf("conformance: assignment-ticket claims reject %q: %w", c.Name, err)
		}
	}
	for _, c := range af.KMSDERCases {
		if c.Reason == "" || c.DERHex == "" || (c.Outcome != ExpectAccept && c.Outcome != ExpectReject) ||
			(c.Outcome == ExpectAccept) != (c.ExpectedRawHex != "") || (c.Outcome == ExpectReject) != (c.RejectClass != "") {
			return fmt.Errorf("conformance: assignment-ticket KMS DER case %q is incomplete", c.Name)
		}
	}
	for _, c := range af.FenceRejects {
		if c.FenceKind == "" || c.RejectClass == "" || c.Reason == "" || c.Mutation == "" {
			return fmt.Errorf("conformance: assignment-ticket fence reject %q is incomplete", c.Name)
		}
		if _, ok := assignmentTicketFenceRejectKinds[c.FenceKind]; !ok {
			return fmt.Errorf("conformance: assignment-ticket fence reject %q has unknown fence kind %q", c.Name, c.FenceKind)
		}
	}
	for _, c := range af.TrustKeyRejects {
		if c.RejectClass == "" || c.Reason == "" {
			return fmt.Errorf("conformance: assignment-ticket trust-key reject %q is incomplete", c.Name)
		}
	}
	return nil
}

func validateAssignmentTicketRejectClass(name, rejectClass string) error {
	if _, ok := assignmentTicketRejectClasses[rejectClass]; !ok {
		return fmt.Errorf("conformance: assignment-ticket case %q has unknown reject class %q", name, rejectClass)
	}
	return nil
}

// ResolveToken returns the exact verifier input for a reject vector.
func (c AssignmentTicketVerifyReject) ResolveToken(g AssignmentTicketGolden) (string, error) {
	if c.Derivation != nil {
		repeated, err := resolveAssignmentRepeat(c.Derivation)
		if err != nil {
			return "", err
		}
		switch c.Derivation.Target {
		case "token":
			return repeated, nil
		case "claims_part":
			return AssignmentTicketPrefix + "." + repeated + "." + g.SignatureB64URL, nil
		default:
			return "", errors.New("conformance: invalid verifier repeat target")
		}
	}
	if c.Token != "" {
		return c.Token, nil
	}
	claims := c.ClaimsB64URL
	if claims == "" {
		claims = g.ClaimsB64URL
	}
	signature := c.SignatureB64URL
	if signature == "" {
		signature = g.SignatureB64URL
	}
	return AssignmentTicketPrefix + "." + claims + "." + signature, nil
}

// ResolveClaims returns the exact strict-parser input for a claims reject.
func (c AssignmentTicketClaimsReject) ResolveClaims() (string, error) {
	if c.Derivation != nil {
		if c.Derivation.Target != "claims_json" {
			return "", errors.New("conformance: invalid claims repeat target")
		}
		return resolveAssignmentRepeat(c.Derivation)
	}
	if c.ClaimsJSON == "" {
		return "", errors.New("conformance: claims reject has no input")
	}
	return c.ClaimsJSON, nil
}

func resolveAssignmentRepeat(derivation *AssignmentTicketRepeatDerivation) (string, error) {
	if derivation == nil || len(derivation.ASCIIChar) != 1 || derivation.ASCIIChar[0] > 0x7f || derivation.Count < 1 || derivation.Count > 4096 {
		return "", errors.New("conformance: invalid assignment-ticket repeat derivation")
	}
	return strings.Repeat(derivation.ASCIIChar, derivation.Count), nil
}
