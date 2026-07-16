// Command verify-assignment-ticket independently checks the committed qat1
// cryptographic bytes using only the Go standard library. It deliberately does
// not import qurl-service or reproduce its ticket parser.
package main

import (
	"bytes"
	"crypto/ecdh"
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
	"io"
	"math/big"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	conformance "github.com/layervai/qurl-conformance"
)

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

func main() {
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("assignment-ticket vectors verified")
}

func verify() error {
	af, err := conformance.AssignmentTicket()
	if err != nil {
		return err
	}
	publicKey, privateScalar, err := verifySyntheticKey(af.SyntheticSigningKey)
	if err != nil {
		return err
	}
	if err := verifyGolden(publicKey, privateScalar, af); err != nil {
		return err
	}
	if err := verifyClaimsCases(af); err != nil {
		return err
	}
	for _, vector := range af.FenceVectors {
		if err := verifyFence(vector); err != nil {
			return err
		}
	}
	if err := verifyDERCases(af.KMSDERCases); err != nil {
		return err
	}
	if err := verifyCryptographicRejects(publicKey, af); err != nil {
		return err
	}
	return verifyTrustKeyRejects(af.TrustKeyRejects)
}

var (
	environmentPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	kidPattern         = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	agentIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
	keyIDPattern       = regexp.MustCompile(`^key_[A-Za-z0-9]{12}$`)
)

type referenceClaims struct {
	V                    int    `json:"v"`
	Iss                  string `json:"iss"`
	Aud                  string `json:"aud"`
	EnvironmentID        string `json:"environment_id"`
	KID                  string `json:"kid"`
	IAT                  int64  `json:"iat"`
	NBF                  int64  `json:"nbf"`
	EXP                  int64  `json:"exp"`
	JTI                  string `json:"jti"`
	AgentID              string `json:"agent_id"`
	AgentPublicKeyB64    string `json:"agent_public_key_b64"`
	CredentialKeyHashB64 string `json:"credential_key_hash_b64"`
	CredentialKeyID      string `json:"credential_key_id"`
	CredentialKind       string `json:"credential_kind"`
	CredentialFenceB64   string `json:"credential_fence_b64"`
	PlacementMode        string `json:"placement_mode"`
	CellID               string `json:"cell_id"`
	AssignmentGeneration int64  `json:"assignment_generation"`
	EndpointRevision     int64  `json:"endpoint_revision"`
	CellFenceB64         string `json:"cell_fence_b64"`
	AssignmentFenceB64   string `json:"assignment_fence_b64"`
}

func verifyClaimsCases(af *conformance.AssignmentTicketFile) error {
	if err := referenceParseClaims([]byte(af.Golden.ClaimsJSON), af.Contract); err != nil {
		return fmt.Errorf("golden claims do not satisfy independent parser: %w", err)
	}
	for _, c := range af.ClaimsRejects {
		input, err := c.ResolveClaims()
		if err != nil {
			return err
		}
		if err := referenceParseClaims([]byte(input), af.Contract); err == nil {
			return fmt.Errorf("claims reject %s passes independent parser", c.Name)
		}
	}
	return nil
}

func referenceParseClaims(raw []byte, contract conformance.AssignmentTicketContract) error {
	if len(raw) > contract.MaxClaimsJSONBytes {
		return errors.New("claims exceed byte limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("claims must be one object")
	}
	values := make(map[string]json.RawMessage, len(contract.ClaimOrder))
	allowed := make(map[string]struct{}, len(contract.ClaimOrder))
	for _, key := range contract.ClaimOrder {
		allowed[key] = struct{}{}
	}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("non-string key")
		}
		if _, ok := allowed[key]; !ok {
			return errors.New("unknown claim")
		}
		if _, duplicate := values[key]; duplicate {
			return errors.New("duplicate claim")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		if bytes.Equal(value, []byte("null")) {
			return errors.New("null claim")
		}
		values[key] = value
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return errors.New("unclosed claims")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing claims data")
	}
	for _, key := range contract.ClaimOrder[:len(contract.ClaimOrder)-1] {
		if _, ok := values[key]; !ok {
			return errors.New("missing required claim")
		}
	}
	var claims referenceClaims
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if err := typed.Decode(&claims); err != nil {
		return err
	}
	if claims.V != 1 || claims.Iss != "qurl-assignment-authority" || claims.Aud != "qurl-agent-registration" {
		return errors.New("profile mismatch")
	}
	if len(claims.EnvironmentID) < 1 || len(claims.EnvironmentID) > 32 || !environmentPattern.MatchString(claims.EnvironmentID) ||
		len(claims.KID) < 1 || len(claims.KID) > contract.MaxKIDCharacters || !kidPattern.MatchString(claims.KID) {
		return errors.New("environment or kid mismatch")
	}
	if claims.IAT <= 30 || claims.NBF != claims.IAT+int64(contract.NotBeforeOffsetSeconds) ||
		claims.EXP <= claims.IAT || claims.EXP-claims.IAT > int64(contract.MaxLifetimeSeconds) {
		return errors.New("time relationship mismatch")
	}
	if !strings.HasPrefix(claims.JTI, "atj_") || len(claims.JTI) != 26 {
		return errors.New("jti shape mismatch")
	}
	jti, err := strictRawURL(strings.TrimPrefix(claims.JTI, "atj_"))
	if err != nil || len(jti) != 16 {
		return errors.New("jti encoding mismatch")
	}
	if !agentIDPattern.MatchString(claims.AgentID) || !keyIDPattern.MatchString(claims.CredentialKeyID) {
		return errors.New("agent or key id mismatch")
	}
	agentKey, err := base64.StdEncoding.Strict().DecodeString(claims.AgentPublicKeyB64)
	if err != nil || len(agentKey) != 32 || base64.StdEncoding.EncodeToString(agentKey) != claims.AgentPublicKeyB64 {
		return errors.New("agent public key mismatch")
	}
	for _, digest := range []string{claims.CredentialKeyHashB64, claims.CredentialFenceB64, claims.CellFenceB64} {
		decoded, err := strictRawURL(digest)
		if err != nil || len(decoded) != sha256.Size || len(digest) != contract.DigestCharacters {
			return errors.New("digest mismatch")
		}
	}
	if !slices.Contains(contract.CredentialKinds, claims.CredentialKind) || claims.AssignmentGeneration < 1 || claims.EndpointRevision < 1 || claims.CellID == "" {
		return errors.New("credential or placement mismatch")
	}
	_, assignmentFencePresent := values["assignment_fence_b64"]
	switch claims.PlacementMode {
	case "new":
		if assignmentFencePresent {
			return errors.New("new placement has assignment fence")
		}
	case "existing":
		decoded, err := strictRawURL(claims.AssignmentFenceB64)
		if !assignmentFencePresent || err != nil || len(decoded) != sha256.Size || len(claims.AssignmentFenceB64) != contract.DigestCharacters {
			return errors.New("existing placement lacks canonical assignment fence")
		}
	default:
		return errors.New("unknown placement mode")
	}
	return nil
}

func verifySyntheticKey(key conformance.AssignmentTicketSyntheticKey) (*ecdsa.PublicKey, *big.Int, error) {
	der, err := strictRawURL(key.PublicKeySPKIDERB64)
	if err != nil {
		return nil, nil, fmt.Errorf("synthetic SPKI: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse synthetic SPKI: %w", err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, nil, errors.New("synthetic SPKI is not a usable P-256 key")
	}
	d, ok := new(big.Int).SetString(key.PrivateScalarHex, 16)
	if !ok || d.Sign() <= 0 || d.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, nil, errors.New("synthetic private scalar is outside P-256")
	}
	privateBytes := make([]byte, 32)
	d.FillBytes(privateBytes)
	ecdhPrivate, err := ecdh.P256().NewPrivateKey(privateBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("derive synthetic public key: %w", err)
	}
	publicBytes := ecdhPrivate.PublicKey().Bytes()
	ecdsaPublicBytes, err := publicKey.Bytes()
	if err != nil || !bytes.Equal(publicBytes, ecdsaPublicBytes) {
		return nil, nil, errors.New("synthetic private/public key mismatch")
	}
	jwkX, err := strictRawURL(key.JWK.X)
	if err != nil {
		return nil, nil, fmt.Errorf("JWK x: %w", err)
	}
	jwkY, err := strictRawURL(key.JWK.Y)
	if err != nil {
		return nil, nil, fmt.Errorf("JWK y: %w", err)
	}
	if len(jwkX) != 32 || len(jwkY) != 32 || !bytes.Equal(jwkX, publicBytes[1:33]) || !bytes.Equal(jwkY, publicBytes[33:]) {
		return nil, nil, errors.New("synthetic SPKI and JWK disagree")
	}
	return publicKey, d, nil
}

func verifyGolden(publicKey *ecdsa.PublicKey, privateScalar *big.Int, af *conformance.AssignmentTicketFile) error {
	golden := af.Golden
	claims, err := strictRawURL(golden.ClaimsB64URL)
	if err != nil {
		return fmt.Errorf("golden claims: %w", err)
	}
	if string(claims) != golden.ClaimsJSON || hex.EncodeToString(claims) != golden.ClaimsUTF8Hex {
		return errors.New("golden claims bytes disagree")
	}
	keys, err := topLevelKeys(claims)
	if err != nil || !slices.Equal(keys, af.Contract.ClaimOrder[:len(af.Contract.ClaimOrder)-1]) {
		return errors.New("golden claims field order disagrees with contract")
	}
	var claimValues map[string]any
	if err := json.Unmarshal(claims, &claimValues); err != nil {
		return err
	}
	if claimValues["credential_kind"] != "connector_bootstrap" || claimValues["placement_mode"] != "new" ||
		claimValues["assignment_fence_b64"] != nil || claimValues["otp"] != nil || strings.Contains(golden.ClaimsJSON, "tunnel_bootstrap") {
		return errors.New("golden claims leaked private/OTP state or lost public Connector vocabulary")
	}
	credentialHash := sha256.Sum256([]byte(golden.SyntheticCredential))
	if base64.RawURLEncoding.EncodeToString(credentialHash[:]) != claimValues["credential_key_hash_b64"] {
		return errors.New("golden synthetic credential hash disagrees with claims")
	}
	preimage := append(append([]byte(af.Contract.SigningDomain), 0), []byte(golden.ClaimsB64URL)...)
	if hex.EncodeToString(preimage) != golden.SigningPreimageHex {
		return errors.New("golden signing preimage disagrees")
	}
	digest := sha256.Sum256(preimage)
	if hex.EncodeToString(digest[:]) != golden.SigningDigestHex {
		return errors.New("golden signing digest disagrees")
	}
	der, err := hex.DecodeString(golden.KMSSignatureDERHex)
	if err != nil {
		return err
	}
	if base64.StdEncoding.EncodeToString(der) != golden.KMSSignatureDERB64 {
		return errors.New("golden KMS DER base64 disagrees")
	}
	nonce, ok := new(big.Int).SetString(golden.SyntheticECDSANonceHex, 16)
	if !ok || nonce.Sign() <= 0 || nonce.Cmp(elliptic.P256().Params().N) >= 0 {
		return errors.New("synthetic ECDSA nonce is invalid")
	}
	derivedDER, err := signWithNonce(privateScalar, nonce, digest[:])
	if err != nil || !bytes.Equal(derivedDER, der) {
		return errors.New("fixed key/nonce do not reproduce synthetic KMS DER")
	}
	raw, err := derToRawLowS(der)
	if err != nil {
		return fmt.Errorf("golden KMS DER: %w", err)
	}
	if hex.EncodeToString(raw) != golden.RawLowSSignatureHex || base64.RawURLEncoding.EncodeToString(raw) != golden.SignatureB64URL {
		return errors.New("golden DER normalization disagrees")
	}
	if !verifyRawSignature(publicKey, digest[:], raw) {
		return errors.New("golden signature does not verify")
	}
	if golden.Token != af.Contract.TokenPrefix+"."+golden.ClaimsB64URL+"."+golden.SignatureB64URL {
		return errors.New("golden token assembly disagrees")
	}
	lrtBody := strings.Replace(golden.LRTBodyTemplate, golden.TicketMarker, golden.Token, 1)
	if len(lrtBody) != golden.LRTBodyBytes || len(lrtBody)+golden.NHPPacketOverheadBytes != golden.CompleteNHPPacketBytes ||
		golden.LRTBodyBytes > af.Contract.NHPBodyMaxBytes || golden.CompleteNHPPacketBytes > af.Contract.NHPPacketMaxBytes {
		return errors.New("golden LRT exceeds or disagrees with NHP size budget")
	}
	if strings.Contains(strings.ToLower(lrtBody), `"otp`) {
		return errors.New("assignment LRT must not carry an OTP")
	}
	return nil
}

func signWithNonce(privateScalar, nonce *big.Int, digest []byte) ([]byte, error) {
	n := elliptic.P256().Params().N
	nonceBytes := make([]byte, 32)
	nonce.FillBytes(nonceBytes)
	noncePrivate, err := ecdh.P256().NewPrivateKey(nonceBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA nonce: %w", err)
	}
	r := new(big.Int).Mod(new(big.Int).SetBytes(noncePrivate.PublicKey().Bytes()[1:33]), n)
	if r.Sign() == 0 {
		return nil, errors.New("zero ECDSA r")
	}
	s := new(big.Int).Mul(r, privateScalar)
	s.Add(s, new(big.Int).SetBytes(digest))
	s.Mul(s, new(big.Int).ModInverse(nonce, n))
	s.Mod(s, n)
	if s.Sign() == 0 {
		return nil, errors.New("zero ECDSA s")
	}
	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

func topLevelKeys(raw []byte) ([]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("claims are not an object")
	}
	var keys []string
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		value, ok := key.(string)
		if !ok {
			return nil, errors.New("claims key is not a string")
		}
		keys = append(keys, value)
		var discard any
		if err := decoder.Decode(&discard); err != nil {
			return nil, err
		}
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, errors.New("claims object is not closed")
	}
	return keys, nil
}

func verifyFence(vector conformance.AssignmentTicketFenceVector) error {
	preimage := append(append([]byte{}, []byte(vector.Domain)...), 0)
	for _, part := range vector.Parts {
		semantic, err := fencePartBytes(part)
		if err != nil {
			return fmt.Errorf("fence %s part %s: %w", vector.Name, part.Name, err)
		}
		declared, err := hex.DecodeString(part.BytesHex)
		if err != nil || !bytes.Equal(semantic, declared) {
			return fmt.Errorf("fence %s part %s semantic bytes disagree", vector.Name, part.Name)
		}
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(declared)))
		preimage = append(preimage, length[:]...)
		preimage = append(preimage, declared...)
	}
	if hex.EncodeToString(preimage) != vector.PreimageHex {
		return fmt.Errorf("fence %s preimage disagrees", vector.Name)
	}
	digest := sha256.Sum256(preimage)
	if hex.EncodeToString(digest[:]) != vector.DigestHex || base64.RawURLEncoding.EncodeToString(digest[:]) != vector.DigestB64URL {
		return fmt.Errorf("fence %s digest disagrees", vector.Name)
	}
	return nil
}

func fencePartBytes(part conformance.AssignmentTicketFencePart) ([]byte, error) {
	switch part.Encoding {
	case "raw_bytes_b64url":
		return strictRawURL(part.Value)
	case "utf8":
		return []byte(part.Value), nil
	case "uint64_be":
		value, err := strconv.ParseUint(part.Value, 10, 64)
		if err != nil {
			return nil, err
		}
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], value)
		return raw[:], nil
	case "bool_byte":
		switch part.Value {
		case "false":
			return []byte{0}, nil
		case "true":
			return []byte{1}, nil
		default:
			return nil, errors.New("invalid boolean spelling")
		}
	default:
		return nil, fmt.Errorf("unknown encoding %q", part.Encoding)
	}
}

func verifyDERCases(cases []conformance.AssignmentTicketDERCase) error {
	for _, c := range cases {
		der, err := hex.DecodeString(c.DERHex)
		if err != nil {
			return fmt.Errorf("DER case %s hex: %w", c.Name, err)
		}
		raw, err := derToRawLowS(der)
		if c.Outcome == conformance.ExpectAccept {
			if err != nil || hex.EncodeToString(raw) != c.ExpectedRawHex {
				return fmt.Errorf("DER accept case %s = %x/%v", c.Name, raw, err)
			}
		} else if err == nil {
			return fmt.Errorf("DER reject case %s unexpectedly normalized", c.Name)
		}
	}
	return nil
}

func verifyCryptographicRejects(publicKey *ecdsa.PublicKey, af *conformance.AssignmentTicketFile) error {
	acceptRaw, err := strictRawURL(af.Golden.SignatureB64URL)
	if err != nil {
		return err
	}
	for _, c := range af.VerifyRejects {
		token, err := c.ResolveToken(af.Golden)
		if err != nil || token == "" {
			return fmt.Errorf("resolve verify reject %s: %w", c.Name, err)
		}
		switch c.Name {
		case "altered_claims", "reordered_claims_original_signature":
			preimage := append(append([]byte(af.Contract.SigningDomain), 0), []byte(c.ClaimsB64URL)...)
			digest := sha256.Sum256(preimage)
			if verifyRawSignature(publicKey, digest[:], acceptRaw) {
				return fmt.Errorf("reject %s still verifies", c.Name)
			}
		case "wrong_signing_domain":
			raw, err := strictRawURL(c.SignatureB64URL)
			if err != nil {
				return err
			}
			correct := sha256.Sum256(append(append([]byte(af.Contract.SigningDomain), 0), []byte(af.Golden.ClaimsB64URL)...))
			wrong := sha256.Sum256(append(append([]byte("qurl-agent-assignment-ticket-v0"), 0), []byte(af.Golden.ClaimsB64URL)...))
			if verifyRawSignature(publicKey, correct[:], raw) || !verifyRawSignature(publicKey, wrong[:], raw) {
				return errors.New("wrong-domain reject does not isolate domain separation")
			}
		case "high_s_raw_signature":
			raw, err := strictRawURL(c.SignatureB64URL)
			if err != nil || len(raw) != 64 {
				return errors.New("high-S reject is not a raw signature")
			}
			digest, _ := hex.DecodeString(af.Golden.SigningDigestHex)
			s := new(big.Int).SetBytes(raw[32:])
			if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)) <= 0 || !verifyRawSignature(publicKey, digest, raw) {
				return errors.New("high-S reject is not mathematically valid high-S")
			}
		case "claims_noncanonical_base64url":
			if decoded, err := base64.RawURLEncoding.DecodeString(c.ClaimsB64URL); err != nil || string(decoded) != af.Golden.ClaimsJSON {
				return errors.New("claims noncanonical reject does not decode to golden bytes")
			}
			if _, err := strictRawURL(c.ClaimsB64URL); err == nil {
				return errors.New("strict decoder accepted noncanonical claims")
			}
		case "signature_noncanonical_base64url":
			if decoded, err := base64.RawURLEncoding.DecodeString(c.SignatureB64URL); err != nil || !bytes.Equal(decoded, acceptRaw) {
				return errors.New("signature noncanonical reject does not decode to golden bytes")
			}
			if _, err := strictRawURL(c.SignatureB64URL); err == nil {
				return errors.New("strict decoder accepted noncanonical signature")
			}
		case "claims_padding":
			if _, err := strictRawURL(c.ClaimsB64URL); err == nil {
				return errors.New("strict decoder accepted padded claims")
			}
		case "signature_padding":
			if _, err := strictRawURL(c.SignatureB64URL); err == nil {
				return errors.New("strict decoder accepted padded signature")
			}
		case "malformed_raw_signature":
			raw, err := strictRawURL(c.SignatureB64URL)
			if err != nil || len(raw) == af.Contract.RawSignatureBytes {
				return errors.New("malformed raw signature does not isolate exact length")
			}
		case "wrong_kid":
			if c.TrustedKID == af.SyntheticSigningKey.KID {
				return errors.New("wrong-kid reject trusts the golden kid")
			}
		case "wrong_environment":
			if c.ExpectedEnvironmentID == af.Golden.EnvironmentID {
				return errors.New("wrong-environment reject uses the golden environment")
			}
		case "wrong_audience":
			claims, err := strictRawURL(c.ClaimsB64URL)
			if err != nil || referenceParseClaims(claims, af.Contract) == nil {
				return errors.New("wrong-audience reject does not reach the claims boundary")
			}
			signature, err := strictRawURL(c.SignatureB64URL)
			digest := sha256.Sum256(append(append([]byte(af.Contract.SigningDomain), 0), []byte(c.ClaimsB64URL)...))
			if err != nil || !verifyRawSignature(publicKey, digest[:], signature) {
				return errors.New("wrong-audience reject does not isolate the claims boundary")
			}
		case "not_yet_valid":
			if c.VerifyAtUnix != af.Golden.ClockUnix+int64(af.Contract.NotBeforeOffsetSeconds)-1 {
				return errors.New("not-yet-valid reject is not exactly nbf-1")
			}
		case "expired":
			if c.VerifyAtUnix != af.Golden.ClockUnix+int64(af.Contract.MaxLifetimeSeconds) {
				return errors.New("expired reject is not exactly exp")
			}
		case "ticket_too_large":
			if len(token) != af.Contract.MaxTicketASCIIBytes+1 {
				return errors.New("ticket size reject is not exactly limit+1")
			}
		case "claims_part_too_large":
			parts := strings.Split(token, ".")
			if len(parts) != 3 || len(parts[1]) != af.Contract.MaxClaimsPartCharacters+1 || len(token) > af.Contract.MaxTicketASCIIBytes {
				return errors.New("claims-part size reject does not isolate claims bound")
			}
		}
	}
	return nil
}

func verifyRawSignature(publicKey *ecdsa.PublicKey, digest, raw []byte) bool {
	if len(raw) != 64 {
		return false
	}
	der, err := asn1.Marshal(ecdsaSignature{R: new(big.Int).SetBytes(raw[:32]), S: new(big.Int).SetBytes(raw[32:])})
	return err == nil && ecdsa.VerifyASN1(publicKey, digest, der)
}

func verifyTrustKeyRejects(cases []conformance.AssignmentTicketTrustReject) error {
	for _, c := range cases {
		der, err := strictRawURL(c.PublicKeySPKIDERB64)
		if c.Name == "empty_spki" {
			if err != nil || len(der) != 0 {
				return errors.New("empty SPKI case is not empty")
			}
			if _, parseErr := x509.ParsePKIXPublicKey(der); parseErr == nil {
				return errors.New("empty SPKI unexpectedly parsed")
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("trust reject %s encoding: %w", c.Name, err)
		}
		parsed, parseErr := x509.ParsePKIXPublicKey(der)
		switch c.Name {
		case "wrong_curve":
			key, ok := parsed.(*ecdsa.PublicKey)
			if parseErr != nil || !ok || key.Curve == elliptic.P256() {
				return errors.New("wrong-curve trust reject is not a valid non-P256 EC key")
			}
		case "malformed_spki":
			if parseErr == nil {
				return errors.New("malformed SPKI unexpectedly parsed")
			}
		}
	}
	return nil
}

func derToRawLowS(der []byte) ([]byte, error) {
	var signature ecdsaSignature
	rest, err := asn1.Unmarshal(der, &signature)
	n := elliptic.P256().Params().N
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil ||
		signature.R.Sign() <= 0 || signature.S.Sign() <= 0 || signature.R.Cmp(n) >= 0 || signature.S.Cmp(n) >= 0 {
		return nil, errors.New("invalid P-256 DER signature")
	}
	s := new(big.Int).Set(signature.S)
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		s.Sub(n, s)
	}
	raw := make([]byte, 64)
	signature.R.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return raw, nil
}

func strictRawURL(value string) ([]byte, error) {
	if strings.Contains(value, "=") {
		return nil, errors.New("padding is forbidden")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, errors.New("noncanonical base64url")
	}
	return raw, nil
}
