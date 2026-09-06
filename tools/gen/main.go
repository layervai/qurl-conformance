// Command gen regenerates the key-dependent qURL v2 conformance artifacts with
// fixed public vector keys. Run once per artifact rotation via
// `make gen-vectors`; NEVER in CI (the accept signature uses a random ECDSA
// nonce, so it is not reproducible). It self-verifies every vector before
// writing.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/layervai/qurl-conformance/tools/gen/internal/genkit"
)

func raw(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

const (
	issuerSigningDomain            = "NHP-QURL-V2-ISSUER"
	issuerVectorKID                = "qurl-issuer-vector-key-do-not-trust"
	issuerPrivateScalarFill   byte = 0x07
	resourcePrivateScalarFill byte = 0x08
	qurlUserPrivateScalarFill byte = 0x09
)

// issuerClaims mirrors the public qURL v2 claims wire order. The root
// conformance tests strict-parse the resulting artifact; the generator does
// not import a consumer's internal protocol package as an authority.
type issuerClaims struct {
	V   int    `json:"v"`
	Iss string `json:"iss"`
	Kid string `json:"kid"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`

	CellPublicKeyB64     string `json:"cell_public_key_b64"`
	CellID               string `json:"cell_id,omitempty"`
	RelayURL             string `json:"relay_url"`
	ResourcePublicKeyB64 string `json:"resource_public_key_b64"`
	QurlUserPublicKeyB64 string `json:"qurl_user_public_key_b64"`
}

func signClaims(privateKey *ecdsa.PrivateKey, claims *issuerClaims) (string, []byte, error) {
	if privateKey == nil || privateKey.Curve != elliptic.P256() || claims == nil || claims.Kid != issuerVectorKID {
		return "", nil, fmt.Errorf("fixed issuer key and claims kid are required")
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", nil, err
	}
	claimsB64 := raw(claimsJSON)
	digest := issuerSignatureDigest(claimsB64)
	providerDER, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		return "", nil, err
	}
	rawSignature, err := normalizeDERSignature(providerDER)
	if err != nil {
		return "", nil, err
	}
	return claimsB64, rawSignature, nil
}

func issuerSignatureDigest(claimsB64 string) [sha256.Size]byte {
	input := append([]byte(issuerSigningDomain), 0)
	input = append(input, claimsB64...)
	return sha256.Sum256(input)
}

func normalizeDERSignature(der []byte) ([]byte, error) {
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		return nil, fmt.Errorf("parse issuer DER signature")
	}
	order := elliptic.P256().Params().N
	if signature.R.Sign() <= 0 || signature.R.Cmp(order) >= 0 || signature.S.Sign() <= 0 || signature.S.Cmp(order) >= 0 {
		return nil, fmt.Errorf("issuer signature scalar is out of range")
	}
	if signature.S.Cmp(new(big.Int).Rsh(new(big.Int).Set(order), 1)) > 0 {
		signature.S = new(big.Int).Sub(order, signature.S)
	}
	rawSignature := make([]byte, 64)
	signature.R.FillBytes(rawSignature[:32])
	signature.S.FillBytes(rawSignature[32:])
	return rawSignature, nil
}

func verifyRawIssuerSignature(publicKey *ecdsa.PublicKey, claimsB64 string, rawSignature []byte) error {
	if publicKey == nil || publicKey.Curve != elliptic.P256() || len(rawSignature) != 64 {
		return fmt.Errorf("invalid raw issuer signature input")
	}
	r := new(big.Int).SetBytes(rawSignature[:32])
	s := new(big.Int).SetBytes(rawSignature[32:])
	order := elliptic.P256().Params().N
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
	if r.Sign() <= 0 || r.Cmp(order) >= 0 || s.Sign() <= 0 || s.Cmp(halfOrder) > 0 {
		return fmt.Errorf("invalid raw issuer signature scalar")
	}
	digest := issuerSignatureDigest(claimsB64)
	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		return fmt.Errorf("issuer signature verification failed")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen: FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("gen: OK — regenerated issuer signature + fragment/transport accept vectors (selfVerify passed)")
}

func run() error {
	issuerPrivate, err := genkit.FixedP256PrivateKey(issuerPrivateScalarFill)
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(&issuerPrivate.PublicKey)
	if err != nil {
		return err
	}

	rpriv, err := genkit.FixedP256PrivateKey(resourcePrivateScalarFill)
	if err != nil {
		return err
	}
	resourceDER, err := x509.MarshalPKIXPublicKey(&rpriv.PublicKey)
	if err != nil {
		return err
	}

	qurlUserPrivateBytes := genkit.FixedX25519PrivateKey(qurlUserPrivateScalarFill)
	qurlUserPrivateKey, err := ecdh.X25519().NewPrivateKey(qurlUserPrivateBytes)
	if err != nil {
		return fmt.Errorf("parse fixed qURL user private key: %w", err)
	}
	qurlUserPublicB64 := raw(qurlUserPrivateKey.PublicKey().Bytes())

	claims := &issuerClaims{
		V: 2, Iss: "qurl-service", Kid: issuerVectorKID,
		Iat: 1781910000, Nbf: 1781910000, Exp: 1781910300,
		Jti:                  "qurl_01JVECTORFIXTURE0000",
		CellPublicKeyB64:     raw(bytes.Repeat([]byte{0x44}, 32)),
		CellID:               "vector-cell",
		RelayURL:             "https://relay.example.com",
		ResourcePublicKeyB64: raw(resourceDER),
		QurlUserPublicKeyB64: qurlUserPublicB64,
	}
	claimsB64, rawSig, err := signClaims(issuerPrivate, claims)
	if err != nil {
		return err
	}

	signingInput := append([]byte(issuerSigningDomain), 0x00)
	signingInput = append(signingInput, []byte(claimsB64)...)

	pubAny, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return err
	}
	pub := pubAny.(*ecdsa.PublicKey)
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)

	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	n := elliptic.P256().Params().N
	highRaw := make([]byte, 64)
	r.FillBytes(highRaw[:32])
	new(big.Int).Sub(n, s).FillBytes(highRaw[32:])
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return err
	}

	if err := verifyRawIssuerSignature(pub, claimsB64, rawSig); err != nil {
		return fmt.Errorf("accept must verify: %w", err)
	}
	if err := verifyRawIssuerSignature(pub, claimsB64, highRaw); err == nil {
		return fmt.Errorf("high-S signature was accepted")
	}
	if err := verifyRawIssuerSignature(pub, claimsB64, der); err == nil {
		return fmt.Errorf("DER signature was accepted as raw")
	}
	repl := byte('A')
	if claimsB64[0] == 'A' {
		repl = 'B'
	}
	tampered := string(repl) + claimsB64[1:]
	if err := verifyRawIssuerSignature(pub, tampered, rawSig); err == nil {
		return fmt.Errorf("tampered claims were accepted")
	}

	doc := map[string]any{
		"description":              fmt.Sprintf("qURL v2 issuer-signature golden vectors: P-256 raw r||s low-S wire signatures over the exact claims bytes. These are VERIFY fixtures (ECDSA's nonce is random, so signatures are re-verified by consumers, never reproduced). The issuer private scalar is 32 bytes of 0x%02x and the resource private scalar is 32 bytes of 0x%02x; both are public test material. Never admit either key or this kid to a production trust store.", issuerPrivateScalarFill, resourcePrivateScalarFill),
		"algorithm":                "ECC_NIST_P256 / ECDSA_SHA_256, wire = raw r||s (64 bytes), low-S",
		"domain_separation_prefix": "NHP-QURL-V2-ISSUER",
		"issuer": map[string]any{
			"kid":          issuerVectorKID,
			"spki_der_b64": raw(spki),
			"jwk":          map[string]any{"kty": "EC", "crv": "P-256", "x": raw(xb), "y": raw(yb)},
		},
		"vectors": []map[string]any{
			{"name": "accept_valid_low_s", "expect": "accept", "reason": "valid 64-byte low-S raw r||s signature over the exact claims bytes", "claims_b64": claimsB64, "sig_b64": raw(rawSig), "sig_encoding": "raw_r_s", "signing_input_b64": raw(signingInput)},
			{"name": "reject_high_s", "expect": "reject", "reason": "signature is not low-S normalized", "reject_class": "high_s", "claims_b64": claimsB64, "sig_b64": raw(highRaw), "sig_encoding": "raw_r_s", "signing_input_b64": raw(signingInput)},
			{"name": "reject_wrong_length_der", "expect": "reject", "reason": "signature is not exactly 64 bytes (raw r||s)", "reject_class": "wrong_length", "claims_b64": claimsB64, "sig_b64": raw(der), "sig_encoding": "der", "signing_input_b64": raw(signingInput)},
		},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile("../../vectors/issuer_signature_vectors.json", append(out, '\n'), 0o644); err != nil {
		return err
	}

	// Rebuild the fragment and transport accept vectors from the fresh claims/sig
	// plus a fixed throwaway secret. ParseFragment does not verify the signature,
	// so a stale signature would otherwise survive a key rotation undetected. The
	// transport fixture must reconstruct the same canonical fragment byte for byte.
	secretJSON, err := json.Marshal(map[string]string{"qurl_user_private_key_b64": raw(qurlUserPrivateBytes)})
	if err != nil {
		return err
	}
	newFragment := "qv2." + claimsB64 + "." + raw(secretJSON) + "." + raw(rawSig)
	parts := strings.Split(newFragment, ".")
	if len(parts) != 4 || parts[0] != "qv2" {
		return fmt.Errorf("rebuilt fragment has invalid shape")
	}
	parsedSecretJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode rebuilt fragment secret: %w", err)
	}
	var parsedSecret struct {
		QurlUserPrivateKeyB64 string `json:"qurl_user_private_key_b64"`
	}
	if err := json.Unmarshal(parsedSecretJSON, &parsedSecret); err != nil {
		return fmt.Errorf("parse rebuilt fragment secret: %w", err)
	}
	parsedPrivateBytes, err := base64.RawURLEncoding.Strict().DecodeString(parsedSecret.QurlUserPrivateKeyB64)
	if err != nil {
		return fmt.Errorf("decode rebuilt fragment qURL user private key: %w", err)
	}
	parsedPrivateKey, err := ecdh.X25519().NewPrivateKey(parsedPrivateBytes)
	if err != nil {
		return fmt.Errorf("parse rebuilt fragment qURL user private key: %w", err)
	}
	if got := raw(parsedPrivateKey.PublicKey().Bytes()); got != claims.QurlUserPublicKeyB64 {
		return fmt.Errorf("rebuilt fragment qURL user X25519 keypair mismatch")
	}
	const cfPath = "../../vectors/qv2_conformance_vectors.json"
	cfBytes, err := os.ReadFile(cfPath)
	if err != nil {
		return err
	}
	var cfDoc struct {
		TransportContract genkit.TransportEncodingContract `json:"transport_contract"`
		Classes           map[string]struct {
			Vectors []struct {
				Name              string `json:"name"`
				Expect            string `json:"expect"`
				Fragment          string `json:"fragment"`
				TransportFragment string `json:"transport_fragment"`
				CanonicalFragment string `json:"canonical_fragment"`
			} `json:"vectors"`
		} `json:"classes"`
	}
	if err := json.Unmarshal(cfBytes, &cfDoc); err != nil {
		return err
	}
	newTransportFragment, err := genkit.EncodeTransportFragment(newFragment, cfDoc.TransportContract)
	if err != nil {
		return err
	}
	var oldFragment string
	for _, v := range cfDoc.Classes["fragment"].Vectors {
		if v.Expect == "accept" && v.Fragment != "" {
			oldFragment = v.Fragment
			break
		}
	}
	if oldFragment == "" {
		return fmt.Errorf("no fragment-class accept vector with a fragment field found")
	}
	var oldTransportFragment, oldCanonicalFragment, oldLegacyFragment string
	for _, v := range cfDoc.Classes["transport"].Vectors {
		switch {
		case v.Name == "accept_valid_qv2_round_trip" && v.Expect == "accept":
			oldTransportFragment = v.TransportFragment
			oldCanonicalFragment = v.CanonicalFragment
		case v.Name == "reject_legacy_qv2_outer_transport" && v.Expect == "reject":
			oldLegacyFragment = v.TransportFragment
		}
	}
	if oldTransportFragment == "" || oldCanonicalFragment == "" || oldLegacyFragment == "" {
		return fmt.Errorf("required transport round-trip and legacy fixtures not found")
	}
	if oldCanonicalFragment != oldFragment {
		return fmt.Errorf("fragment and transport accept fixtures do not share one canonical fragment")
	}
	if oldLegacyFragment != oldFragment {
		return fmt.Errorf("legacy outer-transport reject does not carry the canonical inner fragment")
	}
	updated, err := genkit.ReplaceExactJSONString(cfBytes, oldFragment, newFragment, 3)
	if err != nil {
		return err
	}
	updated, err = genkit.ReplaceExactJSONString(updated, oldTransportFragment, newTransportFragment, 1)
	if err != nil {
		return err
	}
	return os.WriteFile(cfPath, updated, 0o644)
}
