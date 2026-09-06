// Command gen regenerates the key-dependent qURL v2 conformance artifacts with
// fixed public vector keys. Run once per artifact rotation via
// `make gen-vectors`; NEVER in CI (the accept signature uses a random ECDSA
// nonce, so it is not reproducible). It self-verifies every vector before
// writing.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/layervai/qurl-go/qv2"
)

func raw(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen: FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("gen: OK — regenerated issuer signature + fragment/transport accept vectors (selfVerify passed)")
}

func run() error {
	ctx := context.Background()

	issuerPrivate, err := fixedP256PrivateKey(0x07)
	if err != nil {
		return err
	}
	signer, err := qv2.NewLocalSigner(issuerPrivate, "qurl-issuer-vector-key")
	if err != nil {
		return err
	}
	spki, err := signer.PublicKeyDER()
	if err != nil {
		return err
	}

	rpriv, err := fixedP256PrivateKey(0x08)
	if err != nil {
		return err
	}
	resourceDER, err := x509.MarshalPKIXPublicKey(&rpriv.PublicKey)
	if err != nil {
		return err
	}

	qurlUserPrivateBytes := bytes.Repeat([]byte{0x09}, 32)
	qurlUserPrivateKey, err := ecdh.X25519().NewPrivateKey(qurlUserPrivateBytes)
	if err != nil {
		return fmt.Errorf("parse fixed qURL user private key: %w", err)
	}
	qurlUserPublicB64 := raw(qurlUserPrivateKey.PublicKey().Bytes())

	claims := &qv2.Claims{
		V: 2, Iss: "qurl-service", Kid: "qurl-issuer-vector-key",
		Iat: 1781910000, Nbf: 1781910000, Exp: 1781910300,
		Jti:                  "qurl_01JVECTORFIXTURE0000",
		CellPublicKeyB64:     raw(bytes.Repeat([]byte{0x44}, 32)),
		CellID:               "vector-cell",
		RelayURL:             "https://relay.example.com",
		ResourcePublicKeyB64: raw(resourceDER),
		QurlUserPublicKeyB64: qurlUserPublicB64,
	}
	claimsB64, rawSig, err := qv2.SignClaims(ctx, signer, claims)
	if err != nil {
		return err
	}

	signingInput := append([]byte("NHP-QURL-V2-ISSUER"), 0x00)
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

	if err := qv2.VerifyRawIssuerSignature(pub, claimsB64, rawSig); err != nil {
		return fmt.Errorf("accept must verify: %w", err)
	}
	if err := qv2.VerifyRawIssuerSignature(pub, claimsB64, highRaw); !errors.Is(err, qv2.ErrSignatureHighS) {
		return fmt.Errorf("high-S must be ErrSignatureHighS, got %v", err)
	}
	if err := qv2.VerifyRawIssuerSignature(pub, claimsB64, der); !errors.Is(err, qv2.ErrSignatureLength) {
		return fmt.Errorf("DER must be ErrSignatureLength, got %v", err)
	}
	repl := byte('A')
	if claimsB64[0] == 'A' {
		repl = 'B'
	}
	tampered := string(repl) + claimsB64[1:]
	terr := qv2.VerifyRawIssuerSignature(pub, tampered, rawSig)
	if !errors.Is(terr, qv2.ErrSignature) || errors.Is(terr, qv2.ErrSignatureHighS) || errors.Is(terr, qv2.ErrSignatureLength) {
		return fmt.Errorf("tamper must be bare ErrSignature, got %v", terr)
	}

	doc := map[string]any{
		"description":              "qURL v2 issuer-signature golden vectors: P-256 raw r||s low-S wire signatures over the exact claims bytes. These are VERIFY fixtures (ECDSA's nonce is random, so signatures are re-verified by consumers, never reproduced). The issuer private key is a publicly derivable, fixed test scalar; never admit this key or kid to a production trust store.",
		"algorithm":                "ECC_NIST_P256 / ECDSA_SHA_256, wire = raw r||s (64 bytes), low-S",
		"domain_separation_prefix": "NHP-QURL-V2-ISSUER",
		"issuer": map[string]any{
			"kid":          "qurl-issuer-vector-key",
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
	parsedFragment, err := qv2.ParseFragment(newFragment)
	if err != nil {
		return fmt.Errorf("rebuilt fragment must parse: %w", err)
	}
	parsedPrivateBytes, err := base64.RawURLEncoding.DecodeString(parsedFragment.Secret.QurlUserPrivateKeyB64)
	if err != nil {
		return fmt.Errorf("decode rebuilt fragment qURL user private key: %w", err)
	}
	parsedPrivateKey, err := ecdh.X25519().NewPrivateKey(parsedPrivateBytes)
	if err != nil {
		return fmt.Errorf("parse rebuilt fragment qURL user private key: %w", err)
	}
	if got := raw(parsedPrivateKey.PublicKey().Bytes()); got != parsedFragment.Claims.QurlUserPublicKeyB64 {
		return fmt.Errorf("rebuilt fragment qURL user X25519 keypair mismatch")
	}
	const cfPath = "../../vectors/qv2_conformance_vectors.json"
	cfBytes, err := os.ReadFile(cfPath)
	if err != nil {
		return err
	}
	var cfDoc struct {
		TransportContract transportEncodingContract `json:"transport_contract"`
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
	newTransportFragment, err := encodeTransportFragment(newFragment, cfDoc.TransportContract)
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
	var oldTransportFragment, oldCanonicalFragment string
	for _, v := range cfDoc.Classes["transport"].Vectors {
		if v.Name == "accept_valid_qv2_round_trip" && v.Expect == "accept" {
			oldTransportFragment = v.TransportFragment
			oldCanonicalFragment = v.CanonicalFragment
			break
		}
	}
	if oldTransportFragment == "" || oldCanonicalFragment == "" {
		return fmt.Errorf("no transport-class round-trip accept vector found")
	}
	if oldCanonicalFragment != oldFragment {
		return fmt.Errorf("fragment and transport accept fixtures do not share one canonical fragment")
	}
	updated, err := replaceExactJSONString(cfBytes, oldFragment, newFragment, 2)
	if err != nil {
		return err
	}
	updated, err = replaceExactJSONString(updated, oldTransportFragment, newTransportFragment, 1)
	if err != nil {
		return err
	}
	return os.WriteFile(cfPath, updated, 0o644)
}

type transportFieldContract struct {
	MaxEncodedLength int `json:"max_encoded_length"`
	MaxChunks        int `json:"max_chunks"`
}

type transportEncodingContract struct {
	ComponentMax       int `json:"component_max"`
	MaxTransportLength int `json:"max_transport_length"`
	Fields             struct {
		Claims    transportFieldContract `json:"claims"`
		Secret    transportFieldContract `json:"secret"`
		Signature transportFieldContract `json:"signature"`
	} `json:"fields"`
}

func encodeTransportFragment(fragment string, contract transportEncodingContract) (string, error) {
	if contract.ComponentMax <= 0 || contract.MaxTransportLength <= 0 {
		return "", fmt.Errorf("transport size bounds must be positive")
	}
	parts := strings.Split(fragment, ".")
	if len(parts) != 4 || parts[0] != "qv2" {
		return "", fmt.Errorf("canonical fragment has invalid shape")
	}
	fields := []struct {
		name   string
		value  string
		limits transportFieldContract
	}{
		{name: "claims", value: parts[1], limits: contract.Fields.Claims},
		{name: "secret", value: parts[2], limits: contract.Fields.Secret},
		{name: "signature", value: parts[3], limits: contract.Fields.Signature},
	}
	counts := make([]string, 0, 3)
	chunks := make([]string, 0)
	for _, field := range fields {
		if field.limits.MaxEncodedLength <= 0 || field.limits.MaxChunks <= 0 {
			return "", fmt.Errorf("transport %s bounds must be positive", field.name)
		}
		if len(field.value) > field.limits.MaxEncodedLength {
			return "", fmt.Errorf("transport %s exceeds max_encoded_length", field.name)
		}
		fieldChunks := make([]string, 0, (len(field.value)+contract.ComponentMax-1)/contract.ComponentMax)
		for len(field.value) > contract.ComponentMax {
			fieldChunks = append(fieldChunks, field.value[:contract.ComponentMax])
			field.value = field.value[contract.ComponentMax:]
		}
		if field.value == "" {
			return "", fmt.Errorf("canonical fragment has empty field")
		}
		fieldChunks = append(fieldChunks, field.value)
		if len(fieldChunks) > field.limits.MaxChunks {
			return "", fmt.Errorf("transport %s exceeds max_chunks", field.name)
		}
		counts = append(counts, fmt.Sprint(len(fieldChunks)))
		chunks = append(chunks, fieldChunks...)
	}
	transport := "qv2t1." + strings.Join(append(counts, chunks...), ".")
	if len(transport) > contract.MaxTransportLength {
		return "", fmt.Errorf("transport fragment exceeds max_transport_length")
	}
	return transport, nil
}

func replaceExactJSONString(data []byte, oldValue, newValue string, wantCount int) ([]byte, error) {
	oldJSON, err := marshalJSONString(oldValue)
	if err != nil {
		return nil, err
	}
	newJSON, err := marshalJSONString(newValue)
	if err != nil {
		return nil, err
	}
	if got := bytes.Count(data, oldJSON); got != wantCount {
		return nil, fmt.Errorf("JSON string replacement found %d copies, want %d", got, wantCount)
	}
	return bytes.ReplaceAll(data, oldJSON, newJSON), nil
}

func marshalJSONString(value string) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

// fixedP256PrivateKey returns a public, vector-only key. Stable key material
// keeps a claims-only edit from also rotating the issuer and resource public
// keys. The committed signatures remain non-reproducible because ECDSA uses a
// random nonce.
func fixedP256PrivateKey(fill byte) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	scalarBytes := bytes.Repeat([]byte{fill}, 32)
	d := new(big.Int).SetBytes(scalarBytes)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, fmt.Errorf("fixed P-256 scalar is out of range")
	}
	x, y := curve.ScalarBaseMult(scalarBytes)
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}
