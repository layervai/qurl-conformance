// Command gen regenerates the key-dependent qURL v2 conformance artifacts with a
// fresh throwaway issuer key. Run once per key rotation via `make gen-vectors`;
// NEVER in CI (the accept signature uses a random ECDSA nonce, so it is not
// reproducible). It self-verifies every vector before writing.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/layervai/qurl-go/qv2"
)

func raw(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen: FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("gen: OK — wrote vectors/issuer_signature_vectors.json (selfVerify passed)")
}

func run() error {
	ctx := context.Background()

	signer, err := qv2.GenerateLocalSigner("qurl-issuer-vector-key")
	if err != nil {
		return err
	}
	spki, err := signer.PublicKeyDER()
	if err != nil {
		return err
	}

	// Throwaway P-256 resource key (valid DER SPKI, ~91 bytes).
	rpriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	resourceDER, err := x509.MarshalPKIXPublicKey(&rpriv.PublicKey)
	if err != nil {
		return err
	}

	claims := &qv2.Claims{
		V: 2, Iss: "qurl-service", Kid: "qurl-issuer-vector-key",
		Iat: 1781910000, Nbf: 1781910000, Exp: 1781910300,
		Jti:                  "qurl_01JVECTORFIXTURE0000",
		CellPublicKeyB64:     raw(bytes.Repeat([]byte{0x44}, 32)),
		CellID:               "vector-cell",
		RelayURL:             "https://relay.example.com",
		ResourcePublicKeyB64: raw(resourceDER),
		QurlUserPublicKeyB64: raw(bytes.Repeat([]byte{0x55}, 32)),
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

	// Reject vectors derived deterministically from the one signature.
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

	// selfVerify BEFORE writing — never emit an inconsistent artifact.
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
		"description":              "qURL v2 issuer-signature golden vectors: P-256 raw r||s low-S wire signatures over the exact claims bytes. These are VERIFY fixtures (ECDSA's nonce is random, so signatures are re-verified by consumers, never reproduced).",
		"algorithm":                "ECC_NIST_P256 / ECDSA_SHA_256, wire = raw r||s (64 bytes), low-S",
		"domain_separation_prefix": "NHP-QURL-V2-ISSUER",
		"issuer": map[string]any{
			"kid":          "qurl-issuer-vector-key",
			"spki_der_b64": raw(spki),
			"jwk":          map[string]any{"kty": "EC", "crv": "P-256", "x": raw(xb), "y": raw(yb)},
		},
		"vectors": []map[string]any{
			{"name": "accept_valid_low_s", "expect": "accept", "reason": "valid 64-byte low-S raw r||s signature over the exact claims bytes", "claims_b64": claimsB64, "sig_b64": raw(rawSig), "sig_encoding": "raw_r_s", "signing_input_b64": raw(signingInput)},
			{"name": "reject_high_s", "expect": "reject", "reason": "high_s", "claims_b64": claimsB64, "sig_b64": raw(highRaw), "sig_encoding": "raw_r_s", "signing_input_b64": raw(signingInput)},
			{"name": "reject_wrong_length_der", "expect": "reject", "reason": "wrong_length", "claims_b64": claimsB64, "sig_b64": raw(der), "sig_encoding": "der", "signing_input_b64": raw(signingInput)},
		},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("../../vectors/issuer_signature_vectors.json", append(out, '\n'), 0o644)
}
