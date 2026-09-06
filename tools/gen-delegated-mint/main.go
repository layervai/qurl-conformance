// Command gen-delegated-mint rotates the two throwaway P-256 keys in the
// delegated-mint conformance artifact. It never runs in CI because ECDSA uses a
// random nonce. The committed, self-verified JSON is the artifact.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	conformance "github.com/layervai/qurl-conformance"
)

const vectorPath = "../../vectors/delegated_mint_issue_v1_vectors.json"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-delegated-mint: FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("gen-delegated-mint: OK - rotated and verified both delegated-mint test keys")
}

func run() error {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		return err
	}
	var file conformance.DelegatedMintIssueV1File
	if err := json.Unmarshal(raw, &file); err != nil {
		return err
	}
	for _, golden := range []*conformance.DelegatedMintIssueV1Golden{&file.Golden, &file.RefreshGolden} {
		if err := rotateGolden(golden); err != nil {
			return err
		}
	}
	file.RejectCases, err = conformance.DelegatedMintIssueV1RejectCases(file.Golden)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if _, err := conformance.ParseDelegatedMintIssueV1File(out); err != nil {
		return fmt.Errorf("self-verify generated artifact: %w", err)
	}
	return os.WriteFile(vectorPath, out, 0o644)
}

func rotateGolden(golden *conformance.DelegatedMintIssueV1Golden) error {
	canonical, err := conformance.DelegatedMintIssueV1CanonicalBytes(*golden)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return err
	}
	halfN := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	signatureDER, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	golden.CanonicalHex = hex.EncodeToString(canonical)
	golden.SigningDigestHex = hex.EncodeToString(digest[:])
	golden.PublicKeyDERB64URL = base64.RawURLEncoding.EncodeToString(publicDER)
	golden.SignatureDERB64URL = base64.RawURLEncoding.EncodeToString(signatureDER)
	return nil
}
