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
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	conformance "github.com/layervai/qurl-conformance"
)

const vectorPath = "../../vectors/delegated_mint_issue_v1_vectors.json"

func main() {
	rotateKeys := flag.Bool("rotate-keys", false, "replace all committed throwaway signing keys and signatures")
	flag.Parse()
	if err := run(*rotateKeys); err != nil {
		fmt.Fprintln(os.Stderr, "gen-delegated-mint: FAILED:", err)
		os.Exit(1)
	}
	if *rotateKeys {
		fmt.Println("gen-delegated-mint: OK - rotated and verified all delegated-mint signed vectors")
		return
	}
	fmt.Println("gen-delegated-mint: OK - preserved keys and verified all delegated-mint vectors")
}

func run(rotateKeys bool) error {
	return runAtPath(vectorPath, rotateKeys)
}

func runAtPath(path string, rotateKeys bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var file conformance.DelegatedMintIssueV1File
	if err := json.Unmarshal(raw, &file); err != nil {
		return err
	}
	file.Contract = conformance.DelegatedMintIssueV1ContractValue()
	if rotateKeys {
		if err := rotateSignedVectors(&file); err != nil {
			return err
		}
	}
	file.RejectCases, err = conformance.DelegatedMintIssueV1RejectCases(file.Golden)
	if err != nil {
		return err
	}
	file.StateCases = conformance.DelegatedMintIssueV1StateCases(file)
	file.ResponseCases = conformance.DelegatedMintIssueV1ResponseCases()
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if _, err := conformance.ParseDelegatedMintIssueV1File(out); err != nil {
		return fmt.Errorf("self-verify generated artifact: %w", err)
	}
	return os.WriteFile(path, out, 0o644)
}

func rotateSignedVectors(file *conformance.DelegatedMintIssueV1File) error {
	initialKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	refreshKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	if err := rotateGolden(&file.Golden, initialKey); err != nil {
		return err
	}
	for _, golden := range []*conformance.DelegatedMintIssueV1Golden{&file.RetryGolden, &file.RefreshGolden} {
		if err := rotateGolden(golden, refreshKey); err != nil {
			return err
		}
	}
	file.WrongEndpointSigned = file.Golden
	file.WrongEndpointSigned.Authority = "alternate.internal.sandbox.layerv.ai"
	file.WrongEndpointSigned.Nonce = base64.RawURLEncoding.EncodeToString([]byte{
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	})
	if err := rotateGolden(&file.WrongEndpointSigned, initialKey); err != nil {
		return err
	}
	file.NonceReuseSigned = file.RefreshGolden
	file.NonceReuseSigned.Nonce = file.Golden.Nonce
	file.NonceReuseSigned.TimestampUnix = file.Golden.TimestampUnix + conformance.DelegatedMintIssueV1TimestampMaxSkewSeconds
	const refreshCapabilityExpiry = `"capability_expires_at":"2026-09-06T00:00:00Z"`
	nonceReuseExpiry := time.Unix(file.NonceReuseSigned.TimestampUnix+int64(file.Contract.CapabilityTTLSeconds), 0).UTC().Format(time.RFC3339)
	nonceReuseCapabilityExpiry := `"capability_expires_at":"` + nonceReuseExpiry + `"`
	if count := strings.Count(file.NonceReuseSigned.BodyUTF8, refreshCapabilityExpiry); count != 1 {
		return fmt.Errorf("nonce-reuse capability expiry count = %d, want 1", count)
	}
	file.NonceReuseSigned.BodyUTF8 = strings.Replace(file.NonceReuseSigned.BodyUTF8,
		refreshCapabilityExpiry, nonceReuseCapabilityExpiry, 1)
	if err := rotateGolden(&file.NonceReuseSigned, refreshKey); err != nil {
		return err
	}
	file.AuthorityConflictSigned = file.Golden
	file.AuthorityConflictSigned.Nonce = base64.RawURLEncoding.EncodeToString([]byte{
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	})
	const oldFilename = `"display_filename":"diagram.png"`
	const conflictFilename = `"display_filename":"diagram-2.png"`
	if count := strings.Count(file.AuthorityConflictSigned.BodyUTF8, oldFilename); count != 1 {
		return fmt.Errorf("authority-conflict source filename count = %d, want 1", count)
	}
	file.AuthorityConflictSigned.BodyUTF8 = strings.Replace(file.AuthorityConflictSigned.BodyUTF8, oldFilename, conflictFilename, 1)
	if err := rotateGolden(&file.AuthorityConflictSigned, initialKey); err != nil {
		return err
	}
	return nil
}

func rotateGolden(golden *conformance.DelegatedMintIssueV1Golden, privateKey *ecdsa.PrivateKey) error {
	bodyDigest := sha256.Sum256([]byte(golden.BodyUTF8))
	golden.BodySHA256 = hex.EncodeToString(bodyDigest[:])
	canonical, err := conformance.DelegatedMintIssueV1CanonicalBytes(*golden)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
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
