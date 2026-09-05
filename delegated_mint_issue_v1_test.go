package conformance

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestEmbeddedDelegatedMintIssueV1LoadsAndVerifies(t *testing.T) {
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatalf("DelegatedMintIssueV1(): %v", err)
	}
	if file.Artifact != DelegatedMintIssueV1ArtifactID || file.SchemaVersion != DelegatedMintIssueV1SchemaVersion {
		t.Fatalf("identity = %q/v%d", file.Artifact, file.SchemaVersion)
	}
	for _, golden := range []DelegatedMintIssueV1Golden{file.Golden, file.RefreshGolden} {
		canonical, err := DelegatedMintIssueV1CanonicalBytes(golden)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(canonical); got == 0 {
			t.Fatal("canonical signature input is empty")
		}
	}
	if len(file.Golden.Nonce) != 22 || len(file.RefreshGolden.Nonce) != 22 ||
		!strings.HasPrefix(file.Golden.IdempotencyKey, "uci_") || !strings.HasPrefix(file.Golden.BodyUTF8, `{"upload_handle":"upl_`) {
		t.Fatal("golden Connector identifier shapes drifted")
	}
	if file.Contract.TimestampMaxSkewSeconds != 300 || file.Contract.NonceReplayRetentionSeconds != 600 ||
		file.Contract.ExpiryAuthorityRule != "caller_supplies_signed_values_service_requires_capability_timestamp_plus_900_and_initial_authority_at_most_timestamp_plus_86400_refresh_preserves_authority" {
		t.Fatalf("freshness/replay/expiry authority contract drifted: %+v", file.Contract)
	}
	var body struct {
		UploadHandle        string `json:"upload_handle"`
		AudienceKeyID       string `json:"audience_key_id"`
		TargetPath          string `json:"target_path"`
		CapabilityExpiresAt string `json:"capability_expires_at"`
		AuthorityExpiresAt  string `json:"authority_expires_at"`
	}
	if err := json.Unmarshal([]byte(file.Golden.BodyUTF8), &body); err != nil {
		t.Fatalf("decode golden body: %v", err)
	}
	if body.UploadHandle != "upl_VGWeFxH8fk_znKtylEoZVkRb8AXlTbIS03Yj5ssVO70" ||
		body.AudienceKeyID != "key_A1b2C3d4E5f6" || body.TargetPath != "/files/"+body.UploadHandle ||
		body.CapabilityExpiresAt == body.AuthorityExpiresAt {
		t.Fatalf("golden body binding drifted: %+v", body)
	}
}

func TestOpenDelegatedMintIssueV1Artifact(t *testing.T) {
	want := DelegatedMintIssueV1Vectors()
	for _, name := range []string{"delegated_mint_issue_v1_vectors.json", "vectors/delegated_mint_issue_v1_vectors.json"} {
		got, err := Open(name)
		if err != nil {
			t.Fatalf("Open(%q): %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Open(%q) does not match embedded vectors", name)
		}
	}
}

func TestParseDelegatedMintIssueV1FileFailsClosed(t *testing.T) {
	raw := DelegatedMintIssueV1Vectors()
	for name, invalid := range map[string][]byte{
		"duplicate key":  bytes.Replace(raw, []byte(`"artifact":`), []byte(`"artifact":"duplicate","artifact":`), 1),
		"unknown field":  bytes.Replace(raw, []byte("{"), []byte(`{"future":true,`), 1),
		"trailing value": append(append([]byte(nil), raw...), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDelegatedMintIssueV1File(invalid); err == nil {
				t.Fatal("invalid artifact unexpectedly accepted")
			}
		})
	}

	mutate := func(t *testing.T, change func(*DelegatedMintIssueV1File)) []byte {
		t.Helper()
		var file DelegatedMintIssueV1File
		if err := json.Unmarshal(raw, &file); err != nil {
			t.Fatal(err)
		}
		change(&file)
		body, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, test := range []struct {
		name   string
		change func(*DelegatedMintIssueV1File)
	}{
		{name: "contract", change: func(file *DelegatedMintIssueV1File) { file.Contract.NonceDecodedBytes++ }},
		{name: "body", change: func(file *DelegatedMintIssueV1File) { file.Golden.BodyUTF8 += " " }},
		{name: "refresh body", change: func(file *DelegatedMintIssueV1File) { file.RefreshGolden.BodyUTF8 += " " }},
		{name: "refresh widens batch", change: func(file *DelegatedMintIssueV1File) {
			file.RefreshGolden.BodyUTF8 = strings.Replace(file.RefreshGolden.BodyUTF8, `"max_batch_size":100`, `"max_batch_size":101`, 1)
			file.RefreshGolden.BodySHA256 = file.Golden.BodySHA256
		}},
		{name: "canonical", change: func(file *DelegatedMintIssueV1File) {
			file.Golden.CanonicalHex = strings.Repeat("0", len(file.Golden.CanonicalHex))
		}},
		{name: "signature", change: func(file *DelegatedMintIssueV1File) {
			file.Golden.SignatureDERB64URL = file.Golden.SignatureDERB64URL[:len(file.Golden.SignatureDERB64URL)-1] + "A"
		}},
		{name: "padded signature", change: func(file *DelegatedMintIssueV1File) { file.Golden.SignatureDERB64URL += "=" }},
		{name: "high-S signature", change: func(file *DelegatedMintIssueV1File) {
			der, err := base64.RawURLEncoding.Strict().DecodeString(file.Golden.SignatureDERB64URL)
			if err != nil {
				t.Fatal(err)
			}
			var signature struct{ R, S *big.Int }
			if rest, err := asn1.Unmarshal(der, &signature); err != nil || len(rest) != 0 {
				t.Fatalf("parse signature: rest=%x err=%v", rest, err)
			}
			signature.S = new(big.Int).Sub(elliptic.P256().Params().N, signature.S)
			highDER, err := asn1.Marshal(signature)
			if err != nil {
				t.Fatal(err)
			}
			file.Golden.SignatureDERB64URL = base64.RawURLEncoding.EncodeToString(highDER)
		}},
		{name: "nonce", change: func(file *DelegatedMintIssueV1File) { file.Golden.Nonce = "AA" }},
		{name: "idempotency", change: func(file *DelegatedMintIssueV1File) { file.Golden.IdempotencyKey = "bad key" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseDelegatedMintIssueV1File(mutate(t, test.change)); err == nil {
				t.Fatal("mutated artifact unexpectedly accepted")
			}
		})
	}
}

func TestDelegatedMintIssueV1IdempotencyAndAuthority(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	for generation, want := range map[int]string{
		1: file.Golden.IdempotencyKey,
		2: file.RefreshGolden.IdempotencyKey,
	} {
		got, err := DelegatedMintIssueV1IdempotencyKey("fileviewer-sandbox", "upl_VGWeFxH8fk_znKtylEoZVkRb8AXlTbIS03Yj5ssVO70", generation)
		if err != nil || got != want {
			t.Fatalf("generation %d idempotency = %q, %v; want %q", generation, got, err, want)
		}
	}
	for _, authority := range []string{
		"localhost", "127.0.0.1", "[::1]", "api.layerv.ai:443", "api..layerv.ai",
		"api.layerv.ai.", "-api.layerv.ai", "api-.layerv.ai", "api_internal.layerv.ai",
		"API.layerv.ai", "api.layerv.ai\n", "é.layerv.ai",
	} {
		if validDelegatedMintIssueV1Authority(authority) {
			t.Errorf("authority %q unexpectedly accepted", authority)
		}
	}
}

func TestDelegatedMintIssueV1RenewalCannotWidenAuthority(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DelegatedMintIssueV1Golden){
		"batch limit": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"max_batch_size":100`, `"max_batch_size":101`, 1)
		},
		"link TTL limit": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"max_link_ttl_seconds":86400`, `"max_link_ttl_seconds":86401`, 1)
		},
		"audience": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"audience_key_id":"key_A1b2C3d4E5f6"`, `"audience_key_id":"key_Z9y8X7w6V5u4"`, 1)
		},
		"authority expiry": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"authority_expires_at":"2026-09-06T23:15:00Z"`, `"authority_expires_at":"2026-09-07T23:15:00Z"`, 1)
		},
		"capability past authority": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"capability_expires_at":"2026-09-06T00:00:00Z"`, `"capability_expires_at":"2026-09-07T00:00:00Z"`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			refresh := file.RefreshGolden
			mutate(&refresh)
			if err := validateDelegatedMintIssueV1Renewal(file.Golden, refresh); err == nil {
				t.Fatal("widened refresh unexpectedly accepted")
			}
		})
	}
}
