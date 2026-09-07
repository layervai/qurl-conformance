package conformance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

const (
	privateUploadV1ContractUploadCanonicalHex  = "4c562d5155524c2d55504c4f41442d415554482d56310000000004504f53540000000f3132372e302e302e313a3438313233000000142f696e7465726e616c2f76312f75706c6f6164730000000a313738383634353630300000002b576c7061576c7061576c7061576c7061576c7061576c7061576c7061576c7061576c7061576c7061576c6f0000000e6578616d706c652d636c69656e74000000126578616d706c652d7369676e696e672d7631000000106b65795f413162324333643445356636000000403263663234646261356662306133306532366538336232616335623965323965316231363165356331666137343235653733303433333632393338623938323400000001350000000a746578742f706c61696e0000000a7265706f72742e74787400000014323032362d30392d30365432323a30303a30305a0000002431323365343536372d653839622d343264332d613435362d343236363134313734303030"
	privateUploadV1ContractRefreshCanonicalHex = "4c562d5155524c2d55504c4f41442d524546524553482d415554482d5631000000000550415443480000000f3132372e302e302e313a3438313233000000142f696e7465726e616c2f76312f75706c6f6164730000000a313738383634353630300000002b576c7061576c7061576c7061576c7061576c7061576c7061576c7061576c7061576c7061576c7061576c6f0000000e6578616d706c652d636c69656e74000000126578616d706c652d7369676e696e672d76310000004034393437623464323461343230663363376136633566633530306232306233373561653834646639303166353362353166623864323738356566623437346663000000033231390000002431323365343536372d653839622d343264332d613435362d343236363134313734303030"
)

func TestEmbeddedPrivateUploadV1LoadsAndPinsCanonicalContract(t *testing.T) {
	file, err := PrivateUploadV1()
	if err != nil {
		t.Fatalf("PrivateUploadV1(): %v", err)
	}
	if file.Contract.NHPProtocolVersion != "1.1" {
		t.Fatalf("protocol version = %s", file.Contract.NHPProtocolVersion)
	}
	if file.UploadGolden.CanonicalHex != privateUploadV1ContractUploadCanonicalHex {
		t.Fatal("upload canonical bytes differ from the committed contract")
	}
	if file.RefreshGolden.CanonicalHex != privateUploadV1ContractRefreshCanonicalHex {
		t.Fatal("refresh canonical bytes differ from the committed contract")
	}
	if file.UploadGolden.StableRequestDigestHex != "43df0711a0dfce4c1dd82875ce674881d0256d97a66f799ea0e0b7c6b4b9efb8" {
		t.Fatal("upload stable request digest differs from the committed contract")
	}
	if file.Contract.AudienceKeyIDRule != PrivateUploadV1AudienceKeyIDRule || file.Contract.ClientIDRule != PrivateUploadV1ClientIDRule || file.Contract.KeyIDRule != PrivateUploadV1KeyIDRule {
		t.Fatal("identifier grammar differs from the committed contract")
	}
	if file.Contract.UploadRequestIDRule != PrivateUploadV1UploadRequestIDRule || file.Contract.UploadHandleRule != PrivateUploadV1UploadHandleRule ||
		file.Contract.AuthorityExpiresAtRule != PrivateUploadV1AuthorityExpiryRule || file.Contract.BodyLengthRule != PrivateUploadV1BodyLengthRule ||
		file.Contract.Upload.MediaTypeRule != PrivateUploadV1MediaTypeRule || file.Contract.Upload.MediaTypeSubtypeRule != PrivateUploadV1MediaTypeSubtypeRule ||
		file.Contract.Upload.FilenameEncoding != PrivateUploadV1FilenameEncoding ||
		file.Contract.Upload.DisplayFilenameRule != PrivateUploadV1DisplayFilenameRule {
		t.Fatal("request construction rules differ from the committed contract")
	}
	if file.UploadGolden.ClientID != "example-client" || file.UploadGolden.KeyID != "example-signing-v1" ||
		file.RefreshGolden.ClientID != "example-client" || file.RefreshGolden.KeyID != "example-signing-v1" {
		t.Fatal("private-upload fixture identifiers are not neutral")
	}
	if file.Contract.TransportScope != "application_request_after_authenticated_nhp_1_1_ack" {
		t.Fatalf("transport scope = %q", file.Contract.TransportScope)
	}
}

func TestPrivateUploadV1GoldenSignaturesAreCanonicalLowS(t *testing.T) {
	file, err := PrivateUploadV1()
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := strictRawBase64URL(file.FixtureKey.PrivateKeyPKCS8DERB64URL)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		t.Fatal(err)
	}
	private := parsed.(*ecdsa.PrivateKey)
	for _, test := range []struct {
		name      string
		canonical []byte
		signature string
	}{
		{name: "upload", canonical: mustPrivateUploadV1UploadCanonical(t, file.UploadGolden), signature: file.UploadGolden.SignatureDERB64URL},
		{name: "refresh", canonical: mustPrivateUploadV1RefreshCanonical(t, file.RefreshGolden), signature: file.RefreshGolden.SignatureDERB64URL},
	} {
		t.Run(test.name, func(t *testing.T) {
			if class := privateUploadV1VerifySignature(&private.PublicKey, test.canonical, test.signature); class != "" {
				t.Fatalf("golden signature rejected as %q", class)
			}
			// Prove that the published synthetic private key can drive a real
			// signer. ECDSA is randomized, so consumers verify properties and
			// the public key relationship rather than exact signature bytes.
			digest := sha256.Sum256(test.canonical)
			r, s, err := ecdsa.Sign(rand.Reader, private, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)) > 0 {
				s.Sub(elliptic.P256().Params().N, s)
			}
			der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
			if err != nil {
				t.Fatal(err)
			}
			if class := privateUploadV1VerifySignature(&private.PublicKey, test.canonical, base64.RawURLEncoding.EncodeToString(der)); class != "" {
				t.Fatalf("fresh low-S signature rejected as %q", class)
			}
		})
	}
}

func TestPrivateUploadV1HighSRejectsAreExactTwins(t *testing.T) {
	file, err := PrivateUploadV1()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"reject_upload_high_s_signature":  file.UploadGolden.SignatureDERB64URL,
		"reject_refresh_high_s_signature": file.RefreshGolden.SignatureDERB64URL,
	}
	for _, reject := range file.RejectCases {
		lowEncoded, ok := want[reject.Name]
		if !ok {
			continue
		}
		if len(reject.Mutations) != 1 {
			t.Fatalf("%s mutations = %d, want 1", reject.Name, len(reject.Mutations))
		}
		lowDER, err := strictRawBase64URL(lowEncoded)
		if err != nil {
			t.Fatal(err)
		}
		highDER, err := strictRawBase64URL(reject.Mutations[0].Value)
		if err != nil {
			t.Fatal(err)
		}
		var low, high struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(lowDER, &low); err != nil || len(rest) != 0 {
			t.Fatalf("parse low-S signature: rest=%x err=%v", rest, err)
		}
		if rest, err := asn1.Unmarshal(highDER, &high); err != nil || len(rest) != 0 {
			t.Fatalf("parse high-S signature: rest=%x err=%v", rest, err)
		}
		if low.R.Cmp(high.R) != 0 || new(big.Int).Add(low.S, high.S).Cmp(elliptic.P256().Params().N) != 0 {
			t.Fatalf("%s is not the exact high-S twin", reject.Name)
		}
		delete(want, reject.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing high-S twin rejects: %v", want)
	}
}

func TestPrivateUploadV1PublishedRejectsFailClosed(t *testing.T) {
	file, err := PrivateUploadV1()
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := strictRawBase64URL(file.FixtureKey.PrivateKeyPKCS8DERB64URL)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		t.Fatal(err)
	}
	public := &parsed.(*ecdsa.PrivateKey).PublicKey
	seenClasses := make(map[string]bool)
	for _, reject := range file.RejectCases {
		t.Run(reject.Name, func(t *testing.T) {
			candidate, err := privateUploadV1ApplyReject(file, reject)
			if err != nil {
				t.Fatal(err)
			}
			if class := privateUploadV1RejectClass(file, candidate, public); class != reject.RejectClass {
				t.Fatalf("reject class = %q, want %q", class, reject.RejectClass)
			}
			seenClasses[reject.RejectClass] = true
		})
	}
	for _, class := range file.Contract.RejectClasses {
		if !seenClasses[class] {
			t.Errorf("reject class %q has no executable case", class)
		}
	}
}

func TestPrivateUploadV1RefreshAudienceFieldMutationFailsClosed(t *testing.T) {
	file, err := PrivateUploadV1()
	if err != nil {
		t.Fatal(err)
	}
	_, err = privateUploadV1ApplyReject(file, PrivateUploadV1RejectCase{
		Base: "refresh_golden",
		Mutations: []PrivateUploadV1RejectMutation{{
			Target: "request_field",
			Field:  "audience_key_id",
			Value:  file.UploadGolden.AudienceKeyID,
		}},
	})
	if err == nil {
		t.Fatal("refresh audience field mutation unexpectedly accepted")
	}
}

func TestPrivateUploadV1BodiesAndContentDigestsAreExact(t *testing.T) {
	file, err := PrivateUploadV1()
	if err != nil {
		t.Fatal(err)
	}
	uploadBody, err := hex.DecodeString(file.UploadGolden.BodyHex)
	if err != nil || string(uploadBody) != "hello" {
		t.Fatalf("upload body = %q, err=%v", uploadBody, err)
	}
	refreshBody, err := hex.DecodeString(file.RefreshGolden.BodyHex)
	if err != nil {
		t.Fatal(err)
	}
	wantRefresh := `{"upload_handle":"upl_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","upload_request_id":"123e4567-e89b-42d3-a456-426614174000","max_batch_size":50,"max_link_ttl_seconds":300,"authority_expires_at":"2026-09-06T22:00:00Z"}`
	if string(refreshBody) != wantRefresh {
		t.Fatalf("refresh body = %q", refreshBody)
	}
	if file.UploadGolden.ContentType != file.UploadGolden.MediaType {
		t.Fatalf("upload content type = %q, signed media type = %q", file.UploadGolden.ContentType, file.UploadGolden.MediaType)
	}
	if file.RefreshGolden.UploadHandle != "upl_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ||
		file.RefreshGolden.MaxBatchSizeDecimal != "50" || file.RefreshGolden.MaxLinkTTLSecondsDecimal != "300" ||
		file.RefreshGolden.AuthorityExpiresAt != "2026-09-06T22:00:00Z" {
		t.Fatal("refresh stable request inputs differ from the exact body")
	}
}

func TestParsePrivateUploadV1FileFailsClosed(t *testing.T) {
	raw := PrivateUploadV1Vectors()
	for name, invalid := range map[string][]byte{
		"duplicate key":  bytes.Replace(raw, []byte(`"artifact":`), []byte(`"artifact":"duplicate","artifact":`), 1),
		"unknown field":  bytes.Replace(raw, []byte("{"), []byte(`{"future":true,`), 1),
		"trailing value": append(append([]byte(nil), raw...), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePrivateUploadV1File(invalid); err == nil {
				t.Fatal("invalid artifact unexpectedly accepted")
			}
		})
	}

	mutate := func(t *testing.T, change func(*PrivateUploadV1File)) []byte {
		t.Helper()
		var file PrivateUploadV1File
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
		change func(*PrivateUploadV1File)
	}{
		{name: "NHP version", change: func(file *PrivateUploadV1File) { file.Contract.NHPProtocolVersion = "2.0" }},
		{name: "upload canonical", change: func(file *PrivateUploadV1File) {
			file.UploadGolden.CanonicalHex = strings.Repeat("0", len(file.UploadGolden.CanonicalHex))
		}},
		{name: "upload content type", change: func(file *PrivateUploadV1File) { file.UploadGolden.ContentType = "application/octet-stream" }},
		{name: "refresh body", change: func(file *PrivateUploadV1File) { file.RefreshGolden.BodyHex = "00" }},
		{name: "refresh stable decimal", change: func(file *PrivateUploadV1File) { file.RefreshGolden.MaxBatchSizeDecimal = "9007199254740993" }},
		{name: "refresh upload handle", change: func(file *PrivateUploadV1File) { file.RefreshGolden.UploadHandle = "upl_short" }},
		{name: "missing construction reject", change: func(file *PrivateUploadV1File) { file.ConstructionRejectCases = file.ConstructionRejectCases[1:] }},
		{name: "missing reject", change: func(file *PrivateUploadV1File) { file.RejectCases = file.RejectCases[1:] }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParsePrivateUploadV1File(mutate(t, test.change)); err == nil {
				t.Fatal("mutated artifact unexpectedly accepted")
			}
		})
	}
}

func mustPrivateUploadV1UploadCanonical(t *testing.T, golden PrivateUploadV1UploadGolden) []byte {
	t.Helper()
	canonical, err := PrivateUploadV1UploadCanonicalBytes(golden)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func mustPrivateUploadV1RefreshCanonical(t *testing.T, golden PrivateUploadV1RefreshGolden) []byte {
	t.Helper()
	canonical, err := PrivateUploadV1RefreshCanonicalBytes(golden)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
