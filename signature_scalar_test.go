package conformance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestIssuerScalarRangeBoundaries(t *testing.T) {
	vf, err := SignatureVectors()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]SignatureVector{}
	for _, v := range vf.Vectors {
		byName[v.Name] = v
	}
	accept, ok := byName["accept_valid_low_s"]
	if !ok {
		t.Fatal("missing accept signature")
	}
	original := decodeRawBase64URL(t, "accept signature", accept.SigB64Raw)
	if len(original) != 64 {
		t.Fatal("accept signature must be 64 bytes")
	}
	order := elliptic.P256().Params().N
	cases := []struct {
		name   string
		offset int
		value  *big.Int
	}{
		{"reject_r_zero", 0, new(big.Int)}, {"reject_r_order", 0, order},
		{"reject_s_zero", 32, new(big.Int)}, {"reject_s_order", 32, order},
	}
	count := 0
	for _, v := range vf.Vectors {
		if v.RejectClass == RejectClassScalarRange {
			count++
		}
	}
	if count != len(cases) {
		t.Fatalf("scalar-range cases=%d, want %d", count, len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := byName[tc.name]
			if !ok {
				t.Fatal("missing boundary vector")
			}
			if v.Expect != ExpectReject || v.RejectClass != RejectClassScalarRange || v.SigEncoding != "raw_r_s" {
				t.Fatalf("unexpected scalar expectation: %+v", v)
			}
			if v.ClaimsB64 != accept.ClaimsB64 || v.SigningInputB64 != accept.SigningInputB64 {
				t.Fatal("boundary changed the signing input")
			}
			want := append([]byte(nil), original...)
			tc.value.FillBytes(want[tc.offset : tc.offset+32])
			got := decodeRawBase64URL(t, tc.name, v.SigB64Raw)
			if !bytes.Equal(got, want) {
				t.Fatal("boundary must replace exactly one scalar")
			}
			input := decodeRawBase64URL(t, "signing input", v.SigningInputB64)
			digest := sha256.Sum256(input)
			if ecdsa.Verify(fixedVectorP256PublicKey(t, 0x07), digest[:], new(big.Int).SetBytes(got[:32]), new(big.Int).SetBytes(got[32:])) {
				t.Fatal("out-of-range signature accepted")
			}
		})
	}
}
