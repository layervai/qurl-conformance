package verifysdk

import (
	"encoding/base64"
	"errors"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
	"github.com/layervai/qurl-go/qv2"
	"github.com/layervai/qurl-go/relayknock"
)

func b64d(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func TestSignatureClass(t *testing.T) {
	vf, err := conformance.SignatureVectors()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := qv2.ParseP256PublicKeyDER(b64d(t, vf.Issuer.SPKIDERB64))
	if err != nil {
		t.Fatalf("parse issuer spki: %v", err)
	}
	var acceptClaims string
	var acceptSig []byte
	sawAccept, sawReject := false, false
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			sig := b64d(t, v.SigB64Raw)
			verr := qv2.VerifyRawIssuerSignature(pub, v.ClaimsB64, sig)
			switch v.Expect {
			case conformance.ExpectAccept:
				sawAccept = true
				acceptClaims, acceptSig = v.ClaimsB64, sig
				if verr != nil {
					t.Fatalf("accept must verify: %v", verr)
				}
			case conformance.ExpectReject:
				sawReject = true
				if verr == nil {
					t.Fatal("reject unexpectedly verified")
				}
				switch v.Reason {
				case conformance.RejectClassHighS:
					if !errors.Is(verr, qv2.ErrSignatureHighS) {
						t.Fatalf("want ErrSignatureHighS, got %v", verr)
					}
				case conformance.RejectClassWrongLength:
					if !errors.Is(verr, qv2.ErrSignatureLength) {
						t.Fatalf("want ErrSignatureLength, got %v", verr)
					}
				default:
					if !errors.Is(verr, qv2.ErrSignature) {
						t.Fatalf("want ErrSignature, got %v", verr)
					}
				}
			default:
				t.Fatalf("unknown expect %q", v.Expect)
			}
		})
	}
	if !sawAccept || !sawReject {
		t.Fatalf("signature class must exercise accept and reject (accept=%v reject=%v)", sawAccept, sawReject)
	}
	t.Run("payload_tamper", func(t *testing.T) {
		if acceptSig == nil {
			t.Fatal("no accept vector captured")
		}
		repl := byte('A')
		if acceptClaims[0] == 'A' {
			repl = 'B'
		}
		tampered := string(repl) + acceptClaims[1:]
		verr := qv2.VerifyRawIssuerSignature(pub, tampered, acceptSig)
		if !errors.Is(verr, qv2.ErrSignature) {
			t.Fatalf("tamper must return ErrSignature, got %v", verr)
		}
		if errors.Is(verr, qv2.ErrSignatureHighS) || errors.Is(verr, qv2.ErrSignatureLength) {
			t.Fatalf("tamper must fail at the curve check, got %v", verr)
		}
	})
}

func TestFragmentClass(t *testing.T) {
	cf, err := conformance.ConformanceVectors()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range cf.Classes["fragment"].Vectors {
		t.Run(v.Name, func(t *testing.T) {
			_, perr := qv2.ParseFragment(v.Fragment)
			switch v.Expect {
			case conformance.ExpectAccept:
				if perr != nil {
					t.Fatalf("accept must parse: %v", perr)
				}
			case conformance.ExpectReject:
				if perr == nil {
					t.Fatal("reject unexpectedly parsed")
				}
			}
		})
	}
}

func TestRelayAllowlistClass(t *testing.T) {
	cf, err := conformance.ConformanceVectors()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range cf.Classes["relay_allowlist"].Vectors {
		t.Run(v.Name, func(t *testing.T) {
			rerr := qv2.ValidateRelayURL(v.URL, qv2.NewRelayAllowlist(v.Entries))
			switch v.Expect {
			case conformance.ExpectAccept:
				if rerr != nil {
					t.Fatalf("accept must validate: %v", rerr)
				}
			case conformance.ExpectReject:
				if rerr == nil {
					t.Fatal("reject unexpectedly validated")
				}
			}
		})
	}
}

func TestServerIDClass(t *testing.T) {
	cf, err := conformance.ConformanceVectors()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range cf.Classes["server_id"].Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got := relayknock.PubKeyFingerprint(b64d(t, v.CellPublicKeyB64))
			if got != v.ServerID {
				t.Fatalf("fingerprint mismatch: got %q want %q", got, v.ServerID)
			}
		})
	}
}
