package conformance

import (
	"sort"
	"testing"
)

// wantClasses is the closed set of conformance classes the artifact must carry.
var wantClasses = []string{
	"claims_parse",
	"secret_parse",
	"strict_base64",
	"fragment",
	"relay_allowlist",
	"server_id",
}

func TestEmbeddedConformanceFileLoads(t *testing.T) {
	cf, err := ConformanceVectors()
	if err != nil {
		t.Fatalf("ConformanceVectors(): %v", err)
	}

	if cf.Artifact != ConformanceArtifactID {
		t.Errorf("artifact = %q, want %q", cf.Artifact, ConformanceArtifactID)
	}
	if cf.SchemaVersion == 0 {
		t.Errorf("schema_version = 0, want non-zero")
	}

	// All six classes must be present.
	if got, want := len(cf.Classes), len(wantClasses); got != want {
		got := classNames(cf)
		t.Errorf("class count = %d, want %d; got classes %v", len(cf.Classes), want, got)
	}
	for _, name := range wantClasses {
		class, ok := cf.Classes[name]
		if !ok {
			t.Errorf("missing class %q", name)
			continue
		}
		if len(class.Vectors) == 0 {
			t.Errorf("class %q has no vectors", name)
		}
		if class.EntryPoint == "" {
			t.Errorf("class %q has empty entry_point", name)
		}
		if class.Input == "" {
			t.Errorf("class %q has empty input", name)
		}
	}
}

func TestEmbeddedSignatureClassWellFormed(t *testing.T) {
	cf, err := ConformanceVectors()
	if err != nil {
		t.Fatalf("ConformanceVectors(): %v", err)
	}

	sc := cf.SignatureClass
	if sc.EntryPoint == "" {
		t.Errorf("signature_class.entry_point is empty")
	}
	if sc.Composes == "" {
		t.Errorf("signature_class.composes is empty")
	}

	td := sc.TamperDerivation
	if td == nil {
		t.Fatalf("signature_class.tamper_derivation is missing")
	}
	if td.RejectClass != RejectClassTamper {
		t.Errorf("tamper_derivation.reject_class = %q, want %q", td.RejectClass, RejectClassTamper)
	}
	if td.DeriveFrom != TamperDeriveFromAccept {
		t.Errorf("tamper_derivation.derive_from = %q, want %q", td.DeriveFrom, TamperDeriveFromAccept)
	}
	if td.ClaimsTransform != TamperTransformFlipFirstB64 {
		t.Errorf("tamper_derivation.claims_transform = %q, want %q", td.ClaimsTransform, TamperTransformFlipFirstB64)
	}
}

func TestEmbeddedSignatureFileLoads(t *testing.T) {
	vf, err := SignatureVectors()
	if err != nil {
		t.Fatalf("SignatureVectors(): %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatalf("signature vector file has no vectors")
	}
	if vf.Issuer.SPKIDERB64 == "" {
		t.Errorf("issuer.spki_der_b64 is empty")
	}
	if vf.Issuer.JWK.Crv == "" {
		t.Errorf("issuer.jwk.crv is empty")
	}

	var sawAccept bool
	for _, v := range vf.Vectors {
		switch v.Expect {
		case ExpectAccept:
			sawAccept = true
			if v.RejectClass != "" {
				t.Errorf("accept signature vector %q has reject_class %q, want empty", v.Name, v.RejectClass)
			}
		case ExpectReject:
			switch v.RejectClass {
			case RejectClassHighS, RejectClassWrongLength:
			default:
				t.Errorf("reject signature vector %q has reject_class %q, want %q or %q", v.Name, v.RejectClass, RejectClassHighS, RejectClassWrongLength)
			}
		default:
			t.Errorf("vector %q has expect %q, want accept|reject", v.Name, v.Expect)
		}
		if v.ClaimsB64 == "" {
			t.Errorf("vector %q has empty claims_b64", v.Name)
		}
		if v.SigB64Raw == "" {
			t.Errorf("vector %q has empty sig_b64", v.Name)
		}
	}
	if !sawAccept {
		t.Errorf("signature vector file has no accept vector (tamper derivation needs one)")
	}
}

func TestEmbeddedRelayKnockLoads(t *testing.T) {
	rf, err := RelayKnockGolden()
	if err != nil {
		t.Fatalf("RelayKnockGolden(): %v", err)
	}
	if rf.Artifact != RelayKnockArtifactID {
		t.Errorf("artifact = %q, want %q", rf.Artifact, RelayKnockArtifactID)
	}
	if rf.SchemaVersion == 0 {
		t.Errorf("schema_version = 0, want non-zero")
	}
	if rf.Knock.PacketHex == "" {
		t.Errorf("knock.packet_hex is empty")
	}
	if rf.Ack.PacketHex == "" {
		t.Errorf("ack.packet_hex is empty")
	}
}

func TestOpenKnownAndUnknown(t *testing.T) {
	for _, name := range []string{
		"qv2_conformance_vectors.json",
		"vectors/qv2_conformance_vectors.json",
		"issuer_signature_vectors.json",
		"vectors/issuer_signature_vectors.json",
		"relay_knock_golden.json",
		"vectors/relay_knock_golden.json",
	} {
		b, err := Open(name)
		if err != nil {
			t.Errorf("Open(%q): %v", name, err)
		}
		if len(b) == 0 {
			t.Errorf("Open(%q): empty bytes", name)
		}
	}
	if _, err := Open("does_not_exist.json"); err == nil {
		t.Errorf("Open(unknown): want error, got nil")
	}
}

func classNames(cf *ConformanceFile) []string {
	names := make([]string, 0, len(cf.Classes))
	for k := range cf.Classes {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
