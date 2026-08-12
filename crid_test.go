package conformance

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"strings"
	"testing"
)

func TestEmbeddedCRIDV1Loads(t *testing.T) {
	cf, err := CRIDV1()
	if err != nil {
		t.Fatalf("CRIDV1(): %v", err)
	}
	if cf.Artifact != CRIDV1ArtifactID || cf.SchemaVersion != CRIDV1SchemaVersion {
		t.Fatalf("identity = %q/v%d, want %q/v%d", cf.Artifact, cf.SchemaVersion, CRIDV1ArtifactID, CRIDV1SchemaVersion)
	}
	if cf.Contract.Alphabet != CRIDV1Alphabet || cf.Contract.FullCRIDLength != CRIDV1FullCRIDLength || cf.Contract.TruncatedCRIDLength != CRIDV1TruncatedCRIDLength {
		t.Fatalf("contract = %+v", cf.Contract)
	}
	if len(cf.Versions) != 4 || len(cf.ProducerCases) != 6 || len(cf.ConsumerValueCases) != 16 || len(cf.VersionCases) != 4 || len(cf.KeyMatchCases) != 4 {
		t.Fatalf("fixture counts = versions:%d producer:%d values:%d versions-cases:%d key-match:%d",
			len(cf.Versions), len(cf.ProducerCases), len(cf.ConsumerValueCases), len(cf.VersionCases), len(cf.KeyMatchCases))
	}

	for _, c := range cf.ProducerCases {
		fixture := cridV1ProducerFixtures[c.Name]
		der, err := base64.RawURLEncoding.Strict().DecodeString(c.DERSPKIB64URL)
		if err != nil {
			t.Fatalf("producer %q der: %v", c.Name, err)
		}
		digestLength, ok := cridV1RegistryDigestLength(fixture.version)
		if !ok {
			t.Fatalf("producer %q uses unregistered version %#02x", c.Name, fixture.version)
		}
		digest, encoded, crc, crid := deriveCRIDV1(fixture.version, der, digestLength)
		if hex.EncodeToString(digest[:]) != c.DigestHex || hex.EncodeToString(encoded) != c.PayloadHex || hex.EncodeToString(crc) != c.CRCHex || crid != c.ExpectedCRID {
			t.Errorf("producer %q does not re-derive: crid %q want %q", c.Name, crid, c.ExpectedCRID)
		}
		wantFirst := byte('a')
		if c.Environment == CRIDV1EnvironmentTest {
			wantFirst = 'q'
		}
		if len(c.ExpectedCRID) != CRIDV1FullCRIDLength || c.ExpectedCRID[0] != wantFirst {
			t.Errorf("producer %q CRID %q violates the %s first-char property", c.Name, c.ExpectedCRID, c.Environment)
		}
		if last := c.ExpectedCRID[len(c.ExpectedCRID)-1]; last != 'a' && last != 'q' {
			t.Errorf("producer %q CRID final char %q is not a zero-pad character", c.Name, last)
		}
	}
	for _, c := range cf.ConsumerValueCases {
		outcome, rejectClass := deriveCRIDV1ValueExpectation(c.Value)
		if outcome != c.Outcome || rejectClass != c.RejectClass {
			t.Errorf("value %q derived expectation = %q/%q, want %q/%q", c.Name, outcome, rejectClass, c.Outcome, c.RejectClass)
		}
	}
	for _, c := range cf.VersionCases {
		versionHex, known, environment, digestLength, err := deriveCRIDV1VersionExpectation(c.Value)
		if err != nil {
			t.Errorf("version case %q: %v", c.Name, err)
			continue
		}
		if versionHex != c.VersionHex || known != c.Known || environment != c.Environment || digestLength != c.DigestLength {
			t.Errorf("version case %q derived = %q/%t/%q/%d, want %q/%t/%q/%d",
				c.Name, versionHex, known, environment, digestLength, c.VersionHex, c.Known, c.Environment, c.DigestLength)
		}
	}
	for _, c := range cf.KeyMatchCases {
		outcome, err := deriveCRIDV1KeyMatchExpectation(c.CRID, c.DERSPKIB64URL)
		if err != nil {
			t.Errorf("key-match %q: %v", c.Name, err)
			continue
		}
		if outcome != c.Outcome {
			t.Errorf("key-match %q derived outcome = %q, want %q", c.Name, outcome, c.Outcome)
		}
	}
}

// TestCRIDV1ChecksumPolynomialIsCastagnoli ties the artifact's normal-form
// polynomial to the reversed-form table constant the reference derivation
// actually uses, so neither can drift alone.
func TestCRIDV1ChecksumPolynomialIsCastagnoli(t *testing.T) {
	decoded, err := hex.DecodeString(CRIDV1ChecksumPolynomialHex)
	if err != nil || len(decoded) != 4 {
		t.Fatalf("polynomial hex %q: %v", CRIDV1ChecksumPolynomialHex, err)
	}
	normal := binary.BigEndian.Uint32(decoded)
	var reversed uint32
	for i := 0; i < 32; i++ {
		if normal&(1<<i) != 0 {
			reversed |= 1 << (31 - i)
		}
	}
	if reversed != crc32.Castagnoli {
		t.Fatalf("bit-reversed polynomial = %#08x, want crc32.Castagnoli %#08x", reversed, uint32(crc32.Castagnoli))
	}
}

func TestCRIDV1TruncatedFixtureShape(t *testing.T) {
	value := cridV1ValueFixtures["accept_unknown_version_truncated"]
	if len(value) != CRIDV1TruncatedCRIDLength {
		t.Fatalf("truncated fixture length = %d, want %d", len(value), CRIDV1TruncatedCRIDLength)
	}
	switch last := value[len(value)-1]; last {
	case 'a', 'i', 'q', 'y':
	default:
		t.Fatalf("truncated fixture final char %q is not a zero-pad character", last)
	}
}

func TestParseCRIDV1FileFailsClosed(t *testing.T) {
	raw := CRIDV1Vectors()
	mutate := func(t *testing.T, change func(*CRIDV1File)) []byte {
		t.Helper()
		var cf CRIDV1File
		if err := json.Unmarshal(raw, &cf); err != nil {
			t.Fatal(err)
		}
		change(&cf)
		b, err := json.Marshal(cf)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	assertRejects := func(t *testing.T, body []byte, contains string) {
		t.Helper()
		if _, err := ParseCRIDV1File(body); err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("error = %v, want text %q", err, contains)
		}
	}
	producerCase := func(t *testing.T, cf *CRIDV1File, name string) *CRIDV1ProducerCase {
		t.Helper()
		for i := range cf.ProducerCases {
			if cf.ProducerCases[i].Name == name {
				return &cf.ProducerCases[i]
			}
		}
		t.Fatalf("missing producer case %q", name)
		return nil
	}
	valueCase := func(t *testing.T, cf *CRIDV1File, name string) *CRIDV1ValueCase {
		t.Helper()
		for i := range cf.ConsumerValueCases {
			if cf.ConsumerValueCases[i].Name == name {
				return &cf.ConsumerValueCases[i]
			}
		}
		t.Fatalf("missing consumer value case %q", name)
		return nil
	}
	versionCase := func(t *testing.T, cf *CRIDV1File, name string) *CRIDV1VersionCase {
		t.Helper()
		for i := range cf.VersionCases {
			if cf.VersionCases[i].Name == name {
				return &cf.VersionCases[i]
			}
		}
		t.Fatalf("missing version case %q", name)
		return nil
	}
	keyMatchCase := func(t *testing.T, cf *CRIDV1File, name string) *CRIDV1KeyMatchCase {
		t.Helper()
		for i := range cf.KeyMatchCases {
			if cf.KeyMatchCases[i].Name == name {
				return &cf.KeyMatchCases[i]
			}
		}
		t.Fatalf("missing key-match case %q", name)
		return nil
	}
	flipHex := func(s string) string {
		if s[0] == 'f' {
			return "0" + s[1:]
		}
		return "f" + s[1:]
	}
	flipCRID := func(s string) string {
		if s[0] == 'a' {
			return "b" + s[1:]
		}
		return "a" + s[1:]
	}

	t.Run("artifact", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.Artifact = "other" }), "artifact")
	})
	t.Run("schema", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.SchemaVersion++ }), "schema_version")
	})
	t.Run("description", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.Description = "" }), "description")
	})
	t.Run("contract alphabet", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.Contract.Alphabet = strings.ToUpper(cf.Contract.Alphabet) }), "contract")
	})
	t.Run("contract checksum polynomial", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.Contract.ChecksumPolynomialHex = "04c11db7" }), "contract")
	})
	t.Run("contract full crid length", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.Contract.FullCRIDLength = 59 }), "contract")
	})
	t.Run("contract domain separator", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.Contract.DomainSeparatorHex = "01" }), "contract")
	})
	t.Run("registry environment", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.Versions[0].Environment = CRIDV1EnvironmentTest }), "version registry")
	})
	t.Run("registry status", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.Versions[2].Status = CRIDV1StatusActive }), "version registry")
	})
	t.Run("registry order", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.Versions[0], cf.Versions[1] = cf.Versions[1], cf.Versions[0] }), "version registry")
	})
	t.Run("producer digest", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			c := producerCase(t, cf, "resource_key_qv2_v01")
			c.DigestHex = flipHex(c.DigestHex)
		}), "digest_hex")
	})
	t.Run("producer payload", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			c := producerCase(t, cf, "resource_key_qv2_v81")
			c.PayloadHex = flipHex(c.PayloadHex)
		}), "payload_hex")
	})
	t.Run("producer crc", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			c := producerCase(t, cf, "resource_key_issuer_v01")
			c.CRCHex = flipHex(c.CRCHex)
		}), "crc_hex")
	})
	t.Run("producer expected crid", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			c := producerCase(t, cf, "resource_key_issuer_v81")
			c.ExpectedCRID = flipCRID(c.ExpectedCRID)
		}), "expected_crid")
	})
	t.Run("producer version byte", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			producerCase(t, cf, "resource_key_fresh_v01").VersionByte = "02"
		}), "version_byte")
	})
	t.Run("producer environment", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			producerCase(t, cf, "resource_key_fresh_v81").Environment = CRIDV1EnvironmentProduction
		}), "environment")
	})
	t.Run("producer der", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			c := producerCase(t, cf, "resource_key_qv2_v01")
			c.DERSPKIB64URL = "A" + c.DERSPKIB64URL[1:]
		}), "der_spki_b64url")
	})
	t.Run("value", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			c := valueCase(t, cf, "accept_prod_canonical")
			c.Value = flipCRID(c.Value)
		}), "consumer value case")
	})
	t.Run("value outcome", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			c := valueCase(t, cf, "accept_test_canonical")
			c.Outcome = ExpectReject
		}), "expectation")
	})
	t.Run("value reject class", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			c := valueCase(t, cf, "reject_checksum")
			c.RejectClass = CRIDV1RejectCharset
		}), "expectation")
	})
	t.Run("version case value", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			c := versionCase(t, cf, "prod_full")
			c.Value = flipCRID(c.Value)
		}), "version case")
	})
	t.Run("version case hex", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			versionCase(t, cf, "prod_full").VersionHex = "81"
		}), "expectation")
	})
	t.Run("version case known", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			versionCase(t, cf, "unknown_full").Known = true
		}), "expectation")
	})
	t.Run("version case environment", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			versionCase(t, cf, "test_full").Environment = CRIDV1EnvironmentProduction
		}), "expectation")
	})
	t.Run("version case digest length", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			versionCase(t, cf, "unknown_truncated").DigestLength = CRIDV1FullDigestLength
		}), "expectation")
	})
	t.Run("key match crid", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			c := keyMatchCase(t, cf, "match_production")
			c.CRID = flipCRID(c.CRID)
		}), "key-match")
	})
	t.Run("key match der", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			keyMatchCase(t, cf, "match_test").DERSPKIB64URL = cridV1ResourceKeyIssuerB64URL
		}), "key-match")
	})
	t.Run("key match outcome", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) {
			keyMatchCase(t, cf, "mismatch_wrong_key").Outcome = CRIDV1OutcomeMatch
		}), "expectation")
	})
	t.Run("duplicate producer case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.ProducerCases[1] = cf.ProducerCases[0] }), "duplicate")
	})
	t.Run("unknown value case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.ConsumerValueCases[0].Name = "future_case" }), "unknown")
	})
	t.Run("missing value case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.ConsumerValueCases = cf.ConsumerValueCases[1:] }), "count")
	})
	t.Run("missing key match case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(cf *CRIDV1File) { cf.KeyMatchCases = cf.KeyMatchCases[:len(cf.KeyMatchCases)-1] }), "count")
	})
}

// TestDeriveCRIDV1UnknownVersionFixturesReDerive ties the two unknown-version
// crafted fixtures back to the reference derivation inside the repo: both were
// derived from the resource_key_qv2 DER at version 0x7f — the truncated one at
// the 24-byte digest width — so the otherwise-unexercised truncated derivation
// branch is pinned against a committed golden rather than only re-checked by
// the local gate.
func TestDeriveCRIDV1UnknownVersionFixturesReDerive(t *testing.T) {
	der, err := base64.RawURLEncoding.Strict().DecodeString(cridV1ResourceKeyQV2B64URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		digestLength int
		want         string
	}{
		{name: "full", digestLength: CRIDV1FullDigestLength, want: cridV1UnknownVersionFullCRID},
		{name: "truncated", digestLength: CRIDV1TruncatedDigestLength, want: cridV1UnknownVersionTruncCRID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, crid := deriveCRIDV1(0x7f, der, tc.digestLength)
			if crid != tc.want {
				t.Fatalf("deriveCRIDV1(0x7f, qv2, %d) = %q, want the pinned fixture %q", tc.digestLength, crid, tc.want)
			}
			if outcome, rejectClass := deriveCRIDV1ValueExpectation(crid); outcome != ExpectAccept || rejectClass != "" {
				t.Fatalf("re-derived fixture fails its own local gate: %q/%q", outcome, rejectClass)
			}
		})
	}
}
