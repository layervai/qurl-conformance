package conformance

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

func TestEmbeddedCRIDLinkKnockV1Loads(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatalf("CRIDLinkKnockV1(): %v", err)
	}
	if lf.Artifact != CRIDLinkKnockV1ArtifactID || lf.SchemaVersion != CRIDLinkKnockV1SchemaVersion {
		t.Fatalf("identity = %q/v%d, want %q/v%d", lf.Artifact, lf.SchemaVersion, CRIDLinkKnockV1ArtifactID, CRIDLinkKnockV1SchemaVersion)
	}
	if len(lf.ErrorCodes) != 7 || len(lf.ClientResults) != 9 || len(lf.RejectClasses) != 7 {
		t.Fatalf("vocabulary counts = codes:%d results:%d classes:%d", len(lf.ErrorCodes), len(lf.ClientResults), len(lf.RejectClasses))
	}
	if len(lf.RequestCases) != 6 || len(lf.InvalidRequestCases) != 4 || len(lf.ACKCases) != 15 ||
		len(lf.ClientVerificationCases) != 18 || len(lf.RedirectInfoSanitizationCases) != 16 {
		t.Fatalf("fixture counts = requests:%d invalid:%d acks:%d verification:%d sanitization:%d",
			len(lf.RequestCases), len(lf.InvalidRequestCases), len(lf.ACKCases),
			len(lf.ClientVerificationCases), len(lf.RedirectInfoSanitizationCases))
	}

	// The retry contract, stated once more against the committed table.
	for code, wantRetry := range map[string]bool{
		"52600": false, "52601": true, "52602": false, "52603": true, "52604": true, "52605": false, "52606": false,
	} {
		if got, ok := lf.ErrorCodes[code]; !ok || got.Retryable != wantRetry {
			t.Errorf("error code %s retryable = %t (present %t), want %t", code, got.Retryable, ok, wantRetry)
		}
	}

	for _, c := range lf.RequestCases {
		var body, serialized any
		if err := json.Unmarshal(c.Body, &body); err != nil {
			t.Fatalf("request %q body: %v", c.Name, err)
		}
		if err := json.Unmarshal([]byte(c.Serialized), &serialized); err != nil {
			t.Fatalf("request %q serialized: %v", c.Name, err)
		}
		if !reflect.DeepEqual(body, serialized) {
			t.Errorf("request %q serialized does not decode to its body", c.Name)
		}
		if strings.ContainsAny(c.Serialized, "\n\t") || strings.Contains(c.Serialized, `": `) || strings.Contains(c.Serialized, `, "`) {
			t.Errorf("request %q serialized is not compact", c.Name)
		}
		usrData := body.(map[string]any)["usrData"].(map[string]any)
		for _, forbidden := range lf.Constants.ForbiddenUserDataKeys {
			if _, present := usrData[forbidden]; present {
				t.Errorf("request %q carries forbidden user data key %q", c.Name, forbidden)
			}
		}
		sent, hasUserAgent := usrData[lf.Constants.UserDataKeys.UserAgent].(string)
		if hasUserAgent != (c.Input.UserAgent != nil) {
			t.Errorf("request %q user agent presence = %t, input presence = %t", c.Name, hasUserAgent, c.Input.UserAgent != nil)
			continue
		}
		if !hasUserAgent {
			continue
		}
		input := *c.Input.UserAgent
		if len(sent) > lf.Constants.UserAgentMaxBytes || !utf8.ValidString(sent) || !strings.HasPrefix(input, sent) {
			t.Errorf("request %q sends %d bytes that are over the limit, invalid UTF-8, or not a prefix of the input", c.Name, len(sent))
		}
		if rest := input[len(sent):]; rest != "" {
			// Truncation must be maximal: the next whole character does not fit.
			_, size := utf8.DecodeRuneInString(rest)
			if len(sent)+size <= lf.Constants.UserAgentMaxBytes {
				t.Errorf("request %q drops a character that still fits", c.Name)
			}
		}
	}
	requests := make(map[string]CRIDLinkKnockV1RequestCase, len(lf.RequestCases))
	for _, c := range lf.RequestCases {
		requests[c.Name] = c
	}
	sentUserAgent := func(name string) string {
		t.Helper()
		var body cridLinkKnockV1WireRequest
		if err := json.Unmarshal(requests[name].Body, &body); err != nil {
			t.Fatalf("request %q body: %v", name, err)
		}
		return body.UserData.UserAgent
	}
	if got := sentUserAgent("user_agent_at_limit"); len(got) != 256 || got != *requests["user_agent_at_limit"].Input.UserAgent || utf8.RuneCountInString(got) == len(got) {
		t.Errorf("user_agent_at_limit must send its multi-byte 256-byte input unchanged, sent %d bytes", len(got))
	}
	if input, got := *requests["user_agent_truncated"].Input.UserAgent, sentUserAgent("user_agent_truncated"); len(input) != 300 || len(got) != 256 {
		t.Errorf("user_agent_truncated = %d input bytes, %d sent bytes, want 300 and 256", len(input), len(got))
	}
	boundary := *requests["user_agent_truncated_at_code_point_boundary"].Input.UserAgent
	if got := sentUserAgent("user_agent_truncated_at_code_point_boundary"); len(boundary) != 258 || utf8.RuneStart(boundary[256]) ||
		len(utf16.Encode([]rune(boundary))) != 256 || len(got) != 253 {
		t.Errorf("boundary user agent = %d bytes, %d UTF-16 units, %d sent bytes; want a straddled character at byte 256 and 253 sent bytes",
			len(boundary), len(utf16.Encode([]rune(boundary))), len(got))
	}

	for _, c := range lf.ACKCases {
		isLink := c.Expected.ClientResult == CRIDLinkKnockV1ResultLink
		if isLink != (c.Expected.Link != "") || isLink != (c.Expected.Info != nil) {
			t.Errorf("ACK case %q: only a link result carries a link and info", c.Name)
		}
		if isLink && c.Expected.Link != lf.Fixtures.Link {
			t.Errorf("ACK case %q link is not the fixture link", c.Name)
		}
	}
	for _, c := range lf.RedirectInfoSanitizationCases {
		if c.Expected.Publisher.Verified {
			t.Errorf("sanitization case %q reports a verified publisher; no v1 reply does", c.Name)
		}
	}
	sanitized := make(map[string]CRIDLinkKnockV1LinkInfo, len(lf.RedirectInfoSanitizationCases))
	for _, c := range lf.RedirectInfoSanitizationCases {
		sanitized[c.Name] = c.Expected
	}
	atLimit := sanitized["publisher_name_at_limit"].Publisher.Name
	if utf8.RuneCountInString(atLimit) != 128 || len(atLimit) <= 128 || len(utf16.Encode([]rune(atLimit))) <= 128 {
		t.Errorf("publisher_name_at_limit must keep 128 code points that exceed 128 bytes and 128 UTF-16 units, got %d/%d/%d",
			utf8.RuneCountInString(atLimit), len(atLimit), len(utf16.Encode([]rune(atLimit))))
	}
	if sanitized["publisher_name_over_limit"].Publisher.Name != "" {
		t.Error("publisher_name_over_limit must drop the name rather than shorten it")
	}
}

// TestCRIDLinkKnockV1VocabulariesAreExercised keeps every closed vocabulary
// honest: an outcome code, client result or reject class that no case
// exercises would be a promise the artifact does not test.
func TestCRIDLinkKnockV1VocabulariesAreExercised(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	codes := make(map[string]bool, len(lf.ACKCases))
	results := make(map[string]bool, len(lf.ACKCases))
	for _, c := range lf.ACKCases {
		var body struct {
			Code string `json:"errCode"`
		}
		if err := json.Unmarshal(c.Body, &body); err != nil {
			t.Fatalf("ACK case %q body: %v", c.Name, err)
		}
		codes[body.Code] = true
		results[c.Expected.ClientResult] = true
	}
	for code, entry := range lf.ErrorCodes {
		if !codes[code] {
			t.Errorf("error code %s has no ACK case", code)
		}
		if !slices.Contains(lf.ClientResults, entry.ClientResult) {
			t.Errorf("error code %s maps to %q, which is not a client result", code, entry.ClientResult)
		}
	}
	for _, result := range lf.ClientResults {
		if !results[result] {
			t.Errorf("client result %q has no ACK case", result)
		}
	}
	classes := make(map[string]bool, len(lf.ClientVerificationCases))
	accepts := 0
	for _, c := range lf.ClientVerificationCases {
		if c.Outcome == ExpectAccept {
			accepts++
			continue
		}
		classes[c.RejectClass] = true
	}
	for _, class := range lf.RejectClasses {
		if !classes[class] {
			t.Errorf("reject class %q has no verification case", class)
		}
	}
	if accepts == 0 {
		t.Error("the verification suite has no accept case to flip against")
	}
	cridClasses := make(map[string]bool, len(lf.InvalidRequestCases))
	for _, c := range lf.InvalidRequestCases {
		cridClasses[c.CRIDRejectClass] = true
	}
	for _, class := range []string{CRIDV1RejectChecksum, CRIDV1RejectLength, CRIDV1RejectCharset} {
		if !cridClasses[class] {
			t.Errorf("no refused request exercises the CRID v1 %q class", class)
		}
	}
}

// TestCRIDLinkKnockV1FixtureLinkIsThePublishedVectorLink re-derives the
// fixture identities from the fixed public vector scalars instead of from the
// link's own claims, so the family cannot drift onto a link or a CRID that
// merely agrees with itself.
func TestCRIDLinkKnockV1FixtureLinkIsThePublishedVectorLink(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	qv2, err := ConformanceVectors()
	if err != nil {
		t.Fatal(err)
	}
	var published ConformanceVector
	for _, vector := range qv2.Classes["transport"].Vectors {
		if vector.Name == "accept_valid_qv2_round_trip" {
			published = vector
		}
	}
	if published.TransportFragment == "" || lf.Fixtures.Link != lf.Constants.LinkOrigin+"/#"+published.TransportFragment {
		t.Fatal("fixture link is not the link origin plus the published qv2t1 accept fragment")
	}

	resourceDER, err := x509.MarshalPKIXPublicKey(fixedVectorP256PublicKey(t, 0x08))
	if err != nil {
		t.Fatal(err)
	}
	if lf.Fixtures.ResourcePublicKeyB64 != base64.RawURLEncoding.EncodeToString(resourceDER) {
		t.Fatal("fixture resource key is not the fixed 0x08 vector key")
	}
	for version, want := range map[byte]string{0x01: lf.Fixtures.CRID, 0x81: lf.Fixtures.TestEnvironmentCRID} {
		if _, _, _, got := deriveCRIDV1(version, resourceDER, CRIDV1FullDigestLength); got != want {
			t.Errorf("CRID for version %#02x = %q, want fixture %q", version, got, want)
		}
	}

	env, err := loadCRIDLinkKnockV1Environment()
	if err != nil {
		t.Fatal(err)
	}
	issuer := fixedVectorP256PublicKey(t, 0x07)
	if env.issuerPublic.X.Cmp(issuer.X) != 0 || env.issuerPublic.Y.Cmp(issuer.Y) != 0 {
		t.Fatal("composed trust anchor is not the fixed 0x07 vector issuer key")
	}

	// The unrelated CRID is a published CRID of a different published key.
	crids, err := CRIDV1()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range crids.ProducerCases {
		found = found || c.ExpectedCRID == lf.Fixtures.UnrelatedCRID
	}
	if !found {
		t.Fatal("unrelated CRID is not one of the published CRID v1 producer goldens")
	}
}

// failingLinkChecks evaluates every client verification check on its own
// wherever its input exists, instead of stopping at the first failure. The
// reference verifier and this helper must name the same single class, which
// is what makes a declared reject_class independent of check order.
func failingLinkChecks(t *testing.T, env *cridLinkKnockV1Environment, requestedCRID string, body json.RawMessage) []string {
	t.Helper()
	ack, ok := cridLinkKnockV1JSONObject(body)
	if !ok {
		t.Fatal("body is not an object")
	}
	var failing []string
	if !cridLinkKnockV1InfoCRIDMatches(requestedCRID, ack) {
		failing = append(failing, CRIDLinkKnockV1RejectInfoCRIDMismatch)
	}
	redirect, ok := cridLinkKnockV1JSONString(ack["redirectUrl"])
	if !ok || redirect == "" {
		return append(failing, CRIDLinkKnockV1RejectMissingRedirect)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("no fixture carries an unparseable URL: %v", err)
	}
	if parsed.User != nil || parsed.Scheme != "https" || parsed.Host != "qurl.link" {
		failing = append(failing, CRIDLinkKnockV1RejectOrigin)
	}
	if strings.Trim(parsed.Path, "/") != "" || parsed.RawQuery != "" {
		failing = append(failing, CRIDLinkKnockV1RejectPathOrQuery)
	}
	canonical, err := decodeConformanceTransport(env.transportContract, parsed.EscapedFragment())
	if err != nil {
		return append(failing, CRIDLinkKnockV1RejectTransport)
	}
	parts := strings.Split(canonical, ".")
	if !env.verifyIssuerSignature(parts[1], parts[3]) {
		failing = append(failing, CRIDLinkKnockV1RejectIssuerSignature)
	}
	// Read the claims without trusting them, purely to learn whether the CRID
	// check would also have failed.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims cridLinkKnockV1LinkClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if outcome, err := CRIDV1KeyMatchExpectation(requestedCRID, claims.ResourcePublicKeyB64); err != nil || outcome != CRIDV1OutcomeMatch {
		failing = append(failing, CRIDLinkKnockV1RejectCRIDMismatch)
	}
	return failing
}

func TestCRIDLinkKnockV1VerificationCasesIsolateOneFault(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	env, err := loadCRIDLinkKnockV1Environment()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range lf.ClientVerificationCases {
		var want []string
		if c.Outcome == ExpectReject {
			want = []string{c.RejectClass}
		}
		if got := failingLinkChecks(t, env, c.RequestedCRID, c.Body); !slices.Equal(got, want) {
			t.Errorf("verification case %q fails checks %v, want exactly %v", c.Name, got, want)
		}
	}
	// A link-issued ACK case is a full interpreter positive: it passes every
	// check too.
	for _, c := range lf.ACKCases {
		if c.Expected.ClientResult != CRIDLinkKnockV1ResultLink {
			continue
		}
		if got := failingLinkChecks(t, env, c.RequestedCRID, c.Body); len(got) != 0 {
			t.Errorf("ACK case %q fails checks %v", c.Name, got)
		}
	}
}

// TestCRIDLinkKnockV1TamperedSignatureStaysWellFormed pins why the tampered
// link is an issuer_signature reject and nothing weaker: its signature is
// still canonical base64url, 64 bytes, in range and low-S, so only the curve
// check can refuse it.
func TestCRIDLinkKnockV1TamperedSignatureStaysWellFormed(t *testing.T) {
	env, err := loadCRIDLinkKnockV1Environment()
	if err != nil {
		t.Fatal(err)
	}
	tampered := env.tamperedTransport()
	if tampered == env.transport || len(tampered) != len(env.transport) {
		t.Fatal("tampered transport is not a same-length variant of the published one")
	}
	canonical, err := decodeConformanceTransport(env.transportContract, tampered)
	if err != nil {
		t.Fatalf("tampered transport must still be valid framing: %v", err)
	}
	original := strings.Split(env.canonical, ".")
	parts := strings.Split(canonical, ".")
	if parts[1] != original[1] || parts[2] != original[2] || parts[3] == original[3] {
		t.Fatal("tampering must change the signature component only")
	}
	signature, err := strictRawBase64URL(parts[3])
	if err != nil || len(signature) != 64 {
		t.Fatalf("tampered signature is not canonical 64-byte base64url: %v", err)
	}
	publishedSignature, err := strictRawBase64URL(original[3])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signature[32:], publishedSignature[32:]) || bytes.Equal(signature[:32], publishedSignature[:32]) {
		t.Fatal("tampering must change r and leave the low-S s untouched")
	}
	if env.verifyIssuerSignature(parts[1], parts[3]) {
		t.Fatal("tampered signature verified")
	}
	if !env.verifyIssuerSignature(original[1], original[3]) {
		t.Fatal("published signature no longer verifies")
	}
}

func TestCRIDLinkKnockV1TruncateUserAgent(t *testing.T) {
	limit := CRIDLinkKnockV1UserAgentMaxBytes
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"short", "agent/1.0", "agent/1.0"},
		{"exact ascii", strings.Repeat("a", limit), strings.Repeat("a", limit)},
		{"one over ascii", strings.Repeat("a", limit+1), strings.Repeat("a", limit)},
		{"two-byte character ends at the limit", strings.Repeat("a", limit-2) + "é", strings.Repeat("a", limit-2) + "é"},
		{"two-byte character straddles the limit", strings.Repeat("a", limit-1) + "é", strings.Repeat("a", limit-1)},
		{"three-byte character straddles the limit", strings.Repeat("a", limit-1) + "€x", strings.Repeat("a", limit-1)},
		{"four-byte character straddles by one byte", strings.Repeat("a", limit-3) + "\U0001F600", strings.Repeat("a", limit-3)},
		{"four-byte character fits exactly", strings.Repeat("a", limit-4) + "\U0001F600x", strings.Repeat("a", limit-4) + "\U0001F600"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cridLinkKnockV1TruncateUserAgent(tc.input)
			if got != tc.want {
				t.Fatalf("truncated to %d bytes, want %d", len(got), len(tc.want))
			}
			if len(got) > limit || !utf8.ValidString(got) {
				t.Fatalf("result is %d bytes or invalid UTF-8", len(got))
			}
		})
	}
}

func TestCRIDLinkKnockV1WarningsRemainProminent(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("vectors/README_crid_link_knock_v1_vectors.md")
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"notes":  strings.Join(lf.Notes, " "),
		"README": strings.Join(strings.Fields(string(readme)), " "),
	} {
		lower := strings.ToLower(text)
		if !strings.Contains(lower, "never admit") || !strings.Contains(lower, "production trust store") {
			t.Errorf("%s lost the production trust-store warning for the vector issuer key", name)
		}
		if !strings.Contains(lower, "display-only") || !strings.Contains(lower, "unverified") {
			t.Errorf("%s lost the statement that publisher data is display-only and unverified", name)
		}
	}
}

// findCRIDLinkKnockV1Case returns a pointer into cases so a tamper subtest
// can edit the named case in place.
func findCRIDLinkKnockV1Case[C any](t *testing.T, cases []C, want string, name func(C) string) *C {
	t.Helper()
	for i := range cases {
		if name(cases[i]) == want {
			return &cases[i]
		}
	}
	t.Fatalf("missing case %q", want)
	return nil
}

func TestParseCRIDLinkKnockV1FileFailsClosed(t *testing.T) {
	raw := CRIDLinkKnockV1Vectors()
	// encode re-serializes without HTML escaping. json.Marshal would rewrite
	// the angle brackets and ampersand inside a committed request body, and
	// the mutation under test would then never be the first thing to fail.
	encode := func(t *testing.T, value any) []byte {
		t.Helper()
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(value); err != nil {
			t.Fatal(err)
		}
		return encoded.Bytes()
	}
	mutate := func(t *testing.T, change func(*CRIDLinkKnockV1File)) []byte {
		t.Helper()
		var lf CRIDLinkKnockV1File
		if err := json.Unmarshal(raw, &lf); err != nil {
			t.Fatal(err)
		}
		change(&lf)
		return encode(t, lf)
	}
	// mutateDocument edits the untyped document, for shapes the typed form
	// cannot express: unknown members, missing members, explicit empties. It
	// sorts object members, so it is only for faults the loader reports
	// before it compares canonical request bytes.
	mutateDocument := func(t *testing.T, change func(map[string]any)) []byte {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		change(doc)
		return encode(t, doc)
	}
	assertRejects := func(t *testing.T, body []byte, contains string) {
		t.Helper()
		if _, err := ParseCRIDLinkKnockV1File(body); err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("error = %v, want text %q", err, contains)
		}
	}
	requestCase := func(t *testing.T, lf *CRIDLinkKnockV1File, name string) *CRIDLinkKnockV1RequestCase {
		t.Helper()
		return findCRIDLinkKnockV1Case(t, lf.RequestCases, name, func(c CRIDLinkKnockV1RequestCase) string { return c.Name })
	}
	invalidCase := func(t *testing.T, lf *CRIDLinkKnockV1File, name string) *CRIDLinkKnockV1InvalidRequestCase {
		t.Helper()
		return findCRIDLinkKnockV1Case(t, lf.InvalidRequestCases, name, func(c CRIDLinkKnockV1InvalidRequestCase) string { return c.Name })
	}
	ackCase := func(t *testing.T, lf *CRIDLinkKnockV1File, name string) *CRIDLinkKnockV1ACKCase {
		t.Helper()
		return findCRIDLinkKnockV1Case(t, lf.ACKCases, name, func(c CRIDLinkKnockV1ACKCase) string { return c.Name })
	}
	verificationCase := func(t *testing.T, lf *CRIDLinkKnockV1File, name string) *CRIDLinkKnockV1VerificationCase {
		t.Helper()
		return findCRIDLinkKnockV1Case(t, lf.ClientVerificationCases, name, func(c CRIDLinkKnockV1VerificationCase) string { return c.Name })
	}
	sanitizationCase := func(t *testing.T, lf *CRIDLinkKnockV1File, name string) *CRIDLinkKnockV1SanitizationCase {
		t.Helper()
		return findCRIDLinkKnockV1Case(t, lf.RedirectInfoSanitizationCases, name, func(c CRIDLinkKnockV1SanitizationCase) string { return c.Name })
	}
	// setMember rewrites one member of a raw JSON object; a nil value removes it.
	setMember := func(t *testing.T, object json.RawMessage, key string, value any) json.RawMessage {
		t.Helper()
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(object, &fields); err != nil {
			t.Fatal(err)
		}
		if value == nil {
			delete(fields, key)
		} else {
			fields[key] = encode(t, value)
		}
		return encode(t, fields)
	}
	flipCRID := func(s string) string {
		if s[0] == 'a' {
			return "q" + s[1:]
		}
		return "a" + s[1:]
	}
	documentCase := func(t *testing.T, doc map[string]any, section, name string) map[string]any {
		t.Helper()
		for _, entry := range doc[section].([]any) {
			if c := entry.(map[string]any); c["name"] == name {
				return c
			}
		}
		t.Fatalf("missing %s case %q", section, name)
		return nil
	}

	t.Run("artifact", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.Artifact = "other" }), "artifact")
	})
	t.Run("schema", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.SchemaVersion++ }), "schema_version")
	})
	t.Run("description", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.Description = "" }), "description or notes")
	})
	t.Run("notes", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.Notes = nil }), "description or notes")
	})
	t.Run("blank note", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.Notes[0] = "" }), "description or notes")
	})
	t.Run("unknown top-level member", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) { doc["unexpected"] = true }), "unknown field")
	})
	t.Run("unknown nested member", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			documentCase(t, doc, "ack_cases", "denied_not_found")["expected"].(map[string]any)["retryable"] = false
		}), "unknown field")
	})

	for name, change := range map[string]func(*CRIDLinkKnockV1Constants){
		"auth service id":         func(c *CRIDLinkKnockV1Constants) { c.AuthServiceID = "agent" },
		"resource id":             func(c *CRIDLinkKnockV1Constants) { c.ResourceID = "qurl" },
		"crid key":                func(c *CRIDLinkKnockV1Constants) { c.UserDataKeys.CRID = "crid" },
		"user agent key":          func(c *CRIDLinkKnockV1Constants) { c.UserDataKeys.UserAgent = "user_agent" },
		"forbidden key removed":   func(c *CRIDLinkKnockV1Constants) { c.ForbiddenUserDataKeys = c.ForbiddenUserDataKeys[1:] },
		"forbidden key reordered": func(c *CRIDLinkKnockV1Constants) { slices.Reverse(c.ForbiddenUserDataKeys) },
		"knock header type":       func(c *CRIDLinkKnockV1Constants) { c.KnockHeaderType = 2 },
		"ack header type":         func(c *CRIDLinkKnockV1Constants) { c.ACKHeaderType = 1 },
		"user agent limit":        func(c *CRIDLinkKnockV1Constants) { c.UserAgentMaxBytes = 255 },
		"publisher name limit":    func(c *CRIDLinkKnockV1Constants) { c.PublisherNameMaxCodePoints = 64 },
		"link origin":             func(c *CRIDLinkKnockV1Constants) { c.LinkOrigin = "https://qurl.link/" },
	} {
		t.Run("constants "+name, func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { change(&lf.Constants) }), "constants")
		})
	}
	t.Run("composes", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.Composes.IssuerTrustAnchor = "other.json" }), "composes")
	})

	t.Run("error code missing", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { delete(lf.ErrorCodes, "52605") }), "error_codes")
	})
	t.Run("error code added", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			lf.ErrorCodes["52607"] = CRIDLinkKnockV1ErrorCode{Name: "future", ClientResult: CRIDLinkKnockV1ResultInvalid}
		}), "error_codes")
	})
	t.Run("error code renumbered", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			lf.ErrorCodes["52607"] = lf.ErrorCodes["52606"]
			delete(lf.ErrorCodes, "52606")
		}), "error_codes")
	})
	t.Run("error code name", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			code := lf.ErrorCodes["52602"]
			code.Name = "NotFound"
			lf.ErrorCodes["52602"] = code
		}), "error_codes")
	})
	t.Run("error code retryable", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			code := lf.ErrorCodes["52602"]
			code.Retryable = true
			lf.ErrorCodes["52602"] = code
		}), "error_codes")
	})
	t.Run("error code client result", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			code := lf.ErrorCodes["52604"]
			code.ClientResult = CRIDLinkKnockV1ResultClosed
			lf.ErrorCodes["52604"] = code
		}), "error_codes")
	})
	t.Run("error code retryable omitted", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			delete(doc["error_codes"].(map[string]any)["52600"].(map[string]any), "retryable")
		}), "omits required member error_codes.52600.retryable")
	})
	t.Run("client result added", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.ClientResults = append(lf.ClientResults, "busy") }), "client_results")
	})
	t.Run("client result removed", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.ClientResults = lf.ClientResults[:len(lf.ClientResults)-1] }), "client_results")
	})
	t.Run("client result reordered", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { slices.Reverse(lf.ClientResults) }), "client_results")
	})
	t.Run("reject class added", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.RejectClasses = append(lf.RejectClasses, "expired") }), "reject_classes")
	})
	t.Run("reject class removed", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.RejectClasses = lf.RejectClasses[1:] }), "reject_classes")
	})

	for name, change := range map[string]func(*CRIDLinkKnockV1Fixtures){
		"link":                    func(f *CRIDLinkKnockV1Fixtures) { f.Link = strings.Replace(f.Link, "/#", "#", 1) },
		"resource_public_key_b64": func(f *CRIDLinkKnockV1Fixtures) { f.ResourcePublicKeyB64 = cridV1ResourceKeyQV2B64URL },
		"crid":                    func(f *CRIDLinkKnockV1Fixtures) { f.CRID = f.TestEnvironmentCRID },
		"test_environment_crid":   func(f *CRIDLinkKnockV1Fixtures) { f.TestEnvironmentCRID = f.CRID },
		"unrelated_crid":          func(f *CRIDLinkKnockV1Fixtures) { f.UnrelatedCRID = cridV1IssuerProdCRID },
	} {
		t.Run("fixture "+name, func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { change(&lf.Fixtures) }), "fixtures."+name)
		})
	}

	t.Run("request unknown", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.RequestCases[0].Name = "future_case" }), "unknown CRID link knock request case")
	})
	t.Run("request duplicate", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.RequestCases[1] = lf.RequestCases[0] }), "duplicate CRID link knock request case")
	})
	t.Run("request missing", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.RequestCases = lf.RequestCases[1:] }), "request case count")
	})
	t.Run("request input crid", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "minimal")
			c.Input.CRID = lf.Fixtures.TestEnvironmentCRID
		}), "input does not match its fixture")
	})
	t.Run("request input user agent", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "with_user_agent")
			*c.Input.UserAgent += " "
		}), "input does not match its fixture")
	})
	t.Run("request input user agent added", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			requestCase(t, lf, "minimal").Input.UserAgent = cridLinkKnockV1StringPointer("agent/1.0")
		}), "input does not match its fixture")
	})
	t.Run("request serialized member order", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "minimal")
			c.Serialized = strings.Replace(c.Serialized, `"aspId":"qurl","resId":"qurl-crid"`, `"resId":"qurl-crid","aspId":"qurl"`, 1)
		}), "serialized does not re-derive")
	})
	t.Run("request serialized whitespace", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "minimal")
			c.Serialized = strings.Replace(c.Serialized, `,`, `, `, 1)
		}), "serialized does not re-derive")
	})
	t.Run("request serialized unicode escape", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "user_agent_at_limit")
			c.Serialized = strings.Replace(c.Serialized, "ü", "\\"+"u00fc", 1)
		}), "serialized does not re-derive")
	})
	t.Run("request serialized HTML escape", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "user_agent_json_escaping")
			c.Serialized = strings.Replace(c.Serialized, "&", "\\"+"u0026", 1)
		}), "serialized does not re-derive")
	})
	t.Run("request serialized escaped solidus", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "with_user_agent")
			c.Serialized = strings.Replace(c.Serialized, `Mozilla/5.0`, `Mozilla\/5.0`, 1)
		}), "serialized does not re-derive")
	})
	t.Run("request serialized untruncated", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "user_agent_truncated")
			c.Serialized = strings.Replace(c.Serialized, `b"}}`, `bb"}}`, 1)
		}), "serialized does not re-derive")
	})
	t.Run("request serialized split character", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "user_agent_truncated_at_code_point_boundary")
			c.Serialized = strings.Replace(c.Serialized, `c"}}`, "c\U0001F600\"}}", 1)
		}), "serialized does not re-derive")
	})
	t.Run("request body member order", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "minimal")
			c.Body = json.RawMessage(strings.Replace(string(c.Body), `"aspId": "qurl",`, ``, 1))
			c.Body = json.RawMessage(strings.Replace(string(c.Body), `"resId": "qurl-crid",`, `"resId": "qurl-crid", "aspId": "qurl",`, 1))
		}), "body does not serialize")
	})
	t.Run("request body forbidden key", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "minimal")
			c.Body = setMember(t, c.Body, "usrData", map[string]string{
				"qurl_crid": lf.Fixtures.CRID, "qurl_access_token": "at_example",
			})
		}), "body does not serialize")
	})
	t.Run("request body header type", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := requestCase(t, lf, "minimal")
			c.Body = json.RawMessage(strings.Replace(string(c.Body), `"headerType": 1`, `"headerType": 2`, 1))
		}), "body does not serialize")
	})

	t.Run("invalid request unknown", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.InvalidRequestCases[0].Name = "future_case" }), "unknown CRID link knock invalid request case")
	})
	t.Run("invalid request duplicate", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.InvalidRequestCases[1] = lf.InvalidRequestCases[0] }), "duplicate CRID link knock invalid request case")
	})
	t.Run("invalid request missing", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.InvalidRequestCases = lf.InvalidRequestCases[1:] }), "invalid request case count")
	})
	t.Run("invalid request crid repaired", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			invalidCase(t, lf, "reject_checksum").Input.CRID = lf.Fixtures.CRID
		}), "input does not match its fixture")
	})
	t.Run("invalid request user agent", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			invalidCase(t, lf, "reject_empty").Input.UserAgent = cridLinkKnockV1StringPointer("agent/1.0")
		}), "input does not match its fixture")
	})
	t.Run("invalid request class", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			invalidCase(t, lf, "reject_uppercase").CRIDRejectClass = CRIDV1RejectChecksum
		}), "expectation")
	})
	t.Run("invalid request outcome", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			invalidCase(t, lf, "reject_wrong_length").Outcome = ExpectAccept
		}), "expectation")
	})
	t.Run("invalid request empty crid omitted", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			delete(documentCase(t, doc, "invalid_request_cases", "reject_empty")["input"].(map[string]any), "crid")
		}), "omits required member invalid_request_cases.3.input.crid")
	})

	t.Run("ack unknown", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.ACKCases[0].Name = "future_case" }), "unknown CRID link knock ACK case")
	})
	t.Run("ack duplicate", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.ACKCases[1] = lf.ACKCases[0] }), "duplicate CRID link knock ACK case")
	})
	t.Run("ack missing", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.ACKCases = lf.ACKCases[1:] }), "ACK case count")
	})
	t.Run("ack requested crid", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			ackCase(t, lf, "denied_not_found").RequestedCRID = lf.Fixtures.TestEnvironmentCRID
		}), "input does not match its fixture")
	})
	t.Run("ack body code", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := ackCase(t, lf, "denied_not_found")
			c.Body = setMember(t, c.Body, "errCode", "52605")
		}), "input does not match its fixture")
	})
	t.Run("ack body numeric code", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := ackCase(t, lf, "link_issued")
			c.Body = setMember(t, c.Body, "errCode", 52600)
		}), "input does not match its fixture")
	})
	t.Run("ack body link", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := ackCase(t, lf, "link_issued")
			c.Body = setMember(t, c.Body, "redirectUrl", lf.Fixtures.Link+"A")
		}), "input does not match its fixture")
	})
	t.Run("ack body open time", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := ackCase(t, lf, "link_issued")
			c.Body = setMember(t, c.Body, "opnTime", 900)
		}), "input does not match its fixture")
	})
	t.Run("ack unknown client result", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			ackCase(t, lf, "denied_unavailable").Expected.ClientResult = "busy"
		}), "unknown client_result")
	})
	t.Run("ack client result", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			ackCase(t, lf, "denied_resource_offline").Expected.ClientResult = CRIDLinkKnockV1ResultClosed
		}), "expectation")
	})
	t.Run("ack denial treated as link", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := ackCase(t, lf, "denied_with_redirect_is_not_a_link")
			c.Expected = ackCase(t, lf, "link_issued").Expected
		}), "expectation")
	})
	t.Run("ack success code treated as link", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := ackCase(t, lf, "success_code_is_protocol_violation")
			c.Expected = ackCase(t, lf, "link_issued").Expected
		}), "expectation")
	})
	t.Run("ack unknown code treated as denial", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			ackCase(t, lf, "unassigned_code_is_server_error").Expected.ClientResult = CRIDLinkKnockV1ResultInvalid
		}), "expectation")
	})
	t.Run("ack link expectation", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			ackCase(t, lf, "link_issued").Expected.Link = lf.Constants.LinkOrigin + "/"
		}), "expectation")
	})
	t.Run("ack info omitted", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			ackCase(t, lf, "link_issued_without_redirect_info").Expected.Info = nil
		}), "expectation")
	})
	t.Run("ack info invents a name", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			ackCase(t, lf, "link_issued_without_publisher_name").Expected.Info.Publisher.Name = cridLinkKnockV1FixturePublisherName
		}), "expectation")
	})
	t.Run("ack info verified", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			ackCase(t, lf, "link_issued").Expected.Info.Publisher.Verified = true
		}), "expectation")
	})
	t.Run("ack info verified omitted", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			expected := documentCase(t, doc, "ack_cases", "link_issued_without_redirect_info")["expected"].(map[string]any)
			delete(expected["info"].(map[string]any)["publisher"].(map[string]any), "verified")
		}), "omits required member ack_cases.2.expected.info.publisher.verified")
	})
	t.Run("ack empty optional spelled out", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			documentCase(t, doc, "ack_cases", "denied_not_found")["expected"].(map[string]any)["link"] = ""
		}), "writes optional member ack_cases.4.expected.link as empty")
	})

	t.Run("verification unknown", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.ClientVerificationCases[0].Name = "future_case" }), "unknown CRID link knock verification case")
	})
	t.Run("verification duplicate", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.ClientVerificationCases[1] = lf.ClientVerificationCases[0] }), "duplicate CRID link knock verification case")
	})
	t.Run("verification missing", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			lf.ClientVerificationCases = lf.ClientVerificationCases[:len(lf.ClientVerificationCases)-1]
		}), "verification case count")
	})
	t.Run("verification requested crid", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := verificationCase(t, lf, "reject_link_for_another_crid")
			c.RequestedCRID = flipCRID(c.RequestedCRID)
		}), "input does not match its fixture")
	})
	t.Run("verification body repaired", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := verificationCase(t, lf, "reject_origin_userinfo")
			c.Body = setMember(t, c.Body, "redirectUrl", lf.Fixtures.Link)
		}), "input does not match its fixture")
	})
	t.Run("verification body other fault", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := verificationCase(t, lf, "reject_origin_userinfo")
			c.Body = verificationCase(t, lf, "reject_origin_other_port").Body
		}), "input does not match its fixture")
	})
	t.Run("verification outcome", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := verificationCase(t, lf, "reject_tampered_signature")
			c.Outcome, c.RejectClass = ExpectAccept, ""
		}), "expectation")
	})
	t.Run("verification accept flipped", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := verificationCase(t, lf, "accept_link")
			c.Outcome, c.RejectClass = ExpectReject, CRIDLinkKnockV1RejectOrigin
		}), "expectation")
	})
	t.Run("verification class", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			verificationCase(t, lf, "reject_legacy_fragment").RejectClass = CRIDLinkKnockV1RejectIssuerSignature
		}), "expectation")
	})
	t.Run("verification unknown class", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			verificationCase(t, lf, "reject_path").RejectClass = "expired"
		}), "unknown reject_class")
	})
	t.Run("verification empty class spelled out", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			documentCase(t, doc, "client_verification_cases", "accept_link")["reject_class"] = ""
		}), "writes optional member client_verification_cases.0.reject_class as empty")
	})

	t.Run("sanitization unknown", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.RedirectInfoSanitizationCases[0].Name = "future_case" }), "unknown CRID link knock sanitization case")
	})
	t.Run("sanitization duplicate", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			lf.RedirectInfoSanitizationCases[1] = lf.RedirectInfoSanitizationCases[0]
		}), "duplicate CRID link knock sanitization case")
	})
	t.Run("sanitization missing", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			lf.RedirectInfoSanitizationCases = lf.RedirectInfoSanitizationCases[1:]
		}), "sanitization case count")
	})
	t.Run("sanitization input repaired", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "publisher_not_an_object").RedirectInfo = sanitizationCase(t, lf, "full_info").RedirectInfo
		}), "redirect_info does not match its fixture")
	})
	t.Run("sanitization string trusted as verified", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "publisher_verified_string").Expected.Publisher.Verified = true
		}), "expectation")
	})
	t.Run("sanitization over-long name kept", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "publisher_name_over_limit").Expected.Publisher.Name = cridLinkKnockV1PublisherNameOverLimit
		}), "expectation")
	})
	t.Run("sanitization over-long name shortened", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "publisher_name_over_limit").Expected.Publisher.Name = cridLinkKnockV1PublisherNameOverLimit[:128]
		}), "expectation")
	})
	t.Run("sanitization at-limit name dropped", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "publisher_name_at_limit").Expected.Publisher.Name = ""
		}), "expectation")
	})
	t.Run("sanitization non-object publisher named", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "publisher_not_an_object").Expected.Publisher.Name = cridLinkKnockV1FixturePublisherName
		}), "expectation")
	})
	t.Run("sanitization numeric timestamp kept", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "timestamps_not_strings").Expected.ExpiresAt = "2026-06-19T23:05:00Z"
		}), "expectation")
	})
	t.Run("sanitization unknown member surfaced", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			expected := documentCase(t, doc, "redirect_info_sanitization_cases", "unknown_fields_ignored")["expected"].(map[string]any)
			expected["publisher"].(map[string]any)["badge"] = "gold"
		}), "unknown field")
	})
	t.Run("sanitization expected omitted", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			delete(documentCase(t, doc, "redirect_info_sanitization_cases", "info_null"), "expected")
		}), "omits required member redirect_info_sanitization_cases.1.expected")
	})
	t.Run("sanitization redirect info omitted", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			delete(documentCase(t, doc, "redirect_info_sanitization_cases", "info_null"), "redirect_info")
		}), "omits required member redirect_info_sanitization_cases.1.redirect_info")
	})
}

// TestCRIDLinkKnockV1SanitizationNeverTripsTheHardCheck pins the boundary
// between the two redirectInfo rules: a foreign crid is a hard reject, while
// every sanitization input still yields a usable link.
func TestCRIDLinkKnockV1SanitizationNeverTripsTheHardCheck(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	env, err := loadCRIDLinkKnockV1Environment()
	if err != nil {
		t.Fatal(err)
	}
	var baseline json.RawMessage
	for _, c := range lf.ACKCases {
		if c.Name == "link_issued" {
			baseline = c.Body
		}
	}
	for _, c := range lf.RedirectInfoSanitizationCases {
		var body map[string]json.RawMessage
		if err := json.Unmarshal(baseline, &body); err != nil {
			t.Fatal(err)
		}
		body["redirectInfo"] = c.RedirectInfo
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		got, rejectClass, err := env.interpretACK(lf.Fixtures.CRID, encoded)
		if err != nil || rejectClass != "" || got.ClientResult != CRIDLinkKnockV1ResultLink || got.Link != lf.Fixtures.Link {
			t.Errorf("sanitization case %q in a link-issued ACK = %q/%q/%v, want a link", c.Name, got.ClientResult, rejectClass, err)
			continue
		}
		if !reflect.DeepEqual(*got.Info, c.Expected) {
			t.Errorf("sanitization case %q in a link-issued ACK keeps %+v, want %+v", c.Name, *got.Info, c.Expected)
		}
	}
}
