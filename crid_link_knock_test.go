package conformance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
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
	if len(lf.ErrorCodes) != 7 || len(lf.ClientResults) != 10 || len(lf.RejectClasses) != 7 {
		t.Fatalf("vocabulary counts = codes:%d results:%d classes:%d", len(lf.ErrorCodes), len(lf.ClientResults), len(lf.RejectClasses))
	}
	if len(lf.RequestCases) != 6 || len(lf.InvalidRequestCases) != 7 || len(lf.ACKCases) != 17 ||
		len(lf.ClientVerificationCases) != 31 || len(lf.RedirectInfoSanitizationCases) != 20 {
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
	// One cap for every display string. A value at the cap is kept even
	// though it is longer than the cap in bytes and in UTF-16 code units; a
	// value one code point past it is dropped, and only that member goes.
	limit := lf.Constants.InfoTextMaxCodePoints
	for name, kept := range map[string]string{
		"publisher_name_at_limit": sanitized["publisher_name_at_limit"].Publisher.Name,
		"qurl_id_at_limit":        sanitized["qurl_id_at_limit"].QURLID,
	} {
		if utf8.RuneCountInString(kept) != limit || len(kept) <= limit || len(utf16.Encode([]rune(kept))) <= limit {
			t.Errorf("%s must keep %d code points that exceed %d bytes and %d UTF-16 units, got %d/%d/%d",
				name, limit, limit, limit, utf8.RuneCountInString(kept), len(kept), len(utf16.Encode([]rune(kept))))
		}
	}
	type members struct{ qurlID, expiresAt, resourceCreatedAt, name bool }
	for name, want := range map[string]members{
		"publisher_name_over_limit":      {qurlID: true, expiresAt: true, resourceCreatedAt: true},
		"qurl_id_over_limit":             {expiresAt: true, resourceCreatedAt: true, name: true},
		"expires_at_over_limit":          {qurlID: true, resourceCreatedAt: true, name: true},
		"resource_created_at_over_limit": {qurlID: true, expiresAt: true, name: true},
	} {
		info, ok := sanitized[name]
		got := members{info.QURLID != "", info.ExpiresAt != "", info.ResourceCreatedAt != "", info.Publisher.Name != ""}
		if !ok || got != want {
			t.Errorf("%s keeps %+v (present %t), want %+v: an over-long string is dropped and nothing else is", name, got, ok, want)
		}
	}
	// The over-long inputs really are one code point past the cap, and each
	// starts with the genuine value, so a client that shortened one would
	// surface something that looks right.
	for _, c := range lf.RedirectInfoSanitizationCases {
		if !strings.HasSuffix(c.Name, "_over_limit") {
			continue
		}
		fields, _ := cridLinkKnockV1JSONObject(c.RedirectInfo)
		raw := fields[strings.TrimSuffix(c.Name, "_over_limit")]
		if c.Name == "publisher_name_over_limit" {
			publisher, _ := cridLinkKnockV1JSONObject(fields["publisher"])
			raw = publisher["name"]
		}
		if text, ok := cridLinkKnockV1JSONString(raw); !ok || utf8.RuneCountInString(text) != limit+1 || len(text) != limit+1 {
			t.Errorf("%s input is %d code points, want an ASCII string of %d", c.Name, utf8.RuneCountInString(text), limit+1)
		}
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
		ack, ok := cridLinkKnockV1JSONObject(c.Body)
		if !ok {
			t.Fatalf("ACK case %q body is not an object", c.Name)
		}
		// An errCode that is not a string is not a code; those cases exercise
		// the protocol_violation result instead.
		if code, isString := cridLinkKnockV1JSONString(ack["errCode"]); isString {
			codes[code] = true
		}
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
	// Busy belongs to the cookie reply alone: no ACK body may produce it, and
	// every other result must come from an ACK case.
	cookieResult := lf.ReplyTypeRules.Cookie.ClientResult
	if results[cookieResult] {
		t.Errorf("an ACK case produces %q, which only the cookie reply may", cookieResult)
	}
	for _, result := range lf.ClientResults {
		if result != cookieResult && !results[result] {
			t.Errorf("client result %q has no ACK case", result)
		}
	}
	if !slices.Contains(lf.ClientResults, cookieResult) {
		t.Errorf("the cookie reply maps to %q, which is not a client result", cookieResult)
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
	for _, class := range []string{CRIDV1RejectChecksum, CRIDV1RejectLength, CRIDV1RejectCharset, CRIDV1RejectVersion} {
		if !cridClasses[class] {
			t.Errorf("no refused request exercises the CRID v1 %q class", class)
		}
	}
}

// TestCRIDLinkKnockV1RefusesVersionsAClientCannotVerify pins the one place
// where the request gate is stricter than the CRID v1 local gate. A CRID with
// an unregistered or reserved version byte is well formed and the local gate
// forwards it, but a client could never check an issued link against it, so
// it must not ask for one.
func TestCRIDLinkKnockV1RefusesVersionsAClientCannotVerify(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	refused := make(map[string]CRIDLinkKnockV1InvalidRequestCase, len(lf.InvalidRequestCases))
	for _, c := range lf.InvalidRequestCases {
		refused[c.Name] = c
	}
	registry := make(map[string]CRIDV1Version, len(cridV1VersionRegistry))
	for _, row := range cridV1VersionRegistry {
		registry[row.VersionHex] = row
	}
	for _, tc := range []struct {
		name         string
		versionHex   string
		length       int
		digestLength int
		registered   bool
	}{
		{"reject_unregistered_version", "7f", CRIDV1FullCRIDLength, CRIDV1FullDigestLength, false},
		{"reject_reserved_version_02", "02", CRIDV1TruncatedCRIDLength, CRIDV1TruncatedDigestLength, true},
		{"reject_reserved_version_82", "82", CRIDV1TruncatedCRIDLength, CRIDV1TruncatedDigestLength, true},
	} {
		c, ok := refused[tc.name]
		if !ok {
			t.Errorf("missing invalid request case %q", tc.name)
			continue
		}
		crid := c.Input.CRID
		// The generic gate has nothing to object to: shape and checksum hold.
		if outcome, rejectClass := deriveCRIDV1ValueExpectation(crid); outcome != ExpectAccept {
			t.Errorf("%s fails the CRID v1 local gate with class %q; it must be refused for its version alone", tc.name, rejectClass)
			continue
		}
		versionHex, known, _, digestLength, err := deriveCRIDV1VersionExpectation(crid)
		if err != nil || versionHex != tc.versionHex || known != tc.registered || digestLength != tc.digestLength || len(crid) != tc.length {
			t.Errorf("%s = version %q known %t digest %d length %d (%v), want %q/%t/%d/%d",
				tc.name, versionHex, known, digestLength, len(crid), err, tc.versionHex, tc.registered, tc.digestLength, tc.length)
		}
		// A reserved row is registered but not active. If the registry ever
		// activates it, this case stops being a refusal and must be revisited
		// together with the clients that would then verify it.
		if row, registered := registry[tc.versionHex]; registered != tc.registered || (registered && row.Status != CRIDV1StatusReserved) {
			t.Errorf("%s: CRID v1 registry row for %q = %+v (registered %t), want reserved %t", tc.name, tc.versionHex, row, registered, tc.registered)
		}
		if outcome, rejectClass := cridLinkKnockV1RequestExpectation(crid); outcome != ExpectReject || rejectClass != CRIDV1RejectVersion ||
			c.Outcome != ExpectReject || c.CRIDRejectClass != CRIDV1RejectVersion {
			t.Errorf("%s request gate = %q/%q, declared %q/%q; want a refusal under the CRID v1 version class",
				tc.name, outcome, rejectClass, c.Outcome, c.CRIDRejectClass)
		}
		if _, _, err := cridLinkKnockV1SerializeRequest(CRIDLinkKnockV1RequestInput{CRID: crid}); err == nil {
			t.Errorf("%s: the reference request builder built a request for it", tc.name)
		}
	}

	// Every refused input is refused by the builder, and every CRID a case
	// requests a link for is one the request gate lets through: a client
	// never holds an answer to a request it would not have sent.
	for _, c := range lf.InvalidRequestCases {
		if _, _, err := cridLinkKnockV1SerializeRequest(c.Input); err == nil {
			t.Errorf("invalid request case %q: the reference request builder built a request for it", c.Name)
		}
	}
	requested := map[string]string{}
	for _, c := range lf.RequestCases {
		requested["request case "+c.Name] = c.Input.CRID
	}
	for _, c := range lf.ACKCases {
		requested["ACK case "+c.Name] = c.RequestedCRID
	}
	for _, c := range lf.ClientVerificationCases {
		requested["verification case "+c.Name] = c.RequestedCRID
	}
	for name, crid := range requested {
		if outcome, rejectClass := cridLinkKnockV1RequestExpectation(crid); outcome != ExpectAccept {
			t.Errorf("%s requests a link for a CRID the request gate refuses (%q)", name, rejectClass)
		}
	}
	// Both active versions are requestable; the test-environment CRID is the
	// proof that the gate reads the registry instead of hard-coding one byte.
	for _, crid := range []string{lf.Fixtures.CRID, lf.Fixtures.TestEnvironmentCRID, lf.Fixtures.UnrelatedCRID} {
		if outcome, rejectClass := cridLinkKnockV1RequestExpectation(crid); outcome != ExpectAccept {
			t.Errorf("fixture CRID %q is refused (%q)", crid, rejectClass)
		}
	}
}

// TestCRIDLinkKnockV1ReplyTypeRules restates the rules as the relationships a
// client relies on: three disjoint kinds of reply, of which only the ACK has
// an outcome code to read, the cookie reply is busy, and anything else is a
// transport error rather than a client result.
func TestCRIDLinkKnockV1ReplyTypeRules(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	rules := lf.ReplyTypeRules
	if rules.ACK.HeaderType != lf.Constants.ACKHeaderType || rules.Cookie.HeaderType != lf.Constants.CookieHeaderType {
		t.Fatalf("rule header types %d/%d disagree with constants %d/%d",
			rules.ACK.HeaderType, rules.Cookie.HeaderType, lf.Constants.ACKHeaderType, lf.Constants.CookieHeaderType)
	}
	if rules.ACK.HeaderType == rules.Cookie.HeaderType ||
		rules.ACK.HeaderType == lf.Constants.KnockHeaderType || rules.Cookie.HeaderType == lf.Constants.KnockHeaderType {
		t.Fatal("the knock, ACK and cookie header types must be distinct")
	}
	if !rules.ACK.IsACK || !rules.ACK.CarriesOutcomeCode || rules.ACK.Handling != CRIDLinkKnockV1HandlingInterpretACKBody || rules.ACK.ClientResult != "" {
		t.Errorf("ACK rule = %+v: only its body decides the result", rules.ACK)
	}
	if rules.Cookie.IsACK || rules.Cookie.CarriesOutcomeCode || rules.Cookie.Handling != CRIDLinkKnockV1HandlingClientResult ||
		rules.Cookie.ClientResult != CRIDLinkKnockV1ResultBusy {
		t.Errorf("cookie rule = %+v: it is not an ACK, has no outcome code, and means busy", rules.Cookie)
	}
	if rules.Other.HeaderType != 0 || rules.Other.IsACK || rules.Other.CarriesOutcomeCode ||
		rules.Other.Handling != CRIDLinkKnockV1HandlingTransportError || rules.Other.ClientResult != "" {
		t.Errorf("other rule = %+v: any other reply type is a transport error", rules.Other)
	}
	if slices.Contains(lf.ClientResults, rules.Other.Handling) {
		t.Error("a transport error must not be a client result")
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
	// The link is taken apart as text, without a URL parser and without the
	// reference's own method of stripping the origin first: the scheme and the
	// authority are whatever stands in front of the first "/", "?" or "#", and
	// the two checks then look at their own part of the link.
	beforeFragment, fragment, _ := strings.Cut(redirect, "#")
	authorityEnd := len(beforeFragment)
	if schemeEnd := strings.Index(beforeFragment, "://"); schemeEnd >= 0 {
		if pathStart := strings.IndexAny(beforeFragment[schemeEnd+3:], "/?"); pathStart >= 0 {
			authorityEnd = schemeEnd + 3 + pathStart
		}
	}
	if beforeFragment[:authorityEnd] != CRIDLinkKnockV1LinkOrigin {
		failing = append(failing, CRIDLinkKnockV1RejectOrigin)
	}
	if pathAndQuery := beforeFragment[authorityEnd:]; pathAndQuery != "" && pathAndQuery != "/" {
		failing = append(failing, CRIDLinkKnockV1RejectPathOrQuery)
	}
	canonical, err := decodeConformanceTransport(env.transportContract, fragment)
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
}

// TestCRIDLinkKnockV1LinkOriginIsComparedAsText pins checks 2 and 3 on more
// links than the artifact carries. An issued link is the link origin, an
// optional slash, a number sign and the fragment. Everything else is rejected
// by comparing text: as origin when the link does not begin with the link
// origin or its authority runs on past it, and as path_or_query when a path or
// a query follows the origin.
func TestCRIDLinkKnockV1LinkOriginIsComparedAsText(t *testing.T) {
	const origin = CRIDLinkKnockV1LinkOrigin
	for _, tc := range []struct {
		link         string
		wantFragment string
		wantClass    string
	}{
		// The two accepted forms. The fragment is everything after the first
		// number sign, as written.
		{origin + "/#qv2t1.x", "qv2t1.x", ""},
		{origin + "#qv2t1.x", "qv2t1.x", ""},
		{origin + "/#a#b", "a#b", ""},
		{origin + "/#%41", "%41", ""},
		// No fragment, or an empty one: these pass checks 2 and 3 and fail the
		// transport check, which is not this function's.
		{origin + "/", "", ""},
		{origin, "", ""},
		{origin + "/#", "", ""},

		// The link does not begin with the link origin.
		{"http://qurl.link/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"HTTPS://qurl.link/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"Https://qurl.link/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"https://QURL.LINK/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"https://Qurl.link/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"https://user@qurl.link/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"https://example.com/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"https://qurl.li\tnk/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"https://qurl.li\nnk/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"https://qurl.li\rnk/#f", "", CRIDLinkKnockV1RejectOrigin},
		{" " + origin + "/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"//qurl.link/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"qurl.link/#f", "", CRIDLinkKnockV1RejectOrigin},
		{"#f", "", CRIDLinkKnockV1RejectOrigin},
		{"", "", CRIDLinkKnockV1RejectOrigin},

		// The link begins with the link origin and its authority runs on.
		{origin + ":443/#f", "", CRIDLinkKnockV1RejectOrigin},
		{origin + ":8443/#f", "", CRIDLinkKnockV1RejectOrigin},
		{origin + ":/#f", "", CRIDLinkKnockV1RejectOrigin},
		{origin + "./#f", "", CRIDLinkKnockV1RejectOrigin},
		{origin + ".example/#f", "", CRIDLinkKnockV1RejectOrigin},
		{origin + ".example.com/#f", "", CRIDLinkKnockV1RejectOrigin},
		{origin + "x/#f", "", CRIDLinkKnockV1RejectOrigin},
		{origin + "@example.com/#f", "", CRIDLinkKnockV1RejectOrigin},
		{origin + `\@example.com/#f`, "", CRIDLinkKnockV1RejectOrigin},
		{origin + "%2f@example.com/#f", "", CRIDLinkKnockV1RejectOrigin},
		{origin + " /#f", "", CRIDLinkKnockV1RejectOrigin},
		{origin + "\t/#f", "", CRIDLinkKnockV1RejectOrigin},

		// On the link origin, with a path or a query.
		{origin + "/open#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "//#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "/./#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "/@example.com/#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "/?next=open#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "?next=open#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "/?#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "?#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "/.#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "/..#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "/%2e#f", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "/open", "", CRIDLinkKnockV1RejectPathOrQuery},
		{origin + "/?q=1", "", CRIDLinkKnockV1RejectPathOrQuery},
	} {
		fragment, rejectClass := cridLinkKnockV1SplitLink(tc.link, origin)
		if fragment != tc.wantFragment || rejectClass != tc.wantClass {
			t.Errorf("cridLinkKnockV1SplitLink(%q) = %q, %q; want %q, %q", tc.link, fragment, rejectClass, tc.wantFragment, tc.wantClass)
		}
	}

	// Why the comparison is on text. Go's URL parser, like any other, reads
	// each of these as scheme https and host qurl.link with no userinfo, so a
	// client that parsed first and compared components would accept links no
	// server wrote. The artifact rejects all of them as origin.
	for _, link := range []string{"HTTPS://qurl.link/#f", "Https://qurl.link/#f"} {
		parsed, err := url.Parse(link)
		if err != nil || parsed.Scheme+"://"+parsed.Host != origin || parsed.User != nil {
			t.Fatalf("fixture drift: url.Parse(%q) no longer reads as the link origin (%v)", link, err)
		}
		if _, rejectClass := cridLinkKnockV1SplitLink(link, origin); rejectClass != CRIDLinkKnockV1RejectOrigin {
			t.Errorf("%q is rejected as %q, want %q", link, rejectClass, CRIDLinkKnockV1RejectOrigin)
		}
	}

	// The committed cases carry one link of every kind above, each built on the
	// published fragment, and nothing else about them differs from accept_link.
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	fragment := strings.TrimPrefix(lf.Fixtures.Link, origin+"/#")
	links := make(map[string]string, len(lf.ClientVerificationCases))
	bodies := make(map[string]map[string]json.RawMessage, len(lf.ClientVerificationCases))
	for _, c := range lf.ClientVerificationCases {
		ack, ok := cridLinkKnockV1JSONObject(c.Body)
		if !ok {
			t.Fatalf("verification case %q body is not an object", c.Name)
		}
		links[c.Name], _ = cridLinkKnockV1JSONString(ack["redirectUrl"])
		bodies[c.Name] = ack
	}
	for name, want := range map[string]struct{ link, outcome, rejectClass string }{
		"accept_link":                    {origin + "/#" + fragment, ExpectAccept, ""},
		"accept_link_without_slash":      {origin + "#" + fragment, ExpectAccept, ""},
		"reject_origin_lookalike_host":   {"https://qurl.link.example.com/#" + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_origin_http_scheme":      {"http://qurl.link/#" + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_origin_other_port":       {"https://qurl.link:8443/#" + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_origin_userinfo":         {"https://user@qurl.link/#" + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_origin_as_userinfo":      {"https://qurl.link@example.com/#" + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_origin_uppercase_scheme": {"HTTPS://qurl.link/#" + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_origin_uppercase_host":   {"https://QURL.LINK/#" + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_origin_default_port":     {"https://qurl.link:443/#" + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_origin_trailing_dot":     {"https://qurl.link./#" + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_origin_backslash":        {origin + `\@example.com/#` + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_origin_tab_in_host":      {"https://qurl.li\tnk/#" + fragment, ExpectReject, CRIDLinkKnockV1RejectOrigin},
		"reject_path":                    {origin + "/open#" + fragment, ExpectReject, CRIDLinkKnockV1RejectPathOrQuery},
		"reject_query":                   {origin + "/?next=open#" + fragment, ExpectReject, CRIDLinkKnockV1RejectPathOrQuery},
		"reject_empty_query":             {origin + "/?#" + fragment, ExpectReject, CRIDLinkKnockV1RejectPathOrQuery},
		"reject_dot_segment":             {origin + "/.#" + fragment, ExpectReject, CRIDLinkKnockV1RejectPathOrQuery},
	} {
		var declared CRIDLinkKnockV1VerificationCase
		for _, c := range lf.ClientVerificationCases {
			if c.Name == name {
				declared = c
			}
		}
		if links[name] != want.link || declared.Outcome != want.outcome || declared.RejectClass != want.rejectClass {
			t.Errorf("verification case %q = link %q, %q/%q; want link %q, %q/%q",
				name, links[name], declared.Outcome, declared.RejectClass, want.link, want.outcome, want.rejectClass)
			continue
		}
		for member, value := range bodies["accept_link"] {
			if member != "redirectUrl" && !bytes.Equal(bodies[name][member], value) {
				t.Errorf("verification case %q differs from accept_link in %s, not only in its link", name, member)
			}
		}
		if len(bodies[name]) != len(bodies["accept_link"]) || declared.RequestedCRID != lf.Fixtures.CRID {
			t.Errorf("verification case %q differs from accept_link in more than its link", name)
		}
	}
}

// TestCRIDLinkKnockV1ForbiddenUserDataKeys pins the members a link request
// never carries: four that belong to the knocks that open a link, and the one
// name reserved for a later revision. No request case carries any of them, and
// the two members a request does carry are not among them.
func TestCRIDLinkKnockV1ForbiddenUserDataKeys(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"qurl_access_token", "qurl_claims_b64", "qurl_issuer_sig_b64", "qurl_session_secret", "qurl_passkey"}
	if !slices.Equal(lf.Constants.ForbiddenUserDataKeys, want) {
		t.Fatalf("forbidden_user_data_keys = %v, want %v", lf.Constants.ForbiddenUserDataKeys, want)
	}
	for _, sent := range []string{lf.Constants.UserDataKeys.CRID, lf.Constants.UserDataKeys.UserAgent} {
		if slices.Contains(lf.Constants.ForbiddenUserDataKeys, sent) {
			t.Errorf("%q is both sent and forbidden", sent)
		}
	}
	for _, c := range lf.RequestCases {
		// Both forms of the request are read: the body object and its bytes.
		for form, encoded := range map[string][]byte{"body": c.Body, "serialized": []byte(c.Serialized)} {
			var members struct {
				UserData map[string]json.RawMessage `json:"usrData"`
			}
			if err := json.Unmarshal(encoded, &members); err != nil {
				t.Fatalf("request %q %s: %v", c.Name, form, err)
			}
			for key := range members.UserData {
				if key != lf.Constants.UserDataKeys.CRID && key != lf.Constants.UserDataKeys.UserAgent {
					t.Errorf("request %q %s sends the user-data member %q, which a v1 client never sends", c.Name, form, key)
				}
			}
		}
	}
}

// TestCRIDLinkKnockV1IssuedLinkExamplesPassClientVerification ties the two
// suites together. Every ACK case whose expected result is a link must pass
// the same checks the verification accept cases pass, under both the
// reference verifier and the independent evaluator, so an "issued" example
// can never be a link a client would reject.
func TestCRIDLinkKnockV1IssuedLinkExamplesPassClientVerification(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	env, err := loadCRIDLinkKnockV1Environment()
	if err != nil {
		t.Fatal(err)
	}
	issued := 0
	for _, c := range lf.ACKCases {
		if c.Expected.ClientResult != CRIDLinkKnockV1ResultLink {
			continue
		}
		issued++
		ack, ok := cridLinkKnockV1JSONObject(c.Body)
		if !ok {
			t.Fatalf("ACK case %q body is not an object", c.Name)
		}
		if rejectClass := env.linkRejectClass(c.RequestedCRID, ack); rejectClass != "" {
			t.Errorf("ACK case %q is declared a link but the reference verifier rejects it as %q", c.Name, rejectClass)
		}
		if failing := failingLinkChecks(t, env, c.RequestedCRID, c.Body); len(failing) != 0 {
			t.Errorf("ACK case %q is declared a link but fails checks %v", c.Name, failing)
		}
	}
	if issued == 0 {
		t.Fatal("no ACK case issues a link")
	}
	// The converse holds for the interpreter the loader runs: a body that a
	// verification case rejects is never reported as a link.
	for _, c := range lf.ClientVerificationCases {
		if c.Outcome != ExpectReject {
			continue
		}
		result, rejectClass, err := env.interpretACK(c.RequestedCRID, c.Body)
		if err != nil || rejectClass == "" || result.ClientResult != "" || result.Link != "" || result.Info != nil {
			t.Errorf("verification case %q interprets as %+v/%q/%v, want a bare reject", c.Name, result, rejectClass, err)
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

// signedCRIDLinkKnockV1Link builds a link whose inner artifact carries the
// given claims component under a fresh low-S signature of the published test
// issuer key, the fixed 0x07 vector scalar. The proof-of-possession component
// is the published one. This artifact publishes no signature of its own, so a
// link that verifies and still does not parse can only be built in a test.
func signedCRIDLinkKnockV1Link(t *testing.T, env *cridLinkKnockV1Environment, claimsB64 string) string {
	t.Helper()
	issuer, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x07}, 32))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append(append([]byte(env.signingPrefix), 0), claimsB64...))
	r, s, err := ecdsa.Sign(rand.Reader, issuer, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	order := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(order, 1)) > 0 {
		s.Sub(order, s)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	fields := []string{claimsB64, strings.Split(env.canonical, ".")[2], base64.RawURLEncoding.EncodeToString(signature)}
	header := []string{env.transportContract.Prefix}
	var chunks []string
	for _, field := range fields {
		count := 0
		for ; len(field) > env.transportContract.ComponentMax; count++ {
			chunks = append(chunks, field[:env.transportContract.ComponentMax])
			field = field[env.transportContract.ComponentMax:]
		}
		chunks = append(chunks, field)
		header = append(header, strconv.Itoa(count+1))
	}
	return CRIDLinkKnockV1LinkOrigin + "/#" + strings.Join(append(header, chunks...), ".")
}

// TestCRIDLinkKnockV1InnerArtifactFailuresAreIssuerSignatureRejects pins the
// class of a link whose inner artifact verifies but does not parse. A client
// reports any inner-artifact failure as issuer_signature; without that rule
// each of these would surface as a CRID mismatch, or as no reject at all.
func TestCRIDLinkKnockV1InnerArtifactFailuresAreIssuerSignatureRejects(t *testing.T) {
	env, err := loadCRIDLinkKnockV1Environment()
	if err != nil {
		t.Fatal(err)
	}
	body := func(link string) json.RawMessage {
		encoded, err := json.Marshal(map[string]string{"errCode": CRIDLinkKnockV1CodeLinkIssued, "redirectUrl": link})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	claims := func(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
	expiry := strconv.FormatInt(env.expiresUnix, 10)

	// The two claims this step reads, padded with JSON whitespace until the
	// encoding ends in a two-character group. Canonical base64url leaves the
	// low four bits of that group's last character zero; setting one of them
	// keeps the decoded bytes and makes the component non-canonical.
	minimal := `{"exp":` + expiry + `,"resource_public_key_b64":"` + env.resourceKeyB64 + `"}`
	for len(minimal)%3 != 1 {
		minimal += " "
	}
	nonCanonical := claims(minimal)
	nonCanonical = nonCanonical[:len(nonCanonical)-1] + string(nonCanonical[len(nonCanonical)-1]+1)
	if lenient, err := base64.RawURLEncoding.DecodeString(nonCanonical); err != nil || string(lenient) != minimal {
		t.Fatalf("non-canonical claims must still decode leniently to the same bytes: %v", err)
	}
	if _, err := strictRawBase64URL(nonCanonical); err == nil {
		t.Fatal("non-canonical claims decode under the strict decoder")
	}

	// Controls: under a fresh signature, the published claims and the minimal
	// claims are each a usable link, so every reject below is caused by the
	// one thing its claims change.
	for name, claimsB64 := range map[string]string{
		"published claims": strings.Split(env.canonical, ".")[1],
		"minimal claims":   claims(minimal),
	} {
		control := body(signedCRIDLinkKnockV1Link(t, env, claimsB64))
		result, rejectClass, err := env.interpretACK(env.crid, control)
		if err != nil || rejectClass != "" || result.ClientResult != CRIDLinkKnockV1ResultLink {
			t.Fatalf("re-signed %s interpret as %+v/%q/%v, want a link", name, result, rejectClass, err)
		}
		if failing := failingLinkChecks(t, env, env.crid, control); len(failing) != 0 {
			t.Fatalf("re-signed %s fail checks %v", name, failing)
		}
	}

	for name, claimsB64 := range map[string]string{
		"claims are not canonical base64url": nonCanonical,
		"claims are not JSON":                claims("not json"),
		"claims are not an object":           claims(`["` + env.resourceKeyB64 + `"]`),
		"expiry is not a number":             claims(`{"exp":"` + expiry + `","resource_public_key_b64":"` + env.resourceKeyB64 + `"}`),
		"no resource key":                    claims(`{"exp":` + expiry + `}`),
		"resource key is not a string":       claims(`{"exp":` + expiry + `,"resource_public_key_b64":7}`),
		"resource key is empty":              claims(`{"exp":` + expiry + `,"resource_public_key_b64":""}`),
		"resource key is padded base64url":   claims(`{"exp":` + expiry + `,"resource_public_key_b64":"` + env.resourceKeyB64 + `="}`),
	} {
		t.Run(name, func(t *testing.T) {
			link := signedCRIDLinkKnockV1Link(t, env, claimsB64)
			canonical, err := decodeConformanceTransport(env.transportContract, strings.TrimPrefix(link, CRIDLinkKnockV1LinkOrigin+"/#"))
			if err != nil {
				t.Fatalf("link must still be valid framing: %v", err)
			}
			parts := strings.Split(canonical, ".")
			if parts[1] != claimsB64 || !env.verifyIssuerSignature(parts[1], parts[3]) {
				t.Fatal("link must still verify under the trust anchor")
			}
			result, rejectClass, err := env.interpretACK(env.crid, body(link))
			if err != nil || rejectClass != CRIDLinkKnockV1RejectIssuerSignature || result.ClientResult != "" || result.Link != "" || result.Info != nil {
				t.Fatalf("interprets as %+v/%q/%v, want a bare %s reject", result, rejectClass, err, CRIDLinkKnockV1RejectIssuerSignature)
			}
		})
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

// TestCRIDLinkKnockV1RequestCasesHoldNoControlCharacter keeps one sentence of
// the README true: no vector contains a control character. A v1 client
// leaves the user agent out when it holds one, and no case pins that rule
// yet, so no request case may carry one, in its input or in what it sends.
// The reference request builder refuses a fixture that does.
func TestCRIDLinkKnockV1RequestCasesHoldNoControlCharacter(t *testing.T) {
	lf, err := CRIDLinkKnockV1()
	if err != nil {
		t.Fatal(err)
	}
	isControl := func(r rune) bool { return r < 0x20 || r == 0x7f }
	for _, c := range lf.RequestCases {
		var sent cridLinkKnockV1WireRequest
		if err := json.Unmarshal([]byte(c.Serialized), &sent); err != nil {
			t.Fatalf("request %q serialized: %v", c.Name, err)
		}
		if strings.ContainsFunc(sent.UserData.UserAgent, isControl) ||
			(c.Input.UserAgent != nil && strings.ContainsFunc(*c.Input.UserAgent, isControl)) {
			t.Errorf("request case %q carries a control character in its user agent", c.Name)
		}
	}
	build := func(r rune) error {
		userAgent := "agent/1.0 " + string(r) + " end"
		_, _, err := cridLinkKnockV1SerializeRequest(CRIDLinkKnockV1RequestInput{CRID: lf.Fixtures.CRID, UserAgent: &userAgent})
		return err
	}
	for r := rune(0); r <= 0x7f; r++ {
		if err := build(r); isControl(r) != (err != nil) {
			t.Errorf("the reference request builder gives %v for a user agent that holds %U; it refuses the control characters and nothing else in ASCII", err, r)
		}
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
		"cookie header type":      func(c *CRIDLinkKnockV1Constants) { c.CookieHeaderType = 8 },
		"user agent limit":        func(c *CRIDLinkKnockV1Constants) { c.UserAgentMaxBytes = 255 },
		"info text limit":         func(c *CRIDLinkKnockV1Constants) { c.InfoTextMaxCodePoints = 64 },
		"link origin":             func(c *CRIDLinkKnockV1Constants) { c.LinkOrigin = "https://qurl.link/" },
	} {
		t.Run("constants "+name, func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { change(&lf.Constants) }), "constants")
		})
	}
	t.Run("constants forbidden session secret removed", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			lf.Constants.ForbiddenUserDataKeys = slices.DeleteFunc(lf.Constants.ForbiddenUserDataKeys, func(key string) bool {
				return key == "qurl_session_secret"
			})
		}), "constants")
	})
	t.Run("constants retired name limit", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			constants := doc["constants"].(map[string]any)
			constants["publisher_name_max_code_points"] = constants["info_text_max_code_points"]
			delete(constants, "info_text_max_code_points")
		}), "unknown field")
	})
	t.Run("composes", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.Composes.IssuerTrustAnchor = "other.json" }), "composes")
	})

	for name, change := range map[string]func(*CRIDLinkKnockV1ReplyTypeRules){
		"ack header type":             func(r *CRIDLinkKnockV1ReplyTypeRules) { r.ACK.HeaderType = r.Cookie.HeaderType },
		"ack handling":                func(r *CRIDLinkKnockV1ReplyTypeRules) { r.ACK.Handling = CRIDLinkKnockV1HandlingTransportError },
		"cookie header type":          func(r *CRIDLinkKnockV1ReplyTypeRules) { r.Cookie.HeaderType = 8 },
		"cookie declared an ACK":      func(r *CRIDLinkKnockV1ReplyTypeRules) { r.Cookie.IsACK = true },
		"cookie given an outcome":     func(r *CRIDLinkKnockV1ReplyTypeRules) { r.Cookie.CarriesOutcomeCode = true },
		"cookie handling":             func(r *CRIDLinkKnockV1ReplyTypeRules) { r.Cookie.Handling = CRIDLinkKnockV1HandlingInterpretACKBody },
		"cookie client result":        func(r *CRIDLinkKnockV1ReplyTypeRules) { r.Cookie.ClientResult = CRIDLinkKnockV1ResultUnavailable },
		"cookie client result gone":   func(r *CRIDLinkKnockV1ReplyTypeRules) { r.Cookie.ClientResult = "" },
		"other handling":              func(r *CRIDLinkKnockV1ReplyTypeRules) { r.Other.Handling = CRIDLinkKnockV1HandlingInterpretACKBody },
		"other given a header type":   func(r *CRIDLinkKnockV1ReplyTypeRules) { r.Other.HeaderType = 4 },
		"other given a client result": func(r *CRIDLinkKnockV1ReplyTypeRules) { r.Other.ClientResult = CRIDLinkKnockV1ResultBusy },
	} {
		t.Run("reply type rule "+name, func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { change(&lf.ReplyTypeRules) }), "reply_type_rules")
		})
	}
	t.Run("reply type rules omitted", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) { delete(doc, "reply_type_rules") }), "omits required member reply_type_rules")
	})
	t.Run("reply type rule false flag omitted", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			delete(doc["reply_type_rules"].(map[string]any)["cookie"].(map[string]any), "carries_outcome_code")
		}), "omits required member reply_type_rules.cookie.carries_outcome_code")
	})
	t.Run("reply type rule unknown member", func(t *testing.T) {
		assertRejects(t, mutateDocument(t, func(doc map[string]any) {
			doc["reply_type_rules"].(map[string]any)["cookie"].(map[string]any)["answer"] = true
		}), "unknown field")
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
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) { lf.ClientResults = append(lf.ClientResults, "pending") }), "client_results")
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
	for _, forbidden := range cridLinkKnockV1ForbiddenUserDataKeys {
		t.Run("request body forbidden key "+forbidden, func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
				c := requestCase(t, lf, "minimal")
				c.Body = setMember(t, c.Body, "usrData", map[string]string{
					"qurl_crid": lf.Fixtures.CRID, forbidden: "example",
				})
			}), "body does not serialize")
		})
	}
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
	for _, name := range []string{"reject_unregistered_version", "reject_reserved_version_02", "reject_reserved_version_82"} {
		t.Run("invalid request "+name+" sent", func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
				c := invalidCase(t, lf, name)
				c.Outcome, c.CRIDRejectClass = ExpectAccept, ""
			}), "expectation")
		})
		t.Run("invalid request "+name+" given another class", func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
				invalidCase(t, lf, name).CRIDRejectClass = CRIDV1RejectChecksum
			}), "expectation")
		})
	}
	t.Run("invalid request unregistered version made active", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			invalidCase(t, lf, "reject_unregistered_version").Input.CRID = lf.Fixtures.TestEnvironmentCRID
		}), "input does not match its fixture")
	})
	t.Run("invalid request unregistered version from another key", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			invalidCase(t, lf, "reject_unregistered_version").Input.CRID = cridV1UnknownVersionFullCRID
		}), "input does not match its fixture")
	})
	t.Run("invalid request reserved version in full form", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := invalidCase(t, lf, "reject_reserved_version_02")
			c.Input.CRID = lf.Fixtures.CRID
		}), "input does not match its fixture")
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
			ackCase(t, lf, "denied_unavailable").Expected.ClientResult = "pending"
		}), "unknown client_result")
	})
	t.Run("ack denial reported as busy", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			ackCase(t, lf, "denied_unavailable").Expected.ClientResult = CRIDLinkKnockV1ResultBusy
		}), "expectation")
	})
	t.Run("ack numeric code treated as link", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := ackCase(t, lf, "numeric_code_is_protocol_violation")
			c.Expected = ackCase(t, lf, "link_issued").Expected
		}), "expectation")
	})
	t.Run("ack numeric code made a string", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := ackCase(t, lf, "numeric_code_is_protocol_violation")
			c.Body = setMember(t, c.Body, "errCode", CRIDLinkKnockV1CodeLinkIssued)
		}), "input does not match its fixture")
	})
	t.Run("ack null code treated as server error", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			ackCase(t, lf, "null_code_is_protocol_violation").Expected.ClientResult = CRIDLinkKnockV1ResultServerError
		}), "expectation")
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
	for _, name := range []string{
		"reject_origin_as_userinfo", "reject_origin_uppercase_scheme", "reject_origin_uppercase_host",
		"reject_origin_default_port", "reject_origin_trailing_dot",
		"reject_origin_backslash", "reject_origin_tab_in_host",
	} {
		t.Run("verification "+name+" accepted", func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
				c := verificationCase(t, lf, name)
				c.Outcome, c.RejectClass = ExpectAccept, ""
			}), "expectation")
		})
		t.Run("verification "+name+" given the path class", func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
				verificationCase(t, lf, name).RejectClass = CRIDLinkKnockV1RejectPathOrQuery
			}), "expectation")
		})
		t.Run("verification "+name+" respelled as the link origin", func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
				c := verificationCase(t, lf, name)
				c.Body = setMember(t, c.Body, "redirectUrl", lf.Fixtures.Link)
			}), "input does not match its fixture")
		})
	}
	for _, name := range []string{"reject_empty_query", "reject_dot_segment"} {
		t.Run("verification "+name+" accepted", func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
				c := verificationCase(t, lf, name)
				c.Outcome, c.RejectClass = ExpectAccept, ""
			}), "expectation")
		})
		t.Run("verification "+name+" given the origin class", func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
				verificationCase(t, lf, name).RejectClass = CRIDLinkKnockV1RejectOrigin
			}), "expectation")
		})
		t.Run("verification "+name+" respelled as the bare link", func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
				c := verificationCase(t, lf, name)
				c.Body = setMember(t, c.Body, "redirectUrl", lf.Fixtures.Link)
			}), "input does not match its fixture")
		})
	}
	t.Run("verification link without slash rejected", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := verificationCase(t, lf, "accept_link_without_slash")
			c.Outcome, c.RejectClass = ExpectReject, CRIDLinkKnockV1RejectPathOrQuery
		}), "expectation")
	})
	t.Run("verification link without slash given its slash", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := verificationCase(t, lf, "accept_link_without_slash")
			c.Body = setMember(t, c.Body, "redirectUrl", lf.Fixtures.Link)
		}), "input does not match its fixture")
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
	for _, name := range []string{
		"reject_redirect_info_crid_number", "reject_redirect_info_crid_null", "reject_redirect_info_crid_object",
	} {
		t.Run("verification "+name+" accepted", func(t *testing.T) {
			assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
				c := verificationCase(t, lf, name)
				c.Outcome, c.RejectClass = ExpectAccept, ""
			}), "expectation")
		})
	}
	t.Run("verification null crid made absent", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			c := verificationCase(t, lf, "reject_redirect_info_crid_null")
			var info map[string]any
			var body map[string]json.RawMessage
			if err := json.Unmarshal(c.Body, &body); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body["redirectInfo"], &info); err != nil {
				t.Fatal(err)
			}
			delete(info, "crid")
			c.Body = setMember(t, c.Body, "redirectInfo", info)
		}), "input does not match its fixture")
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
	t.Run("sanitization at-limit qurl id dropped", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "qurl_id_at_limit").Expected.QURLID = ""
		}), "expectation")
	})
	t.Run("sanitization over-long qurl id kept", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "qurl_id_over_limit").Expected.QURLID = cridLinkKnockV1OverLimit(cridLinkKnockV1FixtureQURLID)
		}), "expectation")
	})
	t.Run("sanitization over-long qurl id shortened", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "qurl_id_over_limit").Expected.QURLID = cridLinkKnockV1FixtureQURLID
		}), "expectation")
	})
	t.Run("sanitization over-long expiry shortened", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "expires_at_over_limit").Expected.ExpiresAt = sanitizationCase(t, lf, "full_info").Expected.ExpiresAt
		}), "expectation")
	})
	t.Run("sanitization over-long creation time kept", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "resource_created_at_over_limit").Expected.ResourceCreatedAt = cridLinkKnockV1OverLimit(cridLinkKnockV1FixtureResourceCreatedAt)
		}), "expectation")
	})
	t.Run("sanitization over-long input brought under the cap", func(t *testing.T) {
		assertRejects(t, mutate(t, func(lf *CRIDLinkKnockV1File) {
			sanitizationCase(t, lf, "expires_at_over_limit").RedirectInfo = sanitizationCase(t, lf, "full_info").RedirectInfo
		}), "redirect_info does not match its fixture")
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
