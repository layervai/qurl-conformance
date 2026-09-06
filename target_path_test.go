package conformance

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestEmbeddedTargetPathV1Loads(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatalf("TargetPathV1(): %v", err)
	}
	if tf.Artifact != TargetPathArtifactID || tf.SchemaVersion != TargetPathSchemaVersion {
		t.Fatalf("identity = %q/v%d, want %q/v%d", tf.Artifact, tf.SchemaVersion, TargetPathArtifactID, TargetPathSchemaVersion)
	}
	if got, want := len(tf.Cases), len(targetPathFixtures); got != want {
		t.Fatalf("case count = %d, want %d", got, want)
	}

	wantRejectClasses := map[string]bool{
		TargetPathRejectEmpty:            false,
		TargetPathRejectTooLong:          false,
		TargetPathRejectNotAbsolute:      false,
		TargetPathRejectAuthority:        false,
		TargetPathRejectInvalidCharacter: false,
		TargetPathRejectDotSegment:       false,
		TargetPathRejectPercentEncoding:  false,
	}
	for _, c := range tf.Cases {
		outcome, rejectClass, openSupported, deriveErr := deriveTargetPathExpectation(c.Present, c.Value)
		if deriveErr != nil {
			t.Errorf("case %q derive: %v", c.Name, deriveErr)
			continue
		}
		if c.Outcome != outcome || c.RejectClass != rejectClass {
			t.Errorf("case %q expectation = %q/%q, want %q/%q", c.Name, c.Outcome, c.RejectClass, outcome, rejectClass)
		}
		if rejectClass != "" {
			if _, ok := wantRejectClasses[rejectClass]; !ok {
				t.Errorf("case %q has unknown reject_class %q", c.Name, rejectClass)
			} else {
				wantRejectClasses[rejectClass] = true
			}
		}
		if outcome == ExpectAccept && (c.OpenSupported == nil || *c.OpenSupported != openSupported) {
			t.Errorf("case %q open_supported does not match %t", c.Name, openSupported)
		}
		if outcome == ExpectAccept && !openSupported {
			t.Errorf("case %q is accepted but not safe to open", c.Name)
		}
	}
	for rejectClass, present := range wantRejectClasses {
		if !present {
			t.Errorf("reject_class %q has no fixture", rejectClass)
		}
	}
}

func TestTargetPathBoundaryAndPresenceSemantics(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	omitted := targetPathCase(t, tf, "accept_omitted")
	if omitted.Present || omitted.Value != nil || omitted.Outcome != ExpectAccept {
		t.Fatalf("omitted case = %+v", *omitted)
	}
	empty := targetPathCase(t, tf, "reject_explicit_empty")
	if !empty.Present || empty.Value == nil || *empty.Value != "" || empty.RejectClass != TargetPathRejectEmpty {
		t.Fatalf("explicit-empty case = %+v", *empty)
	}
	atMax := targetPathCase(t, tf, "accept_max_bytes")
	tooLong := targetPathCase(t, tf, "reject_too_long")
	if len(*atMax.Value) != TargetPathMaxBytes || len(*tooLong.Value) != TargetPathMaxBytes+1 {
		t.Fatalf("boundary lengths = %d/%d, want %d/%d", len(*atMax.Value), len(*tooLong.Value), TargetPathMaxBytes, TargetPathMaxBytes+1)
	}
	atMaxWithQuery := targetPathCase(t, tf, "accept_max_bytes_with_query")
	tooLongWithQuery := targetPathCase(t, tf, "reject_too_long_with_query")
	if len(*atMaxWithQuery.Value) != TargetPathMaxBytes || len(*tooLongWithQuery.Value) != TargetPathMaxBytes+1 {
		t.Fatalf("query boundary lengths = %d/%d, want %d/%d", len(*atMaxWithQuery.Value), len(*tooLongWithQuery.Value), TargetPathMaxBytes, TargetPathMaxBytes+1)
	}
	overlongNonASCII := targetPathCase(t, tf, "reject_overlong_non_ascii_precedence")
	if got := len(*overlongNonASCII.Value); got != TargetPathMaxBytes+1 {
		t.Fatalf("non-ASCII boundary bytes = %d, want %d", got, TargetPathMaxBytes+1)
	}
	if got := len([]rune(*overlongNonASCII.Value)); got != TargetPathMaxBytes {
		t.Fatalf("non-ASCII boundary characters = %d, want %d", got, TargetPathMaxBytes)
	}
	if overlongNonASCII.RejectClass != TargetPathRejectTooLong {
		t.Fatalf("non-ASCII boundary reject_class = %q, want %q", overlongNonASCII.RejectClass, TargetPathRejectTooLong)
	}
	overlongRelative := targetPathCase(t, tf, "reject_overlong_relative_precedence")
	if got := len(*overlongRelative.Value); got != TargetPathMaxBytes+1 {
		t.Fatalf("relative boundary bytes = %d, want %d", got, TargetPathMaxBytes+1)
	}
	if strings.HasPrefix(*overlongRelative.Value, "/") || overlongRelative.RejectClass != TargetPathRejectTooLong {
		t.Fatalf("relative boundary case = %+v, want too_long before not_absolute", *overlongRelative)
	}
	overlongAuthority := targetPathCase(t, tf, "reject_overlong_authority_precedence")
	if got := len(*overlongAuthority.Value); got != TargetPathMaxBytes+1 {
		t.Fatalf("authority boundary bytes = %d, want %d", got, TargetPathMaxBytes+1)
	}
	if !strings.HasPrefix(*overlongAuthority.Value, "//") || overlongAuthority.RejectClass != TargetPathRejectTooLong {
		t.Fatalf("authority boundary case = %+v, want too_long before authority", *overlongAuthority)
	}
	for _, name := range []string{
		"reject_overlong_dot_segment_precedence",
		"reject_overlong_percent_precedence",
	} {
		c := targetPathCase(t, tf, name)
		if got := len(*c.Value); got != TargetPathMaxBytes+1 {
			t.Errorf("case %q bytes = %d, want %d", name, got, TargetPathMaxBytes+1)
		}
		if c.RejectClass != TargetPathRejectTooLong {
			t.Errorf("case %q class = %q, want too_long precedence", name, c.RejectClass)
		}
	}
}

func TestTargetPathWholeValueAndAuthorityPrecedence(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"reject_trailing_line_feed",
		"reject_trailing_line_feed_after_query",
		"reject_line_feed_in_query",
		"reject_trailing_carriage_return",
		"reject_trailing_carriage_return_line_feed",
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != TargetPathRejectInvalidCharacter {
			t.Errorf("case %q = %+v, want full-value invalid_character rejection", name, *c)
		}
	}
	for _, name := range []string{
		"reject_authority_invalid_character",
		"reject_authority_malformed_percent",
		"reject_authority_dot_segment",
	} {
		authority := targetPathCase(t, tf, name)
		if authority.Outcome != ExpectReject || authority.RejectClass != TargetPathRejectAuthority {
			t.Errorf("authority precedence case %q = %+v, want authority rejection", name, *authority)
		}
	}
	relative := targetPathCase(t, tf, "reject_relative_invalid_character")
	if relative.Outcome != ExpectReject || relative.RejectClass != TargetPathRejectNotAbsolute {
		t.Errorf("relative precedence case = %+v, want not_absolute rejection", *relative)
	}
	dot := targetPathCase(t, tf, "reject_dot_segment_after_interior_empty")
	if dot.Outcome != ExpectReject || dot.RejectClass != TargetPathRejectDotSegment {
		t.Errorf("dot precedence case = %+v, want dot_segment rejection", *dot)
	}
}

func TestTargetPathSecurityCasesHaveIndependentClassPins(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	for name, wantClass := range map[string]string{
		"reject_userinfo_origin_concatenation":      TargetPathRejectNotAbsolute,
		"reject_suffix_host":                        TargetPathRejectNotAbsolute,
		"reject_absolute_url":                       TargetPathRejectNotAbsolute,
		"reject_relative_path":                      TargetPathRejectNotAbsolute,
		"reject_query_only":                         TargetPathRejectNotAbsolute,
		"reject_leading_space":                      TargetPathRejectNotAbsolute,
		"reject_protocol_relative_authority":        TargetPathRejectAuthority,
		"reject_authority_semicolon":                TargetPathRejectAuthority,
		"reject_overlong_dot_segment_precedence":    TargetPathRejectTooLong,
		"reject_overlong_percent_precedence":        TargetPathRejectTooLong,
		"reject_relative_dot_segment_precedence":    TargetPathRejectNotAbsolute,
		"reject_relative_malformed_percent":         TargetPathRejectNotAbsolute,
		"reject_bare_percent":                       TargetPathRejectPercentEncoding,
		"reject_short_percent":                      TargetPathRejectPercentEncoding,
		"reject_non_hex_percent_path":               TargetPathRejectPercentEncoding,
		"reject_non_hex_percent_query":              TargetPathRejectPercentEncoding,
		"reject_truncated_percent_in_query":         TargetPathRejectPercentEncoding,
		"reject_short_percent_in_query":             TargetPathRejectPercentEncoding,
		"reject_percent_followed_by_path_separator": TargetPathRejectPercentEncoding,
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != wantClass {
			t.Errorf("case %q = %+v, want rejected as %q", name, *c, wantClass)
		}
	}
}

func TestTargetPathAcceptedValuesKeepHostFixed(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://r_rs34rcbaf3q.qurl.site"
	const wantHost = "r_rs34rcbaf3q.qurl.site"
	for _, c := range tf.Cases {
		if c.Outcome != ExpectAccept {
			continue
		}
		if !c.Present {
			continue
		}
		value := ""
		if c.Value != nil {
			value = *c.Value
		}
		u, parseErr := url.Parse(origin + value)
		if parseErr != nil {
			t.Errorf("case %q composed URL: %v", c.Name, parseErr)
			continue
		}
		if u.Scheme != "https" || u.Hostname() != wantHost {
			t.Errorf("case %q changed origin to %q://%q", c.Name, u.Scheme, u.Hostname())
		}
		wantPath := value
		if query := strings.IndexByte(wantPath, '?'); query >= 0 {
			wantPath = wantPath[:query]
		}
		if u.Path != wantPath {
			t.Errorf("case %q changed path to %q, want %q", c.Name, u.Path, wantPath)
		}
		if u.RequestURI() != value {
			t.Errorf("case %q changed request target to %q, want exact %q", c.Name, u.RequestURI(), value)
		}
		pathPart, rawQuery, hasQuery := strings.Cut(value, "?")
		// The parsed URL can retain RawPath. A fresh URL forces Go to escape the
		// accepted path again; v1 has no accepted path escapes to preserve.
		serialized := (&url.URL{
			Path:       pathPart,
			RawQuery:   rawQuery,
			ForceQuery: hasQuery && rawQuery == "",
		}).RequestURI()
		if serialized != value {
			t.Errorf("case %q serialized request target to %q, want exact %q", c.Name, serialized, value)
		}
		if u.Path != "" && (!strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//")) {
			t.Errorf("case %q produced unsafe decoded path %q", c.Name, u.Path)
		}
		for _, segment := range strings.Split(u.Path, "/") {
			if segment == "." || segment == ".." {
				t.Errorf("case %q produced decoded dot segment in path %q", c.Name, u.Path)
			}
		}
	}
}

func TestTargetPathRejectsPathEscapesAndPreservesQueryEscapes(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	for name, rejectClass := range map[string]string{
		"reject_percent_encoded_dot_lower":         TargetPathRejectDotSegment,
		"reject_percent_encoded_dot_upper":         TargetPathRejectDotSegment,
		"reject_percent_encoded_single_dot":        TargetPathRejectDotSegment,
		"reject_percent_encoded_dot_with_query":    TargetPathRejectDotSegment,
		"reject_dot_escape_at_query_boundary":      TargetPathRejectDotSegment,
		"reject_mixed_percent_letter_dot_escape":   TargetPathRejectDotSegment,
		"reject_literal_dot_with_percent_escape":   TargetPathRejectDotSegment,
		"reject_percent_encoded_slash_lower":       TargetPathRejectInvalidCharacter,
		"reject_percent_encoded_slash_upper":       TargetPathRejectInvalidCharacter,
		"reject_percent_encoded_letter_upper_path": TargetPathRejectInvalidCharacter,
		"reject_percent_encoded_letter_lower_path": TargetPathRejectInvalidCharacter,
		"reject_percent_encoded_letter_41_path":    TargetPathRejectInvalidCharacter,
		"reject_path_escape_with_valid_query":      TargetPathRejectInvalidCharacter,
		"reject_double_encoded_dot_path":           TargetPathRejectInvalidCharacter,
		"reject_encoded_backslash_lower_path":      TargetPathRejectInvalidCharacter,
		"reject_encoded_backslash_upper_path":      TargetPathRejectInvalidCharacter,
		"reject_encoded_nul_path":                  TargetPathRejectInvalidCharacter,
		"reject_encoded_fragment_marker_path":      TargetPathRejectInvalidCharacter,
		"reject_encoded_query_marker_path":         TargetPathRejectInvalidCharacter,
		"reject_encoded_carriage_return_path":      TargetPathRejectInvalidCharacter,
		"reject_encoded_line_feed_path":            TargetPathRejectInvalidCharacter,
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != rejectClass {
			t.Errorf("case %q = %+v, want rejected as %q", name, *c, rejectClass)
		}
	}
	for name, value := range map[string]string{
		"accept_percent_only_in_query":      "/view/x?sig=a%20b",
		"accept_encoded_dot_slash_in_query": "/view/x?next=%2e%2E%2f%2F",
		"accept_encoded_controls_in_query":  "/view/x?a=%0d%0a%00",
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectAccept || c.OpenSupported == nil || !*c.OpenSupported {
			t.Errorf("case %q = %+v, want accepted and open-supported", name, *c)
		}
		if c.Value == nil || *c.Value != value {
			t.Errorf("case %q value = %v, want byte-exact %q", name, c.Value, value)
		}
	}
}

func TestTargetPathRejectsPrintableCharacterOutsideClosedSet(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	c := targetPathCase(t, tf, "reject_left_bracket")
	if c.Outcome != ExpectReject || c.RejectClass != TargetPathRejectInvalidCharacter {
		t.Errorf("left-bracket case = %+v, want invalid_character rejection", *c)
	}
	for value := byte(0x00); value <= 0x7f; value++ {
		allowed := strings.ContainsRune(tf.Contract.AllowedASCII, rune(value))
		matched := targetPathPattern.MatchString("/" + string(value))
		if allowed != matched {
			t.Errorf("allowed_ascii and validator differ for byte 0x%02x", value)
		}
	}
}

func TestTargetPathRejectsInvalidQueryCharacters(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"reject_fragment_in_query",
		"reject_space_in_query",
		"reject_backslash_in_query",
		"reject_non_ascii_in_query",
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != TargetPathRejectInvalidCharacter {
			t.Errorf("case %q = %+v, want invalid_character rejection", name, *c)
		}
	}
}

func TestTargetPathDotSegmentPrecedence(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"reject_mixed_percent_letter_dot_escape",
		"reject_literal_dot_with_percent_escape",
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != TargetPathRejectDotSegment {
			t.Errorf("case %q = %+v, want dot_segment precedence", name, *c)
		}
	}
}

func TestTargetPathMalformedPercentPrecedence(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"reject_malformed_percent_with_dot_segment",
		"reject_malformed_percent_with_dot_escape",
		"reject_malformed_query_with_dot_escape_path",
		"reject_malformed_query_with_other_path_escape",
		"reject_malformed_query_before_interior_empty",
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != TargetPathRejectPercentEncoding {
			t.Errorf("case %q = %+v, want percent_encoding precedence", name, *c)
		}
	}
}

func TestTargetPathInvalidCharacterPrecedesMalformedPercent(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"reject_semicolon_malformed_percent",
		"reject_left_bracket_malformed_percent",
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != TargetPathRejectInvalidCharacter {
			t.Errorf("case %q = %+v, want invalid_character precedence", name, *c)
		}
	}
}

func TestTargetPathRejectsDotSegmentsNotDotSubstrings(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"accept_dotdot_substring", "accept_three_dot_segment"} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectAccept || c.OpenSupported == nil || !*c.OpenSupported {
			t.Errorf("case %q = %+v, want accepted and open-supported", name, *c)
		}
	}
	for _, name := range []string{"reject_single_dot_segment", "reject_dotdot_leading", "reject_dotdot_middle", "reject_dotdot_trailing"} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != TargetPathRejectDotSegment {
			t.Errorf("case %q = %+v, want dot_segment rejection", name, *c)
		}
	}
}

func TestTargetPathCanonicalSlashRules(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"accept_root", "accept_trailing_slash", "accept_trailing_slash_with_query"} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectAccept || c.OpenSupported == nil || !*c.OpenSupported {
			t.Errorf("case %q = %+v, want accepted and open-supported", name, *c)
		}
	}
	for _, name := range []string{"reject_interior_empty_segment", "reject_interior_empty_segment_with_query", "reject_trailing_double_slash"} {
		interiorEmpty := targetPathCase(t, tf, name)
		if interiorEmpty.Outcome != ExpectReject || interiorEmpty.RejectClass != TargetPathRejectInvalidCharacter {
			t.Errorf("case %q = %+v, want invalid_character rejection", name, *interiorEmpty)
		}
	}
}

func TestTargetPathForbiddenASCIIIsQueryOnly(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	if tf.Contract.ForbiddenPathASCII != TargetPathForbiddenPathASCII {
		t.Fatalf("forbidden path ASCII = %q, want %q", tf.Contract.ForbiddenPathASCII, TargetPathForbiddenPathASCII)
	}
	for name, value := range map[string]string{
		"reject_exclamation_in_path":       "/view/a!b",
		"reject_left_parenthesis_in_path":  "/view/a(b",
		"reject_right_parenthesis_in_path": "/view/a)b",
		"reject_asterisk_in_path":          "/view/a*b",
		"reject_semicolon_in_path":         "/view/abc;x=1",
		"reject_semicolon_path_with_query": "/view/a;b?c=1",
	} {
		pathCase := targetPathCase(t, tf, name)
		if pathCase.Outcome != ExpectReject || pathCase.RejectClass != TargetPathRejectInvalidCharacter {
			t.Errorf("forbidden path ASCII case %q = %+v, want invalid_character rejection", name, *pathCase)
		}
		if pathCase.Value == nil || *pathCase.Value != value {
			t.Errorf("forbidden path ASCII case %q value = %v, want %q", name, pathCase.Value, value)
		}
	}
	for _, character := range TargetPathForbiddenPathASCII {
		if !strings.ContainsRune(tf.Contract.AllowedASCII, character) {
			t.Errorf("query-allowed character %q is missing from allowed_ascii", character)
		}
		value := "/view/x?q=" + string(character)
		outcome, class, openSupported, deriveErr := deriveTargetPathExpectation(true, &value)
		if deriveErr != nil {
			t.Errorf("query byte %q derive: %v", character, deriveErr)
			continue
		}
		if outcome != ExpectAccept || class != "" || !openSupported {
			t.Errorf("query byte %q = (%q, %q, %t), want accepted and open-supported", character, outcome, class, openSupported)
		}
	}
	for name, value := range map[string]string{
		"accept_allowed_query_ascii": "/view/x?q=!()*;",
		"accept_semicolon_in_query":  "/view/abc?x=1;y=2",
	} {
		queryCase := targetPathCase(t, tf, name)
		if queryCase.Outcome != ExpectAccept || queryCase.OpenSupported == nil || !*queryCase.OpenSupported {
			t.Errorf("query case %q = %+v, want accepted and open-supported", name, *queryCase)
		}
		if queryCase.Value == nil || *queryCase.Value != value {
			t.Errorf("query case %q value = %v, want %q", name, queryCase.Value, value)
		}
	}
}

func TestTargetPathForbiddenASCIIIsExactPathOnlySet(t *testing.T) {
	const stablePathByte = ';'
	for _, character := range TargetPathForbiddenPathASCII {
		path := "/x" + string(character) + "y"
		serialized := (&url.URL{Path: path}).RequestURI()
		if character == stablePathByte {
			if serialized != path {
				t.Errorf("stable path byte %q serialized to %q, want %q", character, serialized, path)
			}
			continue
		}
		if serialized == path {
			t.Errorf("URL-drifting path byte %q unexpectedly stayed byte-exact", character)
		}
	}
	for _, character := range []byte(TargetPathAllowedASCII) {
		// '?' delimits the query and '%' starts an escape, so neither can be a
		// raw byte inside an accepted path segment.
		if character == '?' || character == '%' ||
			strings.IndexByte(TargetPathForbiddenPathASCII, character) >= 0 {
			continue
		}
		path := "/x" + string(character) + "y"
		if serialized := (&url.URL{Path: path}).RequestURI(); serialized != path {
			t.Errorf("path byte %q serialized to %q but is not forbidden", character, serialized)
		}
	}
}

func TestTargetPathRejectsApostropheInPathAndQuery(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(tf.Contract.AllowedASCII, '\'') {
		t.Error("apostrophe must not be in allowed_ascii")
	}
	for name, value := range map[string]string{
		"reject_apostrophe_in_path":  "/view/a'b",
		"reject_apostrophe_in_query": "/view/a?q='b",
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != TargetPathRejectInvalidCharacter {
			t.Errorf("case %q = %+v, want invalid_character rejection", name, *c)
		}
		if c.Value == nil || *c.Value != value {
			t.Errorf("case %q value = %v, want %q", name, c.Value, value)
		}
	}
}

func TestTargetPathUsesFirstQuestionMarkAsQueryDelimiter(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	if tf.Contract.QueryDelimiter != "first_question_mark" {
		t.Fatalf("query delimiter = %q, want first_question_mark", tf.Contract.QueryDelimiter)
	}
	accepted := targetPathCase(t, tf, "accept_second_question_mark_in_query")
	if accepted.Outcome != ExpectAccept || accepted.Value == nil ||
		*accepted.Value != "/view/x?next=http://e.example/p?q=1" {
		t.Errorf("second query marker case = %+v, want byte-exact acceptance", *accepted)
	}
	rejected := targetPathCase(t, tf, "reject_dot_segment_before_two_queries")
	if rejected.Outcome != ExpectReject || rejected.RejectClass != TargetPathRejectDotSegment {
		t.Errorf("dot segment before two queries = %+v, want dot_segment", *rejected)
	}
}

func TestParseTargetPathV1FileFailsClosed(t *testing.T) {
	raw := TargetPathV1Vectors()
	mutate := func(t *testing.T, change func(*TargetPathV1File)) []byte {
		t.Helper()
		var tf TargetPathV1File
		if err := json.Unmarshal(raw, &tf); err != nil {
			t.Fatal(err)
		}
		change(&tf)
		body, err := json.Marshal(tf)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	assertRejects := func(t *testing.T, body []byte, contains string) {
		t.Helper()
		if _, err := ParseTargetPathV1File(body); err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("ParseTargetPathV1File() error = %v, want substring %q", err, contains)
		}
	}

	t.Run("duplicate field", func(t *testing.T) {
		body := strings.Replace(string(raw), `"schema_version": 2,`, `"schema_version": 2, "schema_version": 2,`, 1)
		assertRejects(t, []byte(body), "duplicate")
	})
	t.Run("unknown field", func(t *testing.T) {
		body := strings.Replace(string(raw), `"schema_version": 2,`, `"schema_version": 2, "future": true,`, 1)
		assertRejects(t, []byte(body), "unknown field")
	})
	t.Run("artifact", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) { tf.Artifact = "other" }), "artifact")
	})
	t.Run("schema", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) { tf.SchemaVersion++ }), "schema_version")
	})
	t.Run("contract", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) { tf.Contract.MaxBytes++ }), "contract")
	})
	t.Run("allowed ASCII", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) { tf.Contract.AllowedASCII += "<" }), "contract")
	})
	t.Run("forbidden path ASCII", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) { tf.Contract.ForbiddenPathASCII = ";" }), "contract")
	})
	t.Run("query delimiter", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) { tf.Contract.QueryDelimiter = "last_question_mark" }), "contract")
	})
	t.Run("validation order", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) {
			tf.Contract.ValidationOrder[3], tf.Contract.ValidationOrder[4] = tf.Contract.ValidationOrder[4], tf.Contract.ValidationOrder[3]
		}), "contract")
	})
	t.Run("duplicate case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) { tf.Cases[1] = tf.Cases[0] }), "duplicate")
	})
	t.Run("missing case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) { tf.Cases = tf.Cases[1:] }), "count")
	})
	t.Run("unknown case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) { tf.Cases[0].Name = "future_case" }), "unknown")
	})
	t.Run("flipped outcome", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) {
			targetPathCase(t, tf, "accept_root").Outcome = ExpectReject
		}), "expectation")
	})
	t.Run("flipped reject class", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) {
			targetPathCase(t, tf, "reject_fragment").RejectClass = TargetPathRejectDotSegment
		}), "expectation")
	})
	t.Run("accept missing open support", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) {
			targetPathCase(t, tf, "accept_root").OpenSupported = nil
		}), "open_supported")
	})
	t.Run("accept carries empty reject class", func(t *testing.T) {
		body := strings.Replace(string(raw), `      "name": "accept_root",`+"\n", `      "name": "accept_root",`+"\n"+`      "reject_class": "",`+"\n", 1)
		assertRejects(t, []byte(body), "must omit reject_class")
	})
	t.Run("reject has open support", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) {
			value := false
			targetPathCase(t, tf, "reject_fragment").OpenSupported = &value
		}), "must omit")
	})
	t.Run("present without value", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) {
			targetPathCase(t, tf, "accept_root").Value = nil
		}), "value presence")
	})
	t.Run("missing present", func(t *testing.T) {
		body := strings.Replace(string(raw), `      "present": false,`+"\n", "", 1)
		assertRejects(t, []byte(body), "missing present")
	})
	t.Run("omitted with value", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathV1File) {
			value := "/"
			targetPathCase(t, tf, "accept_omitted").Value = &value
		}), "value presence")
	})
	t.Run("omitted with null value", func(t *testing.T) {
		body := strings.Replace(string(raw), `      "present": false,`+"\n", `      "present": false,`+"\n"+`      "value": null,`+"\n", 1)
		assertRejects(t, []byte(body), "value presence")
	})
	t.Run("reject has null open support", func(t *testing.T) {
		body := strings.Replace(string(raw), `      "name": "reject_explicit_empty",`+"\n", `      "name": "reject_explicit_empty",`+"\n"+`      "open_supported": null,`+"\n", 1)
		assertRejects(t, []byte(body), "must omit open_supported")
	})
}

func targetPathCase(t *testing.T, tf *TargetPathV1File, name string) *TargetPathCase {
	t.Helper()
	for i := range tf.Cases {
		if tf.Cases[i].Name == name {
			return &tf.Cases[i]
		}
	}
	t.Fatalf("target-path case %q not found", name)
	return nil
}
