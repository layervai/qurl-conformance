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
		if c.Present && u.RequestURI() != value {
			t.Errorf("case %q changed request target to %q, want exact %q", c.Name, u.RequestURI(), value)
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
		"reject_mixed_percent_letter_dot_escape":   TargetPathRejectDotSegment,
		"reject_literal_dot_with_percent_escape":   TargetPathRejectDotSegment,
		"reject_percent_encoded_slash_lower":       TargetPathRejectInvalidCharacter,
		"reject_percent_encoded_slash_upper":       TargetPathRejectInvalidCharacter,
		"reject_percent_encoded_letter_upper_path": TargetPathRejectInvalidCharacter,
		"reject_percent_encoded_letter_lower_path": TargetPathRejectInvalidCharacter,
		"reject_percent_encoded_letter_41_path":    TargetPathRejectInvalidCharacter,
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
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != TargetPathRejectPercentEncoding {
			t.Errorf("case %q = %+v, want percent_encoding precedence", name, *c)
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
	for _, name := range []string{"accept_root", "accept_trailing_slash"} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectAccept || c.OpenSupported == nil || !*c.OpenSupported {
			t.Errorf("case %q = %+v, want accepted and open-supported", name, *c)
		}
	}
	interiorEmpty := targetPathCase(t, tf, "reject_interior_empty_segment")
	if interiorEmpty.Outcome != ExpectReject || interiorEmpty.RejectClass != TargetPathRejectInvalidCharacter {
		t.Errorf("interior empty segment = %+v, want invalid_character rejection", *interiorEmpty)
	}
}

func TestTargetPathSemicolonIsQueryOnly(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	pathCase := targetPathCase(t, tf, "reject_semicolon_in_path")
	if pathCase.Outcome != ExpectReject || pathCase.RejectClass != TargetPathRejectInvalidCharacter {
		t.Errorf("path semicolon case = %+v, want invalid_character rejection", *pathCase)
	}
	queryCase := targetPathCase(t, tf, "accept_semicolon_in_query")
	if queryCase.Outcome != ExpectAccept || queryCase.OpenSupported == nil || !*queryCase.OpenSupported {
		t.Errorf("query semicolon case = %+v, want accepted and open-supported", *queryCase)
	}
	if queryCase.Value == nil || *queryCase.Value != "/view/abc?x=1;y=2" {
		t.Errorf("query semicolon value = %v, want byte-exact", queryCase.Value)
	}
}

func TestParseTargetPathFileFailsClosed(t *testing.T) {
	raw := TargetPathV1Vectors()
	mutate := func(t *testing.T, change func(*TargetPathFile)) []byte {
		t.Helper()
		var tf TargetPathFile
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
		if _, err := ParseTargetPathFile(body); err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("ParseTargetPathFile() error = %v, want substring %q", err, contains)
		}
	}

	t.Run("duplicate field", func(t *testing.T) {
		body := strings.Replace(string(raw), `"schema_version": 1,`, `"schema_version": 1, "schema_version": 1,`, 1)
		assertRejects(t, []byte(body), "duplicate")
	})
	t.Run("unknown field", func(t *testing.T) {
		body := strings.Replace(string(raw), `"schema_version": 1,`, `"schema_version": 1, "future": true,`, 1)
		assertRejects(t, []byte(body), "unknown field")
	})
	t.Run("artifact", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) { tf.Artifact = "other" }), "artifact")
	})
	t.Run("schema", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) { tf.SchemaVersion++ }), "schema_version")
	})
	t.Run("contract", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) { tf.Contract.MaxBytes++ }), "contract")
	})
	t.Run("duplicate case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) { tf.Cases[1] = tf.Cases[0] }), "duplicate")
	})
	t.Run("missing case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) { tf.Cases = tf.Cases[1:] }), "count")
	})
	t.Run("unknown case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) { tf.Cases[0].Name = "future_case" }), "unknown")
	})
	t.Run("flipped outcome", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) {
			targetPathCase(t, tf, "accept_root").Outcome = ExpectReject
		}), "expectation")
	})
	t.Run("flipped reject class", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) {
			targetPathCase(t, tf, "reject_fragment").RejectClass = TargetPathRejectDotSegment
		}), "expectation")
	})
	t.Run("accept missing open support", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) {
			targetPathCase(t, tf, "accept_root").OpenSupported = nil
		}), "open_supported")
	})
	t.Run("accept carries empty reject class", func(t *testing.T) {
		body := strings.Replace(string(raw), `      "name": "accept_root",`+"\n", `      "name": "accept_root",`+"\n"+`      "reject_class": "",`+"\n", 1)
		assertRejects(t, []byte(body), "must omit reject_class")
	})
	t.Run("reject has open support", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) {
			value := false
			targetPathCase(t, tf, "reject_fragment").OpenSupported = &value
		}), "must omit")
	})
	t.Run("present without value", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) {
			targetPathCase(t, tf, "accept_root").Value = nil
		}), "value presence")
	})
	t.Run("missing present", func(t *testing.T) {
		body := strings.Replace(string(raw), `      "present": false,`+"\n", "", 1)
		assertRejects(t, []byte(body), "missing present")
	})
	t.Run("omitted with value", func(t *testing.T) {
		assertRejects(t, mutate(t, func(tf *TargetPathFile) {
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

func targetPathCase(t *testing.T, tf *TargetPathFile, name string) *TargetPathCase {
	t.Helper()
	for i := range tf.Cases {
		if tf.Cases[i].Name == name {
			return &tf.Cases[i]
		}
	}
	t.Fatalf("target-path case %q not found", name)
	return nil
}
