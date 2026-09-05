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
		if u.Path != "" && (!strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//")) {
			t.Errorf("case %q produced unsafe decoded path %q", c.Name, u.Path)
		}
		for _, segment := range strings.Split(u.Path, "/") {
			if segment == ".." {
				t.Errorf("case %q produced decoded dot segment in path %q", c.Name, u.Path)
			}
		}
	}
}

func TestTargetPathPercentEncodingRemainsRaw(t *testing.T) {
	tf, err := TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"accept_percent_path_upper",
		"accept_percent_path_lower",
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectAccept || c.OpenSupported == nil || *c.OpenSupported {
			t.Errorf("case %q = %+v, want accepted with open_supported=false", name, *c)
		}
		if c.Value == nil || !strings.Contains(*c.Value, "%") {
			t.Errorf("case %q lost its raw percent escape", name)
		}
	}
	queryOnly := targetPathCase(t, tf, "accept_percent_only_in_query")
	if queryOnly.OpenSupported == nil || !*queryOnly.OpenSupported {
		t.Errorf("query-only percent escape must remain open-supported")
	}
	for name, rejectClass := range map[string]string{
		"reject_percent_encoded_dot_lower":   TargetPathRejectDotSegment,
		"reject_percent_encoded_dot_upper":   TargetPathRejectDotSegment,
		"reject_percent_encoded_slash_lower": TargetPathRejectInvalidCharacter,
		"reject_percent_encoded_slash_upper": TargetPathRejectInvalidCharacter,
	} {
		c := targetPathCase(t, tf, name)
		if c.Outcome != ExpectReject || c.RejectClass != rejectClass {
			t.Errorf("case %q = %+v, want rejected as %q", name, *c, rejectClass)
		}
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
	t.Run("contract missing explicit false", func(t *testing.T) {
		body := strings.Replace(string(raw), `    "percent_escaped_path_open_supported": false,`+"\n", "", 1)
		assertRejects(t, []byte(body), "missing percent_escaped_path_open_supported")
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
