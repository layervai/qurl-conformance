package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	// TargetPathArtifactID identifies the shared Connector target-path input contract.
	TargetPathArtifactID = "qurl-target-path-v1-vectors"
	// TargetPathSchemaVersion is the only schema accepted by this release.
	TargetPathSchemaVersion = 1
	// TargetPathMaxBytes is the complete target_path wire-value limit.
	TargetPathMaxBytes = 2048

	TargetPathRejectEmpty            = "empty"
	TargetPathRejectTooLong          = "too_long"
	TargetPathRejectNotAbsolute      = "not_absolute"
	TargetPathRejectAuthority        = "authority"
	TargetPathRejectInvalidCharacter = "invalid_character"
	TargetPathRejectDotSegment       = "dot_segment"
	TargetPathRejectPercentEncoding  = "percent_encoding"
)

// TargetPathFile is the language-neutral target_path mint contract shared by
// service and SDK consumers.
type TargetPathFile struct {
	Artifact      string             `json:"artifact"`
	SchemaVersion int                `json:"schema_version"`
	Description   string             `json:"description"`
	Contract      TargetPathContract `json:"contract"`
	Cases         []TargetPathCase   `json:"cases"`
}

// TargetPathContract freezes the stable wire and runtime rules that every
// consumer must apply without normalization.
type TargetPathContract struct {
	WireField                       string `json:"wire_field"`
	MaxBytes                        int    `json:"max_bytes"`
	OmittedSemantics                string `json:"omitted_semantics"`
	ExplicitEmptySemantics          string `json:"explicit_empty_semantics"`
	AcceptedCharacterSet            string `json:"accepted_character_set"`
	AcceptedValueHandling           string `json:"accepted_value_handling"`
	PercentEncodingHandling         string `json:"percent_encoding_handling"`
	PercentEscapedPathOpenSupported bool   `json:"percent_escaped_path_open_supported"`
	PercentEscapedPathIssue         string `json:"percent_escaped_path_issue"`

	percentEscapedPathOpenSupportedSet bool
}

// UnmarshalJSON requires the explicit false open-support decision. An omitted
// security field must not silently take Go's false zero value.
func (contract *TargetPathContract) UnmarshalJSON(data []byte) error {
	type plain TargetPathContract
	var decoded plain
	if err := strictDecodeArtifact(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["percent_escaped_path_open_supported"]; !ok {
		return errors.New("conformance: target-path contract missing percent_escaped_path_open_supported")
	}
	*contract = TargetPathContract(decoded)
	contract.percentEscapedPathOpenSupportedSet = true
	return nil
}

// TargetPathCase is one direct public-SDK option input. Present distinguishes
// omission from an explicit empty string. OpenSupported is required only for
// accepted cases; a false value records the current percent-escaped path gap.
type TargetPathCase struct {
	Name          string  `json:"name"`
	Present       bool    `json:"present"`
	Value         *string `json:"value,omitempty"`
	Outcome       string  `json:"outcome"`
	RejectClass   string  `json:"reject_class,omitempty"`
	OpenSupported *bool   `json:"open_supported,omitempty"`

	presentSet       bool
	valueSet         bool
	rejectClassSet   bool
	openSupportedSet bool
}

// UnmarshalJSON retains optional-field presence and requires present itself.
// This keeps omission different from explicit null, empty, and false values.
func (c *TargetPathCase) UnmarshalJSON(data []byte) error {
	type plain TargetPathCase
	var decoded plain
	if err := strictDecodeArtifact(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["present"]; !ok {
		return errors.New("conformance: target-path case missing present")
	}
	*c = TargetPathCase(decoded)
	c.presentSet = true
	_, c.valueSet = fields["value"]
	_, c.rejectClassSet = fields["reject_class"]
	_, c.openSupportedSet = fields["open_supported"]
	return nil
}

type targetPathFixture struct {
	present bool
	value   *string
}

func targetPathValue(value string) *string { return &value }

var targetPathFixtures = map[string]targetPathFixture{
	"accept_omitted":                            {present: false},
	"accept_root":                               {present: true, value: targetPathValue("/")},
	"accept_simple_path":                        {present: true, value: targetPathValue("/view/abc123")},
	"accept_path_query":                         {present: true, value: targetPathValue("/view/abc123?sig=deadBEEF&exp=1700000000")},
	"accept_allowed_ascii":                      {present: true, value: targetPathValue("/a-b_c.d~e!f$g&h'i(j)k*l+m,n;o=p:q@r")},
	"accept_deep_path":                          {present: true, value: targetPathValue("/a/b/c/d/e/f")},
	"accept_dotdot_substring":                   {present: true, value: targetPathValue("/view/a..b")},
	"accept_three_dot_segment":                  {present: true, value: targetPathValue("/view/...")},
	"accept_single_dot_segment":                 {present: true, value: targetPathValue("/a/./b")},
	"accept_dotdot_in_query":                    {present: true, value: targetPathValue("/view/x?redir=../../etc")},
	"accept_authority_text_in_query":            {present: true, value: targetPathValue("/path?next=//evil.example")},
	"accept_trailing_slash":                     {present: true, value: targetPathValue("/view/")},
	"accept_empty_query":                        {present: true, value: targetPathValue("/?")},
	"accept_percent_path_upper":                 {present: true, value: targetPathValue("/view/a%4Ab")},
	"accept_percent_path_lower":                 {present: true, value: targetPathValue("/view/a%4ab")},
	"accept_percent_path_safe_41":               {present: true, value: targetPathValue("/view/a%41b")},
	"accept_double_encoded_dot_path":            {present: true, value: targetPathValue("/view/a%252eb")},
	"accept_encoded_backslash_lower_path":       {present: true, value: targetPathValue("/view/a%5cb")},
	"accept_encoded_backslash_upper_path":       {present: true, value: targetPathValue("/view/a%5Cb")},
	"accept_encoded_nul_path":                   {present: true, value: targetPathValue("/view/a%00b")},
	"accept_encoded_fragment_marker_path":       {present: true, value: targetPathValue("/view/a%23b")},
	"accept_encoded_query_marker_path":          {present: true, value: targetPathValue("/view/a%3fb")},
	"accept_encoded_carriage_return_path":       {present: true, value: targetPathValue("/view/a%0db")},
	"accept_encoded_line_feed_path":             {present: true, value: targetPathValue("/view/a%0ab")},
	"accept_percent_only_in_query":              {present: true, value: targetPathValue("/view/x?sig=a%20b")},
	"accept_encoded_dot_slash_in_query":         {present: true, value: targetPathValue("/view/x?next=%2e%2E%2f%2F")},
	"accept_max_bytes":                          {present: true, value: targetPathValue("/" + strings.Repeat("a", TargetPathMaxBytes-1))},
	"reject_explicit_empty":                     {present: true, value: targetPathValue("")},
	"reject_too_long":                           {present: true, value: targetPathValue("/" + strings.Repeat("a", TargetPathMaxBytes))},
	"reject_suffix_host":                        {present: true, value: targetPathValue(".evil.example/x")},
	"reject_relative_path":                      {present: true, value: targetPathValue("view/abc")},
	"reject_absolute_url":                       {present: true, value: targetPathValue("https://evil.example/x")},
	"reject_protocol_relative_authority":        {present: true, value: targetPathValue("//evil.example/path")},
	"reject_leading_backslash":                  {present: true, value: targetPathValue("/\\evil.example")},
	"reject_backslash_in_path":                  {present: true, value: targetPathValue("/view\\..\\x")},
	"reject_fragment":                           {present: true, value: targetPathValue("/view/x#fragment")},
	"reject_space":                              {present: true, value: targetPathValue("/view /x")},
	"reject_tab":                                {present: true, value: targetPathValue("/view\t/x")},
	"reject_newline":                            {present: true, value: targetPathValue("/view\n/x")},
	"reject_carriage_return":                    {present: true, value: targetPathValue("/view\r/x")},
	"reject_nul":                                {present: true, value: targetPathValue("/view\x00/x")},
	"reject_del":                                {present: true, value: targetPathValue("/view\x7f/x")},
	"reject_non_ascii":                          {present: true, value: targetPathValue("/view/é")},
	"reject_dotdot_leading":                     {present: true, value: targetPathValue("/../etc/passwd")},
	"reject_dotdot_middle":                      {present: true, value: targetPathValue("/view/../../secret")},
	"reject_dotdot_trailing":                    {present: true, value: targetPathValue("/view/..")},
	"reject_percent_encoded_dot_lower":          {present: true, value: targetPathValue("/%2e%2e/secret")},
	"reject_percent_encoded_dot_upper":          {present: true, value: targetPathValue("/%2E%2E/secret")},
	"reject_percent_encoded_single_dot":         {present: true, value: targetPathValue("/a%2eb")},
	"reject_percent_encoded_slash_lower":        {present: true, value: targetPathValue("/view%2fsecret")},
	"reject_percent_encoded_slash_upper":        {present: true, value: targetPathValue("/view%2Fsecret")},
	"reject_bare_percent":                       {present: true, value: targetPathValue("/a%")},
	"reject_short_percent":                      {present: true, value: targetPathValue("/a%2")},
	"reject_non_hex_percent_path":               {present: true, value: targetPathValue("/view/x%2Gy")},
	"reject_non_hex_percent_query":              {present: true, value: targetPathValue("/view/x?sig=a%ZZ")},
	"reject_percent_followed_by_path_separator": {present: true, value: targetPathValue("/a%/b")},
}

var targetPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$`)

// ParseTargetPathFile strictly parses and independently re-derives every case.
func ParseTargetPathFile(data []byte) (*TargetPathFile, error) {
	var tf TargetPathFile
	if err := strictDecodeArtifact(data, &tf); err != nil {
		return nil, fmt.Errorf("conformance: parse target-path file: %w", err)
	}
	if tf.Artifact != TargetPathArtifactID {
		return nil, fmt.Errorf("conformance: target-path file has artifact %q, want %q", tf.Artifact, TargetPathArtifactID)
	}
	if tf.SchemaVersion != TargetPathSchemaVersion {
		return nil, fmt.Errorf("conformance: target-path file has schema_version %d, want %d", tf.SchemaVersion, TargetPathSchemaVersion)
	}
	if tf.Description == "" {
		return nil, errors.New("conformance: target-path file has empty description")
	}
	wantContract := TargetPathContract{
		WireField:                          "target_path",
		MaxBytes:                           TargetPathMaxBytes,
		OmittedSemantics:                   "bare_origin",
		ExplicitEmptySemantics:             "reject",
		AcceptedCharacterSet:               "raw_ascii_uri_path_and_query",
		AcceptedValueHandling:              "preserve_exact_bytes",
		PercentEncodingHandling:            "reject_path_dot_and_slash_accept_other_well_formed_without_normalize_or_decode",
		PercentEscapedPathOpenSupported:    false,
		PercentEscapedPathIssue:            "qurl-service#1250",
		percentEscapedPathOpenSupportedSet: true,
	}
	if !tf.Contract.percentEscapedPathOpenSupportedSet || tf.Contract != wantContract {
		return nil, fmt.Errorf("conformance: target-path contract = %+v, want %+v", tf.Contract, wantContract)
	}
	if err := validateTargetPathCases(tf.Cases); err != nil {
		return nil, err
	}
	return &tf, nil
}

func validateTargetPathCases(cases []TargetPathCase) error {
	if len(cases) != len(targetPathFixtures) {
		return fmt.Errorf("conformance: target-path case count = %d, want %d", len(cases), len(targetPathFixtures))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		fixture, ok := targetPathFixtures[c.Name]
		if !ok {
			return fmt.Errorf("conformance: unknown target-path case %q", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate target-path case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if !c.presentSet {
			return fmt.Errorf("conformance: target-path case %q is missing present", c.Name)
		}
		if c.valueSet != c.Present {
			return fmt.Errorf("conformance: target-path case %q value presence does not match present", c.Name)
		}
		if c.Present != fixture.present || !equalOptionalString(c.Value, fixture.value) {
			return fmt.Errorf("conformance: target-path case %q input does not match its fixture", c.Name)
		}
		outcome, rejectClass, openSupported, err := deriveTargetPathExpectation(c.Present, c.Value)
		if err != nil {
			return fmt.Errorf("conformance: target-path case %q: %w", c.Name, err)
		}
		if c.Outcome != outcome || c.RejectClass != rejectClass {
			return fmt.Errorf("conformance: target-path case %q expectation = %q/%q, want %q/%q", c.Name, c.Outcome, c.RejectClass, outcome, rejectClass)
		}
		if outcome == ExpectAccept {
			if c.rejectClassSet {
				return fmt.Errorf("conformance: accepted target-path case %q must omit reject_class", c.Name)
			}
			if !c.openSupportedSet || c.OpenSupported == nil || *c.OpenSupported != openSupported {
				return fmt.Errorf("conformance: target-path case %q open_supported does not match %t", c.Name, openSupported)
			}
		} else {
			if !c.rejectClassSet {
				return fmt.Errorf("conformance: rejected target-path case %q is missing reject_class", c.Name)
			}
			if c.openSupportedSet {
				return fmt.Errorf("conformance: rejected target-path case %q must omit open_supported", c.Name)
			}
		}
	}
	return nil
}

func equalOptionalString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func deriveTargetPathExpectation(present bool, value *string) (outcome, rejectClass string, openSupported bool, err error) {
	if !present {
		if value != nil {
			return "", "", false, errors.New("omitted input must not carry value")
		}
		return ExpectAccept, "", true, nil
	}
	if value == nil {
		return "", "", false, errors.New("present input must carry value")
	}
	p := *value
	if p == "" {
		return ExpectReject, TargetPathRejectEmpty, false, nil
	}
	if len(p) > TargetPathMaxBytes {
		return ExpectReject, TargetPathRejectTooLong, false, nil
	}
	if !strings.HasPrefix(p, "/") {
		return ExpectReject, TargetPathRejectNotAbsolute, false, nil
	}
	if strings.HasPrefix(p, "//") {
		return ExpectReject, TargetPathRejectAuthority, false, nil
	}
	if !targetPathPattern.MatchString(p) {
		return ExpectReject, TargetPathRejectInvalidCharacter, false, nil
	}
	if _, parseErr := url.PathUnescape(p); parseErr != nil {
		return ExpectReject, TargetPathRejectPercentEncoding, false, nil
	}
	pathPart := p
	if i := strings.IndexByte(p, '?'); i >= 0 {
		pathPart = p[:i]
	}
	for i := 0; i < len(pathPart); i++ {
		if pathPart[i] != '%' {
			continue
		}
		// PathUnescape above proves that every percent escape has two following
		// bytes. Keep this guard so later validation reordering stays fail-closed.
		if i+3 > len(pathPart) {
			return ExpectReject, TargetPathRejectPercentEncoding, false, nil
		}
		escape := pathPart[i+1 : i+3]
		switch {
		case strings.EqualFold(escape, "2e"):
			return ExpectReject, TargetPathRejectDotSegment, false, nil
		case strings.EqualFold(escape, "2f"):
			return ExpectReject, TargetPathRejectInvalidCharacter, false, nil
		}
		i += 2
	}
	openSupported = !strings.Contains(pathPart, "%")
	for _, segment := range strings.Split(pathPart, "/") {
		if segment == ".." {
			return ExpectReject, TargetPathRejectDotSegment, false, nil
		}
		if segment == "." {
			// Browsers and routers can remove this segment before the Connector
			// sees it, while the stored authorization scope remains byte exact.
			openSupported = false
		}
	}
	return ExpectAccept, "", openSupported, nil
}
