package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

const (
	// TargetPathArtifactID identifies the shared Connector target-path input contract.
	TargetPathArtifactID = "qurl-target-path-v1-vectors"
	// TargetPathSchemaVersion is the only schema accepted by this release.
	TargetPathSchemaVersion = 2
	// TargetPathMaxBytes is the complete target_path wire-value limit.
	TargetPathMaxBytes = 2048

	// TargetPathReject* constants are the closed v1 local reject vocabulary.
	TargetPathRejectEmpty            = "empty"
	TargetPathRejectTooLong          = "too_long"
	TargetPathRejectNotAbsolute      = "not_absolute"
	TargetPathRejectAuthority        = "authority"
	TargetPathRejectInvalidCharacter = "invalid_character"
	TargetPathRejectDotSegment       = "dot_segment"
	TargetPathRejectPercentEncoding  = "percent_encoding"

	// TargetPathAllowedASCII is the complete raw ASCII alphabet accepted by
	// the whole-value character gate. Later ordered gates further restrict
	// characters and percent escapes in the path component.
	TargetPathAllowedASCII = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~!$&()*+,;=:@%/?-"
	// TargetPathForbiddenPathASCII is the complete set of raw ASCII characters
	// accepted in the query but rejected in the path component.
	TargetPathForbiddenPathASCII = "!()*;"
)

// Keep this order in lockstep with the gates in deriveTargetPathExpectation.
var targetPathValidationOrder = []string{
	"presence",
	"whole_value_empty",
	"whole_value_utf8_byte_length",
	"whole_value_leading_slash",
	"whole_value_protocol_relative_authority",
	"whole_value_raw_ascii_character_set",
	"split_path_at_first_query_delimiter",
	"forbidden_path_ascii",
	"whole_value_percent_syntax",
	"path_encoded_dot",
	"path_literal_dot_segment",
	"path_escape_or_interior_empty_segment",
	"accept",
}

// TargetPathV1File is the language-neutral target_path mint contract shared by
// service and SDK consumers.
type TargetPathV1File struct {
	Artifact      string             `json:"artifact"`
	SchemaVersion int                `json:"schema_version"`
	Description   string             `json:"description"`
	Contract      TargetPathContract `json:"contract"`
	Cases         []TargetPathCase   `json:"cases"`
}

// TargetPathContract freezes the stable wire and runtime rules that every
// consumer must apply without normalization.
type TargetPathContract struct {
	WireField               string   `json:"wire_field"`
	MaxBytes                int      `json:"max_bytes"`
	OmittedSemantics        string   `json:"omitted_semantics"`
	ExplicitEmptySemantics  string   `json:"explicit_empty_semantics"`
	AcceptedCharacterSet    string   `json:"accepted_character_set"`
	AllowedASCII            string   `json:"allowed_ascii"`
	ForbiddenPathASCII      string   `json:"forbidden_path_ascii"`
	QueryDelimiter          string   `json:"query_delimiter"`
	ValidationOrder         []string `json:"validation_order"`
	AcceptedValueHandling   string   `json:"accepted_value_handling"`
	PercentEncodingHandling string   `json:"percent_encoding_handling"`
}

// TargetPathCase is one direct public-SDK option input. Present distinguishes
// omission from an explicit empty string. OpenSupported is required only for
// accepted cases. Every accepted canonical value is safe to open.
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
	"accept_mixed_case_path":                    {present: true, value: targetPathValue("/View/AbC")},
	"accept_path_query":                         {present: true, value: targetPathValue("/view/abc123?sig=deadBEEF&exp=1700000000")},
	"accept_allowed_path_ascii":                 {present: true, value: targetPathValue("/a-b_c.d~e$f&g+h,i=j:k@l")},
	"accept_allowed_query_ascii":                {present: true, value: targetPathValue("/view/x?q=!()*;")},
	"accept_deep_path":                          {present: true, value: targetPathValue("/a/b/c/d/e/f")},
	"accept_dotdot_substring":                   {present: true, value: targetPathValue("/view/a..b")},
	"accept_three_dot_segment":                  {present: true, value: targetPathValue("/view/...")},
	"accept_dotdot_in_query":                    {present: true, value: targetPathValue("/view/x?redir=../../etc")},
	"accept_authority_text_in_query":            {present: true, value: targetPathValue("/path?next=//evil.example")},
	"accept_trailing_slash":                     {present: true, value: targetPathValue("/view/")},
	"accept_trailing_slash_with_query":          {present: true, value: targetPathValue("/view/?a=b")},
	"accept_empty_query":                        {present: true, value: targetPathValue("/?")},
	"accept_percent_only_in_query":              {present: true, value: targetPathValue("/view/x?sig=a%20b")},
	"accept_encoded_dot_slash_in_query":         {present: true, value: targetPathValue("/view/x?next=%2e%2E%2f%2F")},
	"accept_encoded_controls_in_query":          {present: true, value: targetPathValue("/view/x?a=%0d%0a%00")},
	"accept_semicolon_in_query":                 {present: true, value: targetPathValue("/view/abc?x=1;y=2")},
	"accept_second_question_mark_in_query":      {present: true, value: targetPathValue("/view/x?next=http://e.example/p?q=1")},
	"accept_max_bytes":                          {present: true, value: targetPathValue("/" + strings.Repeat("a", TargetPathMaxBytes-1))},
	"accept_max_bytes_with_query":               {present: true, value: targetPathValue("/v?q=" + strings.Repeat("a", TargetPathMaxBytes-5))},
	"reject_explicit_empty":                     {present: true, value: targetPathValue("")},
	"reject_too_long":                           {present: true, value: targetPathValue("/" + strings.Repeat("a", TargetPathMaxBytes))},
	"reject_too_long_with_query":                {present: true, value: targetPathValue("/v?q=" + strings.Repeat("a", TargetPathMaxBytes-4))},
	"reject_overlong_relative_precedence":       {present: true, value: targetPathValue(strings.Repeat("a", TargetPathMaxBytes+1))},
	"reject_overlong_authority_precedence":      {present: true, value: targetPathValue("//" + strings.Repeat("a", TargetPathMaxBytes-1))},
	"reject_overlong_non_ascii_precedence":      {present: true, value: targetPathValue("/" + strings.Repeat("a", TargetPathMaxBytes-2) + "é")},
	"reject_overlong_dot_segment_precedence":    {present: true, value: targetPathValue("/../" + strings.Repeat("a", TargetPathMaxBytes-3))},
	"reject_overlong_percent_precedence":        {present: true, value: targetPathValue("/" + strings.Repeat("a", TargetPathMaxBytes-1) + "%")},
	"reject_suffix_host":                        {present: true, value: targetPathValue(".evil.example/x")},
	"reject_userinfo_origin_concatenation":      {present: true, value: targetPathValue("@evil.example/x")},
	"reject_relative_path":                      {present: true, value: targetPathValue("view/abc")},
	"reject_query_only":                         {present: true, value: targetPathValue("?a=b")},
	"reject_leading_space":                      {present: true, value: targetPathValue(" /view/x")},
	"reject_relative_invalid_character":         {present: true, value: targetPathValue("view/a[b]")},
	"reject_relative_dot_segment_precedence":    {present: true, value: targetPathValue("../etc/passwd")},
	"reject_relative_malformed_percent":         {present: true, value: targetPathValue("a%/b")},
	"reject_absolute_url":                       {present: true, value: targetPathValue("https://evil.example/x")},
	"reject_protocol_relative_authority":        {present: true, value: targetPathValue("//evil.example/path")},
	"reject_authority_invalid_character":        {present: true, value: targetPathValue("//evil.example/a[b]")},
	"reject_authority_malformed_percent":        {present: true, value: targetPathValue("//evil.example/b%")},
	"reject_authority_dot_segment":              {present: true, value: targetPathValue("//evil.example/../b")},
	"reject_authority_semicolon":                {present: true, value: targetPathValue("//evil.example/a;b")},
	"reject_interior_empty_segment":             {present: true, value: targetPathValue("/a//b")},
	"reject_interior_empty_segment_with_query":  {present: true, value: targetPathValue("/a//b?x=1")},
	"reject_trailing_double_slash":              {present: true, value: targetPathValue("/a//")},
	"reject_dot_segment_after_interior_empty":   {present: true, value: targetPathValue("/a//../b")},
	"reject_semicolon_in_path":                  {present: true, value: targetPathValue("/view/abc;x=1")},
	"reject_semicolon_path_with_query":          {present: true, value: targetPathValue("/view/a;b?c=1")},
	"reject_semicolon_malformed_percent":        {present: true, value: targetPathValue("/view/a;b%")},
	"reject_exclamation_in_path":                {present: true, value: targetPathValue("/view/a!b")},
	"reject_exclamation_malformed_percent":      {present: true, value: targetPathValue("/view/a!b%")},
	"reject_apostrophe_in_path":                 {present: true, value: targetPathValue("/view/a'b")},
	"reject_apostrophe_in_query":                {present: true, value: targetPathValue("/view/a?q='b")},
	"reject_left_parenthesis_in_path":           {present: true, value: targetPathValue("/view/a(b")},
	"reject_right_parenthesis_in_path":          {present: true, value: targetPathValue("/view/a)b")},
	"reject_asterisk_in_path":                   {present: true, value: targetPathValue("/view/a*b")},
	"reject_leading_backslash":                  {present: true, value: targetPathValue("/\\evil.example")},
	"reject_backslash_in_path":                  {present: true, value: targetPathValue("/view\\..\\x")},
	"reject_fragment":                           {present: true, value: targetPathValue("/view/x#fragment")},
	"reject_left_bracket":                       {present: true, value: targetPathValue("/view/a[b]")},
	"reject_left_bracket_malformed_percent":     {present: true, value: targetPathValue("/view/a[b]%")},
	"reject_fragment_in_query":                  {present: true, value: targetPathValue("/view/x?a=b#frag")},
	"reject_space":                              {present: true, value: targetPathValue("/view /x")},
	"reject_trailing_space":                     {present: true, value: targetPathValue("/view/x ")},
	"reject_space_in_query":                     {present: true, value: targetPathValue("/view/x?a=b c")},
	"reject_backslash_in_query":                 {present: true, value: targetPathValue("/view/x?a=\\")},
	"reject_tab":                                {present: true, value: targetPathValue("/view\t/x")},
	"reject_newline":                            {present: true, value: targetPathValue("/view\n/x")},
	"reject_carriage_return":                    {present: true, value: targetPathValue("/view\r/x")},
	"reject_trailing_line_feed":                 {present: true, value: targetPathValue("/view/x\n")},
	"reject_trailing_line_feed_after_query":     {present: true, value: targetPathValue("/view/x?a=b\n")},
	"reject_line_feed_in_query":                 {present: true, value: targetPathValue("/view/x?a=b\nc")},
	"reject_trailing_carriage_return":           {present: true, value: targetPathValue("/view/x\r")},
	"reject_trailing_carriage_return_line_feed": {present: true, value: targetPathValue("/view/x\r\n")},
	"reject_nul":                                {present: true, value: targetPathValue("/view\x00/x")},
	"reject_del":                                {present: true, value: targetPathValue("/view\x7f/x")},
	"reject_non_ascii":                          {present: true, value: targetPathValue("/view/é")},
	"reject_non_ascii_in_query":                 {present: true, value: targetPathValue("/view/x?a=é")},
	"reject_single_dot_segment":                 {present: true, value: targetPathValue("/a/./b")},
	"reject_dotdot_leading":                     {present: true, value: targetPathValue("/../etc/passwd")},
	"reject_dotdot_middle":                      {present: true, value: targetPathValue("/view/../../secret")},
	"reject_dotdot_trailing":                    {present: true, value: targetPathValue("/view/..")},
	"reject_dot_segment_before_two_queries":     {present: true, value: targetPathValue("/a/..?b?c")},
	"reject_percent_encoded_dot_lower":          {present: true, value: targetPathValue("/%2e%2e/secret")},
	"reject_percent_encoded_dot_upper":          {present: true, value: targetPathValue("/%2E%2E/secret")},
	"reject_percent_encoded_single_dot":         {present: true, value: targetPathValue("/a%2eb")},
	"reject_percent_encoded_dot_with_query":     {present: true, value: targetPathValue("/%2e%2e/x?a=b")},
	"reject_mixed_percent_letter_dot_escape":    {present: true, value: targetPathValue("/view/a%41b%2ec")},
	"reject_literal_dot_with_percent_escape":    {present: true, value: targetPathValue("/a/../b%41c")},
	"reject_percent_encoded_slash_lower":        {present: true, value: targetPathValue("/view%2fsecret")},
	"reject_percent_encoded_slash_upper":        {present: true, value: targetPathValue("/view%2Fsecret")},
	"reject_percent_encoded_letter_upper_path":  {present: true, value: targetPathValue("/view/a%4Ab")},
	"reject_percent_encoded_letter_lower_path":  {present: true, value: targetPathValue("/view/a%4ab")},
	"reject_percent_encoded_letter_41_path":     {present: true, value: targetPathValue("/view/a%41b")},
	"reject_path_escape_with_valid_query":       {present: true, value: targetPathValue("/view/a%41b?c=1")},
	"reject_path_escape_at_query_boundary":      {present: true, value: targetPathValue("/a%41?b=1")},
	"reject_dot_escape_at_query_boundary":       {present: true, value: targetPathValue("/a%2e?b=1")},
	"reject_double_encoded_dot_path":            {present: true, value: targetPathValue("/view/a%252eb")},
	"reject_encoded_backslash_lower_path":       {present: true, value: targetPathValue("/view/a%5cb")},
	"reject_encoded_backslash_upper_path":       {present: true, value: targetPathValue("/view/a%5Cb")},
	"reject_encoded_nul_path":                   {present: true, value: targetPathValue("/view/a%00b")},
	"reject_encoded_fragment_marker_path":       {present: true, value: targetPathValue("/view/a%23b")},
	"reject_encoded_query_marker_path":          {present: true, value: targetPathValue("/view/a%3fb")},
	"reject_encoded_carriage_return_path":       {present: true, value: targetPathValue("/view/a%0db")},
	"reject_encoded_line_feed_path":             {present: true, value: targetPathValue("/view/a%0ab")},
	"reject_bare_percent":                       {present: true, value: targetPathValue("/a%")},
	"reject_short_percent":                      {present: true, value: targetPathValue("/a%2")},
	"reject_non_hex_percent_path":               {present: true, value: targetPathValue("/view/x%2Gy")},
	"reject_non_hex_percent_query":              {present: true, value: targetPathValue("/view/x?sig=a%ZZ")},
	"reject_truncated_percent_in_query":         {present: true, value: targetPathValue("/view/x?a=b%")},
	"reject_short_percent_in_query":             {present: true, value: targetPathValue("/view/x?a=b%2")},
	"reject_percent_followed_by_path_separator": {present: true, value: targetPathValue("/a%/b")},
	"reject_malformed_percent_with_dot_segment": {present: true, value: targetPathValue("/a/../b%")},
	"reject_malformed_percent_with_dot_escape":  {present: true, value: targetPathValue("/%2e%2e/x%2G")},
	"reject_malformed_query_with_dot_escape_path": {
		present: true, value: targetPathValue("/%2e%2e/x?a=%ZZ"),
	},
	"reject_malformed_query_with_other_path_escape": {
		present: true, value: targetPathValue("/view/a%41b?c=%ZZ"),
	},
	"reject_malformed_query_before_interior_empty": {
		present: true, value: targetPathValue("/a//b?c=%ZZ"),
	},
}

// Use \z instead of $ so every consumer implements a whole-value full match.
// Some regex engines let $ match before a final line terminator.
var targetPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~!$&()*+,;=:@%/?-]*\z`)

func targetPathHasMalformedPercentEscape(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			continue
		}
		if i+2 >= len(value) || !isTargetPathHex(value[i+1]) || !isTargetPathHex(value[i+2]) {
			return true
		}
		i += 2
	}
	return false
}

func isTargetPathHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

// ParseTargetPathV1File strictly parses and independently re-derives every case.
func ParseTargetPathV1File(data []byte) (*TargetPathV1File, error) {
	var tf TargetPathV1File
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
		WireField:               "target_path",
		MaxBytes:                TargetPathMaxBytes,
		OmittedSemantics:        "bare_origin",
		ExplicitEmptySemantics:  "reject",
		AcceptedCharacterSet:    "raw_ascii_path_and_query_without_url_drift",
		AllowedASCII:            TargetPathAllowedASCII,
		ForbiddenPathASCII:      TargetPathForbiddenPathASCII,
		QueryDelimiter:          "first_question_mark",
		ValidationOrder:         targetPathValidationOrder,
		AcceptedValueHandling:   "preserve_exact_bytes",
		PercentEncodingHandling: "reject_all_path_escapes_accept_well_formed_query_escapes_without_normalize_or_decode",
	}
	if !reflect.DeepEqual(tf.Contract, wantContract) {
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
	// Gate order is a published part of the v1 contract. Keep each return below
	// in lockstep with targetPathValidationOrder and its overlap vectors.
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
	pathPart := p
	if i := strings.IndexByte(p, '?'); i >= 0 {
		pathPart = p[:i]
	}
	// URL serializers disagree about these raw path bytes. Reject them before
	// authorization so a later layer cannot change the selected resource. They
	// remain valid and byte-exact in the query, which is not path-authorized.
	if strings.ContainsAny(pathPart, TargetPathForbiddenPathASCII) {
		return ExpectReject, TargetPathRejectInvalidCharacter, false, nil
	}
	if targetPathHasMalformedPercentEscape(p) {
		return ExpectReject, TargetPathRejectPercentEncoding, false, nil
	}
	hasPathEscape := false
	for i := 0; i < len(pathPart); i++ {
		if pathPart[i] != '%' {
			continue
		}
		// The whole-value scan above proves that every percent escape has two
		// following hexadecimal bytes. Keep this guard so later validation
		// reordering stays fail-closed.
		if i+3 > len(pathPart) {
			return ExpectReject, TargetPathRejectPercentEncoding, false, nil
		}
		escape := pathPart[i+1 : i+3]
		if strings.EqualFold(escape, "2e") {
			return ExpectReject, TargetPathRejectDotSegment, false, nil
		}
		hasPathEscape = true
		i += 2
	}
	segments := strings.Split(pathPart, "/")
	hasInteriorEmptySegment := false
	for i, segment := range segments {
		if segment == "." || segment == ".." {
			return ExpectReject, TargetPathRejectDotSegment, false, nil
		}
		// The first empty segment is the required leading slash. The last empty
		// segment is one preserved trailing slash. Any other empty segment would
		// be normalized by common URL stacks and is not canonical.
		if segment == "" && i > 0 && i < len(segments)-1 {
			hasInteriorEmptySegment = true
		}
	}
	if hasPathEscape || hasInteriorEmptySegment {
		return ExpectReject, TargetPathRejectInvalidCharacter, false, nil
	}
	// Every canonical value is open-supported in v1. Keep the separate result
	// as a reserved compatibility gate for a coordinated future contract.
	return ExpectAccept, "", true, nil
}
