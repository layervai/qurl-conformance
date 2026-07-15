package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// AgentAPIKeyIDArtifactID identifies the control-plane API-key ID artifact.
	AgentAPIKeyIDArtifactID = "qurl-agent-api-key-id-vectors"
	// AgentAPIKeyIDSchemaVersion is the only schema accepted by this release.
	AgentAPIKeyIDSchemaVersion = 1

	AgentAPIKeyIDPrefix         = "key_"
	AgentAPIKeyIDSuffixLength   = 12
	AgentAPIKeyIDTotalLength    = len(AgentAPIKeyIDPrefix) + AgentAPIKeyIDSuffixLength
	AgentAPIKeyIDSuffixAlphabet = "ASCII_ALPHANUMERIC"
	AgentAPIKeyIDPattern        = "^key_[A-Za-z0-9]{12}$"

	AgentAPIKeyIDSurfaceRegistrationInfo = "registration_info"
	AgentAPIKeyIDSurfaceCompletion       = "completion"

	AgentAPIKeyIDRejectInvalidID = "invalid_id"
	AgentAPIKeyIDRejectBodyParse = "body_parse"
)

// AgentAPIKeyIDFile freezes producer construction and consumer parsing for the
// two control-plane fields that carry an API-key identifier during enrollment.
type AgentAPIKeyIDFile struct {
	Artifact              string                      `json:"artifact"`
	SchemaVersion         int                         `json:"schema_version"`
	Description           string                      `json:"description"`
	Contract              AgentAPIKeyIDContract       `json:"contract"`
	Surfaces              []AgentAPIKeyIDSurface      `json:"surfaces"`
	ProducerCases         []AgentAPIKeyIDProducerCase `json:"producer_cases"`
	ConsumerValueCases    []AgentAPIKeyIDValueCase    `json:"consumer_value_cases"`
	ConsumerResponseCases []AgentAPIKeyIDResponseCase `json:"consumer_response_cases"`
}

// AgentAPIKeyIDContract is the language-neutral public grammar.
type AgentAPIKeyIDContract struct {
	Prefix         string `json:"prefix"`
	SuffixLength   int    `json:"suffix_length"`
	TotalLength    int    `json:"total_length"`
	SuffixAlphabet string `json:"suffix_alphabet"`
	Pattern        string `json:"pattern"`
}

// AgentAPIKeyIDSurface names one public response field that carries the ID.
type AgentAPIKeyIDSurface struct {
	Name      string `json:"name"`
	WireField string `json:"wire_field"`
}

// AgentAPIKeyIDProducerCase lets an issuer drive its production constructor
// with a deterministic suffix and compare the exact public ID.
type AgentAPIKeyIDProducerCase struct {
	Name       string `json:"name"`
	Suffix     string `json:"suffix"`
	ExpectedID string `json:"expected_id"`
}

// AgentAPIKeyIDValueCase is one direct validator input.
type AgentAPIKeyIDValueCase struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Outcome     string `json:"outcome"`
	RejectClass string `json:"reject_class,omitempty"`
}

// AgentAPIKeyIDResponseCase preserves raw JSON so companion fields, duplicate
// keys, wrong scalar types, and trailing values reach a consumer's response
// parser without lossy re-serialization.
type AgentAPIKeyIDResponseCase struct {
	Name        string `json:"name"`
	Surface     string `json:"surface"`
	BodyJSON    string `json:"body_json"`
	Outcome     string `json:"outcome"`
	ExpectedID  string `json:"expected_id,omitempty"`
	RejectClass string `json:"reject_class,omitempty"`
}

var agentAPIKeyIDSurfaceFields = map[string]string{
	AgentAPIKeyIDSurfaceRegistrationInfo: "key_id",
	AgentAPIKeyIDSurfaceCompletion:       "device_api_key_id",
}

var agentAPIKeyIDProducerFixtures = map[string]string{
	"lowercase_suffix": "abcdefghijkl",
	"uppercase_suffix": "ABCDEFGHIJKL",
	"numeric_suffix":   "012345678901",
	"mixed_suffix":     "A1b2C3d4E5f6",
}

var agentAPIKeyIDValueFixtures = map[string]string{
	"accept_canonical":                  "key_A1b2C3d4E5f6",
	"accept_lowercase_suffix":           "key_abcdefghijkl",
	"accept_uppercase_suffix":           "key_ABCDEFGHIJKL",
	"accept_numeric_suffix":             "key_012345678901",
	"reject_empty":                      "",
	"reject_prefix_only":                "key_",
	"reject_uppercase_prefix":           "KEY_A1b2C3d4E5f6",
	"reject_wrong_prefix":               "api_A1b2C3d4E5f6",
	"reject_short_suffix":               "key_A1b2C3d4E5f",
	"reject_long_suffix":                "key_A1b2C3d4E5f6G",
	"reject_underscore":                 "key_A1b2C3d4E5_6",
	"reject_punctuation":                "key_A1b2C3d4E5-6",
	"reject_non_ascii_lookalike":        "key_A1b2C3d4E5ｆ6",
	"reject_non_ascii_same_byte_length": "key_A1b2C3d4E5é",
	"reject_leading_whitespace":         " key_A1b2C3d4E5f6",
	"reject_trailing_whitespace":        "key_A1b2C3d4E5f6 ",
	"reject_trailing_newline":           "key_A1b2C3d4E5f6\n",
	"reject_embedded_whitespace":        "key_A1b2C3 d4E5f",
}

var agentAPIKeyIDResponseKinds = []string{
	"accept_canonical",
	"accept_with_companion_field",
	"reject_invalid_id",
	"reject_surrounding_whitespace_id",
	"reject_null",
	"reject_number",
	"reject_boolean",
	"reject_object",
	"reject_array",
	"reject_duplicate_field",
	"reject_trailing_json",
	"reject_missing_field",
	"reject_unknown_field",
}

// ParseAgentAPIKeyIDFile strictly parses the API-key identifier artifact and
// independently derives every declared producer and consumer expectation.
func ParseAgentAPIKeyIDFile(data []byte) (*AgentAPIKeyIDFile, error) {
	var af AgentAPIKeyIDFile
	if err := strictDecodeArtifact(data, &af); err != nil {
		return nil, fmt.Errorf("conformance: parse agent API-key ID file: %w", err)
	}
	if af.Artifact != AgentAPIKeyIDArtifactID {
		return nil, fmt.Errorf("conformance: agent API-key ID file has artifact %q, want %q", af.Artifact, AgentAPIKeyIDArtifactID)
	}
	if af.SchemaVersion != AgentAPIKeyIDSchemaVersion {
		return nil, fmt.Errorf("conformance: agent API-key ID file has schema_version %d, want %d", af.SchemaVersion, AgentAPIKeyIDSchemaVersion)
	}
	if af.Description == "" {
		return nil, errors.New("conformance: agent API-key ID file has empty description")
	}
	wantContract := AgentAPIKeyIDContract{
		Prefix:         AgentAPIKeyIDPrefix,
		SuffixLength:   AgentAPIKeyIDSuffixLength,
		TotalLength:    AgentAPIKeyIDTotalLength,
		SuffixAlphabet: AgentAPIKeyIDSuffixAlphabet,
		Pattern:        AgentAPIKeyIDPattern,
	}
	if af.Contract != wantContract {
		return nil, fmt.Errorf("conformance: agent API-key ID contract = %+v, want %+v", af.Contract, wantContract)
	}
	if err := validateAgentAPIKeyIDSurfaces(af.Surfaces); err != nil {
		return nil, err
	}
	if err := validateAgentAPIKeyIDProducerCases(af.ProducerCases); err != nil {
		return nil, err
	}
	if err := validateAgentAPIKeyIDValueCases(af.ConsumerValueCases); err != nil {
		return nil, err
	}
	if err := validateAgentAPIKeyIDResponseCases(af.ConsumerResponseCases); err != nil {
		return nil, err
	}
	return &af, nil
}

func validateAgentAPIKeyIDSurfaces(surfaces []AgentAPIKeyIDSurface) error {
	if len(surfaces) != len(agentAPIKeyIDSurfaceFields) {
		return fmt.Errorf("conformance: agent API-key ID surface count = %d, want %d", len(surfaces), len(agentAPIKeyIDSurfaceFields))
	}
	seen := make(map[string]struct{}, len(surfaces))
	for _, surface := range surfaces {
		field, ok := agentAPIKeyIDSurfaceFields[surface.Name]
		if !ok {
			return fmt.Errorf("conformance: unknown agent API-key ID surface %q", surface.Name)
		}
		if _, duplicate := seen[surface.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate agent API-key ID surface %q", surface.Name)
		}
		seen[surface.Name] = struct{}{}
		if surface.WireField != field {
			return fmt.Errorf("conformance: agent API-key ID surface %q wire_field = %q, want %q", surface.Name, surface.WireField, field)
		}
	}
	return nil
}

func validateAgentAPIKeyIDProducerCases(cases []AgentAPIKeyIDProducerCase) error {
	if len(cases) != len(agentAPIKeyIDProducerFixtures) {
		return fmt.Errorf("conformance: agent API-key ID producer case count = %d, want %d", len(cases), len(agentAPIKeyIDProducerFixtures))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		suffix, ok := agentAPIKeyIDProducerFixtures[c.Name]
		if !ok {
			return fmt.Errorf("conformance: unknown agent API-key ID producer case %q", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate agent API-key ID producer case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.Suffix != suffix {
			return fmt.Errorf("conformance: agent API-key ID producer case %q suffix = %q, want %q", c.Name, c.Suffix, suffix)
		}
		if len(c.Suffix) != AgentAPIKeyIDSuffixLength || !isASCIIAlphanumeric(c.Suffix) || c.ExpectedID != AgentAPIKeyIDPrefix+c.Suffix || !isCanonicalAgentAPIKeyID(c.ExpectedID) {
			return fmt.Errorf("conformance: agent API-key ID producer case %q does not satisfy the declared construction contract", c.Name)
		}
	}
	return nil
}

func validateAgentAPIKeyIDValueCases(cases []AgentAPIKeyIDValueCase) error {
	if len(cases) != len(agentAPIKeyIDValueFixtures) {
		return fmt.Errorf("conformance: agent API-key ID consumer value case count = %d, want %d", len(cases), len(agentAPIKeyIDValueFixtures))
	}
	pattern, err := regexp.Compile(AgentAPIKeyIDPattern)
	if err != nil {
		return fmt.Errorf("conformance: compile agent API-key ID pattern: %w", err)
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		value, ok := agentAPIKeyIDValueFixtures[c.Name]
		if !ok {
			return fmt.Errorf("conformance: unknown agent API-key ID consumer value case %q", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate agent API-key ID consumer value case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.Value != value {
			return fmt.Errorf("conformance: agent API-key ID consumer value case %q value = %q, want %q", c.Name, c.Value, value)
		}
		canonical := isCanonicalAgentAPIKeyID(c.Value)
		if pattern.MatchString(c.Value) != canonical {
			return fmt.Errorf("conformance: agent API-key ID consumer value case %q exposes a pattern/reference disagreement", c.Name)
		}
		wantOutcome, wantRejectClass := ExpectReject, AgentAPIKeyIDRejectInvalidID
		if canonical {
			wantOutcome, wantRejectClass = ExpectAccept, ""
		}
		if c.Outcome != wantOutcome || c.RejectClass != wantRejectClass {
			return fmt.Errorf("conformance: agent API-key ID consumer value case %q expectation = %q/%q, want %q/%q", c.Name, c.Outcome, c.RejectClass, wantOutcome, wantRejectClass)
		}
	}
	return nil
}

func validateAgentAPIKeyIDResponseCases(cases []AgentAPIKeyIDResponseCase) error {
	wantCount := len(agentAPIKeyIDSurfaceFields) * len(agentAPIKeyIDResponseKinds)
	if len(cases) != wantCount {
		return fmt.Errorf("conformance: agent API-key ID consumer response case count = %d, want %d", len(cases), wantCount)
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate agent API-key ID consumer response case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		body, surface, ok := expectedAgentAPIKeyIDResponseBody(c.Name)
		if !ok {
			return fmt.Errorf("conformance: unknown agent API-key ID consumer response case %q", c.Name)
		}
		if c.Surface != surface || c.BodyJSON != body {
			return fmt.Errorf("conformance: agent API-key ID consumer response case %q = %q/%q, want %q/%q", c.Name, c.Surface, c.BodyJSON, surface, body)
		}
		wantOutcome, wantID, wantRejectClass := deriveAgentAPIKeyIDResponse(surface, []byte(body))
		if c.Outcome != wantOutcome || c.ExpectedID != wantID || c.RejectClass != wantRejectClass {
			return fmt.Errorf("conformance: agent API-key ID consumer response case %q expectation = %q/%q/%q, want %q/%q/%q", c.Name, c.Outcome, c.ExpectedID, c.RejectClass, wantOutcome, wantID, wantRejectClass)
		}
	}
	return nil
}

func expectedAgentAPIKeyIDResponseBody(name string) (body, surface string, ok bool) {
	for candidate, field := range agentAPIKeyIDSurfaceFields {
		for _, kind := range agentAPIKeyIDResponseKinds {
			if name != candidate+"_"+kind {
				continue
			}
			body, ok := agentAPIKeyIDResponseBody(candidate, field, kind)
			return body, candidate, ok
		}
	}
	return "", "", false
}

func agentAPIKeyIDResponseBody(surface, field, kind string) (string, bool) {
	canonical := "key_A1b2C3d4E5f6"
	quotedField := `"` + field + `"`
	switch kind {
	case "accept_canonical":
		return `{` + quotedField + `:"` + canonical + `"}`, true
	case "accept_with_companion_field":
		companion := `"key_kind":"bootstrap"`
		if surface == AgentAPIKeyIDSurfaceCompletion {
			companion = `"agent_id":"agent_conform"`
		}
		return `{` + quotedField + `:"` + canonical + `",` + companion + `}`, true
	case "reject_invalid_id":
		return `{` + quotedField + `:"api_A1b2C3d4E5f6"}`, true
	case "reject_surrounding_whitespace_id":
		return `{` + quotedField + `:" ` + canonical + ` "}`, true
	case "reject_null":
		return `{` + quotedField + `:null}`, true
	case "reject_number":
		return `{` + quotedField + `:7}`, true
	case "reject_boolean":
		return `{` + quotedField + `:false}`, true
	case "reject_object":
		return `{` + quotedField + `:{"nested":"value"}}`, true
	case "reject_array":
		return `{` + quotedField + `:[]}`, true
	case "reject_duplicate_field":
		return `{` + quotedField + `:"` + canonical + `",` + quotedField + `:"key_012345678901"}`, true
	case "reject_trailing_json":
		return `{` + quotedField + `:"` + canonical + `"}{}`, true
	case "reject_missing_field":
		return `{}`, true
	case "reject_unknown_field":
		unknown := "keyId"
		if surface == AgentAPIKeyIDSurfaceCompletion {
			unknown = "deviceApiKeyId"
		}
		return `{"` + unknown + `":"` + canonical + `"}`, true
	default:
		return "", false
	}
}

func deriveAgentAPIKeyIDResponse(surface string, body []byte) (outcome, id, rejectClass string) {
	field, ok := agentAPIKeyIDSurfaceFields[surface]
	if !ok {
		return ExpectReject, "", AgentAPIKeyIDRejectBodyParse
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return ExpectReject, "", AgentAPIKeyIDRejectBodyParse
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		return ExpectReject, "", AgentAPIKeyIDRejectBodyParse
	}
	raw, present := object[field]
	if !present || len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return ExpectReject, "", AgentAPIKeyIDRejectBodyParse
	}
	if err := json.Unmarshal(raw, &id); err != nil {
		return ExpectReject, "", AgentAPIKeyIDRejectBodyParse
	}
	if !isCanonicalAgentAPIKeyID(id) {
		return ExpectReject, "", AgentAPIKeyIDRejectInvalidID
	}
	return ExpectAccept, id, ""
}

func isCanonicalAgentAPIKeyID(value string) bool {
	return len(value) == AgentAPIKeyIDTotalLength && strings.HasPrefix(value, AgentAPIKeyIDPrefix) && isASCIIAlphanumeric(value[len(AgentAPIKeyIDPrefix):])
}

func isASCIIAlphanumeric(value string) bool {
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}
