package conformance

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
)

// AssignmentTicketFenceRejectInput is a complete invalid typed fence input.
// Boundary names the validation that must reject it before framing or hashing.
type AssignmentTicketFenceRejectInput struct {
	Name     string                      `json:"name"`
	Kind     string                      `json:"kind"`
	Boundary string                      `json:"boundary"`
	Parts    []AssignmentTicketFencePart `json:"parts"`
}

// Pin each executable recipe to its positive input, so missing or altered
// mutations cannot silently weaken a published rejection case.
func validateAssignmentFenceRejectInputs(af *AssignmentTicketFile) error {
	for _, reject := range af.FenceRejects {
		if af.SchemaVersion == 1 {
			if len(reject.Inputs) != 0 {
				return fmt.Errorf("conformance: v1 fence reject %q is advisory", reject.Name)
			}
			continue
		}
		expected, err := assignmentFenceRejectInputs(reject.Name, af.FenceVectors)
		if err != nil {
			return err
		}
		kind := "all"
		if reject.Name != "uint64_negative_or_overflow" {
			kind = expected[0].Kind
		}
		if reject.FenceKind != kind || !reflect.DeepEqual(reject.Inputs, expected) {
			return fmt.Errorf("conformance: fence reject %q executable inputs drifted", reject.Name)
		}
	}
	return nil
}

func assignmentFenceRejectInputs(name string, vectors []AssignmentTicketFenceVector) ([]AssignmentTicketFenceRejectInput, error) {
	var inputs []AssignmentTicketFenceRejectInput
	for _, vector := range vectors {
		if name == "uint64_negative_or_overflow" {
			for i, part := range vector.Parts {
				if part.Encoding != "uint64_be" {
					continue
				}
				for _, invalid := range []struct{ name, value string }{{"negative", "-1"}, {"overflow", "18446744073709551616"}} {
					parts := slices.Clone(vector.Parts)
					parts[i].Value, parts[i].BytesHex = invalid.value, ""
					inputs = append(inputs, AssignmentTicketFenceRejectInput{Name: vector.Kind + "." + part.Name + "." + invalid.name, Kind: vector.Kind, Boundary: "uint64", Parts: parts})
				}
			}
			continue
		}
		kind := "credential"
		if name == "missing_required_cell_part" {
			kind = "cell"
		}
		if vector.Kind != kind {
			continue
		}
		parts := slices.Clone(vector.Parts)
		index := func(want string) int {
			return slices.IndexFunc(parts, func(p AssignmentTicketFencePart) bool { return p.Name == want })
		}
		boundary := ""
		switch name {
		case "credential_hash_wrong_length":
			i := index("credential_key_hash")
			if i < 0 {
				return nil, fmt.Errorf("conformance: missing credential hash")
			}
			raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[i].Value)
			if err != nil || len(raw) != 32 {
				return nil, fmt.Errorf("conformance: invalid baseline credential hash")
			}
			parts[i].Value, parts[i].BytesHex = base64.RawURLEncoding.EncodeToString(raw[:31]), hex.EncodeToString(raw[:31])
			boundary = "key_length"
		case "credential_scopes_unsorted", "credential_scopes_duplicate":
			a, b := index("scope_0"), index("scope_1")
			if a < 0 || b < 0 {
				return nil, fmt.Errorf("conformance: missing baseline scopes")
			}
			if name == "credential_scopes_unsorted" {
				parts[a].Value, parts[b].Value = parts[b].Value, parts[a].Value
			} else {
				parts[b].Value = parts[a].Value
			}
			parts[a].BytesHex, parts[b].BytesHex = hex.EncodeToString([]byte(parts[a].Value)), hex.EncodeToString([]byte(parts[b].Value))
			boundary = "canonical_scopes"
		case "bool_not_single_byte":
			i := index("has_counter")
			if i < 0 {
				return nil, fmt.Errorf("conformance: missing baseline bool")
			}
			parts[i].Encoding, parts[i].Value, parts[i].BytesHex = "utf8", "false", hex.EncodeToString([]byte("false"))
			boundary = "encoding"
		case "missing_required_cell_part":
			i := index("updated_at_storage")
			if i < 0 {
				return nil, fmt.Errorf("conformance: missing baseline timestamp")
			}
			parts = slices.Delete(parts, i, i+1)
			boundary = "required_part"
		default:
			return nil, fmt.Errorf("conformance: unhandled fence reject %q", name)
		}
		inputs = append(inputs, AssignmentTicketFenceRejectInput{Name: name, Kind: kind, Boundary: boundary, Parts: parts})
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("conformance: no executable inputs for %q", name)
	}
	return inputs, nil
}
