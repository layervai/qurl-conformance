package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	conformance "github.com/layervai/qurl-conformance"
)

func verifyFenceRejectInputs(af *conformance.AssignmentTicketFile) error {
	if af.SchemaVersion == 1 {
		return nil
	} // v1 explicitly carries advisory recipes only.
	bases := make(map[string]conformance.AssignmentTicketFenceVector)
	for _, vector := range af.FenceVectors {
		bases[vector.Kind] = vector
	}
	for _, reject := range af.FenceRejects {
		if len(reject.Inputs) == 0 {
			return fmt.Errorf("fence reject %s has no executable inputs", reject.Name)
		}
		for _, input := range reject.Inputs {
			if reject.FenceKind != "all" && reject.FenceKind != input.Kind {
				return fmt.Errorf("fence reject %s kind disagrees with input", reject.Name)
			}
			base, ok := bases[input.Kind]
			if !ok {
				return fmt.Errorf("fence reject %s has unknown kind %s", input.Name, input.Kind)
			}
			if got := fenceInputBoundary(input.Parts, base.Parts); got != input.Boundary {
				return fmt.Errorf("fence reject %s boundary=%q want=%q", input.Name, got, input.Boundary)
			}
		}
	}
	return nil
}

// Validate typed inputs before any frame or hash can be accepted. Positive
// inputs supply the closed field order and encodings verified by verifyFence.
func fenceInputBoundary(parts, required []conformance.AssignmentTicketFencePart) string {
	if len(parts) != len(required) {
		return "required_part"
	}
	var scopes []string
	var scopeCount uint64
	for i, part := range parts {
		if part.Name != required[i].Name {
			return "required_part"
		}
		if part.Encoding != required[i].Encoding {
			return "encoding"
		}
		raw, err := fencePartBytes(part)
		if err != nil {
			if part.Encoding == "uint64_be" {
				return "uint64"
			}
			return "encoding"
		}
		declared, err := hex.DecodeString(part.BytesHex)
		if err != nil || !bytes.Equal(raw, declared) {
			return "bytes"
		}
		if part.Name == "credential_key_hash" && len(raw) != 32 {
			return "key_length"
		}
		if part.Name == "scope_count" {
			scopeCount = binary.BigEndian.Uint64(raw)
		} else if strings.HasPrefix(part.Name, "scope_") {
			scopes = append(scopes, part.Value)
		}
	}
	if uint64(len(scopes)) != scopeCount {
		return "canonical_scopes"
	}
	for i, scope := range scopes {
		if scope == "" || (i > 0 && scopes[i-1] >= scope) {
			return "canonical_scopes"
		}
	}
	return ""
}
