// Package conformance is the single public source of truth for the qURL
// cross-language conformance vectors. It embeds the JSON artifacts under
// vectors/ and exposes strict, typed loaders so any consumer — in any language
// that can call this Go module, or that copies the JSON directly — can re-run
// the same wire-truth against its own implementation.
//
// Two families live here, each under its own artifact id so they stay decoupled
// by layer:
//
//   - The qURL v2 verify-path vectors (qv2_conformance_vectors.json composing
//     issuer_signature_vectors.json): the claims/secret/base64/fragment/relay/
//     server-id classes and the issuer-signature golden bytes.
//   - The relay/NHP-handshake golden packets (relay_knock_golden.json): the
//     deterministic relay-knock packet plus a frozen, server-sealed ack reply
//     for the Noise handshake layer, which the qURL verify path does not import.
//
// The verify-path artifact is BEHAVIORAL: a consumer feeds each class's input
// through its real parser/validator and asserts the declared accept/reject
// outcome (and, where the class is about the distinction, the reject_class),
// rather than trusting a stored boolean. A verifier that drifts from the
// contract fails its own run.
//
// This module is stdlib-only and has no build-time dependencies; the generator
// that produces the vectors is intentionally not part of it.
package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Expectation constants for a vector's Expect field, shared by both artifacts.
const (
	ExpectAccept = "accept"
	ExpectReject = "reject"
)

// reject_class vocabulary. These constants are the fixed cross-language vocabulary
// the README pins, so every consumer can switch on a closed, known set. They are
// pinned precisely only where the class is about the distinction (signature
// high_s vs wrong_length; encoding; key_length); JSON-schema faults use the coarse
// "parse" because a conformant verifier may surface any of several internal
// sentinels for them.
const (
	// RejectClassParse is the coarse class for a JSON-schema violation (duplicate
	// key, unknown field, null, wrong type, missing required, out-of-range/ordering).
	RejectClassParse = "parse"
	// RejectClassEncoding is a base64url encoding-layer rejection.
	RejectClassEncoding = "encoding"
	// RejectClassKeyLength is a decoded-key wrong-length rejection.
	RejectClassKeyLength = "key_length"
	// RejectClassFragment is a fragment wire-shape rejection.
	RejectClassFragment = "fragment"
	// RejectClassRelayURL is a relay_url HTTPS/allowlist rejection.
	RejectClassRelayURL = "relay_url"
	// RejectClassTamper is the signature-class payload-tamper rejection: a valid
	// signature verified against a flipped claims input (derived, not stored).
	RejectClassTamper = "tamper"
	// RejectClassHighS is a signature that is not low-S normalized.
	RejectClassHighS = "high_s"
	// RejectClassWrongLength is a signature that is not exactly 64 bytes (raw r||s).
	RejectClassWrongLength = "wrong_length"
)

// Signature-class tamper derivation identifiers. These pin the artifact's
// language-agnostic derivation so a consumer applies exactly what the JSON
// specifies rather than a hardcoded rule.
const (
	// TamperDeriveFromAccept is the only supported derive_from: start from the
	// composed file's accept vector.
	TamperDeriveFromAccept = "accept_vector"
	// TamperTransformFlipFirstB64 flips the FIRST base64url character of the accept
	// vector's claims_b64 between 'A' and 'B' ('A'->'B', any other char->'A'). The
	// first symbol encodes the top 6 bits of decoded byte 0, so this changes the
	// DECODED claims (not just don't-care tail bits) AND keeps the string canonical
	// base64url. That makes the derived tamper identical for every consumer
	// regardless of whether it hashes the base64 string, decodes-then-hashes, or
	// strict-decodes before verifying.
	TamperTransformFlipFirstB64 = "flip_first_base64url_char_A_B"
)

// ConformanceArtifactID is the fixed identity string the top-level "artifact"
// field must carry. The loader enforces it so a consumer that relies on "the
// loader rejects malformed files" cannot silently load a DIFFERENT document into
// these structs. A consumer in another language should assert the same id.
const ConformanceArtifactID = "qurl-v2-conformance-vectors"

// ConformanceFile is the top-level conformance artifact document.
type ConformanceFile struct {
	Artifact       string                      `json:"artifact"`
	SchemaVersion  int                         `json:"schema_version"`
	Description    string                      `json:"description"`
	SourceOfTruth  string                      `json:"source_of_truth"`
	Notes          []string                    `json:"notes"`
	SignatureClass ConformanceSignatureClass   `json:"signature_class"`
	Classes        map[string]ConformanceClass `json:"classes"`
}

// ConformanceSignatureClass records that the signature class is composed from a
// separate file rather than carrying its own bytes, plus the language-agnostic
// payload-tamper derivation every consumer synthesizes from the composed file's
// accept vector (so the tamper negative is portable without a second copy of
// signature bytes).
type ConformanceSignatureClass struct {
	EntryPoint string `json:"entry_point"`
	Composes   string `json:"composes"`
	Comment    string `json:"comment"`
	// TamperDerivation specifies the derived payload-tamper reject. It is optional
	// in the schema's struct but consumers assert it is present and well-formed.
	TamperDerivation *ConformanceTamperDerivation `json:"tamper_derivation,omitempty"`
}

// ConformanceTamperDerivation specifies how a consumer derives the payload-tamper
// reject from the composed signature file's accept vector. It is a derivation, not
// stored bytes, so every consumer synthesizes the SAME negative.
//
//   - RejectClass: the reject_class label for the derived case ("tamper").
//   - DeriveFrom: which composed vector to start from ("accept_vector").
//   - ClaimsTransform: the transform applied to that vector's claims_b64 to make
//     the signature no longer valid over it ("flip_first_base64url_char_A_B": flip
//     the FIRST base64url character between 'A' and 'B'). The signature bytes are
//     reused UNCHANGED, so the case fails only at the curve check.
type ConformanceTamperDerivation struct {
	RejectClass     string `json:"reject_class"`
	Comment         string `json:"comment"`
	DeriveFrom      string `json:"derive_from"`
	ClaimsTransform string `json:"claims_transform"`
}

// ConformanceClass is one named class: an entry-point label, the input field
// name, an optional human comment, and the ordered vectors.
type ConformanceClass struct {
	EntryPoint string              `json:"entry_point"`
	Input      string              `json:"input"`
	Comment    string              `json:"comment"`
	Vectors    []ConformanceVector `json:"vectors"`
}

// ConformanceVector is one case. Only the fields relevant to a vector's class are
// populated; the loader does not interpret them — the consumer routes each class to
// the matching entry point and reads the fields that class uses.
type ConformanceVector struct {
	Name        string `json:"name"`
	Expect      string `json:"expect"`
	RejectClass string `json:"reject_class"`
	Reason      string `json:"reason"`

	// claims_parse / secret_parse: raw JSON text fed directly to the parser.
	ClaimsJSON string `json:"claims_json"`
	SecretJSON string `json:"secret_json"`

	// strict_base64: the base64url string verbatim.
	ValueB64 string `json:"value_b64"`

	// fragment: a full fragment body.
	Fragment string `json:"fragment"`

	// relay_allowlist: the allowlist entries and the URL to validate.
	Entries []string `json:"entries"`
	URL     string   `json:"url"`

	// server_id: the cell public key (base64url) and its expected routing id.
	CellPublicKeyB64 string `json:"cell_public_key_b64"`
	ServerID         string `json:"server_id"`
}

// VectorFile is the top-level committed issuer-signature fixture document. The
// signature class of the conformance artifact composes this file by reference.
type VectorFile struct {
	// Description documents the contract for a human reader of the JSON.
	Description string `json:"description"`
	// Algorithm pins the signing profile (informational; verifiers do not
	// negotiate).
	Algorithm string `json:"algorithm"`
	// DomainSeparationPrefix is the ASCII prefix; the 0x00 separator follows it.
	DomainSeparationPrefix string `json:"domain_separation_prefix"`
	// Issuer is the shared issuer key all vectors are signed/verified under.
	Issuer IssuerKeyMaterial `json:"issuer"`
	// Vectors is the ordered list of accept/reject cases.
	Vectors []SignatureVector `json:"vectors"`
}

// IssuerKeyMaterial is the issuer public key in both import forms.
type IssuerKeyMaterial struct {
	KID string `json:"kid"`
	// SPKIDERB64 is the DER SPKI public key, base64url.
	SPKIDERB64 string `json:"spki_der_b64"`
	// JWK is the same public key as a P-256 JWK (crv/x/y), for WebCrypto "jwk".
	JWK ECPublicJWK `json:"jwk"`
}

// ECPublicJWK is a minimal P-256 public-key JWK. x and y are fixed-width 32-byte
// base64url (leading zeros preserved) so a strict importer accepts them.
type ECPublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// SignatureVector is one accept-or-reject case.
type SignatureVector struct {
	Name string `json:"name"`
	// Expect is "accept" or "reject".
	Expect string `json:"expect"`
	// Reason documents why (and, for rejects, names the failure class).
	Reason string `json:"reason"`
	// ClaimsB64 is the exact base64url claims string (primary verify input).
	ClaimsB64 string `json:"claims_b64"`
	// SigB64Raw is the signature as base64url. For accept/high-S it is 64-byte
	// raw r||s; for the wrong-length case it is the DER form (the realistic
	// "passed signer output straight through" mistake).
	SigB64Raw string `json:"sig_b64"`
	// SigEncoding documents the signature's byte form ("raw_r_s" or "der").
	SigEncoding string `json:"sig_encoding"`
	// SigningInputB64 is a cross-check value a verifier reconstructs itself as
	// prefix + 0x00 + claims_b64; it is not the data fed to the verifier.
	SigningInputB64 string `json:"signing_input_b64"`
}

// ParseConformanceFile strictly parses the conformance artifact from raw bytes. It
// returns an error (never an empty/zero document) when the bytes are malformed or
// are not the qURL v2 conformance artifact, so a consumer test FAILS rather than
// silently skipping or misreading the contract. DisallowUnknownFields keeps a
// typo'd or stale schema field from being ignored.
func ParseConformanceFile(data []byte) (*ConformanceFile, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cf ConformanceFile
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("conformance: parse conformance file: %w", err)
	}
	if cf.Artifact != ConformanceArtifactID {
		return nil, fmt.Errorf("conformance: conformance file has artifact %q, want %q", cf.Artifact, ConformanceArtifactID)
	}
	if cf.SchemaVersion == 0 {
		return nil, fmt.Errorf("conformance: conformance file missing schema_version")
	}
	if len(cf.Classes) == 0 {
		return nil, fmt.Errorf("conformance: conformance file has no classes")
	}
	return &cf, nil
}

// ParseVectorFile strictly parses an issuer-signature vector file from raw bytes.
// It returns an error (never an empty/zero document) if the bytes are malformed,
// so a consumer test FAILS rather than silently skipping the contract.
func ParseVectorFile(data []byte) (*VectorFile, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var vf VectorFile
	if err := dec.Decode(&vf); err != nil {
		return nil, fmt.Errorf("conformance: parse vector file: %w", err)
	}
	if len(vf.Vectors) == 0 {
		return nil, fmt.Errorf("conformance: vector file has no vectors")
	}
	return &vf, nil
}

// RelayKnockArtifactID is the fixed identity string the relay-knock artifact's
// top-level "artifact" field must carry. The loader enforces it so a consumer
// that relies on "the loader rejects malformed files" cannot silently load a
// DIFFERENT document into these structs. A consumer in another language should
// assert the same id.
const RelayKnockArtifactID = "qurl-relay-knock-golden-vectors"

// RelayKnockFile is the top-level relay/NHP-handshake golden artifact: a
// deterministic knock packet a conformant initiator must reproduce byte-for-byte,
// plus a frozen ack reply (sealed at origin with a random server ephemeral, so it
// is NOT reproducible by a client — only decryptable). Both cases decode into the
// same RelayKnockCase, which carries the UNION of the fields either case uses.
type RelayKnockFile struct {
	Artifact      string         `json:"artifact"`
	SchemaVersion int            `json:"schema_version"`
	Description   string         `json:"description"`
	SourceOfTruth string         `json:"source_of_truth"`
	Notes         []string       `json:"notes"`
	Knock         RelayKnockCase `json:"knock"`
	Ack           RelayKnockCase `json:"ack"`
}

// RelayKnockCase is one golden packet (knock or ack). Every value is the exact
// hex (or, for the numeric fields, the stringified value) the case uses; only the
// fields relevant to a given case are populated. All fields are strings — including
// timestamp_nanos, which exceeds 2^53 and so is carried as a decimal string rather
// than a JSON number.
type RelayKnockCase struct {
	// ServerStaticPrivHex / ServerStaticPubHex are the server static X25519 key.
	// The knock case carries both; the ack case carries only the public half.
	ServerStaticPrivHex string `json:"server_static_priv_hex,omitempty"`
	ServerStaticPubHex  string `json:"server_static_pub_hex"`
	// DeviceStaticPrivHex / DeviceStaticPubHex are the initiator (device) static
	// X25519 key, used by the knock case.
	DeviceStaticPrivHex string `json:"device_static_priv_hex,omitempty"`
	DeviceStaticPubHex  string `json:"device_static_pub_hex,omitempty"`
	// AgentStaticPrivHex is the agent (responder-side decryptor) static private
	// X25519 key, used by the ack case to open the reply. It is the same key as the
	// knock case's device_static_priv_hex.
	AgentStaticPrivHex string `json:"agent_static_priv_hex,omitempty"`
	// EphemeralPrivHex is the fixed initiator ephemeral private key the knock case
	// seals under (so the knock packet is deterministic).
	EphemeralPrivHex string `json:"ephemeral_priv_hex,omitempty"`
	// TimestampNanos is the handshake timestamp, decimal string (exceeds 2^53).
	TimestampNanos string `json:"timestamp_nanos"`
	// Counter is the knock counter as a decimal string.
	Counter string `json:"counter,omitempty"`
	// CounterHex is the ack counter as a hex string (no 0x prefix, no padding).
	CounterHex string `json:"counter_hex,omitempty"`
	// PreambleHex is the 32-bit knock preamble as a hex string.
	PreambleHex string `json:"preamble_hex,omitempty"`
	// BodyHex is the plaintext body the case carries, hex-encoded.
	BodyHex string `json:"body_hex"`
	// PacketHex is the full wire packet, hex-encoded: for knock, the value a
	// conformant BuildKnock must reproduce; for ack, the frozen value a conformant
	// DecryptReply must open.
	PacketHex string `json:"packet_hex"`
}

// ParseRelayKnockFile strictly parses the relay-knock golden artifact from raw
// bytes. It returns an error (never an empty/zero document) when the bytes are
// malformed or are not the relay-knock artifact, so a consumer test FAILS rather
// than silently skipping or misreading the contract. DisallowUnknownFields keeps a
// typo'd or stale schema field from being ignored.
func ParseRelayKnockFile(data []byte) (*RelayKnockFile, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rf RelayKnockFile
	if err := dec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("conformance: parse relay-knock file: %w", err)
	}
	if rf.Artifact != RelayKnockArtifactID {
		return nil, fmt.Errorf("conformance: relay-knock file has artifact %q, want %q", rf.Artifact, RelayKnockArtifactID)
	}
	if rf.SchemaVersion == 0 {
		return nil, errors.New("conformance: relay-knock file missing schema_version")
	}
	// Fail closed on a blank load-bearing field: a consumer that re-runs the
	// golden bytes (rebuild knock.packet_hex / decrypt ack.packet_hex) must not
	// silently "pass" on an empty packet or body.
	if rf.Knock.PacketHex == "" {
		return nil, errors.New("conformance: relay-knock file missing knock.packet_hex")
	}
	if rf.Knock.BodyHex == "" {
		return nil, errors.New("conformance: relay-knock file missing knock.body_hex")
	}
	if rf.Ack.PacketHex == "" {
		return nil, errors.New("conformance: relay-knock file missing ack.packet_hex")
	}
	if rf.Ack.BodyHex == "" {
		return nil, errors.New("conformance: relay-knock file missing ack.body_hex")
	}
	return &rf, nil
}
