// Package conformance is the single public source of truth for the qURL
// cross-language conformance vectors. It embeds the JSON artifacts under
// vectors/ and exposes strict, typed loaders so any consumer — in any language
// that can call this Go module, or that copies the JSON directly — can re-run
// the same wire-truth against its own implementation.
//
// Six families live here, each under its own artifact id so they stay decoupled
// by layer:
//
//   - The qURL v2 verify-path vectors (qv2_conformance_vectors.json composing
//     issuer_signature_vectors.json): the claims/secret/base64/fragment/relay/
//     server-id classes and the issuer-signature golden bytes.
//   - The relay/NHP-handshake golden packets (relay_knock_golden.json): the
//     deterministic relay-knock packet plus a frozen, server-sealed ack reply
//     for the Noise handshake layer, which the qURL verify path does not import.
//   - The NHP agent-registration golden packets
//     (agent_registration_golden.json): deterministic OTP/REG requests plus
//     frozen RAK replies.
//   - The NHP agent-assignment golden packets
//     (agent_assignment_golden.json): deterministic LST/LRT assignment and
//     completion, assigned-cell REG/RAK activation, and strict error bodies.
//   - The registered-agent knock application contract
//     (agent_knock_application_vectors.json): exact KNK JSON, RunID request
//     policy, and already-decrypted ACK/COK disposition vectors, with no
//     duplicate packet bytes.
//   - The agent API-key ID contract (agent_api_key_id_vectors.json): issuer
//     construction and strict consumer cases for registration-info key_id and
//     completion device_api_key_id.
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
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Expectation constants for accept/reject vector fields across artifacts.
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
	// RejectClass is the machine-readable rejection class. It is present on reject
	// vectors and absent on accept vectors.
	RejectClass string `json:"reject_class,omitempty"`
	// Reason documents why in human-readable prose.
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
	var cf ConformanceFile
	if err := strictDecodeArtifact(data, &cf); err != nil {
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
	var vf VectorFile
	if err := strictDecodeArtifact(data, &vf); err != nil {
		return nil, fmt.Errorf("conformance: parse vector file: %w", err)
	}
	if len(vf.Vectors) == 0 {
		return nil, fmt.Errorf("conformance: vector file has no vectors")
	}
	for _, v := range vf.Vectors {
		switch v.Expect {
		case ExpectAccept:
			if v.RejectClass != "" {
				return nil, fmt.Errorf("conformance: accept signature vector %q has reject_class %q", v.Name, v.RejectClass)
			}
		case ExpectReject:
			switch v.RejectClass {
			case RejectClassHighS, RejectClassWrongLength:
			default:
				return nil, fmt.Errorf("conformance: reject signature vector %q has reject_class %q, want %q or %q", v.Name, v.RejectClass, RejectClassHighS, RejectClassWrongLength)
			}
		default:
			return nil, fmt.Errorf("conformance: signature vector %q has expect %q, want accept|reject", v.Name, v.Expect)
		}
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
	var rf RelayKnockFile
	if err := strictDecodeArtifact(data, &rf); err != nil {
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

// AgentRegistrationArtifactID is the fixed identity string the agent-registration
// artifact's top-level "artifact" field must carry. The loader enforces it so a
// consumer that relies on "the loader rejects malformed files" cannot silently
// load a DIFFERENT document into these structs. A consumer in another language
// should assert the same id.
const AgentRegistrationArtifactID = "qurl-agent-registration-golden-vectors"

// AgentRegistrationFile is the top-level NHP agent-registration golden artifact:
// the OTP request, the emailed-code and pre-issued-key REG requests (all three
// DETERMINISTIC — a conformant initiator must reproduce packet_hex byte-for-byte),
// and the server register-ack (RAK) success/error replies (FROZEN, sealed at
// origin with a random server ephemeral, so NOT reproducible by a client — only
// decryptable). Every case decodes into the same AgentRegistrationCase, which
// carries the UNION of the fields the deterministic and frozen cases use.
//
// The reg_emailed → rak pair is counter-matched (rak_success/rak_error echo
// reg_emailed's counter), so a consumer can validate the RAK-must-echo-its-REG
// counter contract (conformance#19) against a positive fixture.
type AgentRegistrationFile struct {
	Artifact      string                `json:"artifact"`
	SchemaVersion int                   `json:"schema_version"`
	Description   string                `json:"description"`
	SourceOfTruth string                `json:"source_of_truth"`
	Notes         []string              `json:"notes"`
	OTP           AgentRegistrationCase `json:"otp"`
	RegEmailed    AgentRegistrationCase `json:"reg_emailed"`
	RegPreissued  AgentRegistrationCase `json:"reg_preissued"`
	RakSuccess    AgentRegistrationCase `json:"rak_success"`
	RakError      AgentRegistrationCase `json:"rak_error"`
}

// AgentRegistrationCase is one golden packet: an OTP/REG initiator request or a
// RAK reply. Every value is the exact hex (or, for the numeric fields, the
// stringified value) the case uses; only the fields relevant to a given case are
// populated. All fields are strings — including timestamp_nanos, which exceeds
// 2^53 and so is carried as a decimal string rather than a JSON number.
//
// Deterministic cases (otp, reg_emailed, reg_preissued) carry the same fields as
// relay_knock's knock: the server/device static keypairs, the fixed initiator
// ephemeral, the timestamp/counter/preamble, the plaintext body, and the full
// packet a conformant builder must reproduce. Frozen cases (rak_success,
// rak_error) carry the ack-style fields: the server static PUBLIC key, the agent
// (responder-side decryptor) static PRIVATE key, the counter as hex, the body,
// and the frozen packet a conformant decryptor must open.
type AgentRegistrationCase struct {
	// ServerStaticPrivHex / ServerStaticPubHex are the server static X25519 key.
	// Deterministic cases carry both; frozen (RAK) cases carry only the public half.
	ServerStaticPrivHex string `json:"server_static_priv_hex,omitempty"`
	ServerStaticPubHex  string `json:"server_static_pub_hex"`
	// DeviceStaticPrivHex / DeviceStaticPubHex are the initiator (agent/device)
	// static X25519 key, used by the deterministic OTP/REG cases.
	DeviceStaticPrivHex string `json:"device_static_priv_hex,omitempty"`
	DeviceStaticPubHex  string `json:"device_static_pub_hex,omitempty"`
	// AgentStaticPrivHex is the agent (responder-side decryptor) static private
	// X25519 key, used by the frozen RAK cases to open the reply. It is the same
	// key as the deterministic cases' device_static_priv_hex.
	AgentStaticPrivHex string `json:"agent_static_priv_hex,omitempty"`
	// EphemeralPrivHex is the fixed initiator ephemeral private key the
	// deterministic cases seal under (so the packet is reproducible).
	EphemeralPrivHex string `json:"ephemeral_priv_hex,omitempty"`
	// TimestampNanos is the handshake timestamp, decimal string (exceeds 2^53).
	TimestampNanos string `json:"timestamp_nanos"`
	// Counter is the deterministic-case counter as a decimal string.
	Counter string `json:"counter,omitempty"`
	// CounterHex is the frozen RAK counter as a hex string (no 0x prefix, no
	// padding). It echoes reg_emailed's counter for the matched pair.
	CounterHex string `json:"counter_hex,omitempty"`
	// PreambleHex is the 32-bit HeaderCommon preamble as a hex string
	// (deterministic cases).
	PreambleHex string `json:"preamble_hex,omitempty"`
	// BodyHex is the plaintext registration body the case carries, hex-encoded
	// (AgentOTPMsg / AgentRegisterMsg / ServerRegisterAckMsg JSON).
	BodyHex string `json:"body_hex"`
	// PacketHex is the full wire packet, hex-encoded: for a deterministic case,
	// the value a conformant builder must reproduce; for a frozen RAK case, the
	// value a conformant decryptor must open.
	PacketHex string `json:"packet_hex"`
}

// ParseAgentRegistrationFile strictly parses the agent-registration golden
// artifact from raw bytes. It returns an error (never an empty/zero document)
// when the bytes are malformed or are not the agent-registration artifact, so a
// consumer test FAILS rather than silently skipping or misreading the contract.
// DisallowUnknownFields keeps a typo'd or stale schema field from being ignored.
func ParseAgentRegistrationFile(data []byte) (*AgentRegistrationFile, error) {
	var af AgentRegistrationFile
	if err := strictDecodeArtifact(data, &af); err != nil {
		return nil, fmt.Errorf("conformance: parse agent-registration file: %w", err)
	}
	if af.Artifact != AgentRegistrationArtifactID {
		return nil, fmt.Errorf("conformance: agent-registration file has artifact %q, want %q", af.Artifact, AgentRegistrationArtifactID)
	}
	if af.SchemaVersion == 0 {
		return nil, errors.New("conformance: agent-registration file missing schema_version")
	}
	// Fail closed on a blank load-bearing field: a consumer that re-runs the
	// golden bytes (rebuild the OTP/REG packet_hex / decrypt the RAK packet_hex)
	// must not silently "pass" on an empty packet or body.
	for _, c := range []struct {
		name string
		c    AgentRegistrationCase
	}{
		{"otp", af.OTP},
		{"reg_emailed", af.RegEmailed},
		{"reg_preissued", af.RegPreissued},
		{"rak_success", af.RakSuccess},
		{"rak_error", af.RakError},
	} {
		if c.c.PacketHex == "" {
			return nil, fmt.Errorf("conformance: agent-registration file missing %s.packet_hex", c.name)
		}
		if c.c.BodyHex == "" {
			return nil, fmt.Errorf("conformance: agent-registration file missing %s.body_hex", c.name)
		}
	}
	return &af, nil
}

// AgentAssignmentArtifactID is the fixed identity of the NHP assignment,
// assigned-cell activation, and registration-completion golden artifact.
const AgentAssignmentArtifactID = "qurl-agent-assignment-golden-vectors"

// The exact NHP header values used for list request/result exchanges. Results
// echo their request's counter and never use the overload-cookie reply type.
const (
	AgentAssignmentRequestHeaderName = "NHP_LST"
	AgentAssignmentRequestHeaderType = 5
	AgentAssignmentResultHeaderName  = "NHP_LRT"
	AgentAssignmentResultHeaderType  = 6
	// REG/RAK are shared NHP wire identities; these constants describe the
	// assigned-cell activation step, not a second registration wire format.
	AgentRegistrationRequestHeaderName = "NHP_REG"
	AgentRegistrationRequestHeaderType = 13
	AgentRegistrationResultHeaderName  = "NHP_RAK"
	AgentRegistrationResultHeaderType  = 14
)

// Agent-assignment reject outcome and class vocabulary.
const (
	AgentAssignmentErrorOutcomeReject         = "reject"
	AgentAssignmentRejectBodyParse            = "body_parse"
	AgentAssignmentRejectUnknownField         = "unknown_field"
	AgentAssignmentRejectMissingField         = "missing_field"
	AgentAssignmentRejectWrongType            = "wrong_type"
	AgentAssignmentRejectListOnError          = "list_on_error"
	AgentAssignmentRejectRetryAfterMissing    = "retry_after_missing"
	AgentAssignmentRejectRetryAfterInvalid    = "retry_after_invalid"
	AgentAssignmentRejectRetryAfterUnexpected = "retry_after_unexpected"
	AgentAssignmentRejectSemantic             = "semantic"
	AgentAssignmentRejectUnknownErrorCode     = "unknown_error_code"
)

// Producer revisions for the deterministic wire and error contracts.
const (
	// AgentAssignmentQURLGoProducerRevision is the merged qurl-go revision
	// used to build and authenticate-open every assignment lifecycle packet.
	AgentAssignmentQURLGoProducerRevision = "8a69642957030b9ce0a1b8b356246d265a9f577d"
	// AgentAssignmentNHPProducerRevision is the merged NHP revision that owns
	// the closed assignment and registration error-code taxonomy.
	AgentAssignmentNHPProducerRevision = "9653fcb185c77629b787ad046c13c760baba88f4"
)

// Exact synthetic production-shaped fixture values.
const (
	// AgentAssignmentBootstrapCredentialFixture is the exact synthetic,
	// production-shaped credential fixture. Secret scanners must allow only
	// this value, never an lv_live_conformance_* wildcard.
	AgentAssignmentBootstrapCredentialFixture = "lv_live_conformance_bootstrap_secret_0001"
	// AgentAssignmentDeviceAPIKeyFixture is the exact synthetic,
	// production-shaped device-key fixture. Secret scanners must allow only
	// this value, never an lv_live_conformance_* wildcard.
	AgentAssignmentDeviceAPIKeyFixture = "lv_live_conformance_device_secret_0001"
)

// NHP Curve packets use a 240-byte HeaderCurve and the transport reads into a
// fixed 4096-byte PacketBufferSize. These inclusive framing bounds reject
// impossible fixtures before the producer verifier authenticates their bodies.
const (
	agentAssignmentCurveHeaderBytes  = 240
	agentAssignmentPacketBufferBytes = 4096
)

// AgentAssignmentFile pins four complete deterministic NHP exchanges: initial
// assignment and refresh against the bootstrap hub, assigned-cell registration
// with the assignment ticket, and registration completion against that cell.
// ErrorContract is application-layer behavioral data for the same lifecycle.
type AgentAssignmentFile struct {
	Artifact                   string                       `json:"artifact"`
	SchemaVersion              int                          `json:"schema_version"`
	Description                string                       `json:"description"`
	SourceOfTruth              string                       `json:"source_of_truth"`
	Notes                      []string                     `json:"notes"`
	PublicRegistrationKeyKinds []string                     `json:"public_registration_key_kinds"`
	Keys                       AgentAssignmentKeys          `json:"keys"`
	InitialAssignment          AgentAssignmentExchange      `json:"initial_assignment"`
	RefreshAssignment          AgentAssignmentExchange      `json:"refresh_assignment"`
	AssignedCellRegistration   AgentAssignmentExchange      `json:"assigned_cell_registration"`
	RegistrationCompletion     AgentAssignmentExchange      `json:"registration_completion"`
	RequestCases               []AgentAssignmentRequestCase `json:"request_cases"`
	SuccessResultCases         []AgentAssignmentResultCase  `json:"success_result_cases"`
	ErrorContract              AgentAssignmentErrorContract `json:"error_contract"`
}

// AgentAssignmentKeys names the three synthetic static X25519 identities used by
// the exchanges. Keeping keys at the top level makes the hub/cell trust boundary
// explicit without repeating private material in every packet case.
type AgentAssignmentKeys struct {
	Hub          AgentAssignmentKey `json:"hub"`
	AssignedCell AgentAssignmentKey `json:"assigned_cell"`
	Agent        AgentAssignmentKey `json:"agent"`
}

type AgentAssignmentKey struct {
	StaticPrivHex string `json:"static_priv_hex"`
	StaticPubHex  string `json:"static_pub_hex"`
}

type AgentAssignmentExchange struct {
	Request AgentAssignmentPacket `json:"request"`
	Result  AgentAssignmentPacket `json:"result"`
}

// AgentAssignmentPacket is one deterministic LST, LRT, REG, or RAK packet.
// body_json is a string, rather than an embedded object, because its exact UTF-8
// bytes and field order are cryptographic input; body_hex must encode those same
// bytes.
type AgentAssignmentPacket struct {
	HeaderName       string `json:"header_name"`
	HeaderType       int    `json:"header_type"`
	SenderKey        string `json:"sender_key"`
	ReceiverKey      string `json:"receiver_key"`
	EphemeralPrivHex string `json:"ephemeral_priv_hex"`
	TimestampNanos   string `json:"timestamp_nanos"`
	Counter          string `json:"counter"`
	PreambleHex      string `json:"preamble_hex"`
	BodyJSON         string `json:"body_json"`
	BodyHex          string `json:"body_hex"`
	PacketHex        string `json:"packet_hex"`
}

type agentAssignmentListRequest struct {
	UsrID   string          `json:"usrId"`
	DevID   string          `json:"devId"`
	AspID   string          `json:"aspId"`
	UsrData json.RawMessage `json:"usrData"`
}

type agentAssignmentInitialRequestData struct {
	Query      string `json:"query"`
	Version    int    `json:"version"`
	Mode       string `json:"mode"`
	Credential string `json:"credential"`
}

type agentAssignmentRefreshRequestData struct {
	Query   string `json:"query"`
	Version int    `json:"version"`
	Mode    string `json:"mode"`
}

type agentAssignmentCompletionRequestData struct {
	Query        string `json:"query"`
	Version      int    `json:"version"`
	DeviceAPIKey string `json:"device_api_key"`
}

type agentAssignmentListSuccess struct {
	ErrCode string          `json:"errCode"`
	List    json.RawMessage `json:"list"`
}

type agentAssignmentRegistrationMetadata struct {
	KeyID   string `json:"key_id"`
	KeyKind string `json:"key_kind"`
}

type agentAssignmentWireEndpoint struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	ServerPublicKeyB64 string `json:"server_public_key_b64"`
}

type agentAssignmentWireAssignment struct {
	CellID               string                      `json:"cell_id"`
	AssignmentGeneration int                         `json:"assignment_generation"`
	EndpointRevision     int                         `json:"endpoint_revision"`
	LeaseExpiresAt       string                      `json:"lease_expires_at"`
	NHPUDPEndpoint       agentAssignmentWireEndpoint `json:"nhp_udp_endpoint"`
}

type agentAssignmentInitialResult struct {
	Query                     string                              `json:"query"`
	Version                   int                                 `json:"version"`
	Mode                      string                              `json:"mode"`
	AgentID                   string                              `json:"agent_id"`
	Registration              agentAssignmentRegistrationMetadata `json:"registration"`
	Assignment                agentAssignmentWireAssignment       `json:"assignment"`
	AssignmentTicket          string                              `json:"assignment_ticket"`
	AssignmentTicketExpiresAt string                              `json:"assignment_ticket_expires_at"`
}

type agentAssignmentRefreshResult struct {
	Query      string                        `json:"query"`
	Version    int                           `json:"version"`
	Mode       string                        `json:"mode"`
	AgentID    string                        `json:"agent_id"`
	Assignment agentAssignmentWireAssignment `json:"assignment"`
}

type agentAssignmentRegisterRequest struct {
	UsrID   string                             `json:"usrId"`
	DevID   string                             `json:"devId"`
	AspID   string                             `json:"aspId"`
	OTP     string                             `json:"otp"`
	UsrData agentAssignmentRegisterRequestData `json:"usrData"`
}

type agentAssignmentRegisterRequestData struct {
	Hostname         string `json:"hostname"`
	Version          string `json:"version"`
	AssignmentTicket string `json:"assignment_ticket"`
}

type agentAssignmentRegisterResult struct {
	ErrCode string `json:"errCode"`
	AspID   string `json:"aspId"`
}

type agentAssignmentCompletionResult struct {
	Query          string `json:"query"`
	Version        int    `json:"version"`
	DeviceAPIKeyID string `json:"device_api_key_id"`
}

// AgentAssignmentErrorContract is the closed v1 authenticated error taxonomy.
// Valid cases drive production parsers/classifiers; malformed cases drive their
// strict reject paths. Error bodies are strings so duplicate keys and trailing
// JSON reach the consumer unchanged.
type AgentAssignmentErrorContract struct {
	Status                 string                         `json:"status"`
	ProducerRevision       string                         `json:"producer_revision"`
	Rules                  AgentAssignmentErrorRules      `json:"rules"`
	AssignmentCases        []AgentAssignmentErrorCase     `json:"assignment_cases"`
	InitialCredentialCases []AgentAssignmentErrorCase     `json:"initial_credential_cases"`
	CompletionCases        []AgentAssignmentErrorCase     `json:"completion_cases"`
	RegistrationCases      []AgentAssignmentErrorCase     `json:"registration_cases"`
	MalformedCases         []AgentAssignmentMalformedCase `json:"malformed_cases"`
}

type AgentAssignmentErrorRules struct {
	ListErrorHeaderName              string   `json:"list_error_header_name"`
	ListErrorHeaderType              int      `json:"list_error_header_type"`
	RegistrationErrorHeaderName      string   `json:"registration_error_header_name"`
	RegistrationErrorHeaderType      int      `json:"registration_error_header_type"`
	ListOmittedOnError               bool     `json:"list_omitted_on_error"`
	CookieChallengeAllowed           bool     `json:"cookie_challenge_allowed"`
	RetryAfterSecondsPermittedCodes  []string `json:"retry_after_seconds_permitted_codes"`
	RetryAfterSecondsRequiredCodes   []string `json:"retry_after_seconds_required_codes"`
	RetryAfterSecondsPositiveInteger bool     `json:"retry_after_seconds_positive_integer"`
	ErrMsgControlsPolicy             bool     `json:"err_msg_controls_policy"`
}

type AgentAssignmentErrorCase struct {
	Name              string `json:"name"`
	Phase             string `json:"phase"`
	HeaderName        string `json:"header_name"`
	HeaderType        int    `json:"header_type"`
	BodyJSON          string `json:"body_json"`
	ErrCode           string `json:"err_code"`
	Outcome           string `json:"outcome"`
	RetryAfterSeconds *int   `json:"retry_after_seconds,omitempty"`
}

type AgentAssignmentMalformedCase struct {
	Name        string `json:"name"`
	Phase       string `json:"phase"`
	HeaderName  string `json:"header_name"`
	HeaderType  int    `json:"header_type"`
	BodyJSON    string `json:"body_json"`
	Outcome     string `json:"outcome"`
	RejectClass string `json:"reject_class"`
}

// AgentAssignmentCase is an authenticated application request or result that a
// producer/consumer must reject. BodyJSON stays raw so duplicate keys and
// trailing JSON survive artifact parsing.
type AgentAssignmentCase struct {
	Name        string `json:"name"`
	Phase       string `json:"phase"`
	HeaderName  string `json:"header_name"`
	HeaderType  int    `json:"header_type"`
	BodyJSON    string `json:"body_json"`
	Outcome     string `json:"outcome"`
	RejectClass string `json:"reject_class"`
}

// AgentAssignmentRequestCase is an authenticated application request reject.
// It is intentionally distinct from AgentAssignmentResultCase so callers
// cannot interchange request and result cases at compile time.
type AgentAssignmentRequestCase AgentAssignmentCase

// AgentAssignmentResultCase is an authenticated success-envelope reject.
// It is intentionally distinct from AgentAssignmentRequestCase so callers
// cannot interchange request and result cases at compile time.
type AgentAssignmentResultCase AgentAssignmentCase

type agentAssignmentListErrorBody struct {
	ErrCode           string          `json:"errCode"`
	ErrMsg            string          `json:"errMsg,omitempty"`
	RetryAfterSeconds *int            `json:"retryAfterSeconds,omitempty"`
	List              json.RawMessage `json:"list,omitempty"`
}

type agentAssignmentRegistrationErrorBody struct {
	ErrCode string `json:"errCode"`
	ErrMsg  string `json:"errMsg,omitempty"`
	AspID   string `json:"aspId"`
}

type agentAssignmentPhaseSchema struct {
	requestHeaderName string
	requestHeaderType int
	resultHeaderName  string
	resultHeaderType  int
	requestOuterKeys  map[string]struct{}
	requestDataKeys   map[string]struct{}
	resultOuterKeys   map[string]struct{}
	resultListKeys    map[string]struct{}
}

var (
	agentAssignmentPublicRegistrationKeyKinds = []string{"bootstrap", "connector_bootstrap", "account", "agent"}
	agentAssignmentListRequestKeys            = jsonTagKeySet(reflect.TypeOf(agentAssignmentListRequest{}))
	agentAssignmentRegisterKeys               = jsonTagKeySet(reflect.TypeOf(agentAssignmentRegisterRequest{}))
	agentAssignmentListSuccessKeys            = jsonTagKeySet(reflect.TypeOf(agentAssignmentListSuccess{}))
	agentAssignmentRegisterAckKeys            = jsonTagKeySet(reflect.TypeOf(agentAssignmentRegisterResult{}))
	agentAssignmentRegistrationKeys           = jsonTagKeySet(reflect.TypeOf(agentAssignmentRegistrationMetadata{}))
	agentAssignmentAssignmentKeys             = jsonTagKeySet(reflect.TypeOf(agentAssignmentWireAssignment{}))
	agentAssignmentEndpointKeys               = jsonTagKeySet(reflect.TypeOf(agentAssignmentWireEndpoint{}))
	agentAssignmentListErrorKeys              = jsonTagKeySet(reflect.TypeOf(agentAssignmentListErrorBody{}))
	agentAssignmentRAKErrorKeys               = jsonTagKeySet(reflect.TypeOf(agentAssignmentRegistrationErrorBody{}))

	agentAssignmentPhases = map[string]agentAssignmentPhaseSchema{
		"initial_assignment": {
			requestHeaderName: AgentAssignmentRequestHeaderName,
			requestHeaderType: AgentAssignmentRequestHeaderType,
			resultHeaderName:  AgentAssignmentResultHeaderName,
			resultHeaderType:  AgentAssignmentResultHeaderType,
			requestOuterKeys:  agentAssignmentListRequestKeys,
			requestDataKeys:   jsonTagKeySet(reflect.TypeOf(agentAssignmentInitialRequestData{})),
			resultOuterKeys:   agentAssignmentListSuccessKeys,
			resultListKeys:    jsonTagKeySet(reflect.TypeOf(agentAssignmentInitialResult{})),
		},
		"refresh_assignment": {
			requestHeaderName: AgentAssignmentRequestHeaderName,
			requestHeaderType: AgentAssignmentRequestHeaderType,
			resultHeaderName:  AgentAssignmentResultHeaderName,
			resultHeaderType:  AgentAssignmentResultHeaderType,
			requestOuterKeys:  agentAssignmentListRequestKeys,
			requestDataKeys:   jsonTagKeySet(reflect.TypeOf(agentAssignmentRefreshRequestData{})),
			resultOuterKeys:   agentAssignmentListSuccessKeys,
			resultListKeys:    jsonTagKeySet(reflect.TypeOf(agentAssignmentRefreshResult{})),
		},
		"assigned_cell_registration": {
			requestHeaderName: AgentRegistrationRequestHeaderName,
			requestHeaderType: AgentRegistrationRequestHeaderType,
			resultHeaderName:  AgentRegistrationResultHeaderName,
			resultHeaderType:  AgentRegistrationResultHeaderType,
			requestOuterKeys:  agentAssignmentRegisterKeys,
			requestDataKeys:   jsonTagKeySet(reflect.TypeOf(agentAssignmentRegisterRequestData{})),
			resultOuterKeys:   agentAssignmentRegisterAckKeys,
		},
		"registration_completion": {
			requestHeaderName: AgentAssignmentRequestHeaderName,
			requestHeaderType: AgentAssignmentRequestHeaderType,
			resultHeaderName:  AgentAssignmentResultHeaderName,
			resultHeaderType:  AgentAssignmentResultHeaderType,
			requestOuterKeys:  agentAssignmentListRequestKeys,
			requestDataKeys:   jsonTagKeySet(reflect.TypeOf(agentAssignmentCompletionRequestData{})),
			resultOuterKeys:   agentAssignmentListSuccessKeys,
			resultListKeys:    jsonTagKeySet(reflect.TypeOf(agentAssignmentCompletionResult{})),
		},
	}
)

// ParseAgentAssignmentFile strictly parses and validates the deterministic
// assignment artifact. It fails closed on schema drift, missing crypto inputs,
// body byte drift, semantic envelope drift, type/role mix-ups, unmatched
// counters, or an incomplete/malformed error taxonomy.
func ParseAgentAssignmentFile(data []byte) (*AgentAssignmentFile, error) {
	var af AgentAssignmentFile
	if err := strictDecodeArtifact(data, &af); err != nil {
		return nil, fmt.Errorf("conformance: parse agent-assignment file: %w", err)
	}
	if af.Artifact != AgentAssignmentArtifactID {
		return nil, fmt.Errorf("conformance: agent-assignment file has artifact %q, want %q", af.Artifact, AgentAssignmentArtifactID)
	}
	if af.SchemaVersion != 1 {
		return nil, fmt.Errorf("conformance: agent-assignment file has schema_version %d, want 1", af.SchemaVersion)
	}
	if !slices.Equal(af.PublicRegistrationKeyKinds, agentAssignmentPublicRegistrationKeyKinds) {
		return nil, errors.New("conformance: agent-assignment public registration key_kind vocabulary drifted")
	}
	for _, fixture := range []struct {
		name string
		key  AgentAssignmentKey
	}{
		{name: "hub", key: af.Keys.Hub},
		{name: "assigned_cell", key: af.Keys.AssignedCell},
		{name: "agent", key: af.Keys.Agent},
	} {
		if err := validateAgentAssignmentHex(fixture.name+".static_priv_hex", fixture.key.StaticPrivHex, 32); err != nil {
			return nil, err
		}
		if err := validateAgentAssignmentHex(fixture.name+".static_pub_hex", fixture.key.StaticPubHex, 32); err != nil {
			return nil, err
		}
		if err := validateAgentAssignmentKeyPair(fixture.name, fixture.key); err != nil {
			return nil, err
		}
	}
	for _, exchange := range []struct {
		name     string
		exchange AgentAssignmentExchange
		target   string
	}{
		{name: "initial_assignment", exchange: af.InitialAssignment, target: "hub"},
		{name: "refresh_assignment", exchange: af.RefreshAssignment, target: "hub"},
		{name: "assigned_cell_registration", exchange: af.AssignedCellRegistration, target: "assigned_cell"},
		{name: "registration_completion", exchange: af.RegistrationCompletion, target: "assigned_cell"},
	} {
		phase := agentAssignmentPhases[exchange.name]
		// Every lifecycle exchange is agent -> target -> agent.
		if err := validateAgentAssignmentPacket(exchange.name+".request", exchange.exchange.Request, phase.requestHeaderName, phase.requestHeaderType, "agent", exchange.target); err != nil {
			return nil, err
		}
		if err := validateAgentAssignmentPacket(exchange.name+".result", exchange.exchange.Result, phase.resultHeaderName, phase.resultHeaderType, exchange.target, "agent"); err != nil {
			return nil, err
		}
		if exchange.exchange.Result.Counter != exchange.exchange.Request.Counter {
			return nil, fmt.Errorf("conformance: %s result counter %q does not echo request counter %q", exchange.name, exchange.exchange.Result.Counter, exchange.exchange.Request.Counter)
		}
	}
	if err := validateAgentAssignmentSuccessBodies(&af); err != nil {
		return nil, err
	}
	if err := validateAgentAssignmentRequestCases(af.RequestCases); err != nil {
		return nil, err
	}
	if err := validateAgentAssignmentResultCases(af.SuccessResultCases); err != nil {
		return nil, err
	}
	if err := validateAgentAssignmentErrorContract(af.ErrorContract); err != nil {
		return nil, err
	}
	return &af, nil
}

func validateAgentAssignmentRequestCases(cases []AgentAssignmentRequestCase) error {
	expected := map[string]agentAssignmentCaseExpectation{
		"reject_duplicate_outer_dev_id":              {"initial_assignment", AgentAssignmentRejectBodyParse},
		"reject_duplicate_initial_credential":        {"initial_assignment", AgentAssignmentRejectBodyParse},
		"reject_alias_outer_dev_id":                  {"initial_assignment", AgentAssignmentRejectUnknownField},
		"reject_alias_initial_query":                 {"initial_assignment", AgentAssignmentRejectUnknownField},
		"reject_missing_initial_credential":          {"initial_assignment", AgentAssignmentRejectMissingField},
		"reject_client_owner_id":                     {"initial_assignment", AgentAssignmentRejectUnknownField},
		"reject_client_public_key":                   {"initial_assignment", AgentAssignmentRejectUnknownField},
		"reject_client_cell_id":                      {"initial_assignment", AgentAssignmentRejectUnknownField},
		"reject_client_endpoint":                     {"initial_assignment", AgentAssignmentRejectUnknownField},
		"reject_trailing_initial_value":              {"initial_assignment", AgentAssignmentRejectBodyParse},
		"reject_null_usr_data":                       {"initial_assignment", AgentAssignmentRejectWrongType},
		"reject_non_object_usr_data":                 {"initial_assignment", AgentAssignmentRejectWrongType},
		"reject_refresh_credential":                  {"refresh_assignment", AgentAssignmentRejectUnknownField},
		"reject_refresh_assignment_ticket":           {"refresh_assignment", AgentAssignmentRejectUnknownField},
		"reject_completion_assignment_ticket":        {"registration_completion", AgentAssignmentRejectUnknownField},
		"reject_duplicate_completion_device_api_key": {"registration_completion", AgentAssignmentRejectBodyParse},
		"reject_duplicate_registration_ticket":       {"assigned_cell_registration", AgentAssignmentRejectBodyParse},
		"reject_registration_client_placement":       {"assigned_cell_registration", AgentAssignmentRejectUnknownField},
		"reject_wrong_query":                         {"initial_assignment", AgentAssignmentRejectSemantic},
		"reject_wrong_version":                       {"refresh_assignment", AgentAssignmentRejectSemantic},
		"reject_wrong_mode":                          {"refresh_assignment", AgentAssignmentRejectSemantic},
	}
	baseCases := make([]AgentAssignmentCase, len(cases))
	for i, c := range cases {
		baseCases[i] = AgentAssignmentCase(c)
	}
	return validateAgentAssignmentCases("request", baseCases, expected, false, func(c AgentAssignmentCase) string {
		return classifyAgentAssignmentRequest(AgentAssignmentRequestCase(c))
	})
}

func validateAgentAssignmentResultCases(cases []AgentAssignmentResultCase) error {
	expected := map[string]agentAssignmentCaseExpectation{
		"reject_duplicate_initial_err_code":       {"initial_assignment", AgentAssignmentRejectBodyParse},
		"reject_alias_initial_err_code":           {"initial_assignment", AgentAssignmentRejectUnknownField},
		"reject_missing_initial_list":             {"initial_assignment", AgentAssignmentRejectMissingField},
		"reject_initial_private_key_kind":         {"initial_assignment", AgentAssignmentRejectSemantic},
		"reject_initial_unknown_key_kind":         {"initial_assignment", AgentAssignmentRejectSemantic},
		"reject_null_refresh_list":                {"refresh_assignment", AgentAssignmentRejectWrongType},
		"reject_refresh_result_assignment_ticket": {"refresh_assignment", AgentAssignmentRejectUnknownField},
		"reject_completion_list_type":             {"registration_completion", AgentAssignmentRejectWrongType},
		"reject_completion_device_api_key":        {"registration_completion", AgentAssignmentRejectUnknownField},
		"reject_completion_device_api_key_hash":   {"registration_completion", AgentAssignmentRejectUnknownField},
		"reject_completion_device_key_commitment": {"registration_completion", AgentAssignmentRejectUnknownField},
		"reject_trailing_registration_result":     {"assigned_cell_registration", AgentAssignmentRejectBodyParse},
	}
	baseCases := make([]AgentAssignmentCase, len(cases))
	for i, c := range cases {
		baseCases[i] = AgentAssignmentCase(c)
	}
	if err := validateAgentAssignmentCases("success-result", baseCases, expected, true, func(c AgentAssignmentCase) string {
		return classifyAgentAssignmentResult(AgentAssignmentResultCase(c))
	}); err != nil {
		return err
	}
	expectedRejectedKeyKinds := map[string]string{
		"reject_initial_private_key_kind": "tunnel_bootstrap",
		"reject_initial_unknown_key_kind": "future_kind",
	}
	for _, c := range cases {
		want, ok := expectedRejectedKeyKinds[c.Name]
		if !ok {
			continue
		}
		result, err := decodeAgentAssignmentInitialResultCase(c.BodyJSON)
		if err != nil || result.Registration.KeyKind != want {
			return fmt.Errorf("conformance: agent-assignment success-result case %q key_kind drifted", c.Name)
		}
	}
	return nil
}

type agentAssignmentCaseExpectation struct {
	phase, rejectClass string
}

func validateAgentAssignmentCases(kind string, cases []AgentAssignmentCase, expected map[string]agentAssignmentCaseExpectation, result bool, classify func(AgentAssignmentCase) string) error {
	if len(cases) != len(expected) {
		return fmt.Errorf("conformance: agent-assignment %s cases has %d entries, want %d", kind, len(cases), len(expected))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		want, known := expected[c.Name]
		if !known {
			return fmt.Errorf("conformance: agent-assignment has unknown %s case %q", kind, c.Name)
		}
		if _, exists := seen[c.Name]; exists {
			return fmt.Errorf("conformance: agent-assignment repeats %s case %q", kind, c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.Phase != want.phase || c.RejectClass != want.rejectClass || c.BodyJSON == "" || c.Outcome != AgentAssignmentErrorOutcomeReject {
			return fmt.Errorf("conformance: agent-assignment %s case %q fields drifted", kind, c.Name)
		}
		phase := agentAssignmentPhases[c.Phase]
		wantHeader, wantType := phase.requestHeaderName, phase.requestHeaderType
		if result {
			wantHeader, wantType = phase.resultHeaderName, phase.resultHeaderType
		}
		if c.HeaderName != wantHeader || c.HeaderType != wantType {
			return fmt.Errorf("conformance: agent-assignment %s case %q has wrong header", kind, c.Name)
		}
		if got := classify(c); got != c.RejectClass {
			return fmt.Errorf("conformance: agent-assignment %s case %q classifies as %q, want %q", kind, c.Name, got, c.RejectClass)
		}
	}
	return nil
}

func classifyAgentAssignmentResult(c AgentAssignmentResultCase) string {
	if err := validateAgentAssignmentSuccessKeys(c.Phase, []byte(c.BodyJSON)); err != nil {
		return classifyAgentAssignmentStrictError(err)
	}
	if c.Phase == "initial_assignment" {
		result, err := decodeAgentAssignmentInitialResultCase(c.BodyJSON)
		if err != nil {
			return AgentAssignmentRejectBodyParse
		}
		if !isAgentAssignmentPublicRegistrationKeyKind(result.Registration.KeyKind) {
			return AgentAssignmentRejectSemantic
		}
	}
	return ""
}

func decodeAgentAssignmentInitialResultCase(bodyJSON string) (*agentAssignmentInitialResult, error) {
	list, err := decodeAgentAssignmentListSuccess("initial_assignment result case", bodyJSON)
	if err != nil {
		return nil, err
	}
	var result *agentAssignmentInitialResult
	if err := strictDecodeArtifact(list, &result); err != nil {
		return nil, fmt.Errorf("initial assignment result body: %w", err)
	}
	if result == nil {
		return nil, errors.New("initial assignment result body is null")
	}
	return result, nil
}

func isAgentAssignmentPublicRegistrationKeyKind(value string) bool {
	return slices.Contains(agentAssignmentPublicRegistrationKeyKinds, value)
}

func classifyAgentAssignmentRequest(c AgentAssignmentRequestCase) string {
	phase, ok := agentAssignmentPhases[c.Phase]
	if !ok || c.HeaderName != phase.requestHeaderName || c.HeaderType != phase.requestHeaderType {
		return AgentAssignmentRejectSemantic
	}
	if err := validateAgentAssignmentRequestKeys(c.Phase, []byte(c.BodyJSON)); err != nil {
		return classifyAgentAssignmentStrictError(err)
	}

	if c.Phase == "assigned_cell_registration" {
		var body *agentAssignmentRegisterRequest
		if err := strictDecodeArtifact([]byte(c.BodyJSON), &body); err != nil || body == nil {
			return classifyAgentAssignmentStrictError(err)
		}
		if body.UsrID == "" || body.DevID != "agent-conform" || body.AspID != "agent" || body.OTP == "" || body.UsrData.Hostname == "" || body.UsrData.Version == "" || body.UsrData.AssignmentTicket == "" {
			return AgentAssignmentRejectSemantic
		}
		return ""
	}

	var body *agentAssignmentListRequest
	if err := strictDecodeArtifact([]byte(c.BodyJSON), &body); err != nil || body == nil {
		return classifyAgentAssignmentStrictError(err)
	}
	if body.UsrID != "" || body.DevID != "agent-conform" || body.AspID != "agent" {
		return AgentAssignmentRejectSemantic
	}
	switch c.Phase {
	case "initial_assignment":
		var data *agentAssignmentInitialRequestData
		if err := strictDecodeArtifact(body.UsrData, &data); err != nil || data == nil {
			return classifyAgentAssignmentStrictError(err)
		}
		if data.Query != "cell_assignment" || data.Version != 1 || data.Mode != "enroll" || data.Credential == "" {
			return AgentAssignmentRejectSemantic
		}
	case "refresh_assignment":
		var data *agentAssignmentRefreshRequestData
		if err := strictDecodeArtifact(body.UsrData, &data); err != nil || data == nil {
			return classifyAgentAssignmentStrictError(err)
		}
		if data.Query != "cell_assignment" || data.Version != 1 || data.Mode != "refresh" {
			return AgentAssignmentRejectSemantic
		}
	case "registration_completion":
		var data *agentAssignmentCompletionRequestData
		if err := strictDecodeArtifact(body.UsrData, &data); err != nil || data == nil {
			return classifyAgentAssignmentStrictError(err)
		}
		if data.Query != "agent_registration_completion" || data.Version != 1 || data.DeviceAPIKey == "" {
			return AgentAssignmentRejectSemantic
		}
	default:
		return AgentAssignmentRejectSemantic
	}
	return ""
}

func validateAgentAssignmentRequestKeys(phase string, body []byte) error {
	schema, ok := agentAssignmentPhases[phase]
	if !ok {
		return fmt.Errorf("unknown phase %q", phase)
	}
	outer, err := checkAgentAssignmentExactObject("", body, schema.requestOuterKeys)
	if err != nil {
		return err
	}
	if _, err := checkAgentAssignmentExactObject("usrData", outer["usrData"], schema.requestDataKeys); err != nil {
		return err
	}
	return nil
}

func validateAgentAssignmentSuccessKeys(phase string, body []byte) error {
	schema, ok := agentAssignmentPhases[phase]
	if !ok {
		return fmt.Errorf("unknown phase %q", phase)
	}
	outer, err := checkAgentAssignmentExactObject("", body, schema.resultOuterKeys)
	if err != nil {
		return err
	}
	if schema.resultListKeys == nil {
		return nil
	}
	list, err := checkAgentAssignmentExactObject("list", outer["list"], schema.resultListKeys)
	if err != nil {
		return err
	}
	if phase == "initial_assignment" {
		if _, err := checkAgentAssignmentExactObject("registration", list["registration"], agentAssignmentRegistrationKeys); err != nil {
			return err
		}
	}
	if phase == "initial_assignment" || phase == "refresh_assignment" {
		assignment, err := checkAgentAssignmentExactObject("assignment", list["assignment"], agentAssignmentAssignmentKeys)
		if err != nil {
			return err
		}
		if _, err := checkAgentAssignmentExactObject("nhp_udp_endpoint", assignment["nhp_udp_endpoint"], agentAssignmentEndpointKeys); err != nil {
			return err
		}
	}
	return nil
}

func checkAgentAssignmentExactObject(prefix string, body []byte, keys map[string]struct{}) (map[string]json.RawMessage, error) {
	fields, err := decodeAgentAssignmentExactObject(body, keys)
	if err == nil {
		err = requireAgentAssignmentExactKeys(fields, keys)
	}
	if err != nil && prefix != "" {
		return nil, fmt.Errorf("%s: %w", prefix, err)
	}
	return fields, err
}

type agentAssignmentRejectError struct {
	class string
	err   error
}

func (e *agentAssignmentRejectError) Error() string { return e.err.Error() }

func newAgentAssignmentRejectError(class, format string, args ...any) error {
	return &agentAssignmentRejectError{class: class, err: fmt.Errorf(format, args...)}
}

func decodeAgentAssignmentExactObject(body []byte, allowed map[string]struct{}) (map[string]json.RawMessage, error) {
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, newAgentAssignmentRejectError(AgentAssignmentRejectWrongType, "value is not an object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, newAgentAssignmentRejectError(AgentAssignmentRejectWrongType, "value is not an object")
	}
	for key := range fields {
		if _, ok := allowed[key]; !ok {
			return nil, newAgentAssignmentRejectError(AgentAssignmentRejectUnknownField, "unknown field %q", key)
		}
	}
	return fields, nil
}

func requireAgentAssignmentExactKeys(fields map[string]json.RawMessage, required map[string]struct{}) error {
	for key := range required {
		if _, ok := fields[key]; !ok {
			return newAgentAssignmentRejectError(AgentAssignmentRejectMissingField, "missing field %q", key)
		}
	}
	return nil
}

func classifyAgentAssignmentStrictError(err error) string {
	var rejectErr *agentAssignmentRejectError
	if errors.As(err, &rejectErr) {
		return rejectErr.class
	}
	return AgentAssignmentRejectBodyParse
}

func validateAgentAssignmentPacket(name string, packet AgentAssignmentPacket, wantName string, wantType int, wantSender string, wantReceiver string) error {
	if packet.HeaderName != wantName || packet.HeaderType != wantType {
		return fmt.Errorf("conformance: %s header = %q/%d, want %q/%d", name, packet.HeaderName, packet.HeaderType, wantName, wantType)
	}
	if packet.SenderKey != wantSender || packet.ReceiverKey != wantReceiver {
		return fmt.Errorf("conformance: %s key roles = %q -> %q, want %q -> %q", name, packet.SenderKey, packet.ReceiverKey, wantSender, wantReceiver)
	}
	if err := validateAgentAssignmentHex(name+".ephemeral_priv_hex", packet.EphemeralPrivHex, 32); err != nil {
		return err
	}
	if err := validateAgentAssignmentUint64(name+".timestamp_nanos", packet.TimestampNanos); err != nil {
		return err
	}
	if err := validateAgentAssignmentUint64(name+".counter", packet.Counter); err != nil {
		return err
	}
	if err := validateAgentAssignmentHex(name+".preamble_hex", packet.PreambleHex, 4); err != nil {
		return err
	}
	if !json.Valid([]byte(packet.BodyJSON)) {
		return fmt.Errorf("conformance: %s.body_json is not valid JSON", name)
	}
	body, err := hex.DecodeString(packet.BodyHex)
	if err != nil {
		return fmt.Errorf("conformance: %s.body_hex is not hex: %w", name, err)
	}
	if !bytes.Equal(body, []byte(packet.BodyJSON)) {
		return fmt.Errorf("conformance: %s.body_hex does not encode body_json bytes", name)
	}
	if packet.BodyHex != hex.EncodeToString(body) {
		return fmt.Errorf("conformance: %s.body_hex is not canonical lowercase hex", name)
	}
	wire, err := hex.DecodeString(packet.PacketHex)
	if err != nil {
		return fmt.Errorf("conformance: %s.packet_hex is not hex: %w", name, err)
	}
	if len(wire) < agentAssignmentCurveHeaderBytes || len(wire) > agentAssignmentPacketBufferBytes {
		return fmt.Errorf("conformance: %s.packet_hex decodes to %d bytes, want %d..%d", name, len(wire), agentAssignmentCurveHeaderBytes, agentAssignmentPacketBufferBytes)
	}
	preamble, err := hex.DecodeString(packet.PreambleHex)
	if err != nil {
		return fmt.Errorf("conformance: decode %s.preamble_hex: %w", name, err)
	}
	if !bytes.Equal(wire[:4], preamble) {
		return fmt.Errorf("conformance: %s.packet_hex does not start with preamble_hex", name)
	}
	if packet.PacketHex != hex.EncodeToString(wire) {
		return fmt.Errorf("conformance: %s.packet_hex is not canonical lowercase hex", name)
	}
	return nil
}

func validateAgentAssignmentSuccessBodies(af *AgentAssignmentFile) error {
	for _, c := range []struct {
		phase   string
		request string
		result  string
	}{
		{phase: "initial_assignment", request: af.InitialAssignment.Request.BodyJSON, result: af.InitialAssignment.Result.BodyJSON},
		{phase: "refresh_assignment", request: af.RefreshAssignment.Request.BodyJSON, result: af.RefreshAssignment.Result.BodyJSON},
		{phase: "assigned_cell_registration", request: af.AssignedCellRegistration.Request.BodyJSON, result: af.AssignedCellRegistration.Result.BodyJSON},
		{phase: "registration_completion", request: af.RegistrationCompletion.Request.BodyJSON, result: af.RegistrationCompletion.Result.BodyJSON},
	} {
		if err := validateAgentAssignmentRequestKeys(c.phase, []byte(c.request)); err != nil {
			return fmt.Errorf("conformance: %s.request exact-key validation: %w", c.phase, err)
		}
		if err := validateAgentAssignmentSuccessKeys(c.phase, []byte(c.result)); err != nil {
			return fmt.Errorf("conformance: %s.result exact-key validation: %w", c.phase, err)
		}
	}

	var initialRequest *agentAssignmentListRequest
	if err := strictDecodeArtifact([]byte(af.InitialAssignment.Request.BodyJSON), &initialRequest); err != nil || initialRequest == nil {
		return fmt.Errorf("conformance: initial_assignment.request body is not strict v1 JSON: %v", err)
	}
	var initialData *agentAssignmentInitialRequestData
	if err := strictDecodeArtifact(initialRequest.UsrData, &initialData); err != nil || initialData == nil {
		return fmt.Errorf("conformance: initial_assignment.request usrData is not strict v1 JSON: %v", err)
	}
	if initialRequest.UsrID != "" || initialRequest.DevID == "" || initialRequest.AspID != "agent" || initialData.Query != "cell_assignment" || initialData.Version != 1 || initialData.Mode != "enroll" || initialData.Credential != AgentAssignmentBootstrapCredentialFixture {
		return errors.New("conformance: initial_assignment.request semantic fields drifted")
	}

	initialList, err := decodeAgentAssignmentListSuccess("initial_assignment.result", af.InitialAssignment.Result.BodyJSON)
	if err != nil {
		return err
	}
	var initialResult *agentAssignmentInitialResult
	if err := strictDecodeArtifact(initialList, &initialResult); err != nil || initialResult == nil {
		return fmt.Errorf("conformance: initial_assignment.result list is not strict v1 JSON: %v", err)
	}
	if initialResult.Query != "cell_assignment" || initialResult.Version != 1 || initialResult.Mode != "enroll" || initialResult.AgentID != initialRequest.DevID || initialResult.Registration.KeyID == "" || initialResult.Registration.KeyKind != "bootstrap" || initialResult.AssignmentTicket == "" {
		return errors.New("conformance: initial_assignment.result semantic fields drifted")
	}
	if strings.Contains(af.InitialAssignment.Result.BodyJSON, initialData.Credential) {
		return errors.New("conformance: initial_assignment.result echoes the enrollment credential")
	}
	if err := validateAgentAssignmentWireAssignment("initial_assignment.result", initialResult.Assignment, af.Keys.AssignedCell); err != nil {
		return err
	}
	if err := validateAgentAssignmentTimes(initialResult.Assignment.LeaseExpiresAt, initialResult.AssignmentTicketExpiresAt); err != nil {
		return fmt.Errorf("conformance: initial_assignment.result: %w", err)
	}

	var refreshRequest *agentAssignmentListRequest
	if err := strictDecodeArtifact([]byte(af.RefreshAssignment.Request.BodyJSON), &refreshRequest); err != nil || refreshRequest == nil {
		return fmt.Errorf("conformance: refresh_assignment.request body is not strict v1 JSON: %v", err)
	}
	var refreshData *agentAssignmentRefreshRequestData
	if err := strictDecodeArtifact(refreshRequest.UsrData, &refreshData); err != nil || refreshData == nil {
		return fmt.Errorf("conformance: refresh_assignment.request usrData is not strict v1 JSON: %v", err)
	}
	if refreshRequest.UsrID != "" || refreshRequest.DevID != initialRequest.DevID || refreshRequest.AspID != "agent" || refreshData.Query != "cell_assignment" || refreshData.Version != 1 || refreshData.Mode != "refresh" {
		return errors.New("conformance: refresh_assignment.request semantic fields drifted")
	}
	refreshList, err := decodeAgentAssignmentListSuccess("refresh_assignment.result", af.RefreshAssignment.Result.BodyJSON)
	if err != nil {
		return err
	}
	var refreshResult *agentAssignmentRefreshResult
	if err := strictDecodeArtifact(refreshList, &refreshResult); err != nil || refreshResult == nil {
		return fmt.Errorf("conformance: refresh_assignment.result list is not strict v1 JSON: %v", err)
	}
	if refreshResult.Query != "cell_assignment" || refreshResult.Version != 1 || refreshResult.Mode != "refresh" || refreshResult.AgentID != initialRequest.DevID {
		return errors.New("conformance: refresh_assignment.result semantic fields drifted")
	}
	if !reflect.DeepEqual(refreshResult.Assignment, initialResult.Assignment) {
		return errors.New("conformance: refresh_assignment result changed the sticky assignment fixture")
	}
	// DeepEqual proves the refresh lease is the initial lease validated above.

	var registrationRequest *agentAssignmentRegisterRequest
	if err := strictDecodeArtifact([]byte(af.AssignedCellRegistration.Request.BodyJSON), &registrationRequest); err != nil || registrationRequest == nil {
		return fmt.Errorf("conformance: assigned_cell_registration.request body is not strict v1 JSON: %v", err)
	}
	if registrationRequest.UsrID != initialResult.Registration.KeyID || registrationRequest.DevID != initialRequest.DevID || registrationRequest.AspID != "agent" || registrationRequest.OTP != initialData.Credential || registrationRequest.UsrData.AssignmentTicket != initialResult.AssignmentTicket || registrationRequest.UsrData.Hostname == "" || registrationRequest.UsrData.Version == "" {
		return errors.New("conformance: assigned_cell_registration.request does not carry the exact hub registration metadata, credential, devId, and ticket")
	}
	var registrationResult *agentAssignmentRegisterResult
	if err := strictDecodeArtifact([]byte(af.AssignedCellRegistration.Result.BodyJSON), &registrationResult); err != nil || registrationResult == nil {
		return fmt.Errorf("conformance: assigned_cell_registration.result body is not strict v1 JSON: %v", err)
	}
	if registrationResult.ErrCode != "0" || registrationResult.AspID != "agent" {
		return errors.New("conformance: assigned_cell_registration.result is not an exact success RAK")
	}

	var completionRequest *agentAssignmentListRequest
	if err := strictDecodeArtifact([]byte(af.RegistrationCompletion.Request.BodyJSON), &completionRequest); err != nil || completionRequest == nil {
		return fmt.Errorf("conformance: registration_completion.request body is not strict v1 JSON: %v", err)
	}
	var completionData *agentAssignmentCompletionRequestData
	if err := strictDecodeArtifact(completionRequest.UsrData, &completionData); err != nil || completionData == nil {
		return fmt.Errorf("conformance: registration_completion.request usrData is not strict v1 JSON: %v", err)
	}
	if completionRequest.UsrID != "" || completionRequest.DevID != initialRequest.DevID || completionRequest.AspID != "agent" || completionData.Query != "agent_registration_completion" || completionData.Version != 1 || completionData.DeviceAPIKey != AgentAssignmentDeviceAPIKeyFixture {
		return errors.New("conformance: registration_completion.request semantic fields drifted")
	}
	completionList, err := decodeAgentAssignmentListSuccess("registration_completion.result", af.RegistrationCompletion.Result.BodyJSON)
	if err != nil {
		return err
	}
	var completionResult *agentAssignmentCompletionResult
	if err := strictDecodeArtifact(completionList, &completionResult); err != nil || completionResult == nil {
		return fmt.Errorf("conformance: registration_completion.result list is not strict v1 JSON: %v", err)
	}
	if completionResult.Query != "agent_registration_completion" || completionResult.Version != 1 || completionResult.DeviceAPIKeyID == "" {
		return errors.New("conformance: registration_completion.result semantic fields drifted")
	}
	if strings.Contains(af.RegistrationCompletion.Result.BodyJSON, completionData.DeviceAPIKey) {
		return errors.New("conformance: registration_completion.result echoes the device API-key secret")
	}
	return nil
}

func decodeAgentAssignmentListSuccess(name, bodyJSON string) (json.RawMessage, error) {
	var envelope *agentAssignmentListSuccess
	if err := strictDecodeArtifact([]byte(bodyJSON), &envelope); err != nil || envelope == nil {
		return nil, fmt.Errorf("conformance: %s body is not strict v1 JSON: %v", name, err)
	}
	if envelope.ErrCode != "0" || len(envelope.List) == 0 {
		return nil, fmt.Errorf("conformance: %s is not an exact success LRT", name)
	}
	return envelope.List, nil
}

func validateAgentAssignmentWireAssignment(name string, assignment agentAssignmentWireAssignment, cellKey AgentAssignmentKey) error {
	if assignment.CellID == "" || assignment.AssignmentGeneration < 1 || assignment.EndpointRevision < 1 || assignment.NHPUDPEndpoint.Host == "" || assignment.NHPUDPEndpoint.Port < 1 || assignment.NHPUDPEndpoint.Port > 65535 {
		return fmt.Errorf("conformance: %s assignment fields are incomplete", name)
	}
	endpointKey, err := base64.StdEncoding.DecodeString(assignment.NHPUDPEndpoint.ServerPublicKeyB64)
	if err != nil {
		return fmt.Errorf("conformance: %s endpoint server key is not padded standard base64: %w", name, err)
	}
	wantKey, err := hex.DecodeString(cellKey.StaticPubHex)
	if err != nil {
		return fmt.Errorf("conformance: decode assigned-cell public key: %w", err)
	}
	if !bytes.Equal(endpointKey, wantKey) {
		return fmt.Errorf("conformance: %s endpoint server key is not the assigned-cell key", name)
	}
	if assignment.NHPUDPEndpoint.ServerPublicKeyB64 != base64.StdEncoding.EncodeToString(endpointKey) {
		return fmt.Errorf("conformance: %s endpoint server key is not canonical padded standard base64", name)
	}
	return nil
}

func validateAgentAssignmentTimes(lease, ticketExpiry string) error {
	leaseTime, err := time.Parse(time.RFC3339, lease)
	if err != nil {
		return fmt.Errorf("lease_expires_at is not RFC3339: %w", err)
	}
	ticketTime, err := time.Parse(time.RFC3339, ticketExpiry)
	if err != nil {
		return fmt.Errorf("assignment_ticket_expires_at is not RFC3339: %w", err)
	}
	if !leaseTime.After(ticketTime) {
		return errors.New("assignment ticket must expire before the assignment lease")
	}
	return nil
}

type agentAssignmentExpectedError struct {
	outcome        string
	retryPermitted bool
	retryRequired  bool
}

var (
	agentAssignmentAssignmentErrors = map[string]agentAssignmentExpectedError{
		"52200": {outcome: "retry", retryPermitted: true},
		"52201": {outcome: "identity_rejected"},
		"52202": {outcome: "reassignment_required"},
		"52203": {outcome: "quota_exceeded"},
		"52204": {outcome: "rate_limited", retryPermitted: true, retryRequired: true},
		"52205": {outcome: "invalid_request"},
	}
	agentAssignmentInitialCredentialErrors = map[string]agentAssignmentExpectedError{
		"52106": {outcome: "key_rejected"},
		"52107": {outcome: "registration_disabled"},
		"52108": {outcome: "bootstrap_consumed"},
		"52109": {outcome: "invalid_request"},
	}
	agentAssignmentCompletionErrors = map[string]agentAssignmentExpectedError{
		"52300": {outcome: "retry", retryPermitted: true},
		"52301": {outcome: "identity_rejected"},
		"52302": {outcome: "quota_exceeded"},
		"52303": {outcome: "credential_conflict"},
		"52304": {outcome: "invalid_request"},
	}
	agentAssignmentRegistrationErrors = map[string]agentAssignmentExpectedError{
		"52103": {outcome: "identity_conflict"},
		"52110": {outcome: "ticket_invalid"},
		"52111": {outcome: "ticket_expired"},
		"52112": {outcome: "quota_exceeded"},
	}
	agentAssignmentListErrorGroups = []map[string]agentAssignmentExpectedError{
		agentAssignmentAssignmentErrors,
		agentAssignmentInitialCredentialErrors,
		agentAssignmentCompletionErrors,
	}
)

func validateAgentAssignmentErrorContract(contract AgentAssignmentErrorContract) error {
	if contract.Status != "ready" || contract.ProducerRevision != AgentAssignmentNHPProducerRevision {
		return errors.New("conformance: agent-assignment error taxonomy is not pinned to its merged production NHP producer")
	}
	rules := contract.Rules
	retryPermitted, retryRequired := agentAssignmentRetryAfterCodes()
	if rules.ListErrorHeaderName != AgentAssignmentResultHeaderName || rules.ListErrorHeaderType != AgentAssignmentResultHeaderType ||
		rules.RegistrationErrorHeaderName != AgentRegistrationResultHeaderName || rules.RegistrationErrorHeaderType != AgentRegistrationResultHeaderType ||
		!rules.ListOmittedOnError || rules.CookieChallengeAllowed || !rules.RetryAfterSecondsPositiveInteger || rules.ErrMsgControlsPolicy ||
		!slices.Equal(rules.RetryAfterSecondsPermittedCodes, retryPermitted) ||
		!slices.Equal(rules.RetryAfterSecondsRequiredCodes, retryRequired) {
		return errors.New("conformance: agent-assignment error rules drifted from the closed v1 contract")
	}

	errorNames := make(map[string]struct{})
	for _, group := range []struct {
		name         string
		phase        string
		cases        []AgentAssignmentErrorCase
		expected     map[string]agentAssignmentExpectedError
		registration bool
	}{
		{name: "assignment_cases", phase: "cell_assignment", cases: contract.AssignmentCases, expected: agentAssignmentAssignmentErrors},
		{name: "initial_credential_cases", phase: "initial_assignment", cases: contract.InitialCredentialCases, expected: agentAssignmentInitialCredentialErrors},
		{name: "completion_cases", phase: "registration_completion", cases: contract.CompletionCases, expected: agentAssignmentCompletionErrors},
		{name: "registration_cases", phase: "assigned_cell_registration", cases: contract.RegistrationCases, expected: agentAssignmentRegistrationErrors, registration: true},
	} {
		if err := validateAgentAssignmentErrorCases(group.name, group.phase, group.cases, group.expected, group.registration, errorNames); err != nil {
			return err
		}
	}
	if len(contract.MalformedCases) == 0 {
		return errors.New("conformance: agent-assignment error contract has no malformed cases")
	}
	expectedMalformed := map[string]agentAssignmentCaseExpectation{
		"reject_duplicate_err_code":               {"cell_assignment", AgentAssignmentRejectBodyParse},
		"reject_unknown_list_error_field":         {"cell_assignment", AgentAssignmentRejectUnknownField},
		"reject_trailing_list_error_value":        {"cell_assignment", AgentAssignmentRejectBodyParse},
		"reject_null_list_error":                  {"cell_assignment", AgentAssignmentRejectWrongType},
		"reject_non_object_list_error":            {"cell_assignment", AgentAssignmentRejectWrongType},
		"reject_list_present_on_error":            {"cell_assignment", AgentAssignmentRejectListOnError},
		"reject_rate_limit_missing_retry_after":   {"cell_assignment", AgentAssignmentRejectRetryAfterMissing},
		"reject_zero_retry_after":                 {"cell_assignment", AgentAssignmentRejectRetryAfterInvalid},
		"reject_string_retry_after":               {"registration_completion", AgentAssignmentRejectRetryAfterInvalid},
		"reject_unexpected_retry_after":           {"cell_assignment", AgentAssignmentRejectRetryAfterUnexpected},
		"reject_duplicate_registration_err_code":  {"assigned_cell_registration", AgentAssignmentRejectBodyParse},
		"reject_unknown_registration_error_field": {"assigned_cell_registration", AgentAssignmentRejectUnknownField},
		"reject_registration_error_list":          {"assigned_cell_registration", AgentAssignmentRejectUnknownField},
		"reject_unknown_list_error_code":          {"cell_assignment", AgentAssignmentRejectUnknownErrorCode},
		"reject_unknown_registration_error_code":  {"assigned_cell_registration", AgentAssignmentRejectUnknownErrorCode},
	}
	if len(contract.MalformedCases) != len(expectedMalformed) {
		return fmt.Errorf("conformance: agent-assignment error contract has %d malformed cases, want %d", len(contract.MalformedCases), len(expectedMalformed))
	}
	seenMalformed := make(map[string]struct{}, len(contract.MalformedCases))
	for _, c := range contract.MalformedCases {
		want, known := expectedMalformed[c.Name]
		if !known {
			return fmt.Errorf("conformance: unknown agent-assignment malformed case %q", c.Name)
		}
		if c.Name == "" || c.Phase == "" || c.BodyJSON == "" {
			return errors.New("conformance: agent-assignment malformed case has a blank load-bearing field")
		}
		if _, exists := seenMalformed[c.Name]; exists {
			return fmt.Errorf("conformance: duplicate agent-assignment malformed case %q", c.Name)
		}
		if _, exists := errorNames[c.Name]; exists {
			return fmt.Errorf("conformance: duplicate agent-assignment error name %q across valid and malformed cases", c.Name)
		}
		seenMalformed[c.Name] = struct{}{}
		errorNames[c.Name] = struct{}{}
		if c.Phase != want.phase || c.RejectClass != want.rejectClass {
			return fmt.Errorf("conformance: malformed case %q phase/class = %q/%q, want %q/%q", c.Name, c.Phase, c.RejectClass, want.phase, want.rejectClass)
		}
		if c.HeaderName == AgentRegistrationResultHeaderName {
			if c.Phase != "assigned_cell_registration" || c.HeaderType != AgentRegistrationResultHeaderType {
				return fmt.Errorf("conformance: malformed registration case %q has wrong phase/header", c.Name)
			}
		} else if c.HeaderName != AgentAssignmentResultHeaderName || c.HeaderType != AgentAssignmentResultHeaderType ||
			(c.Phase != "cell_assignment" && c.Phase != "registration_completion" && c.Phase != "initial_assignment") {
			return fmt.Errorf("conformance: malformed list case %q has wrong phase/header", c.Name)
		}
		if c.Outcome != AgentAssignmentErrorOutcomeReject {
			return fmt.Errorf("conformance: malformed case %q outcome = %q, want %q", c.Name, c.Outcome, AgentAssignmentErrorOutcomeReject)
		}
		gotClass := classifyAgentAssignmentMalformed(c)
		if gotClass == "" {
			return fmt.Errorf("conformance: malformed case %q is accepted by the strict v1 parser", c.Name)
		}
		if gotClass != c.RejectClass {
			return fmt.Errorf("conformance: malformed case %q reject_class = %q, parser derives %q", c.Name, c.RejectClass, gotClass)
		}
	}
	return nil
}

func validateAgentAssignmentErrorCases(group, phase string, cases []AgentAssignmentErrorCase, expected map[string]agentAssignmentExpectedError, registration bool, names map[string]struct{}) error {
	if len(cases) != len(expected) {
		return fmt.Errorf("conformance: agent-assignment %s has %d cases, want %d", group, len(cases), len(expected))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		want, ok := expected[c.ErrCode]
		if !ok {
			return fmt.Errorf("conformance: agent-assignment %s case %q has unknown err_code %q", group, c.Name, c.ErrCode)
		}
		if _, exists := seen[c.ErrCode]; exists {
			return fmt.Errorf("conformance: agent-assignment %s repeats err_code %q", group, c.ErrCode)
		}
		seen[c.ErrCode] = struct{}{}
		if _, exists := names[c.Name]; exists {
			return fmt.Errorf("conformance: agent-assignment repeats error case name %q", c.Name)
		}
		names[c.Name] = struct{}{}
		if c.Name == "" || c.Phase != phase || c.BodyJSON == "" || c.Outcome != want.outcome {
			return fmt.Errorf("conformance: agent-assignment %s case for %s has invalid name/phase/body/outcome", group, c.ErrCode)
		}
		if registration {
			if c.HeaderName != AgentRegistrationResultHeaderName || c.HeaderType != AgentRegistrationResultHeaderType {
				return fmt.Errorf("conformance: agent-assignment %s case %q has wrong RAK header", group, c.Name)
			}
			if _, err := decodeAgentAssignmentExactObject([]byte(c.BodyJSON), agentAssignmentRAKErrorKeys); err != nil {
				return fmt.Errorf("conformance: agent-assignment %s case %q has invalid exact RAK keys: %v", group, c.Name, err)
			}
			var body *agentAssignmentRegistrationErrorBody
			if err := strictDecodeArtifact([]byte(c.BodyJSON), &body); err != nil || body == nil {
				return fmt.Errorf("conformance: agent-assignment %s case %q has invalid RAK body: %v", group, c.Name, err)
			}
			if body.ErrCode != c.ErrCode || body.AspID != "agent" {
				return fmt.Errorf("conformance: agent-assignment %s case %q RAK fields drifted", group, c.Name)
			}
			if c.RetryAfterSeconds != nil {
				return fmt.Errorf("conformance: agent-assignment %s case %q carries retry_after_seconds", group, c.Name)
			}
			if got := classifyAgentAssignmentValidErrorCase(c); got != "" {
				return fmt.Errorf("conformance: agent-assignment %s case %q is over-rejected as %q", group, c.Name, got)
			}
			continue
		}
		if c.HeaderName != AgentAssignmentResultHeaderName || c.HeaderType != AgentAssignmentResultHeaderType {
			return fmt.Errorf("conformance: agent-assignment %s case %q has wrong LRT header", group, c.Name)
		}
		if _, err := decodeAgentAssignmentExactObject([]byte(c.BodyJSON), agentAssignmentListErrorKeys); err != nil {
			return fmt.Errorf("conformance: agent-assignment %s case %q has invalid exact LRT keys: %v", group, c.Name, err)
		}
		var body *agentAssignmentListErrorBody
		if err := strictDecodeArtifact([]byte(c.BodyJSON), &body); err != nil || body == nil {
			return fmt.Errorf("conformance: agent-assignment %s case %q has invalid LRT body: %v", group, c.Name, err)
		}
		if body.ErrCode != c.ErrCode || len(body.List) != 0 {
			return fmt.Errorf("conformance: agent-assignment %s case %q error fields drifted or list is present", group, c.Name)
		}
		if !equalOptionalInt(body.RetryAfterSeconds, c.RetryAfterSeconds) {
			return fmt.Errorf("conformance: agent-assignment %s case %q retry_after_seconds disagrees with body", group, c.Name)
		}
		if body.RetryAfterSeconds != nil && (!want.retryPermitted || *body.RetryAfterSeconds <= 0) {
			return fmt.Errorf("conformance: agent-assignment %s case %q carries invalid retryAfterSeconds", group, c.Name)
		}
		if want.retryRequired && body.RetryAfterSeconds == nil {
			return fmt.Errorf("conformance: agent-assignment %s case %q is missing required retryAfterSeconds", group, c.Name)
		}
		if got := classifyAgentAssignmentValidErrorCase(c); got != "" {
			return fmt.Errorf("conformance: agent-assignment %s case %q is over-rejected as %q", group, c.Name, got)
		}
	}
	return nil
}

func classifyAgentAssignmentValidErrorCase(c AgentAssignmentErrorCase) string {
	return classifyAgentAssignmentMalformed(AgentAssignmentMalformedCase{
		Phase:      c.Phase,
		HeaderName: c.HeaderName,
		HeaderType: c.HeaderType,
		BodyJSON:   c.BodyJSON,
	})
}

func equalOptionalInt(a, b *int) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func classifyAgentAssignmentMalformed(c AgentAssignmentMalformedCase) string {
	if c.HeaderName == AgentRegistrationResultHeaderName && c.HeaderType == AgentRegistrationResultHeaderType {
		if _, err := decodeAgentAssignmentExactObject([]byte(c.BodyJSON), agentAssignmentRAKErrorKeys); err != nil {
			return classifyAgentAssignmentStrictError(err)
		}
		var body *agentAssignmentRegistrationErrorBody
		if err := strictDecodeArtifact([]byte(c.BodyJSON), &body); err != nil {
			return AgentAssignmentRejectBodyParse
		}
		if body == nil || body.ErrCode == "" || body.AspID != "agent" {
			return AgentAssignmentRejectBodyParse
		}
		if !isKnownAgentAssignmentRegistrationErrorCode(body.ErrCode) {
			return AgentAssignmentRejectUnknownErrorCode
		}
		return ""
	}
	if c.HeaderName != AgentAssignmentResultHeaderName || c.HeaderType != AgentAssignmentResultHeaderType {
		return AgentAssignmentRejectBodyParse
	}
	if _, err := decodeAgentAssignmentExactObject([]byte(c.BodyJSON), agentAssignmentListErrorKeys); err != nil {
		return classifyAgentAssignmentStrictError(err)
	}
	var body *agentAssignmentListErrorBody
	if err := strictDecodeArtifact([]byte(c.BodyJSON), &body); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Field == "retryAfterSeconds" {
			return AgentAssignmentRejectRetryAfterInvalid
		}
		return AgentAssignmentRejectBodyParse
	}
	if body == nil || body.ErrCode == "" {
		return AgentAssignmentRejectBodyParse
	}
	if !isKnownAgentAssignmentListErrorCode(body.ErrCode) {
		return AgentAssignmentRejectUnknownErrorCode
	}
	if len(body.List) != 0 {
		return AgentAssignmentRejectListOnError
	}
	permitted, required := agentAssignmentRetryAfterPolicy(body.ErrCode)
	if required && body.RetryAfterSeconds == nil {
		return AgentAssignmentRejectRetryAfterMissing
	}
	if body.RetryAfterSeconds != nil && *body.RetryAfterSeconds <= 0 {
		return AgentAssignmentRejectRetryAfterInvalid
	}
	if body.RetryAfterSeconds != nil && !permitted {
		return AgentAssignmentRejectRetryAfterUnexpected
	}
	return ""
}

func agentAssignmentRetryAfterPolicy(code string) (permitted, required bool) {
	for _, group := range agentAssignmentListErrorGroups {
		if expected, ok := group[code]; ok {
			return expected.retryPermitted, expected.retryRequired
		}
	}
	return false, false
}

func agentAssignmentRetryAfterCodes() (permitted, required []string) {
	for _, group := range agentAssignmentListErrorGroups {
		for code, expected := range group {
			if expected.retryPermitted {
				permitted = append(permitted, code)
			}
			if expected.retryRequired {
				required = append(required, code)
			}
		}
	}
	slices.Sort(permitted)
	slices.Sort(required)
	return permitted, required
}

func isKnownAgentAssignmentListErrorCode(code string) bool {
	for _, group := range agentAssignmentListErrorGroups {
		if _, ok := group[code]; ok {
			return true
		}
	}
	return false
}

func isKnownAgentAssignmentRegistrationErrorCode(code string) bool {
	_, ok := agentAssignmentRegistrationErrors[code]
	return ok
}

func validateAgentAssignmentHex(name string, value string, wantBytes int) error {
	if len(value) != wantBytes*2 || value != strings.ToLower(value) {
		return fmt.Errorf("conformance: %s is not canonical lowercase hex", name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("conformance: %s is not hex: %w", name, err)
	}
	if len(decoded) != wantBytes {
		return fmt.Errorf("conformance: %s decodes to %d bytes, want %d", name, len(decoded), wantBytes)
	}
	return nil
}

func validateAgentAssignmentKeyPair(name string, key AgentAssignmentKey) error {
	privateBytes, err := hex.DecodeString(key.StaticPrivHex)
	if err != nil {
		return fmt.Errorf("conformance: decode %s private key: %w", name, err)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return fmt.Errorf("conformance: parse %s private key: %w", name, err)
	}
	wantPublic, err := hex.DecodeString(key.StaticPubHex)
	if err != nil {
		return fmt.Errorf("conformance: decode %s public key: %w", name, err)
	}
	if !bytes.Equal(privateKey.PublicKey().Bytes(), wantPublic) {
		return fmt.Errorf("conformance: %s static private/public keys do not form an X25519 pair", name)
	}
	return nil
}

func validateAgentAssignmentUint64(name, value string) error {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != value {
		return fmt.Errorf("conformance: %s %q is not canonical positive uint64 decimal", name, value)
	}
	return nil
}

// AgentKnockApplicationArtifactID is the fixed identity of the registered-agent
// knock application-body artifact. It is deliberately separate from
// RelayKnockArtifactID: this document starts after Noise decryption and carries
// no packet bytes, private keys, nonces, or ciphertext.
const AgentKnockApplicationArtifactID = "qurl-agent-knock-application-vectors"

// Agent-knock application outcomes. A consumer drives each reply through its
// real reply interpreter and derives one of these outcomes; it must not trust the
// stored label without exercising the application parser and correlation gates.
const (
	AgentKnockOutcomeSuccess = "success"
	AgentKnockOutcomeDeny    = "deny"
	AgentKnockOutcomeRetry   = "retry"
	AgentKnockOutcomeReject  = "reject"
)

// Agent-knock application reject classes form a closed, consumer-neutral
// vocabulary. ServerDeny and ServerBusy are authenticated platform outcomes;
// the other classes are fail-closed client dispositions: validation failures
// plus the unsupported pre-access feature gate.
const (
	AgentKnockRejectServerDeny           = "server_deny"
	AgentKnockRejectServerBusy           = "server_busy"
	AgentKnockRejectWrongResource        = "wrong_resource"
	AgentKnockRejectMissingToken         = "missing_token"
	AgentKnockRejectMissingHost          = "missing_host"
	AgentKnockRejectBodyParse            = "body_parse"
	AgentKnockRejectUnsupportedPreAccess = "unsupported_pre_access"
	AgentKnockRejectCounter              = "counter"
	AgentKnockRejectReplyType            = "reply_type"
)

// Agent-knock request reject classes distinguish strict JSON-shape failures
// from RunID policy failures. MissingRunID is specific to the native Connector
// entry point; the generic protocol parser intentionally accepts an omitted or
// empty RunID while rejecting every malformed non-empty value.
const (
	AgentKnockRejectMissingRunID = "missing_run_id"
	AgentKnockRejectInvalidRunID = "invalid_run_id"
)

// AgentKnockRunIDLength is the exact lowercase-hex length of a canonical
// native-UDP-SDK-generated knock cycle identifier (8 random bytes).
const AgentKnockRunIDLength = 16

// AgentKnockApplicationFile is the versioned application-layer contract for a
// registered-agent NHP knock. Request carries one deterministic body golden;
// RequestCases pin generic-parser versus native-Connector RunID policy; and
// ReplyCases cover the complete current ACK producer envelope, success result
// values, authenticated deny, overload, unsupported pre-access, and fail-closed
// application/correlation negatives without duplicating Noise packet vectors.
type AgentKnockApplicationFile struct {
	Artifact      string                       `json:"artifact"`
	SchemaVersion int                          `json:"schema_version"`
	Description   string                       `json:"description"`
	SourceOfTruth string                       `json:"source_of_truth"`
	Notes         []string                     `json:"notes"`
	Request       AgentKnockApplicationRequest `json:"request"`
	RequestCases  []AgentKnockRequestCase      `json:"request_cases"`
	ReplyCases    []AgentKnockReplyCase        `json:"reply_cases"`
}

// AgentKnockApplicationRequest pins the outer NHP type, semantic synthetic
// inputs, and exact compact JSON body. Keeping the semantic inputs beside the
// golden prevents a consumer from merely copying BodyJSON: it must construct
// the body through its production serializer and compare the resulting bytes.
type AgentKnockApplicationRequest struct {
	WireType int                                `json:"wire_type"`
	Fields   AgentKnockApplicationRequestFields `json:"fields"`
	BodyJSON string                             `json:"body_json"`
}

// AgentKnockApplicationRequestFields names the six load-bearing registered-
// agent fields without importing any producer implementation type.
type AgentKnockApplicationRequestFields struct {
	HeaderType      int    `json:"header_type"`
	UserID          string `json:"user_id"`
	DeviceID        string `json:"device_id"`
	AuthServiceID   string `json:"auth_service_id"`
	KnockResourceID string `json:"knock_resource_id"`
	RunID           string `json:"run_id"`
}

// AgentKnockRequestCase is one authenticated KNK JSON-body input evaluated at
// both protocol entry points. BodyJSON remains raw so duplicate keys and alias
// spellings reach each consumer's real strict parser.
type AgentKnockRequestCase struct {
	Name            string                       `json:"name"`
	BodyJSON        string                       `json:"body_json"`
	GenericParser   AgentKnockRequestExpectation `json:"generic_parser"`
	NativeConnector AgentKnockRequestExpectation `json:"native_connector"`
}

// AgentKnockRequestExpectation is the declared result at one request parser.
// ParsedRunID is required on accept (including the accepted empty generic
// value) and absent on reject; RejectClass follows the inverse rule.
type AgentKnockRequestExpectation struct {
	Outcome     string  `json:"outcome"`
	ParsedRunID *string `json:"parsed_run_id,omitempty"`
	RejectClass string  `json:"reject_class,omitempty"`
}

// AgentKnockReplyCase is one already-decrypted reply disposition. Counter
// values are decimal strings so JavaScript consumers never lose uint64
// precision. BodyJSON stays raw so malformed application shapes, including
// deliberate trailing data, survive the artifact and reach the consumer's real
// parser. ExpectedACToken and ExpectedResourceHost are present only on success
// and pin the exact requested-resource map values a conforming interpreter must
// return; optional ACK metadata cannot substitute for either.
type AgentKnockReplyCase struct {
	Name                 string `json:"name"`
	ReplyType            int    `json:"reply_type"`
	RequestCounter       string `json:"request_counter"`
	ReplyCounter         string `json:"reply_counter"`
	BodyJSON             string `json:"body_json"`
	Outcome              string `json:"outcome"`
	RejectClass          string `json:"reject_class,omitempty"`
	ExpectedACToken      string `json:"expected_ac_token,omitempty"`
	ExpectedResourceHost string `json:"expected_resource_host,omitempty"`
}

// ParseAgentKnockApplicationFile strictly parses and validates the
// application-body artifact. It rejects duplicate/unknown/trailing outer
// fields, stale schema versions, missing or unknown cases, invalid
// enums/counters, duplicate case names, and a request golden that does not
// exactly match its semantic fields. It independently derives both declared
// request-parser outcomes and cross-checks success result labels against the
// requested resource's raw body maps so labels cannot drift, and rejects a
// declared success that carries any non-null preActions value. Remaining reply
// semantics stay the consumer's job: those bodies include intentional wrong-map
// shapes and trailing data that must reach the production parser. Invalid raw
// JSON is allowed only for an explicit body_parse reject.
func ParseAgentKnockApplicationFile(data []byte) (*AgentKnockApplicationFile, error) {
	var af AgentKnockApplicationFile
	if err := strictDecodeArtifact(data, &af); err != nil {
		return nil, fmt.Errorf("conformance: parse agent-knock application file: %w", err)
	}
	if af.Artifact != AgentKnockApplicationArtifactID {
		return nil, fmt.Errorf("conformance: agent-knock application file has artifact %q, want %q", af.Artifact, AgentKnockApplicationArtifactID)
	}
	if af.SchemaVersion != 3 {
		return nil, fmt.Errorf("conformance: agent-knock application file has schema_version %d, want 3", af.SchemaVersion)
	}
	if af.Description == "" || af.SourceOfTruth == "" || len(af.Notes) == 0 {
		return nil, errors.New("conformance: agent-knock application file missing description, source_of_truth, or notes")
	}
	if err := validateAgentKnockRequest(af.Request); err != nil {
		return nil, err
	}
	if err := validateAgentKnockRequestCases(af.Request, af.RequestCases); err != nil {
		return nil, err
	}
	if len(af.ReplyCases) == 0 {
		return nil, errors.New("conformance: agent-knock application file has no reply_cases")
	}

	required := []string{
		"ack_success", "ack_success_optional_metadata", "ack_deny", "cookie_challenge",
		"reject_wrong_resource", "reject_missing_ac_token",
		"reject_empty_ac_token", "reject_missing_resource_host",
		"reject_empty_resource_host", "reject_malformed_ac_tokens_map",
		"reject_malformed_resource_host_map", "reject_pre_access_action_requested",
		"reject_pre_access_action_other_resource", "reject_malformed_pre_actions",
		"reject_malformed_asp_token", "reject_malformed_redirect_url",
		"reject_malformed_opn_time", "reject_malformed_agent_addr",
		"reject_unknown_ack_field", "reject_duplicate_ack_field",
		"reject_trailing_ack_data", "reject_null_ack_body",
		"reject_non_object_ack_body", "reject_counter_mismatch", "reject_reply_type_mismatch",
	}
	allowed := make(map[string]struct{}, len(required))
	for _, name := range required {
		allowed[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(af.ReplyCases))
	for _, c := range af.ReplyCases {
		if _, ok := allowed[c.Name]; !ok {
			return nil, fmt.Errorf("conformance: unknown agent-knock reply case %q", c.Name)
		}
		if _, ok := seen[c.Name]; ok {
			return nil, fmt.Errorf("conformance: duplicate agent-knock reply case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if err := validateAgentKnockReplyCase(c); err != nil {
			return nil, err
		}
		if c.Outcome == AgentKnockOutcomeSuccess {
			if err := validateAgentKnockExpectedResult(af.Request.Fields.KnockResourceID, c); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range required {
		if _, present := seen[name]; !present {
			return nil, fmt.Errorf("conformance: agent-knock application file missing reply case %q", name)
		}
	}
	return &af, nil
}

// strictDecodeArtifact applies the same fail-closed JSON contract to every
// vector family: one top-level value, no duplicate object keys at any depth,
// and no unknown typed fields. rejectDuplicateJSONKeys already walks through
// EOF, so the typed decoder needs no redundant second trailing-data pass.
func strictDecodeArtifact(data []byte, dst any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func validateAgentKnockRequest(r AgentKnockApplicationRequest) error {
	if r.WireType != 1 {
		return fmt.Errorf("conformance: agent-knock request wire_type = %d, want NHP_KNK (1)", r.WireType)
	}
	if r.Fields.HeaderType != r.WireType {
		return fmt.Errorf("conformance: agent-knock request header_type %d does not match wire_type %d", r.Fields.HeaderType, r.WireType)
	}
	if r.Fields.UserID == "" || r.Fields.DeviceID == "" || r.Fields.AuthServiceID == "" || r.Fields.KnockResourceID == "" {
		return errors.New("conformance: agent-knock request has an empty required identity field")
	}
	if !isCanonicalAgentKnockRunID(r.Fields.RunID) {
		return fmt.Errorf("conformance: agent-knock request run_id %q is not %d lowercase hexadecimal characters", r.Fields.RunID, AgentKnockRunIDLength)
	}
	if !json.Valid([]byte(r.BodyJSON)) {
		return errors.New("conformance: agent-knock request body_json is not valid JSON")
	}
	// Field order and json.Marshal's default HTML escaping mirror the Go
	// producer wire struct. Equality here intentionally pins exact compact bytes,
	// including wire names and omission of optional fields; consumers rebuild
	// the same bytes from Request.Fields.
	// runId remains omitempty to mirror the generic producer wire struct; the
	// canonical request golden above deliberately requires a non-empty value.
	want, err := json.Marshal(struct {
		HeaderType int    `json:"headerType"`
		UserID     string `json:"usrId"`
		DeviceID   string `json:"devId"`
		AspID      string `json:"aspId"`
		ResourceID string `json:"resId"`
		RunID      string `json:"runId,omitempty"`
	}{r.Fields.HeaderType, r.Fields.UserID, r.Fields.DeviceID, r.Fields.AuthServiceID, r.Fields.KnockResourceID, r.Fields.RunID})
	if err != nil {
		return fmt.Errorf("conformance: marshal agent-knock request golden: %w", err)
	}
	if !bytes.Equal(want, []byte(r.BodyJSON)) {
		return fmt.Errorf("conformance: agent-knock request body_json does not match fields: got %s want %s", r.BodyJSON, want)
	}
	return nil
}

// validateAgentKnockRequestCases enforces a closed set: unlike the reply-case
// loader (which only rejects duplicates and missing-required names), the RunID
// request policy is exhaustive, so an unrecognized case name is a mismatch
// against a derivable expectation rather than a benign addition and is rejected.
func validateAgentKnockRequestCases(request AgentKnockApplicationRequest, cases []AgentKnockRequestCase) error {
	if len(cases) == 0 {
		return errors.New("conformance: agent-knock application file has no request_cases")
	}
	required := []string{
		"canonical_run_id", "missing_run_id", "empty_run_id",
		"reject_duplicate_run_id", "reject_alias_run_id",
		"reject_alias_snake_case_run_id", "reject_whitespace_run_id",
		"reject_internal_whitespace_run_id", "reject_uppercase_run_id", "reject_short_run_id",
		"reject_long_run_id", "reject_nonhex_run_id",
	}
	requiredSet := make(map[string]struct{}, len(required))
	for _, name := range required {
		requiredSet[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		if _, ok := requiredSet[c.Name]; !ok {
			return fmt.Errorf("conformance: unknown agent-knock request case %q", c.Name)
		}
		if _, ok := seen[c.Name]; ok {
			return fmt.Errorf("conformance: duplicate agent-knock request case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if err := validateAgentKnockRequestCase(request, c); err != nil {
			return err
		}
	}
	for _, name := range required {
		if _, present := seen[name]; !present {
			return fmt.Errorf("conformance: agent-knock application file missing request case %q", name)
		}
	}
	return nil
}

// agentKnockRequestWireBody mirrors the generic producer wire shape. orgId,
// results, and usrData are tolerated-but-unexercised forward-compat fields: no
// request_case carries them, so they are accepted (not required) and never
// gate RunID policy — do not assume the parser is stricter than the vectors.
type agentKnockRequestWireBody struct {
	HeaderType      int                        `json:"headerType"`
	UserID          string                     `json:"usrId"`
	DeviceID        string                     `json:"devId"`
	OrganizationID  string                     `json:"orgId,omitempty"`
	AuthServiceID   string                     `json:"aspId"`
	KnockResourceID string                     `json:"resId"`
	RunID           json.RawMessage            `json:"runId"`
	CheckResults    map[string]json.RawMessage `json:"results,omitempty"`
	UserData        map[string]json.RawMessage `json:"usrData,omitempty"`
}

func validateAgentKnockRequestCase(request AgentKnockApplicationRequest, c AgentKnockRequestCase) error {
	if c.Name == "" || c.BodyJSON == "" {
		return errors.New("conformance: agent-knock request case missing name or body_json")
	}
	body := []byte(c.BodyJSON)
	if !json.Valid(body) {
		return fmt.Errorf("conformance: agent-knock request case %q body_json is not valid JSON", c.Name)
	}
	if want, required := expectedAgentKnockRequestCaseBody(request, c.Name); required && !bytes.Equal(body, want) {
		return fmt.Errorf("conformance: agent-knock request case %q body_json does not match its required exact vector: got %s want %s", c.Name, c.BodyJSON, want)
	}
	generic, connector := deriveAgentKnockRequestExpectations(request.Fields, body)
	if err := compareAgentKnockRequestExpectation(c.Name, "generic_parser", c.GenericParser, generic); err != nil {
		return err
	}
	return compareAgentKnockRequestExpectation(c.Name, "native_connector", c.NativeConnector, connector)
}

func expectedAgentKnockRequestCaseBody(request AgentKnockApplicationRequest, name string) ([]byte, bool) {
	canonical := request.BodyJSON
	runIDSuffix := `,"runId":"` + request.Fields.RunID + `"}`
	if !strings.HasSuffix(canonical, runIDSuffix) {
		return nil, true
	}
	base := strings.TrimSuffix(canonical, runIDSuffix) + "}"
	addField := func(body, key, value string) string {
		return body[:len(body)-1] + `,"` + key + `":"` + value + `"}`
	}
	withRunID := func(runID string) string { return addField(base, "runId", runID) }

	var body string
	switch name {
	case "canonical_run_id":
		body = canonical
	case "missing_run_id":
		body = base
	case "empty_run_id":
		body = withRunID("")
	case "reject_duplicate_run_id":
		body = addField(withRunID(request.Fields.RunID), "runId", "fedcba9876543210")
	case "reject_alias_run_id":
		body = addField(base, "runID", request.Fields.RunID)
	case "reject_alias_snake_case_run_id":
		body = addField(base, "run_id", request.Fields.RunID)
	case "reject_whitespace_run_id":
		body = withRunID(" " + request.Fields.RunID + " ")
	case "reject_internal_whitespace_run_id":
		body = withRunID("01234567 89abcde")
	case "reject_uppercase_run_id":
		body = withRunID("0123456789ABCDEF")
	case "reject_short_run_id":
		body = withRunID("0123456789abcde")
	case "reject_long_run_id":
		body = withRunID("0123456789abcdef0")
	case "reject_nonhex_run_id":
		body = withRunID("0123456789abcdeg")
	default:
		return nil, false
	}
	return []byte(body), true
}

func deriveAgentKnockRequestExpectations(fields AgentKnockApplicationRequestFields, body []byte) (AgentKnockRequestExpectation, AgentKnockRequestExpectation) {
	bodyParse := requestRejectExpectation(AgentKnockRejectBodyParse)
	// DisallowUnknownFields still matches JSON names case-insensitively, so it
	// accepts runID for the runId tag. The raw exact-key gate must run first.
	if err := rejectUnknownAgentKnockRequestKeys(body); err != nil {
		return bodyParse, bodyParse
	}
	var wire agentKnockRequestWireBody
	if err := strictDecodeArtifact(body, &wire); err != nil {
		return bodyParse, bodyParse
	}
	if wire.HeaderType != fields.HeaderType || wire.UserID != fields.UserID || wire.DeviceID != fields.DeviceID ||
		wire.AuthServiceID != fields.AuthServiceID || wire.KnockResourceID != fields.KnockResourceID {
		return bodyParse, bodyParse
	}
	if len(wire.RunID) == 0 {
		return requestAcceptExpectation(""), requestRejectExpectation(AgentKnockRejectMissingRunID)
	}
	var runID string
	if bytes.Equal(wire.RunID, []byte("null")) || json.Unmarshal(wire.RunID, &runID) != nil {
		return bodyParse, bodyParse
	}
	if runID == "" {
		return requestAcceptExpectation(""), requestRejectExpectation(AgentKnockRejectMissingRunID)
	}
	if !isCanonicalAgentKnockRunID(runID) {
		invalid := requestRejectExpectation(AgentKnockRejectInvalidRunID)
		return invalid, invalid
	}
	accepted := requestAcceptExpectation(runID)
	return accepted, accepted
}

// agentKnockRequestWireKeys is the exact set of JSON keys the request body may
// carry, derived once from agentKnockRequestWireBody's struct tags so the two
// cannot drift: adding a forward-compat field to the struct extends the gate
// automatically. The gate itself is load-bearing — encoding/json matches tags
// case-insensitively, so DisallowUnknownFields alone would accept runID.
var agentKnockRequestWireKeys = jsonTagKeySet(reflect.TypeOf(agentKnockRequestWireBody{}))

// jsonTagKeySet returns the set of json field names declared on a struct type,
// with any ",omitempty"/options suffix stripped.
func jsonTagKeySet(t reflect.Type) map[string]struct{} {
	keys := make(map[string]struct{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			keys[name] = struct{}{}
		}
	}
	return keys
}

func rejectUnknownAgentKnockRequestKeys(body []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return err
	}
	for key := range fields {
		if _, ok := agentKnockRequestWireKeys[key]; !ok {
			return fmt.Errorf("unknown agent-knock request field %q", key)
		}
	}
	return nil
}

func requestAcceptExpectation(runID string) AgentKnockRequestExpectation {
	return AgentKnockRequestExpectation{Outcome: ExpectAccept, ParsedRunID: &runID}
}

func requestRejectExpectation(class string) AgentKnockRequestExpectation {
	return AgentKnockRequestExpectation{Outcome: ExpectReject, RejectClass: class}
}

func compareAgentKnockRequestExpectation(caseName, entryPoint string, got, want AgentKnockRequestExpectation) error {
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("conformance: agent-knock request case %q %s expectation = %+v, want %+v", caseName, entryPoint, got, want)
	}
	return nil
}

func isCanonicalAgentKnockRunID(runID string) bool {
	if len(runID) != AgentKnockRunIDLength {
		return false
	}
	for i := range runID {
		if (runID[i] < '0' || runID[i] > '9') && (runID[i] < 'a' || runID[i] > 'f') {
			return false
		}
	}
	return true
}

func validateAgentKnockReplyCase(c AgentKnockReplyCase) error {
	if c.Name == "" || c.BodyJSON == "" {
		return errors.New("conformance: agent-knock reply case missing name or body_json")
	}
	// body_parse is the sole disposition allowed to carry invalid JSON because
	// trailing-data vectors must reach the consumer's strict production parser.
	if !json.Valid([]byte(c.BodyJSON)) && !(c.Outcome == AgentKnockOutcomeReject && c.RejectClass == AgentKnockRejectBodyParse) {
		return fmt.Errorf("conformance: agent-knock reply case %q body_json is not valid JSON", c.Name)
	}
	req, err := strconv.ParseUint(c.RequestCounter, 10, 64)
	if err != nil {
		return fmt.Errorf("conformance: agent-knock reply case %q request_counter: %w", c.Name, err)
	}
	reply, err := strconv.ParseUint(c.ReplyCounter, 10, 64)
	if err != nil {
		return fmt.Errorf("conformance: agent-knock reply case %q reply_counter: %w", c.Name, err)
	}
	if c.Outcome != AgentKnockOutcomeSuccess && c.Outcome != AgentKnockOutcomeDeny &&
		c.Outcome != AgentKnockOutcomeRetry && c.Outcome != AgentKnockOutcomeReject {
		return fmt.Errorf("conformance: agent-knock reply case %q has unknown outcome %q", c.Name, c.Outcome)
	}
	// Expected-result presence is a pure function of success-ness: required on
	// success, forbidden on every other outcome.
	if c.Outcome == AgentKnockOutcomeSuccess && (c.ExpectedACToken == "" || c.ExpectedResourceHost == "") {
		return fmt.Errorf("conformance: success agent-knock reply case %q must carry a non-empty expected result", c.Name)
	}
	if c.Outcome != AgentKnockOutcomeSuccess && (c.ExpectedACToken != "" || c.ExpectedResourceHost != "") {
		return fmt.Errorf("conformance: non-success agent-knock reply case %q must not carry an expected result", c.Name)
	}
	switch c.Outcome {
	case AgentKnockOutcomeSuccess:
		if c.RejectClass != "" || c.ReplyType != 2 || req != reply {
			return fmt.Errorf("conformance: success agent-knock reply case %q must be matched NHP_ACK with no reject_class", c.Name)
		}
	case AgentKnockOutcomeDeny:
		if c.RejectClass != AgentKnockRejectServerDeny || c.ReplyType != 2 || req != reply {
			return fmt.Errorf("conformance: deny agent-knock reply case %q must be matched NHP_ACK with reject_class %q", c.Name, AgentKnockRejectServerDeny)
		}
	case AgentKnockOutcomeRetry:
		// NHP_COK is an authenticated overload signal, not a completed
		// transaction. The reference relay returns it before applying the
		// ordinary reply-counter echo gate, so its two valid counters remain
		// intentionally unconstrained relative to one another.
		if c.RejectClass != AgentKnockRejectServerBusy || c.ReplyType != 7 {
			return fmt.Errorf("conformance: retry agent-knock reply case %q must be NHP_COK with reject_class %q", c.Name, AgentKnockRejectServerBusy)
		}
	case AgentKnockOutcomeReject:
		switch c.RejectClass {
		case AgentKnockRejectWrongResource, AgentKnockRejectMissingToken,
			AgentKnockRejectMissingHost, AgentKnockRejectBodyParse,
			AgentKnockRejectUnsupportedPreAccess:
			if c.ReplyType != 2 || req != reply {
				return fmt.Errorf("conformance: application reject case %q must be a matched NHP_ACK", c.Name)
			}
		case AgentKnockRejectCounter:
			if c.ReplyType != 2 || req == reply {
				return fmt.Errorf("conformance: counter reject case %q must be NHP_ACK with a non-echoed counter", c.Name)
			}
		case AgentKnockRejectReplyType:
			if c.ReplyType == 2 || c.ReplyType == 7 || req != reply {
				return fmt.Errorf("conformance: reply_type reject case %q must be a matched counter with neither NHP_ACK nor NHP_COK", c.Name)
			}
		default:
			return fmt.Errorf("conformance: reject agent-knock reply case %q has unknown reject_class %q", c.Name, c.RejectClass)
		}
	}
	return nil
}

func validateAgentKnockExpectedResult(resourceID string, c AgentKnockReplyCase) error {
	var body struct {
		ResourceHost     map[string]string           `json:"resHost"`
		ACTokens         map[string]string           `json:"acTokens"`
		PreAccessActions map[string]*json.RawMessage `json:"preActions"`
	}
	if err := json.Unmarshal([]byte(c.BodyJSON), &body); err != nil {
		return fmt.Errorf("conformance: success agent-knock reply case %q result body: %w", c.Name, err)
	}
	if got := body.ACTokens[resourceID]; c.ExpectedACToken != got {
		return fmt.Errorf("conformance: success agent-knock reply case %q expected_ac_token %q does not match acTokens[%q] %q", c.Name, c.ExpectedACToken, resourceID, got)
	}
	if got := body.ResourceHost[resourceID]; c.ExpectedResourceHost != got {
		return fmt.Errorf("conformance: success agent-knock reply case %q expected_resource_host %q does not match resHost[%q] %q", c.Name, c.ExpectedResourceHost, resourceID, got)
	}
	for key, action := range body.PreAccessActions {
		if action != nil {
			return fmt.Errorf("conformance: success agent-knock reply case %q has non-null preActions[%q]", c.Name, key)
		}
	}
	return nil
}

// requireJSONEOF rejects a second JSON value or trailing non-space bytes after a
// successfully decoded artifact. json.Decoder.Decode alone accepts both.
func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("trailing data: %w", err)
	}
	return errors.New("multiple JSON values")
}

// rejectDuplicateJSONKeys walks one raw JSON value before typed decoding. The
// standard library otherwise accepts the last value for a repeated object key,
// which would make a typo or malicious contract edit ambiguous across languages.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSONValue(dec); err != nil {
		return err
	}
	return requireJSONEOF(dec)
}

func walkJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key has type %T, want string", keyToken)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("object ended with %v, want }", end)
		}
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("array ended with %v, want ]", end)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}
