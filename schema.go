// Package conformance is the single public source of truth for the qURL
// cross-language conformance vectors. It embeds the JSON artifacts under
// vectors/ and exposes strict, typed loaders so any consumer — in any language
// that can call this Go module, or that copies the JSON directly — can re-run
// the same wire-truth against its own implementation.
//
// Five families live here, each under its own artifact id so they stay decoupled
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
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
// the other classes are fail-closed client validation failures.
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
// fields, stale schema versions, missing mandatory cases, invalid
// enums/counters, duplicate case names, and a request golden that does not
// exactly match its semantic fields. It independently derives both declared
// request-parser outcomes from each raw body so case labels cannot drift.
// Reply body semantics remain the consumer's job: those bodies include
// intentional wrong-map shapes and trailing data that must reach the production
// parser. Invalid raw JSON is allowed only for an explicit body_parse reject.
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
		"reject_unknown_ack_field", "reject_duplicate_ack_field",
		"reject_trailing_ack_data", "reject_null_ack_body",
		"reject_non_object_ack_body", "reject_counter_mismatch", "reject_reply_type_mismatch",
	}
	seen := make(map[string]struct{}, len(af.ReplyCases))
	for _, c := range af.ReplyCases {
		if _, ok := seen[c.Name]; ok {
			return nil, fmt.Errorf("conformance: duplicate agent-knock reply case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if err := validateAgentKnockReplyCase(c); err != nil {
			return nil, err
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
	if c.Outcome != AgentKnockOutcomeSuccess && (c.ExpectedACToken != "" || c.ExpectedResourceHost != "") {
		return fmt.Errorf("conformance: non-success agent-knock reply case %q must not carry an expected result", c.Name)
	}
	switch c.Outcome {
	case AgentKnockOutcomeSuccess:
		if c.RejectClass != "" || c.ReplyType != 2 || req != reply || c.ExpectedACToken == "" || c.ExpectedResourceHost == "" {
			return fmt.Errorf("conformance: success agent-knock reply case %q must be matched NHP_ACK with no reject_class and non-empty expected result", c.Name)
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
