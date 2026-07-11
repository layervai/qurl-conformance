// Package conformance is the single public source of truth for the qURL
// cross-language conformance vectors. It embeds the JSON artifacts under
// vectors/ and exposes strict, typed loaders so any consumer — in any language
// that can call this Go module, or that copies the JSON directly — can re-run
// the same wire-truth against its own implementation.
//
// Four families live here, each under its own artifact id so they stay decoupled
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
//     (agent_knock_application_vectors.json): exact KNK JSON plus already-
//     decrypted ACK/COK disposition vectors, with no duplicate packet bytes.
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
	"strconv"
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
	AgentKnockRejectServerDeny    = "server_deny"
	AgentKnockRejectServerBusy    = "server_busy"
	AgentKnockRejectWrongResource = "wrong_resource"
	AgentKnockRejectMissingToken  = "missing_token"
	AgentKnockRejectMissingHost   = "missing_host"
	AgentKnockRejectBodyParse     = "body_parse"
	AgentKnockRejectCounter       = "counter"
	AgentKnockRejectReplyType     = "reply_type"
)

// AgentKnockApplicationFile is the versioned application-layer contract for a
// registered-agent NHP knock. Request carries one deterministic body golden;
// ReplyCases cover success, authenticated deny, overload, and fail-closed
// application/correlation negatives without duplicating Noise packet vectors.
type AgentKnockApplicationFile struct {
	Artifact      string                       `json:"artifact"`
	SchemaVersion int                          `json:"schema_version"`
	Description   string                       `json:"description"`
	SourceOfTruth string                       `json:"source_of_truth"`
	Notes         []string                     `json:"notes"`
	Request       AgentKnockApplicationRequest `json:"request"`
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

// AgentKnockApplicationRequestFields names the five load-bearing registered-
// agent fields without importing any producer implementation type.
type AgentKnockApplicationRequestFields struct {
	HeaderType    int    `json:"header_type"`
	UserID        string `json:"user_id"`
	DeviceID      string `json:"device_id"`
	AuthServiceID string `json:"auth_service_id"`
	ResourceID    string `json:"resource_id"`
}

// AgentKnockReplyCase is one already-decrypted reply disposition. Counter
// values are decimal strings so JavaScript consumers never lose uint64
// precision. BodyJSON stays raw so malformed application shapes survive the
// artifact and reach the consumer's real parser.
type AgentKnockReplyCase struct {
	Name           string `json:"name"`
	ReplyType      int    `json:"reply_type"`
	RequestCounter string `json:"request_counter"`
	ReplyCounter   string `json:"reply_counter"`
	BodyJSON       string `json:"body_json"`
	Outcome        string `json:"outcome"`
	RejectClass    string `json:"reject_class,omitempty"`
}

// ParseAgentKnockApplicationFile strictly parses and validates the
// application-body artifact. It rejects duplicate/unknown/trailing outer
// fields, stale schema versions, missing mandatory cases, invalid
// enums/counters, duplicate case names, and a request golden that does not
// exactly match its semantic fields. Reply body semantics remain the consumer's
// job: those bodies include intentional wrong-map shapes that must reach the
// production parser.
func ParseAgentKnockApplicationFile(data []byte) (*AgentKnockApplicationFile, error) {
	var af AgentKnockApplicationFile
	if err := strictDecodeArtifact(data, &af); err != nil {
		return nil, fmt.Errorf("conformance: parse agent-knock application file: %w", err)
	}
	if af.Artifact != AgentKnockApplicationArtifactID {
		return nil, fmt.Errorf("conformance: agent-knock application file has artifact %q, want %q", af.Artifact, AgentKnockApplicationArtifactID)
	}
	if af.SchemaVersion != 1 {
		return nil, fmt.Errorf("conformance: agent-knock application file has schema_version %d, want 1", af.SchemaVersion)
	}
	if af.Description == "" || af.SourceOfTruth == "" || len(af.Notes) == 0 {
		return nil, errors.New("conformance: agent-knock application file missing description, source_of_truth, or notes")
	}
	if err := validateAgentKnockRequest(af.Request); err != nil {
		return nil, err
	}
	if len(af.ReplyCases) == 0 {
		return nil, errors.New("conformance: agent-knock application file has no reply_cases")
	}

	required := map[string]bool{
		"ack_success": false, "ack_deny": false, "cookie_challenge": false,
		"reject_wrong_resource": false, "reject_missing_ac_token": false,
		"reject_empty_ac_token": false, "reject_missing_resource_host": false,
		"reject_empty_resource_host": false, "reject_malformed_ac_tokens_map": false,
		"reject_malformed_resource_host_map": false, "reject_counter_mismatch": false,
		"reject_reply_type_mismatch": false,
	}
	seen := make(map[string]struct{}, len(af.ReplyCases))
	for _, c := range af.ReplyCases {
		if _, ok := seen[c.Name]; ok {
			return nil, fmt.Errorf("conformance: duplicate agent-knock reply case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if _, ok := required[c.Name]; ok {
			required[c.Name] = true
		}
		if err := validateAgentKnockReplyCase(c); err != nil {
			return nil, err
		}
	}
	for name, present := range required {
		if !present {
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
	if r.Fields.UserID == "" || r.Fields.DeviceID == "" || r.Fields.AuthServiceID == "" || r.Fields.ResourceID == "" {
		return errors.New("conformance: agent-knock request has an empty required identity field")
	}
	if !json.Valid([]byte(r.BodyJSON)) {
		return errors.New("conformance: agent-knock request body_json is not valid JSON")
	}
	// Field order mirrors the producer wire struct. Equality here intentionally
	// pins exact compact bytes, including wire names and omission of optional
	// fields; consumers rebuild the same bytes from Request.Fields.
	want, err := json.Marshal(struct {
		HeaderType int    `json:"headerType"`
		UserID     string `json:"usrId"`
		DeviceID   string `json:"devId"`
		AspID      string `json:"aspId"`
		ResourceID string `json:"resId"`
	}{r.Fields.HeaderType, r.Fields.UserID, r.Fields.DeviceID, r.Fields.AuthServiceID, r.Fields.ResourceID})
	if err != nil {
		return fmt.Errorf("conformance: marshal agent-knock request golden: %w", err)
	}
	if !bytes.Equal(want, []byte(r.BodyJSON)) {
		return fmt.Errorf("conformance: agent-knock request body_json does not match fields: got %s want %s", r.BodyJSON, want)
	}
	return nil
}

func validateAgentKnockReplyCase(c AgentKnockReplyCase) error {
	if c.Name == "" || c.BodyJSON == "" {
		return errors.New("conformance: agent-knock reply case missing name or body_json")
	}
	if !json.Valid([]byte(c.BodyJSON)) {
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
		if c.RejectClass != AgentKnockRejectServerBusy || c.ReplyType != 7 {
			return fmt.Errorf("conformance: retry agent-knock reply case %q must be NHP_COK with reject_class %q", c.Name, AgentKnockRejectServerBusy)
		}
	case AgentKnockOutcomeReject:
		switch c.RejectClass {
		case AgentKnockRejectWrongResource, AgentKnockRejectMissingToken,
			AgentKnockRejectMissingHost, AgentKnockRejectBodyParse:
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
	default:
		return fmt.Errorf("conformance: agent-knock reply case %q has unknown outcome %q", c.Name, c.Outcome)
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
