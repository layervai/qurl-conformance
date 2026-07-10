package conformance

import (
	"embed"
	"fmt"
)

//go:embed vectors/qv2_conformance_vectors.json vectors/issuer_signature_vectors.json vectors/relay_knock_golden.json vectors/agent_registration_golden.json
var vectorsFS embed.FS

const (
	conformanceVectorsName = "vectors/qv2_conformance_vectors.json"
	issuerSignatureName    = "vectors/issuer_signature_vectors.json"
	relayKnockName         = "vectors/relay_knock_golden.json"
	agentRegistrationName  = "vectors/agent_registration_golden.json"
)

// QV2Vectors returns the raw bytes of the embedded qURL v2 conformance vectors
// (qv2_conformance_vectors.json). The bytes are the canonical wire-truth; a
// consumer that prefers to drive its own strict parser can feed these directly.
func QV2Vectors() []byte {
	b, err := vectorsFS.ReadFile(conformanceVectorsName)
	if err != nil {
		// Unreachable: the file is embedded at build time.
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", conformanceVectorsName, err))
	}
	return b
}

// IssuerSignatureVectors returns the raw bytes of the embedded issuer-signature
// golden vectors (issuer_signature_vectors.json), which the signature class
// composes by reference.
func IssuerSignatureVectors() []byte {
	b, err := vectorsFS.ReadFile(issuerSignatureName)
	if err != nil {
		// Unreachable: the file is embedded at build time.
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", issuerSignatureName, err))
	}
	return b
}

// RelayKnockVectors returns the raw bytes of the embedded relay/NHP-handshake
// golden packets (relay_knock_golden.json). The bytes are the canonical
// wire-truth; a consumer that prefers to drive its own strict parser can feed
// these directly.
func RelayKnockVectors() []byte {
	b, err := vectorsFS.ReadFile(relayKnockName)
	if err != nil {
		// Unreachable: the file is embedded at build time.
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", relayKnockName, err))
	}
	return b
}

// AgentRegistrationVectors returns the raw bytes of the embedded NHP
// agent-registration golden packets (agent_registration_golden.json): the OTP/REG
// requests and the RAK replies. The bytes are the canonical wire-truth; a consumer
// that prefers to drive its own strict parser can feed these directly.
func AgentRegistrationVectors() []byte {
	b, err := vectorsFS.ReadFile(agentRegistrationName)
	if err != nil {
		// Unreachable: the file is embedded at build time.
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", agentRegistrationName, err))
	}
	return b
}

// Open returns the raw bytes of an embedded vectors file by its base name (for
// example "qv2_conformance_vectors.json" or "issuer_signature_vectors.json"), or
// by its full "vectors/..." path. It returns an error for any other name.
func Open(name string) ([]byte, error) {
	switch name {
	case conformanceVectorsName, "qv2_conformance_vectors.json":
		return vectorsFS.ReadFile(conformanceVectorsName)
	case issuerSignatureName, "issuer_signature_vectors.json":
		return vectorsFS.ReadFile(issuerSignatureName)
	case relayKnockName, "relay_knock_golden.json":
		return vectorsFS.ReadFile(relayKnockName)
	case agentRegistrationName, "agent_registration_golden.json":
		return vectorsFS.ReadFile(agentRegistrationName)
	default:
		return nil, fmt.Errorf("conformance: unknown embedded file %q", name)
	}
}

// ConformanceVectors strictly parses the embedded qURL v2 conformance artifact
// into a typed document, returning an error if it is malformed or is not the
// expected artifact.
func ConformanceVectors() (*ConformanceFile, error) {
	return ParseConformanceFile(QV2Vectors())
}

// SignatureVectors strictly parses the embedded issuer-signature vector file into
// a typed document, returning an error if it is malformed.
func SignatureVectors() (*VectorFile, error) {
	return ParseVectorFile(IssuerSignatureVectors())
}

// RelayKnockGolden strictly parses the embedded relay/NHP-handshake golden
// artifact into a typed document, returning an error if it is malformed or is not
// the expected artifact.
func RelayKnockGolden() (*RelayKnockFile, error) {
	return ParseRelayKnockFile(RelayKnockVectors())
}

// AgentRegistrationGolden strictly parses the embedded NHP agent-registration
// golden artifact into a typed document, returning an error if it is malformed or
// is not the expected artifact.
func AgentRegistrationGolden() (*AgentRegistrationFile, error) {
	return ParseAgentRegistrationFile(AgentRegistrationVectors())
}
