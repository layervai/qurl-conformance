package conformance

import (
	"embed"
	"fmt"
)

//go:embed vectors/qv2_conformance_vectors.json vectors/issuer_signature_vectors.json vectors/relay_knock_golden.json vectors/agent_registration_golden.json vectors/agent_assignment_golden.json vectors/agent_knock_application_vectors.json vectors/agent_session_control_vectors.json vectors/agent_api_key_id_vectors.json vectors/assignment_ticket_v1_vectors.json
var vectorsFS embed.FS

const (
	conformanceVectorsName    = "vectors/qv2_conformance_vectors.json"
	issuerSignatureName       = "vectors/issuer_signature_vectors.json"
	relayKnockName            = "vectors/relay_knock_golden.json"
	agentRegistrationName     = "vectors/agent_registration_golden.json"
	agentAssignmentName       = "vectors/agent_assignment_golden.json"
	agentKnockApplicationName = "vectors/agent_knock_application_vectors.json"
	agentSessionControlName   = "vectors/agent_session_control_vectors.json"
	agentAPIKeyIDName         = "vectors/agent_api_key_id_vectors.json"
	assignmentTicketName      = "vectors/assignment_ticket_v1_vectors.json"
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

// AgentAssignmentVectors returns the raw bytes of the deterministic NHP LST/LRT
// assignment and registration-completion packets plus the account-only OTP
// request contract.
func AgentAssignmentVectors() []byte {
	b, err := vectorsFS.ReadFile(agentAssignmentName)
	if err != nil {
		// Unreachable: the file is embedded at build time.
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", agentAssignmentName, err))
	}
	return b
}

// AgentKnockApplicationVectors returns the raw bytes of the registered-agent
// knock application-body vectors. Unlike RelayKnockVectors, this artifact starts
// after Noise decryption and contains no packet bytes.
func AgentKnockApplicationVectors() []byte {
	b, err := vectorsFS.ReadFile(agentKnockApplicationName)
	if err != nil {
		// Unreachable: the file is embedded at build time.
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", agentKnockApplicationName, err))
	}
	return b
}

// AgentSessionControlVectors returns the deterministic native-UDP overload
// re-knock and clean-exit packet artifact.
func AgentSessionControlVectors() []byte {
	b, err := vectorsFS.ReadFile(agentSessionControlName)
	if err != nil {
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", agentSessionControlName, err))
	}
	return b
}

// AgentAPIKeyIDVectors returns the raw bytes of the control-plane API-key ID
// producer and consumer vectors used by agent registration.
func AgentAPIKeyIDVectors() []byte {
	b, err := vectorsFS.ReadFile(agentAPIKeyIDName)
	if err != nil {
		// Unreachable: the file is embedded at build time.
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", agentAPIKeyIDName, err))
	}
	return b
}

// AssignmentTicketVectors returns the raw bytes of the standalone qat1
// cryptographic and fence artifact.
func AssignmentTicketVectors() []byte {
	b, err := vectorsFS.ReadFile(assignmentTicketName)
	if err != nil {
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", assignmentTicketName, err))
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
	case agentAssignmentName, "agent_assignment_golden.json":
		return vectorsFS.ReadFile(agentAssignmentName)
	case agentKnockApplicationName, "agent_knock_application_vectors.json":
		return vectorsFS.ReadFile(agentKnockApplicationName)
	case agentSessionControlName, "agent_session_control_vectors.json":
		return vectorsFS.ReadFile(agentSessionControlName)
	case agentAPIKeyIDName, "agent_api_key_id_vectors.json":
		return vectorsFS.ReadFile(agentAPIKeyIDName)
	case assignmentTicketName, "assignment_ticket_v1_vectors.json":
		return vectorsFS.ReadFile(assignmentTicketName)
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

// AgentAssignmentGolden strictly parses the embedded deterministic NHP LST/LRT
// assignment and registration-completion artifact plus account-only OTP.
func AgentAssignmentGolden() (*AgentAssignmentFile, error) {
	return ParseAgentAssignmentFile(AgentAssignmentVectors())
}

// AgentKnockApplication strictly parses the embedded registered-agent knock
// application-body artifact into a typed document.
func AgentKnockApplication() (*AgentKnockApplicationFile, error) {
	return ParseAgentKnockApplicationFile(AgentKnockApplicationVectors())
}

// AgentSessionControl strictly parses the native-UDP overload re-knock and
// clean-exit packet artifact.
func AgentSessionControl() (*AgentSessionControlFile, error) {
	return ParseAgentSessionControlFile(AgentSessionControlVectors())
}

// AgentAPIKeyIDs strictly parses the embedded agent API-key ID artifact.
func AgentAPIKeyIDs() (*AgentAPIKeyIDFile, error) {
	return ParseAgentAPIKeyIDFile(AgentAPIKeyIDVectors())
}

// AssignmentTicket strictly parses the embedded standalone qat1 artifact.
func AssignmentTicket() (*AssignmentTicketFile, error) {
	return ParseAssignmentTicketFile(AssignmentTicketVectors())
}
