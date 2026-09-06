package conformance

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed vectors/*.json
var vectorsFS embed.FS

const (
	conformanceVectorsName      = "vectors/qv2_conformance_vectors.json"
	issuerSignatureName         = "vectors/issuer_signature_vectors.json"
	relayKnockName              = "vectors/relay_knock_golden.json"
	agentRegistrationName       = "vectors/agent_registration_golden.json"
	agentAssignmentName         = "vectors/agent_assignment_golden.json"
	agentKnockApplicationName   = "vectors/agent_knock_application_vectors.json"
	agentSessionControlName     = "vectors/agent_session_control_vectors.json"
	agentAPIKeyIDName           = "vectors/agent_api_key_id_vectors.json"
	assignmentTicketName        = "vectors/assignment_ticket_v1_vectors.json"
	connectorAuthorityName      = "vectors/connector_authority_lambda_v1_vectors.json"
	connectorResourceLSTV1Name  = "vectors/connector_resource_lst_v1_vectors.json"
	connectorHubRequestIDName   = "vectors/connector_hub_request_id_v1_vectors.json"
	connectorHubLSTCookieName   = "vectors/connector_hub_lst_cookie_v1_vectors.json"
	agentCredentialRecoveryName = "vectors/agent_credential_recovery_v1_vectors.json"
	cridV1Name                  = "vectors/crid_v1_vectors.json"
	targetPathV1Name            = "vectors/target_path_v1_vectors.json"
	delegatedMintIssueV1Name    = "vectors/delegated_mint_issue_v1_vectors.json"
)

func mustReadVector(name string) []byte {
	b, err := vectorsFS.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", name, err))
	}
	return b
}

// QV2Vectors returns the raw bytes of the embedded qURL v2 conformance vectors
// (qv2_conformance_vectors.json). The bytes are the canonical wire-truth; a
// consumer that prefers to drive its own strict parser can feed these directly.
func QV2Vectors() []byte {
	return mustReadVector(conformanceVectorsName)
}

// IssuerSignatureVectors returns the raw bytes of the embedded issuer-signature
// golden vectors (issuer_signature_vectors.json), which the signature class
// composes by reference.
func IssuerSignatureVectors() []byte {
	return mustReadVector(issuerSignatureName)
}

// RelayKnockVectors returns the raw bytes of the embedded relay/NHP-handshake
// golden packets (relay_knock_golden.json). The bytes are the canonical
// wire-truth; a consumer that prefers to drive its own strict parser can feed
// these directly.
func RelayKnockVectors() []byte {
	return mustReadVector(relayKnockName)
}

// AgentRegistrationVectors returns the raw bytes of the embedded NHP
// agent-registration golden packets (agent_registration_golden.json): the OTP/REG
// requests and the RAK replies. The bytes are the canonical wire-truth; a consumer
// that prefers to drive its own strict parser can feed these directly.
func AgentRegistrationVectors() []byte {
	return mustReadVector(agentRegistrationName)
}

// AgentAssignmentVectors returns the raw bytes of the deterministic NHP LST/LRT
// assignment and registration-completion packets plus the account-only OTP
// request contract.
func AgentAssignmentVectors() []byte {
	return mustReadVector(agentAssignmentName)
}

// AgentKnockApplicationVectors returns the raw bytes of the registered-agent
// knock application-body vectors. Unlike RelayKnockVectors, this artifact starts
// after Noise decryption and contains no packet bytes.
func AgentKnockApplicationVectors() []byte {
	return mustReadVector(agentKnockApplicationName)
}

// AgentSessionControlVectors returns the deterministic native-UDP overload
// re-knock and exact-session retirement packet artifact.
func AgentSessionControlVectors() []byte {
	return mustReadVector(agentSessionControlName)
}

// AgentAPIKeyIDVectors returns the raw bytes of the control-plane API-key ID
// producer and consumer vectors used by agent registration.
func AgentAPIKeyIDVectors() []byte {
	return mustReadVector(agentAPIKeyIDName)
}

// AssignmentTicketVectors returns the raw bytes of the standalone qat1
// cryptographic and fence artifact.
func AssignmentTicketVectors() []byte {
	return mustReadVector(assignmentTicketName)
}

// ConnectorAuthorityLambdaVectors returns the raw bytes of the private,
// operation-specific NHP-to-authority invocation artifact.
func ConnectorAuthorityLambdaVectors() []byte {
	return mustReadVector(connectorAuthorityName)
}

// ConnectorResourceLSTV1Vectors returns the exact registered-agent NHP_LST and
// NHP_LRT application bodies for resolving one Connector resource.
func ConnectorResourceLSTV1Vectors() []byte {
	return mustReadVector(connectorResourceLSTV1Name)
}

// ConnectorHubRequestIDVectors returns the private Hub replay-key derivation
// KAT shared by Hub worker implementations.
func ConnectorHubRequestIDVectors() []byte {
	return mustReadVector(connectorHubRequestIDName)
}

// ConnectorHubLSTCookieVectors returns the Hub assignment return-routability
// challenge and proof contract.
func ConnectorHubLSTCookieVectors() []byte {
	return mustReadVector(connectorHubLSTCookieName)
}

// AgentCredentialRecoveryVectors returns the UDP-only same-agent device-
// credential recovery contract shared by the Hub, assigned cell, Authority,
// and native SDK.
func AgentCredentialRecoveryVectors() []byte {
	return mustReadVector(agentCredentialRecoveryName)
}

// CRIDV1Vectors returns the raw bytes of the CRID v1 derivation and
// validation vectors shared by every producer and consumer of the
// cryptographic resource identifier.
func CRIDV1Vectors() []byte {
	return mustReadVector(cridV1Name)
}

// TargetPathV1Vectors returns the raw bytes of the canonical target_path
// request contract shared by the service and SDKs.
func TargetPathV1Vectors() []byte {
	return mustReadVector(targetPathV1Name)
}

// DelegatedMintIssueV1Vectors returns the private Connector-to-service issue
// signature contract and its byte-exact golden request.
func DelegatedMintIssueV1Vectors() []byte {
	return mustReadVector(delegatedMintIssueV1Name)
}

// Open returns the raw bytes of an embedded vectors file by its base name (for
// example "qv2_conformance_vectors.json" or "issuer_signature_vectors.json"), or
// by its full "vectors/..." path. It returns an error for any other name.
func Open(name string) ([]byte, error) {
	base := strings.TrimPrefix(name, "vectors/")
	if base == "" || strings.Contains(base, "/") || (name != base && name != "vectors/"+base) {
		return nil, fmt.Errorf("conformance: unknown embedded file %q", name)
	}
	b, err := vectorsFS.ReadFile("vectors/" + base)
	if err != nil {
		return nil, fmt.Errorf("conformance: unknown embedded file %q", name)
	}
	return b, nil
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
// exact-session retirement packet artifact.
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

// ConnectorAuthorityLambda strictly parses the embedded private invocation
// artifact shared by NHP workers and Connector Authority handlers.
func ConnectorAuthorityLambda() (*ConnectorAuthorityLambdaFile, error) {
	return ParseConnectorAuthorityLambdaFile(ConnectorAuthorityLambdaVectors())
}

// ConnectorResourceLSTV1 strictly parses the registered-agent Connector
// resource-discovery application contract.
func ConnectorResourceLSTV1() (*ConnectorResourceLSTV1File, error) {
	return ParseConnectorResourceLSTV1File(ConnectorResourceLSTV1Vectors())
}

// ConnectorHubRequestID strictly parses the embedded private Hub replay-key
// derivation artifact.
func ConnectorHubRequestID() (*ConnectorHubRequestIDFile, error) {
	return ParseConnectorHubRequestIDFile(ConnectorHubRequestIDVectors())
}

// ConnectorHubLSTCookie strictly parses the Hub assignment
// return-routability challenge artifact.
func ConnectorHubLSTCookie() (*ConnectorHubLSTCookieFile, error) {
	return ParseConnectorHubLSTCookieFile(ConnectorHubLSTCookieVectors())
}

// AgentCredentialRecovery strictly parses the UDP-only same-agent device-
// credential recovery artifact.
func AgentCredentialRecovery() (*AgentCredentialRecoveryFile, error) {
	return ParseAgentCredentialRecoveryFile(AgentCredentialRecoveryVectors())
}

// CRIDV1 strictly parses the embedded CRID v1 derivation and validation
// artifact.
func CRIDV1() (*CRIDV1File, error) {
	return ParseCRIDV1File(CRIDV1Vectors())
}

// TargetPathV1 strictly parses the embedded target_path contract artifact.
func TargetPathV1() (*TargetPathV1File, error) {
	return ParseTargetPathV1File(TargetPathV1Vectors())
}

// DelegatedMintIssueV1 strictly parses and verifies the private Connector
// capability-issue signature artifact.
func DelegatedMintIssueV1() (*DelegatedMintIssueV1File, error) {
	return ParseDelegatedMintIssueV1File(DelegatedMintIssueV1Vectors())
}
