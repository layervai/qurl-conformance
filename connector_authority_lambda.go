package conformance

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// ConnectorAuthorityLambdaArtifactID identifies the private NHP-to-authority
	// invocation contract. It is deliberately separate from the public UDP
	// agent-assignment artifact.
	ConnectorAuthorityLambdaArtifactID = "qurl-connector-authority-lambda-v1-vectors"
	// ConnectorAuthorityLambdaSchemaVersion is the only artifact schema accepted
	// by this release.
	ConnectorAuthorityLambdaSchemaVersion = 1

	ConnectorAuthorityLambdaRequestVersion   = 1
	ConnectorAuthorityLambdaMaxRequestBytes  = 4096
	ConnectorAuthorityLambdaMaxResponseBytes = 4096
	// ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes is shared with
	// assignmentticket v1 so this adapter accepts every valid qat1 token that
	// still fits inside the operation's 4096-byte request envelope.
	ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes = 2304
	ConnectorAuthorityLambdaTimestampFormat               = "RFC3339_UTC_WHOLE_SECONDS"
	ConnectorAuthorityLambdaHubRequestIDFormat            = "lowercase_sha256_hex"
	ConnectorAuthorityLambdaResponseRule                  = "exactly_one_of_result_or_error"

	ConnectorAuthorityOperationIssueAssignment      = "IssueAssignment"
	ConnectorAuthorityOperationRefreshAssignment    = "RefreshAssignment"
	ConnectorAuthorityOperationIssueRegistrationOTP = "IssueRegistrationOTP"
	ConnectorAuthorityOperationActivateRegistration = "ActivateRegistration"
	ConnectorAuthorityOperationCompleteRegistration = "CompleteRegistration"

	ConnectorAuthorityMappingSourceResponse  = "authority_response"
	ConnectorAuthorityMappingSourcePreInvoke = "nhp_preinvoke"
	ConnectorAuthorityNHPActionEmitLRT       = "emit_lrt"
	ConnectorAuthorityNHPActionEmitRAK       = "emit_rak"
	ConnectorAuthorityNHPActionNoReply       = "no_application_reply"
	ConnectorAuthorityNHPActionDropNoReply   = "drop_no_reply"
	ConnectorAuthorityRecoveryNone           = "none"
	ConnectorAuthorityRecoveryPendingExact   = "bounded_exact_pending_activation_transport_retry"
)

var connectorAuthorityOperationNames = []string{
	ConnectorAuthorityOperationIssueAssignment,
	ConnectorAuthorityOperationRefreshAssignment,
	ConnectorAuthorityOperationIssueRegistrationOTP,
	ConnectorAuthorityOperationActivateRegistration,
	ConnectorAuthorityOperationCompleteRegistration,
}

var (
	connectorAuthorityAgentIDPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
	connectorAuthorityCellIDPattern       = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	connectorAuthorityDNSLabelPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	connectorAuthorityHubRequestIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ConnectorAuthorityLambdaFile freezes the private synchronous invocation
// bodies shared by authority handlers and NHP workers. It does not define a
// public API or a generic operation-dispatch envelope.
type ConnectorAuthorityLambdaFile struct {
	Artifact      string                                       `json:"artifact"`
	SchemaVersion int                                          `json:"schema_version"`
	Description   string                                       `json:"description"`
	Protocol      ConnectorAuthorityLambdaProtocol             `json:"protocol"`
	Fixtures      ConnectorAuthorityLambdaFixtures             `json:"fixtures"`
	Operations    map[string]ConnectorAuthorityLambdaOperation `json:"operations"`
}

// ConnectorAuthorityLambdaProtocol is the closed framing profile applied
// before operation-specific decoding.
type ConnectorAuthorityLambdaProtocol struct {
	RequestVersion                int    `json:"request_version"`
	MaxRequestBytes               int    `json:"max_request_bytes"`
	MaxResponseBytes              int    `json:"max_response_bytes"`
	MaxAssignmentTicketASCIIBytes int    `json:"max_assignment_ticket_ascii_bytes"`
	TimestampFormat               string `json:"timestamp_format"`
	HubRequestIDFormat            string `json:"hub_request_id_format"`
	ResponseRule                  string `json:"response_rule"`
}

// ConnectorAuthorityLambdaFixtures are synthetic, non-production values used
// by every golden and mapping case.
type ConnectorAuthorityLambdaFixtures struct {
	AgentID                       string `json:"agent_id"`
	AuthenticatedPeerPublicKeyB64 string `json:"authenticated_peer_public_key_b64"`
	HubRequestID                  string `json:"hub_request_id"`
	Credential                    string `json:"credential"`
	AssignmentTicket              string `json:"assignment_ticket"`
	CredentialKeyID               string `json:"credential_key_id"`
	RegistrationCredential        string `json:"registration_credential"`
	ObservedSourceAddress         string `json:"observed_source_address"`
	Hostname                      string `json:"hostname"`
	AgentVersion                  string `json:"agent_version"`
	DeviceAPIKey                  string `json:"device_api_key"`
	DeviceAPIKeyID                string `json:"device_api_key_id"`
	RegistrationKeyKind           string `json:"registration_key_kind"`
	CellID                        string `json:"cell_id"`
	AssignmentGeneration          int64  `json:"assignment_generation"`
	EndpointRevision              int64  `json:"endpoint_revision"`
	LeaseExpiresAt                string `json:"lease_expires_at"`
	NHPHost                       string `json:"nhp_host"`
	NHPPort                       int    `json:"nhp_port"`
	ServerPublicKeyB64            string `json:"server_public_key_b64"`
	AssignmentTicketExpiresAt     string `json:"assignment_ticket_expires_at"`
}

// ConnectorAuthorityLambdaOperation is one separately permissioned function's
// complete request, response, reject, and public-mapping contract.
type ConnectorAuthorityLambdaOperation struct {
	RequestGolden           ConnectorAuthorityLambdaBodyCase     `json:"request_golden"`
	SuccessGolden           ConnectorAuthorityLambdaBodyCase     `json:"success_golden"`
	SemanticErrors          []ConnectorAuthorityLambdaErrorCase  `json:"semantic_errors"`
	RequestRejects          []ConnectorAuthorityLambdaRejectCase `json:"request_rejects"`
	ResponseProducerRejects []ConnectorAuthorityLambdaRejectCase `json:"response_producer_rejects"`
	PublicMappingCases      []ConnectorAuthorityPublicMapping    `json:"public_mapping_cases"`
}

// ConnectorAuthorityLambdaBodyCase preserves exact raw JSON bytes for a valid
// request or response.
type ConnectorAuthorityLambdaBodyCase struct {
	Name     string `json:"name"`
	BodyJSON string `json:"body_json"`
}

// ConnectorAuthorityLambdaErrorCase freezes one operation-specific semantic
// error code and its exact private response body.
type ConnectorAuthorityLambdaErrorCase struct {
	Code     string `json:"code"`
	BodyJSON string `json:"body_json"`
}

// ConnectorAuthorityLambdaRejectCase preserves raw malformed input. Oversize
// cases derive an exact byte sequence from the fill byte and length instead of
// committing thousands of redundant characters.
type ConnectorAuthorityLambdaRejectCase struct {
	Name             string `json:"name"`
	BodyJSON         string `json:"body_json,omitempty"`
	BodyFillByteHex  string `json:"body_fill_byte_hex,omitempty"`
	DerivedBodyBytes int    `json:"derived_body_bytes,omitempty"`
	Outcome          string `json:"outcome"`
	RejectClass      string `json:"reject_class"`
}

// ConnectorAuthorityPublicMapping freezes how an authority outcome, or an NHP
// pre-invoke gate, becomes a public application reply or deliberate absence of
// one. PrivateResponseBodyJSON is empty only for pre-invoke cases. NHPBodyJSON
// is empty when NHPAction is no_application_reply or drop_no_reply.
type ConnectorAuthorityPublicMapping struct {
	Name                    string `json:"name"`
	MappingSource           string `json:"mapping_source"`
	PrivateOutcome          string `json:"private_outcome,omitempty"`
	PrivateResponseBodyJSON string `json:"private_response_body_json,omitempty"`
	NHPAction               string `json:"nhp_action"`
	NHPBodyJSON             string `json:"nhp_body_json,omitempty"`
	RecoveryAction          string `json:"recovery_action"`
}

// Private request shapes. Environment, cell, owner, assignment generation,
// and operation selector are absent by construction.
type ConnectorAuthorityIssueAssignmentRequest struct {
	Version                       int    `json:"version"`
	HubRequestID                  string `json:"hub_request_id"`
	AgentID                       string `json:"agent_id"`
	AuthenticatedPeerPublicKeyB64 string `json:"authenticated_peer_public_key_b64"`
	Credential                    string `json:"credential"`
}

type ConnectorAuthorityRefreshAssignmentRequest struct {
	Version                       int    `json:"version"`
	HubRequestID                  string `json:"hub_request_id"`
	AgentID                       string `json:"agent_id"`
	AuthenticatedPeerPublicKeyB64 string `json:"authenticated_peer_public_key_b64"`
}

type ConnectorAuthorityIssueRegistrationOTPRequest struct {
	Version                       int    `json:"version"`
	AssignmentTicket              string `json:"assignment_ticket"`
	CredentialKeyID               string `json:"credential_key_id"`
	CredentialSecret              string `json:"credential_secret"`
	AuthenticatedPeerPublicKeyB64 string `json:"authenticated_peer_public_key_b64"`
	AgentID                       string `json:"agent_id"`
	ObservedSourceAddress         string `json:"observed_source_address"`
}

type ConnectorAuthorityActivateRegistrationRequest struct {
	Version                       int    `json:"version"`
	AssignmentTicket              string `json:"assignment_ticket"`
	CredentialKeyID               string `json:"credential_key_id"`
	RegistrationCredential        string `json:"registration_credential"`
	AuthenticatedPeerPublicKeyB64 string `json:"authenticated_peer_public_key_b64"`
	AgentID                       string `json:"agent_id"`
	Hostname                      string `json:"hostname"`
	AgentVersion                  string `json:"agent_version"`
}

type ConnectorAuthorityCompleteRegistrationRequest struct {
	Version                       int    `json:"version"`
	AuthenticatedPeerPublicKeyB64 string `json:"authenticated_peer_public_key_b64"`
	AgentID                       string `json:"agent_id"`
	DeviceAPIKey                  string `json:"device_api_key"`
}

// ConnectorAuthorityAssignmentResult is the only placement result shape. The
// initial operation additionally wraps registration metadata and a ticket;
// refresh does not.
type ConnectorAuthorityAssignmentResult struct {
	CellID               string                           `json:"cell_id"`
	AssignmentGeneration int64                            `json:"assignment_generation"`
	EndpointRevision     int64                            `json:"endpoint_revision"`
	LeaseExpiresAt       string                           `json:"lease_expires_at"`
	NHPUDPEndpoint       ConnectorAuthorityNHPUDPEndpoint `json:"nhp_udp_endpoint"`
}

type ConnectorAuthorityNHPUDPEndpoint struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	ServerPublicKeyB64 string `json:"server_public_key_b64"`
}

type ConnectorAuthorityRegistrationResult struct {
	KeyID   string `json:"key_id"`
	KeyKind string `json:"key_kind"`
}

type ConnectorAuthorityIssueAssignmentResult struct {
	AgentID                   string                               `json:"agent_id"`
	Registration              ConnectorAuthorityRegistrationResult `json:"registration"`
	Assignment                ConnectorAuthorityAssignmentResult   `json:"assignment"`
	AssignmentTicket          string                               `json:"assignment_ticket"`
	AssignmentTicketExpiresAt string                               `json:"assignment_ticket_expires_at"`
}

type ConnectorAuthorityRefreshAssignmentResult struct {
	AgentID    string                             `json:"agent_id"`
	Assignment ConnectorAuthorityAssignmentResult `json:"assignment"`
}

type ConnectorAuthorityCompleteRegistrationResult struct {
	DeviceAPIKeyID string `json:"device_api_key_id"`
}

type connectorAuthorityResponseEnvelope struct {
	Version int             `json:"version"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type connectorAuthorityError struct {
	Code              string `json:"code"`
	RetryAfterSeconds *int64 `json:"retry_after_seconds,omitempty"`
}

// ParseConnectorAuthorityLambdaFile strictly parses and independently validates
// the embedded private invocation artifact.
func ParseConnectorAuthorityLambdaFile(data []byte) (*ConnectorAuthorityLambdaFile, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("conformance: Connector Authority Lambda file is not valid UTF-8")
	}
	var file ConnectorAuthorityLambdaFile
	if err := strictDecodeArtifact(data, &file); err != nil {
		return nil, fmt.Errorf("conformance: parse Connector Authority Lambda file: %w", err)
	}
	if file.Artifact != ConnectorAuthorityLambdaArtifactID {
		return nil, fmt.Errorf("conformance: Connector Authority Lambda artifact = %q, want %q", file.Artifact, ConnectorAuthorityLambdaArtifactID)
	}
	if file.SchemaVersion != ConnectorAuthorityLambdaSchemaVersion {
		return nil, fmt.Errorf("conformance: Connector Authority Lambda schema_version = %d, want %d", file.SchemaVersion, ConnectorAuthorityLambdaSchemaVersion)
	}
	if strings.TrimSpace(file.Description) == "" {
		return nil, errors.New("conformance: Connector Authority Lambda description is empty")
	}
	wantProtocol := ConnectorAuthorityLambdaProtocol{
		RequestVersion: ConnectorAuthorityLambdaRequestVersion, MaxRequestBytes: ConnectorAuthorityLambdaMaxRequestBytes,
		MaxResponseBytes: ConnectorAuthorityLambdaMaxResponseBytes, MaxAssignmentTicketASCIIBytes: ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes,
		TimestampFormat:    ConnectorAuthorityLambdaTimestampFormat,
		HubRequestIDFormat: ConnectorAuthorityLambdaHubRequestIDFormat,
		ResponseRule:       ConnectorAuthorityLambdaResponseRule,
	}
	if file.Protocol != wantProtocol {
		return nil, fmt.Errorf("conformance: Connector Authority Lambda protocol = %+v, want %+v", file.Protocol, wantProtocol)
	}
	if err := validateConnectorAuthorityFixtures(file.Fixtures); err != nil {
		return nil, err
	}
	if len(file.Operations) != len(connectorAuthorityOperationNames) {
		return nil, fmt.Errorf("conformance: Connector Authority Lambda operation count = %d, want %d", len(file.Operations), len(connectorAuthorityOperationNames))
	}
	for _, name := range connectorAuthorityOperationNames {
		op, ok := file.Operations[name]
		if !ok {
			return nil, fmt.Errorf("conformance: Connector Authority Lambda operation %q is missing", name)
		}
		if err := validateConnectorAuthorityOperation(name, op, file.Fixtures); err != nil {
			return nil, err
		}
	}
	return &file, nil
}

func validateConnectorAuthorityFixtures(f ConnectorAuthorityLambdaFixtures) error {
	if !connectorAuthorityAgentIDPattern.MatchString(f.AgentID) {
		return errors.New("conformance: Connector Authority fixture agent_id is not canonical")
	}
	if err := validateConnectorAuthorityX25519KeyEncoding(f.AuthenticatedPeerPublicKeyB64); err != nil {
		return fmt.Errorf("conformance: Connector Authority fixture peer key: %w", err)
	}
	if !connectorAuthorityHubRequestIDPattern.MatchString(f.HubRequestID) {
		return errors.New("conformance: Connector Authority fixture hub_request_id is not canonical")
	}
	if !isConnectorAuthorityAPIKey(f.Credential) || !isConnectorAuthorityAPIKey(f.DeviceAPIKey) {
		return errors.New("conformance: Connector Authority fixture API key is not canonical")
	}
	if f.DeviceAPIKey == f.Credential {
		return errors.New("conformance: Connector Authority fixture device API key must differ from the initial credential")
	}
	if !isCanonicalAgentAPIKeyID(f.CredentialKeyID) || !isCanonicalAgentAPIKeyID(f.DeviceAPIKeyID) {
		return errors.New("conformance: Connector Authority fixture key id is not canonical")
	}
	if !validConnectorAuthorityASCII(f.AssignmentTicket, 1, ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes) || !validConnectorAuthorityASCII(f.RegistrationCredential, 1, 128) {
		return errors.New("conformance: Connector Authority fixture ticket or registration credential is invalid")
	}
	if !isCanonicalConnectorAuthorityAddress(f.ObservedSourceAddress) {
		return errors.New("conformance: Connector Authority fixture observed source address is not canonical")
	}
	if !validConnectorAuthorityMetadata(f.Hostname, 253) || !validConnectorAuthorityMetadata(f.AgentVersion, 64) {
		return errors.New("conformance: Connector Authority fixture agent metadata is invalid")
	}
	if f.RegistrationKeyKind != "account" || !connectorAuthorityCellIDPattern.MatchString(f.CellID) || f.AssignmentGeneration < 1 || f.EndpointRevision < 1 ||
		!validConnectorAuthorityHost(f.NHPHost) || f.NHPPort < 1 || f.NHPPort > 65535 {
		return errors.New("conformance: Connector Authority fixture assignment metadata is invalid")
	}
	if err := validateConnectorAuthorityX25519ServerKey(f.ServerPublicKeyB64); err != nil {
		return fmt.Errorf("conformance: Connector Authority fixture server key: %w", err)
	}
	lease, err := parseConnectorAuthorityTimestamp(f.LeaseExpiresAt)
	if err != nil {
		return fmt.Errorf("conformance: Connector Authority fixture lease: %w", err)
	}
	ticketExpiry, err := parseConnectorAuthorityTimestamp(f.AssignmentTicketExpiresAt)
	if err != nil {
		return fmt.Errorf("conformance: Connector Authority fixture ticket expiry: %w", err)
	}
	if !ticketExpiry.Before(lease) {
		return errors.New("conformance: Connector Authority fixture ticket expiry must precede lease expiry")
	}
	return nil
}

func validateConnectorAuthorityOperation(name string, op ConnectorAuthorityLambdaOperation, f ConnectorAuthorityLambdaFixtures) error {
	if op.RequestGolden.Name != "accept_request" || op.SuccessGolden.Name != "accept_success" {
		return fmt.Errorf("conformance: Connector Authority %s golden names are not canonical", name)
	}
	if len(op.RequestGolden.BodyJSON) > ConnectorAuthorityLambdaMaxRequestBytes || len(op.SuccessGolden.BodyJSON) > ConnectorAuthorityLambdaMaxResponseBytes {
		return fmt.Errorf("conformance: Connector Authority %s golden body exceeds protocol cap", name)
	}
	if err := validateConnectorAuthorityRequest(name, []byte(op.RequestGolden.BodyJSON)); err != nil {
		return fmt.Errorf("conformance: Connector Authority %s request golden: %w", name, err)
	}
	if err := validateConnectorAuthorityGoldenRequest(name, op.RequestGolden.BodyJSON, f); err != nil {
		return err
	}
	if _, err := validateConnectorAuthorityResponse(name, []byte(op.SuccessGolden.BodyJSON)); err != nil {
		return fmt.Errorf("conformance: Connector Authority %s success golden: %w", name, err)
	}
	if err := validateConnectorAuthorityGoldenSuccess(name, op.SuccessGolden.BodyJSON, f); err != nil {
		return err
	}
	if err := validateConnectorAuthoritySemanticErrors(name, op.SemanticErrors); err != nil {
		return err
	}
	if err := validateConnectorAuthorityRejects(name, "request", op.RequestRejects); err != nil {
		return err
	}
	if err := validateConnectorAuthorityRejects(name, "response", op.ResponseProducerRejects); err != nil {
		return err
	}
	return validateConnectorAuthorityMappings(name, op, f)
}

func validateConnectorAuthorityRequest(operation string, data []byte) error {
	if len(data) > ConnectorAuthorityLambdaMaxRequestBytes {
		return errors.New("request exceeds 4096 bytes")
	}
	if !utf8.Valid(data) {
		return errors.New("request is not valid UTF-8")
	}
	if err := requireConnectorAuthorityVersionLexeme(data); err != nil {
		return err
	}
	if err := requireConnectorAuthorityRequestMembers(operation, data); err != nil {
		return err
	}
	switch operation {
	case ConnectorAuthorityOperationIssueAssignment:
		var request ConnectorAuthorityIssueAssignmentRequest
		if err := strictDecodeArtifact(data, &request); err != nil {
			return err
		}
		if request.Version != 1 || !connectorAuthorityAgentIDPattern.MatchString(request.AgentID) ||
			validateConnectorAuthorityX25519KeyEncoding(request.AuthenticatedPeerPublicKeyB64) != nil ||
			!connectorAuthorityHubRequestIDPattern.MatchString(request.HubRequestID) || !isConnectorAuthorityAPIKey(request.Credential) {
			return errors.New("invalid IssueAssignment request semantics")
		}
	case ConnectorAuthorityOperationRefreshAssignment:
		var request ConnectorAuthorityRefreshAssignmentRequest
		if err := strictDecodeArtifact(data, &request); err != nil {
			return err
		}
		if request.Version != 1 || !connectorAuthorityAgentIDPattern.MatchString(request.AgentID) ||
			validateConnectorAuthorityX25519KeyEncoding(request.AuthenticatedPeerPublicKeyB64) != nil ||
			!connectorAuthorityHubRequestIDPattern.MatchString(request.HubRequestID) {
			return errors.New("invalid RefreshAssignment request semantics")
		}
	case ConnectorAuthorityOperationIssueRegistrationOTP:
		var request ConnectorAuthorityIssueRegistrationOTPRequest
		if err := strictDecodeArtifact(data, &request); err != nil {
			return err
		}
		if request.Version != 1 || !validConnectorAuthorityASCII(request.AssignmentTicket, 1, ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes) ||
			!isCanonicalAgentAPIKeyID(request.CredentialKeyID) || !isConnectorAuthorityAPIKey(request.CredentialSecret) ||
			validateConnectorAuthorityX25519KeyEncoding(request.AuthenticatedPeerPublicKeyB64) != nil || !connectorAuthorityAgentIDPattern.MatchString(request.AgentID) ||
			!isCanonicalConnectorAuthorityAddress(request.ObservedSourceAddress) {
			return errors.New("invalid IssueRegistrationOTP request semantics")
		}
	case ConnectorAuthorityOperationActivateRegistration:
		var request ConnectorAuthorityActivateRegistrationRequest
		if err := strictDecodeArtifact(data, &request); err != nil {
			return err
		}
		if request.Version != 1 || !validConnectorAuthorityASCII(request.AssignmentTicket, 1, ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes) ||
			!isCanonicalAgentAPIKeyID(request.CredentialKeyID) || !validConnectorAuthorityASCII(request.RegistrationCredential, 0, 128) ||
			validateConnectorAuthorityX25519KeyEncoding(request.AuthenticatedPeerPublicKeyB64) != nil || !connectorAuthorityAgentIDPattern.MatchString(request.AgentID) ||
			!validConnectorAuthorityMetadata(request.Hostname, 253) || !validConnectorAuthorityMetadata(request.AgentVersion, 64) {
			return errors.New("invalid ActivateRegistration request semantics")
		}
	case ConnectorAuthorityOperationCompleteRegistration:
		var request ConnectorAuthorityCompleteRegistrationRequest
		if err := strictDecodeArtifact(data, &request); err != nil {
			return err
		}
		if request.Version != 1 || validateConnectorAuthorityX25519KeyEncoding(request.AuthenticatedPeerPublicKeyB64) != nil ||
			!connectorAuthorityAgentIDPattern.MatchString(request.AgentID) || !isConnectorAuthorityAPIKey(request.DeviceAPIKey) {
			return errors.New("invalid CompleteRegistration request semantics")
		}
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	return nil
}

func requireConnectorAuthorityRequestMembers(operation string, data []byte) error {
	required, err := connectorAuthorityRequestMembers(operation)
	if err != nil {
		return err
	}
	_, err = validateConnectorAuthorityExactObject(data, required, required)
	return err
}

func connectorAuthorityRequestMembers(operation string) ([]string, error) {
	switch operation {
	case ConnectorAuthorityOperationIssueAssignment:
		return []string{"version", "hub_request_id", "agent_id", "authenticated_peer_public_key_b64", "credential"}, nil
	case ConnectorAuthorityOperationRefreshAssignment:
		return []string{"version", "hub_request_id", "agent_id", "authenticated_peer_public_key_b64"}, nil
	case ConnectorAuthorityOperationIssueRegistrationOTP:
		return []string{"version", "assignment_ticket", "credential_key_id", "credential_secret", "authenticated_peer_public_key_b64", "agent_id", "observed_source_address"}, nil
	case ConnectorAuthorityOperationActivateRegistration:
		return []string{"version", "assignment_ticket", "credential_key_id", "registration_credential", "authenticated_peer_public_key_b64", "agent_id", "hostname", "agent_version"}, nil
	case ConnectorAuthorityOperationCompleteRegistration:
		return []string{"version", "authenticated_peer_public_key_b64", "agent_id", "device_api_key"}, nil
	default:
		return nil, fmt.Errorf("unknown operation %q", operation)
	}
}

func validateConnectorAuthorityResponse(operation string, data []byte) (string, error) {
	if len(data) > ConnectorAuthorityLambdaMaxResponseBytes {
		return "", errors.New("response exceeds 4096 bytes")
	}
	if !utf8.Valid(data) {
		return "", errors.New("response is not valid UTF-8")
	}
	if err := requireConnectorAuthorityVersionLexeme(data); err != nil {
		return "", err
	}
	object, err := validateConnectorAuthorityExactObject(data, []string{"version"}, []string{"version", "result", "error"})
	if err != nil {
		return "", err
	}
	resultRaw, hasResult := object["result"]
	errorRaw, hasError := object["error"]
	if hasResult == hasError {
		return "", errors.New("response must contain exactly one result or error key")
	}
	if (hasResult && string(resultRaw) == "null") || (hasError && string(errorRaw) == "null") {
		return "", errors.New("response result or error must not be null")
	}
	var envelope connectorAuthorityResponseEnvelope
	if err := strictDecodeArtifact(data, &envelope); err != nil {
		return "", err
	}
	if envelope.Version != 1 {
		return "", errors.New("response version must be 1")
	}
	if hasResult {
		if err := validateConnectorAuthorityResult(operation, resultRaw); err != nil {
			return "", err
		}
		return "success", nil
	}
	var responseError connectorAuthorityError
	errorObject, err := validateConnectorAuthorityExactObject(errorRaw, []string{"code"}, []string{"code", "retry_after_seconds"})
	if err != nil {
		return "", err
	}
	if retryRaw, present := errorObject["retry_after_seconds"]; present && string(retryRaw) == "null" {
		return "", errors.New("retry_after_seconds must not be null")
	}
	if err := strictDecodeArtifact(errorRaw, &responseError); err != nil {
		return "", err
	}
	if !connectorAuthorityErrorAllowed(operation, responseError.Code) {
		return "", fmt.Errorf("unknown %s error code %q", operation, responseError.Code)
	}
	if connectorAuthorityRequiresRetryAfter(operation, responseError.Code) {
		if responseError.RetryAfterSeconds == nil || *responseError.RetryAfterSeconds < 1 {
			return "", errors.New("rate_limited requires positive retry_after_seconds")
		}
	} else if responseError.RetryAfterSeconds != nil {
		return "", errors.New("retry_after_seconds is forbidden for this error")
	}
	return responseError.Code, nil
}

func validateConnectorAuthorityResult(operation string, raw []byte) error {
	if len(raw) == 0 || raw[0] != '{' {
		return errors.New("result must be an object")
	}
	switch operation {
	case ConnectorAuthorityOperationIssueAssignment:
		object, err := validateConnectorAuthorityExactObject(raw,
			[]string{"agent_id", "registration", "assignment", "assignment_ticket", "assignment_ticket_expires_at"},
			[]string{"agent_id", "registration", "assignment", "assignment_ticket", "assignment_ticket_expires_at"})
		if err != nil {
			return err
		}
		if _, err := validateConnectorAuthorityExactObject(object["registration"], []string{"key_id", "key_kind"}, []string{"key_id", "key_kind"}); err != nil {
			return fmt.Errorf("registration: %w", err)
		}
		if err := validateConnectorAuthorityAssignmentRaw(object["assignment"]); err != nil {
			return err
		}
		var result ConnectorAuthorityIssueAssignmentResult
		if err := strictDecodeArtifact(raw, &result); err != nil {
			return err
		}
		if !connectorAuthorityAgentIDPattern.MatchString(result.AgentID) || !isCanonicalAgentAPIKeyID(result.Registration.KeyID) ||
			!isConnectorAuthorityRegistrationKind(result.Registration.KeyKind) || !validConnectorAuthorityASCII(result.AssignmentTicket, 1, ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes) ||
			validateConnectorAuthorityTimestamp(result.AssignmentTicketExpiresAt) != nil {
			return errors.New("invalid IssueAssignment result semantics")
		}
		if err := validateConnectorAuthorityAssignment(result.Assignment); err != nil {
			return err
		}
		ticketExpiry, _ := parseConnectorAuthorityTimestamp(result.AssignmentTicketExpiresAt)
		leaseExpiry, _ := parseConnectorAuthorityTimestamp(result.Assignment.LeaseExpiresAt)
		if !ticketExpiry.Before(leaseExpiry) {
			return errors.New("assignment ticket expiry must precede lease expiry")
		}
		return nil
	case ConnectorAuthorityOperationRefreshAssignment:
		object, err := validateConnectorAuthorityExactObject(raw, []string{"agent_id", "assignment"}, []string{"agent_id", "assignment"})
		if err != nil {
			return err
		}
		if err := validateConnectorAuthorityAssignmentRaw(object["assignment"]); err != nil {
			return err
		}
		var result ConnectorAuthorityRefreshAssignmentResult
		if err := strictDecodeArtifact(raw, &result); err != nil {
			return err
		}
		if !connectorAuthorityAgentIDPattern.MatchString(result.AgentID) {
			return errors.New("invalid RefreshAssignment agent_id")
		}
		return validateConnectorAuthorityAssignment(result.Assignment)
	case ConnectorAuthorityOperationIssueRegistrationOTP, ConnectorAuthorityOperationActivateRegistration:
		if _, err := validateConnectorAuthorityExactObject(raw, nil, nil); err != nil {
			return err
		}
		return nil
	case ConnectorAuthorityOperationCompleteRegistration:
		if _, err := validateConnectorAuthorityExactObject(raw, []string{"device_api_key_id"}, []string{"device_api_key_id"}); err != nil {
			return err
		}
		var result ConnectorAuthorityCompleteRegistrationResult
		if err := strictDecodeArtifact(raw, &result); err != nil {
			return err
		}
		if !isCanonicalAgentAPIKeyID(result.DeviceAPIKeyID) {
			return errors.New("invalid CompleteRegistration device_api_key_id")
		}
		return nil
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
}

func validateConnectorAuthorityAssignmentRaw(raw []byte) error {
	object, err := validateConnectorAuthorityExactObject(raw,
		[]string{"cell_id", "assignment_generation", "endpoint_revision", "lease_expires_at", "nhp_udp_endpoint"},
		[]string{"cell_id", "assignment_generation", "endpoint_revision", "lease_expires_at", "nhp_udp_endpoint"})
	if err != nil {
		return fmt.Errorf("assignment: %w", err)
	}
	if _, err := validateConnectorAuthorityExactObject(object["nhp_udp_endpoint"],
		[]string{"host", "port", "server_public_key_b64"},
		[]string{"host", "port", "server_public_key_b64"}); err != nil {
		return fmt.Errorf("assignment endpoint: %w", err)
	}
	return nil
}

func validateConnectorAuthorityAssignment(a ConnectorAuthorityAssignmentResult) error {
	if !connectorAuthorityCellIDPattern.MatchString(a.CellID) || a.AssignmentGeneration < 1 || a.EndpointRevision < 1 || validateConnectorAuthorityTimestamp(a.LeaseExpiresAt) != nil ||
		!validConnectorAuthorityHost(a.NHPUDPEndpoint.Host) || a.NHPUDPEndpoint.Port < 1 || a.NHPUDPEndpoint.Port > 65535 ||
		validateConnectorAuthorityX25519ServerKey(a.NHPUDPEndpoint.ServerPublicKeyB64) != nil {
		return errors.New("invalid assignment result semantics")
	}
	return nil
}

func validateConnectorAuthorityGoldenRequest(operation, body string, f ConnectorAuthorityLambdaFixtures) error {
	want, err := connectorAuthorityGoldenRequest(operation, f)
	if err != nil {
		return err
	}
	if body != want {
		return fmt.Errorf("conformance: Connector Authority %s request golden does not match fixtures", operation)
	}
	return nil
}

func validateConnectorAuthorityGoldenSuccess(operation, body string, f ConnectorAuthorityLambdaFixtures) error {
	want, err := connectorAuthorityGoldenSuccess(operation, f)
	if err != nil {
		return err
	}
	if body != want {
		return fmt.Errorf("conformance: Connector Authority %s success golden does not match fixtures", operation)
	}
	return nil
}

func connectorAuthorityGoldenRequest(operation string, f ConnectorAuthorityLambdaFixtures) (string, error) {
	var value any
	switch operation {
	case ConnectorAuthorityOperationIssueAssignment:
		value = ConnectorAuthorityIssueAssignmentRequest{
			Version: 1, HubRequestID: f.HubRequestID, AgentID: f.AgentID,
			AuthenticatedPeerPublicKeyB64: f.AuthenticatedPeerPublicKeyB64, Credential: f.Credential,
		}
	case ConnectorAuthorityOperationRefreshAssignment:
		value = ConnectorAuthorityRefreshAssignmentRequest{
			Version: 1, HubRequestID: f.HubRequestID, AgentID: f.AgentID, AuthenticatedPeerPublicKeyB64: f.AuthenticatedPeerPublicKeyB64,
		}
	case ConnectorAuthorityOperationIssueRegistrationOTP:
		value = ConnectorAuthorityIssueRegistrationOTPRequest{
			Version: 1, AssignmentTicket: f.AssignmentTicket, CredentialKeyID: f.CredentialKeyID, CredentialSecret: f.Credential,
			AuthenticatedPeerPublicKeyB64: f.AuthenticatedPeerPublicKeyB64, AgentID: f.AgentID, ObservedSourceAddress: f.ObservedSourceAddress,
		}
	case ConnectorAuthorityOperationActivateRegistration:
		value = ConnectorAuthorityActivateRegistrationRequest{
			Version: 1, AssignmentTicket: f.AssignmentTicket, CredentialKeyID: f.CredentialKeyID, RegistrationCredential: f.RegistrationCredential,
			AuthenticatedPeerPublicKeyB64: f.AuthenticatedPeerPublicKeyB64, AgentID: f.AgentID, Hostname: f.Hostname, AgentVersion: f.AgentVersion,
		}
	case ConnectorAuthorityOperationCompleteRegistration:
		value = ConnectorAuthorityCompleteRegistrationRequest{
			Version: 1, AuthenticatedPeerPublicKeyB64: f.AuthenticatedPeerPublicKeyB64, AgentID: f.AgentID, DeviceAPIKey: f.DeviceAPIKey,
		}
	default:
		return "", fmt.Errorf("unknown operation %q", operation)
	}
	encoded, err := json.Marshal(value)
	return string(encoded), err
}

func connectorAuthorityAssignmentFromFixtures(f ConnectorAuthorityLambdaFixtures) ConnectorAuthorityAssignmentResult {
	return ConnectorAuthorityAssignmentResult{
		CellID: f.CellID, AssignmentGeneration: f.AssignmentGeneration, EndpointRevision: f.EndpointRevision,
		LeaseExpiresAt: f.LeaseExpiresAt,
		NHPUDPEndpoint: ConnectorAuthorityNHPUDPEndpoint{
			Host: f.NHPHost, Port: f.NHPPort, ServerPublicKeyB64: f.ServerPublicKeyB64,
		},
	}
}

func connectorAuthorityGoldenSuccess(operation string, f ConnectorAuthorityLambdaFixtures) (string, error) {
	assignment := connectorAuthorityAssignmentFromFixtures(f)
	var result any
	switch operation {
	case ConnectorAuthorityOperationIssueAssignment:
		result = ConnectorAuthorityIssueAssignmentResult{
			AgentID: f.AgentID,
			Registration: ConnectorAuthorityRegistrationResult{
				KeyID: f.CredentialKeyID, KeyKind: f.RegistrationKeyKind,
			},
			Assignment:       assignment,
			AssignmentTicket: f.AssignmentTicket, AssignmentTicketExpiresAt: f.AssignmentTicketExpiresAt,
		}
	case ConnectorAuthorityOperationRefreshAssignment:
		result = ConnectorAuthorityRefreshAssignmentResult{AgentID: f.AgentID, Assignment: assignment}
	case ConnectorAuthorityOperationIssueRegistrationOTP, ConnectorAuthorityOperationActivateRegistration:
		result = struct{}{}
	case ConnectorAuthorityOperationCompleteRegistration:
		result = ConnectorAuthorityCompleteRegistrationResult{DeviceAPIKeyID: f.DeviceAPIKeyID}
	default:
		return "", fmt.Errorf("unknown operation %q", operation)
	}
	return marshalConnectorAuthorityResponse(result, nil)
}

func marshalConnectorAuthorityResponse(result any, responseError *connectorAuthorityError) (string, error) {
	envelope := struct {
		Version int                      `json:"version"`
		Result  any                      `json:"result,omitempty"`
		Error   *connectorAuthorityError `json:"error,omitempty"`
	}{Version: 1, Result: result, Error: responseError}
	encoded, err := json.Marshal(envelope)
	return string(encoded), err
}

func connectorAuthoritySemanticCodes(operation string) []string {
	switch operation {
	case ConnectorAuthorityOperationIssueAssignment:
		return []string{"invalid_request", "credential_invalid", "credential_consumed", "unavailable"}
	case ConnectorAuthorityOperationRefreshAssignment:
		return []string{"invalid_request", "identity_rejected", "reassignment_in_progress", "unavailable"}
	case ConnectorAuthorityOperationIssueRegistrationOTP:
		return []string{"invalid_request", "rejected", "email_unavailable", "rate_limited", "send_failed", "unavailable"}
	case ConnectorAuthorityOperationActivateRegistration:
		return []string{"invalid_request", "credential_rejected", "ticket_invalid", "not_yet_valid", "ticket_expired", "identity_conflict", "quota", "reenrollment_required", "unavailable"}
	case ConnectorAuthorityOperationCompleteRegistration:
		return []string{"invalid_request", "identity_rejected", "quota", "conflict", "unavailable"}
	default:
		return nil
	}
}

func connectorAuthorityErrorAllowed(operation, code string) bool {
	return slices.Contains(connectorAuthoritySemanticCodes(operation), code)
}

// connectorAuthorityRequiresRetryAfter reports whether an error body must carry
// a positive retry_after_seconds. It is required for exactly this operation/code
// pair and forbidden for every other error, so all validators derive the rule
// from here rather than repeating the literal pair.
func connectorAuthorityRequiresRetryAfter(operation, code string) bool {
	return operation == ConnectorAuthorityOperationIssueRegistrationOTP && code == "rate_limited"
}

func validateConnectorAuthoritySemanticErrors(operation string, cases []ConnectorAuthorityLambdaErrorCase) error {
	wantCodes := connectorAuthoritySemanticCodes(operation)
	if len(cases) != len(wantCodes) {
		return fmt.Errorf("conformance: Connector Authority %s semantic error count = %d, want %d", operation, len(cases), len(wantCodes))
	}
	for index, code := range wantCodes {
		c := cases[index]
		if c.Code != code {
			return fmt.Errorf("conformance: Connector Authority %s semantic error %d = %q, want %q", operation, index, c.Code, code)
		}
		var retryAfter *int64
		if connectorAuthorityRequiresRetryAfter(operation, code) {
			value := int64(60)
			retryAfter = &value
		}
		wantBody, err := marshalConnectorAuthorityResponse(nil, &connectorAuthorityError{Code: code, RetryAfterSeconds: retryAfter})
		if err != nil || c.BodyJSON != wantBody {
			return fmt.Errorf("conformance: Connector Authority %s semantic error %q body is not canonical", operation, code)
		}
		outcome, err := validateConnectorAuthorityResponse(operation, []byte(c.BodyJSON))
		if err != nil || outcome != code {
			return fmt.Errorf("conformance: Connector Authority %s semantic error %q is invalid: %v", operation, code, err)
		}
	}
	return nil
}

var connectorAuthorityRequestRejectClasses = map[string]string{
	"reject_duplicate_field":    "duplicate_key",
	"reject_case_alias":         "case_alias",
	"reject_unknown_field":      "unknown_field",
	"reject_null_field":         "null_field",
	"reject_wrong_type":         "wrong_type",
	"reject_missing_field":      "missing_field",
	"reject_trailing_data":      "trailing_data",
	"reject_nonlexical_version": "version_encoding",
	"reject_non_object":         "non_object",
	"reject_oversize":           "oversize",
}

var connectorAuthorityResponseRejectClasses = func() map[string]string {
	classes := maps.Clone(connectorAuthorityRequestRejectClasses)
	classes["reject_both_result_and_error"] = "response_xor"
	classes["reject_neither_result_nor_error"] = "response_xor"
	classes["reject_unknown_error_code"] = "unknown_error_code"
	classes["reject_retry_after_policy"] = "retry_after_policy"
	classes["reject_invalid_result"] = "invalid_result"
	return classes
}()

func validateConnectorAuthorityRejects(operation, kind string, cases []ConnectorAuthorityLambdaRejectCase) error {
	expected := connectorAuthorityRequestRejectClasses
	limit := ConnectorAuthorityLambdaMaxRequestBytes
	if kind == "response" {
		expected = connectorAuthorityResponseRejectClasses
		limit = ConnectorAuthorityLambdaMaxResponseBytes
	}
	if len(cases) != len(expected) {
		return fmt.Errorf("conformance: Connector Authority %s %s reject count = %d, want %d", operation, kind, len(cases), len(expected))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		wantClass, ok := expected[c.Name]
		if !ok {
			return fmt.Errorf("conformance: Connector Authority %s has unknown %s reject %q", operation, kind, c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: Connector Authority %s has duplicate %s reject %q", operation, kind, c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.Outcome != ExpectReject || c.RejectClass != wantClass {
			return fmt.Errorf("conformance: Connector Authority %s %s reject %q expectation drifted", operation, kind, c.Name)
		}
		var data []byte
		if c.Name == "reject_oversize" {
			fill, err := hex.DecodeString(c.BodyFillByteHex)
			if err != nil || len(fill) != 1 || c.DerivedBodyBytes != limit+1 || c.BodyJSON != "" {
				return fmt.Errorf("conformance: Connector Authority %s %s oversize recipe is invalid", operation, kind)
			}
			data = bytes.Repeat(fill, c.DerivedBodyBytes)
		} else {
			if c.BodyFillByteHex != "" || c.DerivedBodyBytes != 0 || c.BodyJSON == "" || len(c.BodyJSON) > limit {
				return fmt.Errorf("conformance: Connector Authority %s %s reject %q body recipe is invalid", operation, kind, c.Name)
			}
			data = []byte(c.BodyJSON)
		}
		var (
			gotClass  string
			acceptErr error
		)
		if kind == "request" {
			gotClass = classifyConnectorAuthorityRequestReject(operation, data)
			acceptErr = validateConnectorAuthorityRequest(operation, data)
		} else {
			gotClass = classifyConnectorAuthorityResponseReject(operation, data)
			_, acceptErr = validateConnectorAuthorityResponse(operation, data)
		}
		if gotClass != c.RejectClass {
			return fmt.Errorf("conformance: Connector Authority %s %s reject %q class = %q, want %q", operation, kind, c.Name, gotClass, c.RejectClass)
		}
		if acceptErr == nil {
			return fmt.Errorf("conformance: Connector Authority %s %s reject %q is accepted by the typed validator", operation, kind, c.Name)
		}
	}
	return nil
}

func classifyConnectorAuthorityRequestReject(operation string, data []byte) string {
	if len(data) > ConnectorAuthorityLambdaMaxRequestBytes {
		return "oversize"
	}
	object, class := connectorAuthorityRawObject(data)
	if class != "" {
		return class
	}
	required, err := connectorAuthorityRequestMembers(operation)
	if err != nil {
		return ""
	}
	if class := classifyConnectorAuthorityObjectFields(object, required, required); class != "" {
		return class
	}
	if class := classifyConnectorAuthorityVersionLexeme(object["version"]); class != "" {
		return class
	}
	// Every non-version member in the closed v1 request set is a JSON string.
	// Adding another wire type requires extending this classifier and its fixtures.
	for _, name := range required[1:] {
		if len(object[name]) == 0 || object[name][0] != '"' {
			return "wrong_type"
		}
	}
	return ""
}

func classifyConnectorAuthorityResponseReject(operation string, data []byte) string {
	if len(data) > ConnectorAuthorityLambdaMaxResponseBytes {
		return "oversize"
	}
	object, class := connectorAuthorityRawObject(data)
	if class != "" {
		return class
	}
	if class := classifyConnectorAuthorityObjectFields(object, []string{"version"}, []string{"version", "result", "error"}); class != "" {
		return class
	}
	if class := classifyConnectorAuthorityVersionLexeme(object["version"]); class != "" {
		return class
	}
	result, hasResult := object["result"]
	responseError, hasError := object["error"]
	if hasResult == hasError {
		return "response_xor"
	}
	if (hasResult && string(result) == "null") || (hasError && string(responseError) == "null") {
		return "null_field"
	}
	if hasResult {
		if err := validateConnectorAuthorityResult(operation, result); err != nil {
			return "invalid_result"
		}
		return ""
	}
	errorObject, class := connectorAuthorityRawObject(responseError)
	if class != "" {
		return "wrong_type"
	}
	if class := classifyConnectorAuthorityObjectFields(errorObject, []string{"code"}, []string{"code", "retry_after_seconds"}); class != "" {
		return class
	}
	if len(errorObject["code"]) == 0 || errorObject["code"][0] != '"' {
		return "wrong_type"
	}
	var code string
	if err := json.Unmarshal(errorObject["code"], &code); err != nil {
		return "wrong_type"
	}
	if !connectorAuthorityErrorAllowed(operation, code) {
		return "unknown_error_code"
	}
	if retry, ok := errorObject["retry_after_seconds"]; ok {
		if string(retry) == "null" {
			return "null_field"
		}
		var seconds int64
		if err := json.Unmarshal(retry, &seconds); err != nil || !connectorAuthorityRequiresRetryAfter(operation, code) || seconds < 1 {
			return "retry_after_policy"
		}
	} else if connectorAuthorityRequiresRetryAfter(operation, code) {
		return "retry_after_policy"
	}
	return ""
}

// classifyConnectorAuthorityVersionLexeme reports the reject class for a
// version member that is absent or not the exact JSON integer lexeme 1.
func classifyConnectorAuthorityVersionLexeme(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "missing_field"
	}
	if string(raw) != "1" {
		if raw[0] >= '0' && raw[0] <= '9' {
			return "version_encoding"
		}
		return "wrong_type"
	}
	return ""
}

func connectorAuthorityRawObject(data []byte) (map[string]json.RawMessage, string) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		// malformed_json is an internal sentinel, not a committed reject class.
		// It prevents malformed bodies from aliasing onto missing_field.
		return nil, "malformed_json"
	}
	if requireJSONEOF(decoder) != nil {
		return nil, "trailing_data"
	}
	if rejectDuplicateJSONKeys(raw) != nil {
		return nil, "duplicate_key"
	}
	if len(raw) == 0 || raw[0] != '{' {
		return nil, "non_object"
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, "non_object"
	}
	return object, ""
}

func classifyConnectorAuthorityObjectFields(object map[string]json.RawMessage, required, allowed []string) string {
	// Reject fixtures must isolate one anomaly. Map iteration intentionally does
	// not define precedence between multiple unknown/aliased keys, so combining
	// defects would make a claimed reject class ambiguous.
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for name := range object {
		if _, ok := allowedSet[name]; ok {
			continue
		}
		for allowedName := range allowedSet {
			if strings.EqualFold(name, allowedName) {
				return "case_alias"
			}
		}
		return "unknown_field"
	}
	for _, name := range required {
		raw, ok := object[name]
		if !ok {
			return "missing_field"
		}
		if string(raw) == "null" {
			return "null_field"
		}
	}
	return ""
}

// connectorAuthorityPreInvokeMappings lists the NHP pre-invoke gate names for
// an operation. These public dispositions are produced before the authority is
// called, so they have no private outcome or response body.
func connectorAuthorityPreInvokeMappings(operation string) []string {
	switch operation {
	case ConnectorAuthorityOperationIssueAssignment:
		return []string{"registration_disabled", "assignment_rate_limited"}
	case ConnectorAuthorityOperationRefreshAssignment:
		return []string{"assignment_rate_limited"}
	default:
		return nil
	}
}

func validateConnectorAuthorityMappings(operation string, op ConnectorAuthorityLambdaOperation, f ConnectorAuthorityLambdaFixtures) error {
	preInvoke := connectorAuthorityPreInvokeMappings(operation)
	wantCount := 1 + len(op.SemanticErrors) + len(preInvoke)
	if len(op.PublicMappingCases) != wantCount {
		return fmt.Errorf("conformance: Connector Authority %s mapping count = %d, want %d", operation, len(op.PublicMappingCases), wantCount)
	}
	privateBodies := map[string]string{"success": op.SuccessGolden.BodyJSON}
	for _, semantic := range op.SemanticErrors {
		privateBodies[semantic.Code] = semantic.BodyJSON
	}
	secrets := []struct {
		name  string
		value string
	}{
		{name: "initial credential", value: f.Credential},
		{name: "registration credential", value: f.RegistrationCredential},
		{name: "device API key", value: f.DeviceAPIKey},
	}
	seen := make(map[string]struct{}, len(op.PublicMappingCases))
	for _, mapping := range op.PublicMappingCases {
		if _, duplicate := seen[mapping.Name]; duplicate {
			return fmt.Errorf("conformance: Connector Authority %s duplicate mapping %q", operation, mapping.Name)
		}
		seen[mapping.Name] = struct{}{}
		for _, secret := range secrets {
			if strings.Contains(mapping.NHPBodyJSON, secret.value) {
				return fmt.Errorf("conformance: Connector Authority %s mapping %q exposes the %s", operation, mapping.Name, secret.name)
			}
		}
		if mapping.MappingSource == ConnectorAuthorityMappingSourcePreInvoke {
			if !slices.Contains(preInvoke, mapping.Name) || mapping.PrivateOutcome != "" || mapping.PrivateResponseBodyJSON != "" {
				return fmt.Errorf("conformance: Connector Authority %s invalid pre-invoke mapping %q", operation, mapping.Name)
			}
		} else if mapping.MappingSource == ConnectorAuthorityMappingSourceResponse {
			body, ok := privateBodies[mapping.PrivateOutcome]
			if !ok || mapping.Name != mapping.PrivateOutcome || mapping.PrivateResponseBodyJSON != body {
				return fmt.Errorf("conformance: Connector Authority %s invalid authority mapping %q", operation, mapping.Name)
			}
		} else {
			return fmt.Errorf("conformance: Connector Authority %s mapping %q has unknown source", operation, mapping.Name)
		}
		wantAction, wantBody, wantRecovery, err := connectorAuthorityExpectedPublicMapping(operation, mapping.Name, f)
		if err != nil {
			return err
		}
		if mapping.NHPAction != wantAction || mapping.NHPBodyJSON != wantBody || mapping.RecoveryAction != wantRecovery {
			return fmt.Errorf("conformance: Connector Authority %s mapping %q public disposition drifted", operation, mapping.Name)
		}
	}
	for outcome := range privateBodies {
		if _, ok := seen[outcome]; !ok {
			return fmt.Errorf("conformance: Connector Authority %s mapping for %q is missing", operation, outcome)
		}
	}
	for _, name := range preInvoke {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("conformance: Connector Authority %s pre-invoke mapping %q is missing", operation, name)
		}
	}
	return nil
}

func connectorAuthorityExpectedPublicMapping(operation, outcome string, f ConnectorAuthorityLambdaFixtures) (action, body, recovery string, err error) {
	recovery = ConnectorAuthorityRecoveryNone
	switch operation {
	case ConnectorAuthorityOperationIssueAssignment:
		action = ConnectorAuthorityNHPActionEmitLRT
		switch outcome {
		case "success":
			body, err = connectorAuthorityPublicAssignmentSuccess("enroll", f)
		case "invalid_request":
			body = `{"errCode":"52109","errMsg":"invalid enrollment input"}`
		case "credential_invalid":
			body = `{"errCode":"52106","errMsg":"API key invalid"}`
		case "credential_consumed":
			body = `{"errCode":"52108","errMsg":"bootstrap key already consumed"}`
		case "unavailable":
			body = `{"errCode":"52200","errMsg":"assignment temporarily unavailable"}`
		case "registration_disabled":
			body = `{"errCode":"52107","errMsg":"registration disabled"}`
		case "assignment_rate_limited":
			body = `{"errCode":"52204","errMsg":"assignment rate limited","retryAfterSeconds":60}`
		default:
			err = fmt.Errorf("conformance: unknown IssueAssignment mapping %q", outcome)
		}
	case ConnectorAuthorityOperationRefreshAssignment:
		action = ConnectorAuthorityNHPActionEmitLRT
		switch outcome {
		case "success":
			body, err = connectorAuthorityPublicAssignmentSuccess("refresh", f)
		case "invalid_request":
			body = `{"errCode":"52205","errMsg":"invalid assignment request"}`
		case "identity_rejected":
			body = `{"errCode":"52201","errMsg":"assignment identity rejected"}`
		case "reassignment_in_progress":
			body = `{"errCode":"52202","errMsg":"reassignment in progress"}`
		case "unavailable":
			body = `{"errCode":"52200","errMsg":"assignment temporarily unavailable"}`
		case "assignment_rate_limited":
			body = `{"errCode":"52204","errMsg":"assignment rate limited","retryAfterSeconds":60}`
		default:
			err = fmt.Errorf("conformance: unknown RefreshAssignment mapping %q", outcome)
		}
	case ConnectorAuthorityOperationIssueRegistrationOTP:
		action = ConnectorAuthorityNHPActionNoReply
		if outcome != "success" && !connectorAuthorityErrorAllowed(operation, outcome) {
			err = fmt.Errorf("conformance: unknown IssueRegistrationOTP mapping %q", outcome)
		}
	case ConnectorAuthorityOperationActivateRegistration:
		action = ConnectorAuthorityNHPActionEmitRAK
		switch outcome {
		case "success":
			body = `{"errCode":"0","aspId":"agent"}`
		case "invalid_request":
			body = `{"errCode":"52109","errMsg":"invalid enrollment input","aspId":"agent"}`
		case "credential_rejected":
			body = `{"errCode":"52100","errMsg":"registration credential invalid","aspId":"agent"}`
		case "ticket_invalid", "not_yet_valid":
			body = `{"errCode":"52110","errMsg":"assignment ticket invalid","aspId":"agent"}`
		case "ticket_expired":
			body = `{"errCode":"52111","errMsg":"assignment ticket expired","aspId":"agent"}`
		case "identity_conflict":
			body = `{"errCode":"52103","errMsg":"device identity already enrolled elsewhere","aspId":"agent"}`
		case "quota":
			body = `{"errCode":"52112","errMsg":"agent registration quota exceeded","aspId":"agent"}`
		case "reenrollment_required":
			body = `{"errCode":"52101","errMsg":"registration credential expired","aspId":"agent"}`
		case "unavailable":
			action, recovery = ConnectorAuthorityNHPActionDropNoReply, ConnectorAuthorityRecoveryPendingExact
		default:
			err = fmt.Errorf("conformance: unknown ActivateRegistration mapping %q", outcome)
		}
	case ConnectorAuthorityOperationCompleteRegistration:
		action = ConnectorAuthorityNHPActionEmitLRT
		switch outcome {
		case "success":
			body, err = connectorAuthorityPublicCompletionSuccess(f)
		case "invalid_request":
			body = `{"errCode":"52304","errMsg":"invalid completion request"}`
		case "identity_rejected":
			body = `{"errCode":"52301","errMsg":"completion identity rejected"}`
		case "quota":
			body = `{"errCode":"52302","errMsg":"device credential quota exceeded"}`
		case "conflict":
			body = `{"errCode":"52303","errMsg":"different device credential candidate already recorded"}`
		case "unavailable":
			body = `{"errCode":"52300","errMsg":"completion temporarily unavailable","retryAfterSeconds":5}`
		default:
			err = fmt.Errorf("conformance: unknown CompleteRegistration mapping %q", outcome)
		}
	default:
		err = fmt.Errorf("conformance: unknown operation %q", operation)
	}
	return action, body, recovery, err
}

type connectorAuthorityPublicEnrollList struct {
	Query                     string                               `json:"query"`
	Version                   int                                  `json:"version"`
	Mode                      string                               `json:"mode"`
	AgentID                   string                               `json:"agent_id"`
	Registration              ConnectorAuthorityRegistrationResult `json:"registration"`
	Assignment                ConnectorAuthorityAssignmentResult   `json:"assignment"`
	AssignmentTicket          string                               `json:"assignment_ticket"`
	AssignmentTicketExpiresAt string                               `json:"assignment_ticket_expires_at"`
}

type connectorAuthorityPublicRefreshList struct {
	Query      string                             `json:"query"`
	Version    int                                `json:"version"`
	Mode       string                             `json:"mode"`
	AgentID    string                             `json:"agent_id"`
	Assignment ConnectorAuthorityAssignmentResult `json:"assignment"`
}

func connectorAuthorityPublicAssignmentSuccess(mode string, f ConnectorAuthorityLambdaFixtures) (string, error) {
	assignment := connectorAuthorityAssignmentFromFixtures(f)
	var publicBody any
	switch mode {
	case "enroll":
		publicBody = struct {
			ErrCode string                             `json:"errCode"`
			List    connectorAuthorityPublicEnrollList `json:"list"`
		}{
			ErrCode: "0",
			List: connectorAuthorityPublicEnrollList{
				Query: "cell_assignment", Version: 1, Mode: "enroll", AgentID: f.AgentID,
				Registration: ConnectorAuthorityRegistrationResult{KeyID: f.CredentialKeyID, KeyKind: f.RegistrationKeyKind},
				Assignment:   assignment, AssignmentTicket: f.AssignmentTicket, AssignmentTicketExpiresAt: f.AssignmentTicketExpiresAt,
			},
		}
	case "refresh":
		publicBody = struct {
			ErrCode string                              `json:"errCode"`
			List    connectorAuthorityPublicRefreshList `json:"list"`
		}{
			ErrCode: "0",
			List:    connectorAuthorityPublicRefreshList{Query: "cell_assignment", Version: 1, Mode: "refresh", AgentID: f.AgentID, Assignment: assignment},
		}
	default:
		return "", fmt.Errorf("unknown assignment mode %q", mode)
	}
	encoded, err := json.Marshal(publicBody)
	return string(encoded), err
}

func connectorAuthorityPublicCompletionSuccess(f ConnectorAuthorityLambdaFixtures) (string, error) {
	value := struct {
		ErrCode string `json:"errCode"`
		List    struct {
			Query          string `json:"query"`
			Version        int    `json:"version"`
			DeviceAPIKeyID string `json:"device_api_key_id"`
		} `json:"list"`
	}{ErrCode: "0"}
	value.List.Query = "agent_registration_completion"
	value.List.Version = 1
	value.List.DeviceAPIKeyID = f.DeviceAPIKeyID
	encoded, err := json.Marshal(value)
	return string(encoded), err
}

func requireConnectorAuthorityVersionLexeme(data []byte) error {
	if rejectDuplicateJSONKeys(data) != nil {
		return errors.New("duplicate JSON key")
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&object); err != nil || object == nil {
		return errors.New("body must be one JSON object")
	}
	if requireJSONEOF(decoder) != nil {
		return errors.New("trailing JSON value")
	}
	raw, ok := object["version"]
	if !ok || string(raw) != "1" {
		return errors.New("version must use the exact JSON integer lexeme 1")
	}
	return nil
}

func validateConnectorAuthorityExactObject(data []byte, required, allowed []string) (map[string]json.RawMessage, error) {
	object, class := connectorAuthorityRawObject(data)
	if class != "" {
		return nil, fmt.Errorf("invalid JSON object: %s", class)
	}
	if class := classifyConnectorAuthorityObjectFields(object, required, allowed); class != "" {
		return nil, fmt.Errorf("invalid JSON object fields: %s", class)
	}
	return object, nil
}

func validateConnectorAuthorityX25519KeyEncoding(value string) error {
	_, err := decodeConnectorAuthorityX25519Key(value)
	return err
}

func decodeConnectorAuthorityX25519Key(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("key is not canonical padded standard-base64 X25519")
	}
	return decoded, nil
}

func validateConnectorAuthorityX25519ServerKey(value string) error {
	decoded, err := decodeConnectorAuthorityX25519Key(value)
	if err != nil {
		return err
	}
	if !isCanonicalConnectorAuthorityX25519U(decoded) {
		return errors.New("key does not contain a canonical X25519 u-coordinate")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(decoded)
	if err != nil {
		return errors.New("key is not usable X25519")
	}
	privateBytes := make([]byte, 32)
	privateBytes[0] = 9
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return errors.New("internal X25519 validation setup failed")
	}
	if _, err := privateKey.ECDH(publicKey); err != nil {
		return errors.New("key is low-order X25519")
	}
	return nil
}

func isCanonicalConnectorAuthorityX25519U(raw []byte) bool {
	if len(raw) != 32 {
		return false
	}
	if raw[31] != 0x7f {
		return raw[31] < 0x7f
	}
	for index := 30; index >= 1; index-- {
		if raw[index] != 0xff {
			return true
		}
	}
	return raw[0] < 0xed
}

func isConnectorAuthorityAPIKey(value string) bool {
	if len(value) != 51 || (!strings.HasPrefix(value, "lv_live_") && !strings.HasPrefix(value, "lv_test_")) {
		return false
	}
	encoded := value[8:]
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == encoded
}

func validConnectorAuthorityASCII(value string, minBytes, maxBytes int) bool {
	if len(value) < minBytes || len(value) > maxBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validConnectorAuthorityMetadata(value string, maxRunes int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxRunes {
		return false
	}
	for _, character := range value {
		if !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}

func isCanonicalConnectorAuthorityAddress(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.String() == value && addr.Zone() == ""
}

func validConnectorAuthorityHost(value string) bool {
	if value == "" || len(value) > 253 || value != strings.TrimSpace(value) || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) > 63 || !connectorAuthorityDNSLabelPattern.MatchString(label) {
			return false
		}
	}
	switch labels[0] {
	case "internal", "localhost", "metadata", "private":
		return false
	}
	return strings.HasSuffix(value, ".layerv.ai") || strings.HasSuffix(value, ".layerv.xyz")
}

func parseConnectorAuthorityTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || strings.Contains(value, ".") || parsed.Format(time.RFC3339) != value {
		return time.Time{}, errors.New("timestamp is not canonical whole-second UTC RFC3339")
	}
	return parsed, nil
}

func validateConnectorAuthorityTimestamp(value string) error {
	_, err := parseConnectorAuthorityTimestamp(value)
	return err
}

func isConnectorAuthorityRegistrationKind(value string) bool {
	switch value {
	case "bootstrap", "connector_bootstrap", "account", "agent":
		return true
	default:
		return false
	}
}
