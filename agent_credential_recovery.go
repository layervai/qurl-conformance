package conformance

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	AgentCredentialRecoveryArtifactID           = "qurl-agent-credential-recovery-v1-vectors"
	AgentCredentialRecoveryHubCookieProfile     = AgentCredentialRecoveryArtifactID + "/hub_cookie_composition"
	AgentCredentialRecoverySchemaVersion        = 1
	AgentCredentialRecoveryRequestHeader        = "NHP_LST"
	AgentCredentialRecoveryRequestType          = 5
	AgentCredentialRecoveryResultHeader         = "NHP_LRT"
	AgentCredentialRecoveryResultType           = 6
	AgentCredentialRecoveryGrantPrefix          = "qrg1."
	AgentCredentialRecoveryMaxGrantBytes        = 2304
	AgentCredentialRecoveryGrantLifetimeSeconds = 900
	AgentCredentialRecoveryHorizonSeconds       = 90 * 24 * 60 * 60
	AgentCredentialRecoveryPacketOverheadBytes  = ConnectorHubLSTCookiePacketOverhead
	AgentCredentialRecoveryMaxBodyBytes         = 3840
	AgentCredentialRecoveryMaxPacketBytes       = 4096

	AgentCredentialRecoveryHubPhase  = "hub_issue_recovery"
	AgentCredentialRecoveryCellPhase = "assigned_cell_complete_recovery"
)

var (
	agentCredentialRecoveryGrantPattern       = regexp.MustCompile("^" + regexp.QuoteMeta(AgentCredentialRecoveryGrantPrefix) + "[A-Za-z0-9_-]+$")
	agentCredentialRecoveryCellIDPattern      = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	agentCredentialRecoveryDNSLabelPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	agentCredentialRecoveryAPIKeyPrefixes     = []string{"lv_live_", "lv_test_"}
	agentCredentialRecoveryLayerVHostSuffixes = []string{".layerv.ai", ".layerv.xyz"}
)

// AgentCredentialRecoveryFile freezes the public UDP Hub and assigned-cell
// bodies, grant-binding and flow mutations, and the closed result taxonomy for
// explicit same-agent device-credential recovery. It carries only what an SDK
// sends, receives, or must enforce; the platform's internal invocation bodies
// and replay-key derivation are not part of this public contract.
type AgentCredentialRecoveryFile struct {
	Artifact          string                                      `json:"artifact"`
	SchemaVersion     int                                         `json:"schema_version"`
	Description       string                                      `json:"description"`
	Protocol          AgentCredentialRecoveryProtocol             `json:"protocol"`
	Fixtures          AgentCredentialRecoveryFixtures             `json:"fixtures"`
	HubCookie         AgentCredentialRecoveryHubCookieComposition `json:"hub_cookie_composition"`
	PublicExchanges   map[string]AgentCredentialRecoveryExchange  `json:"public_exchanges"`
	RequestRejects    []AgentCredentialRecoveryBodyCase           `json:"request_rejects"`
	ResultRejects     []AgentCredentialRecoveryBodyCase           `json:"result_rejects"`
	ErrorCases        []AgentCredentialRecoveryErrorCase          `json:"error_cases"`
	IssueReplayCases  []AgentCredentialRecoveryBindingCase        `json:"issue_replay_cases"`
	GrantBindingCases []AgentCredentialRecoveryBindingCase        `json:"grant_binding_cases"`
	FlowCases         []AgentCredentialRecoveryBindingCase        `json:"flow_cases"`
}

type AgentCredentialRecoveryProtocol struct {
	Transport                                string   `json:"transport"`
	RequestHeaderName                        string   `json:"request_header_name"`
	RequestHeaderType                        int      `json:"request_header_type"`
	ResultHeaderName                         string   `json:"result_header_name"`
	ResultHeaderType                         int      `json:"result_header_type"`
	ResultCounterRule                        string   `json:"result_counter_rule"`
	HubQuery                                 string   `json:"hub_query"`
	HubMode                                  string   `json:"hub_mode"`
	CellQuery                                string   `json:"cell_query"`
	AuthenticatedIdentityProof               string   `json:"authenticated_identity_proof"`
	TakeoverPolicy                           string   `json:"takeover_policy"`
	RecoveryCredentialKind                   string   `json:"recovery_credential_kind"`
	RecoveryCredentialScope                  string   `json:"recovery_credential_scope"`
	MalformedRecoveryCredentialOutcome       string   `json:"malformed_recovery_credential_outcome"`
	CanonicalRecoveryCredentialRejectOutcome string   `json:"canonical_recovery_credential_reject_outcome"`
	IssueSemanticFingerprintFields           []string `json:"issue_semantic_fingerprint_fields"`
	IssueReplayRule                          string   `json:"issue_replay_rule"`
	HubCookieContract                        string   `json:"hub_cookie_contract"`
	MaxRecoveryGrantASCIIBytes               int      `json:"max_recovery_grant_ascii_bytes"`
	RecoveryGrantLifetimeSeconds             int64    `json:"recovery_grant_lifetime_seconds"`
	NonemptyPacketOverheadBytes              int      `json:"nonempty_packet_overhead_bytes"`
	RecoveryHorizonSeconds                   int64    `json:"recovery_horizon_seconds"`
	RecoveryHorizonAnchor                    string   `json:"recovery_horizon_anchor"`
	RecoveryEpisodeIdentity                  string   `json:"recovery_episode_identity"`
	NewRecoveryEpisodeRule                   string   `json:"new_recovery_episode_rule"`
	RecoveryDeadlineRule                     string   `json:"recovery_deadline_rule"`
	LaterGrantOrLocalClockExtensionAllowed   bool     `json:"later_grant_or_local_clock_extension_allowed"`
	MaxPlaintextBodyBytes                    int      `json:"max_plaintext_body_bytes"`
	MaxPacketBytes                           int      `json:"max_packet_bytes"`
	RetryRule                                string   `json:"retry_rule"`
	HTTPFallbackAllowed                      bool     `json:"http_fallback_allowed"`
	RelayFallbackAllowed                     bool     `json:"relay_fallback_allowed"`
	ClientCellSelectionAllowed               bool     `json:"client_cell_selection_allowed"`
}

// UnmarshalJSON requires every false-valued security decision to be present;
// a missing key must not silently inherit Go's false zero value.
func (protocol *AgentCredentialRecoveryProtocol) UnmarshalJSON(data []byte) error {
	type plain AgentCredentialRecoveryProtocol
	var decoded plain
	if err := strictDecodeArtifact(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, required := range []string{
		"later_grant_or_local_clock_extension_allowed",
		"http_fallback_allowed",
		"relay_fallback_allowed",
		"client_cell_selection_allowed",
	} {
		if _, ok := fields[required]; !ok {
			return fmt.Errorf("conformance: agent credential recovery protocol missing %s", required)
		}
	}
	*protocol = AgentCredentialRecoveryProtocol(decoded)
	return nil
}

// AgentCredentialRecoveryFixtures names every value the public goldens carry.
// Each field appears in at least one public Hub or assigned-cell body.
type AgentCredentialRecoveryFixtures struct {
	AgentID                string `json:"agent_id"`
	RequestNonce           string `json:"request_nonce"`
	RecoveryCredential     string `json:"recovery_credential"`
	RecoveryGrant          string `json:"recovery_grant"`
	RecoveryGrantIssuedAt  string `json:"recovery_grant_issued_at"`
	RecoveryGrantExpiresAt string `json:"recovery_grant_expires_at"`
	DeviceAPIKeyCandidate  string `json:"device_api_key_candidate"`
	DeviceAPIKeyID         string `json:"device_api_key_id"`
	CellID                 string `json:"cell_id"`
	AssignmentGeneration   int64  `json:"assignment_generation"`
	EndpointRevision       int64  `json:"endpoint_revision"`
	LeaseExpiresAt         string `json:"lease_expires_at"`
	NHPHost                string `json:"nhp_host"`
	NHPPort                int    `json:"nhp_port"`
	ServerPublicKeyB64     string `json:"server_public_key_b64"`
}

type AgentCredentialRecoveryExchange struct {
	Phase           string `json:"phase"`
	RequestBodyJSON string `json:"request_body_json"`
	SuccessBodyJSON string `json:"success_body_json"`
}

type AgentCredentialRecoveryHubCookieComposition struct {
	BaseContractArtifact            string                               `json:"base_contract_artifact"`
	Phase                           string                               `json:"phase"`
	UnprovenCounter                 string                               `json:"unproven_counter"`
	ProofCounter                    string                               `json:"proof_counter"`
	UnprovenBodyJSON                string                               `json:"unproven_body_json"`
	ProofBodyJSON                   string                               `json:"proof_body_json"`
	RequestNonce                    string                               `json:"request_nonce"`
	UnprovenHeaderFlagsHex          string                               `json:"unproven_header_flags_hex"`
	ProofHeaderFlagsHex             string                               `json:"proof_header_flags_hex"`
	UnprovenRequestBodyBytes        int                                  `json:"unproven_request_body_bytes"`
	UnprovenRequestPacketBytes      int                                  `json:"unproven_request_packet_bytes"`
	ChallengeBodyJSON               string                               `json:"challenge_body_json"`
	ChallengeBodyBytes              int                                  `json:"challenge_body_bytes"`
	ChallengePacketBytes            int                                  `json:"challenge_packet_bytes"`
	ProofRequestPacketBytes         int                                  `json:"proof_request_packet_bytes"`
	SuccessBodyBytes                int                                  `json:"success_body_bytes"`
	SuccessPacketBytes              int                                  `json:"success_packet_bytes"`
	MaximumGrantSuccessBodyBytes    int                                  `json:"maximum_grant_success_body_bytes"`
	MaximumGrantSuccessPacketBytes  int                                  `json:"maximum_grant_success_packet_bytes"`
	AuthorityInvocationsBeforeProof int                                  `json:"authority_invocations_before_proof"`
	AuthorityInvocationsAfterProof  int                                  `json:"authority_invocations_after_proof"`
	Cases                           []AgentCredentialRecoveryBindingCase `json:"cases"`
}

type AgentCredentialRecoveryBodyCase struct {
	Name        string `json:"name"`
	Phase       string `json:"phase"`
	BodyJSON    string `json:"body_json"`
	Outcome     string `json:"outcome"`
	RejectClass string `json:"reject_class"`
}

type AgentCredentialRecoveryErrorCase struct {
	Name              string `json:"name"`
	Phase             string `json:"phase"`
	BodyJSON          string `json:"body_json"`
	ErrCode           string `json:"err_code"`
	Outcome           string `json:"outcome"`
	RetryAfterSeconds int64  `json:"retry_after_seconds,omitempty"`
}

type AgentCredentialRecoveryBindingCase struct {
	Name        string `json:"name"`
	Mutation    string `json:"mutation"`
	Outcome     string `json:"outcome"`
	RejectClass string `json:"reject_class,omitempty"`
}

type agentCredentialRecoveryOuterRequest struct {
	UserID  *string         `json:"usrId"`
	AgentID string          `json:"devId"`
	AspID   string          `json:"aspId"`
	Data    json.RawMessage `json:"usrData"`
}

type agentCredentialRecoveryHubRequest struct {
	Query        string `json:"query"`
	Version      int    `json:"version"`
	Mode         string `json:"mode"`
	RequestNonce string `json:"request_nonce"`
	Credential   string `json:"credential"`
}

type agentCredentialRecoveryCellRequest struct {
	Query         string `json:"query"`
	Version       int    `json:"version"`
	RecoveryGrant string `json:"recovery_grant"`
	DeviceAPIKey  string `json:"device_api_key"`
}

type agentCredentialRecoveryEnvelope struct {
	ErrCode string          `json:"errCode"`
	ErrMsg  string          `json:"errMsg,omitempty"`
	Retry   *int64          `json:"retryAfterSeconds,omitempty"`
	List    json.RawMessage `json:"list,omitempty"`
}

type agentCredentialRecoveryHubResult struct {
	Query                  string                        `json:"query"`
	Version                int                           `json:"version"`
	Mode                   string                        `json:"mode"`
	AgentID                string                        `json:"agent_id"`
	Assignment             agentAssignmentWireAssignment `json:"assignment"`
	RecoveryGrant          string                        `json:"recovery_grant"`
	RecoveryGrantIssuedAt  string                        `json:"recovery_grant_issued_at"`
	RecoveryGrantExpiresAt string                        `json:"recovery_grant_expires_at"`
}

type agentCredentialRecoveryCellResult struct {
	Query          string `json:"query"`
	Version        int    `json:"version"`
	DeviceAPIKeyID string `json:"device_api_key_id"`
}

func ParseAgentCredentialRecoveryFile(data []byte) (*AgentCredentialRecoveryFile, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("conformance: agent credential recovery file is not valid UTF-8")
	}
	var file AgentCredentialRecoveryFile
	if err := strictDecodeArtifact(data, &file); err != nil {
		return nil, fmt.Errorf("conformance: parse agent credential recovery file: %w", err)
	}
	if file.Artifact != AgentCredentialRecoveryArtifactID || file.SchemaVersion != AgentCredentialRecoverySchemaVersion || strings.TrimSpace(file.Description) == "" {
		return nil, errors.New("conformance: agent credential recovery artifact identity is invalid")
	}
	if err := validateAgentCredentialRecoveryProtocol(file.Protocol); err != nil {
		return nil, err
	}
	if err := validateAgentCredentialRecoveryFixtures(file.Fixtures); err != nil {
		return nil, err
	}
	if err := validateAgentCredentialRecoveryExchanges(file.PublicExchanges, file.Fixtures); err != nil {
		return nil, err
	}
	if err := validateAgentCredentialRecoveryHubCookie(file.HubCookie, file.PublicExchanges, file.Fixtures); err != nil {
		return nil, err
	}
	if err := validateAgentCredentialRecoveryErrors(file.ErrorCases); err != nil {
		return nil, err
	}
	if err := validateAgentCredentialRecoveryIssueReplayCases(file.IssueReplayCases); err != nil {
		return nil, err
	}
	if err := validateAgentCredentialRecoveryBodyCases(file.RequestRejects, true); err != nil {
		return nil, err
	}
	if err := validateAgentCredentialRecoveryBodyCases(file.ResultRejects, false); err != nil {
		return nil, err
	}
	if err := validateAgentCredentialRecoveryBindingCases(file.GrantBindingCases); err != nil {
		return nil, err
	}
	if err := validateAgentCredentialRecoveryFlowCases(file.FlowCases); err != nil {
		return nil, err
	}
	return &file, nil
}

func validateAgentCredentialRecoveryProtocol(got AgentCredentialRecoveryProtocol) error {
	want := AgentCredentialRecoveryProtocol{
		Transport:                                "NHP_UDP_ONLY",
		RequestHeaderName:                        AgentCredentialRecoveryRequestHeader,
		RequestHeaderType:                        AgentCredentialRecoveryRequestType,
		ResultHeaderName:                         AgentCredentialRecoveryResultHeader,
		ResultHeaderType:                         AgentCredentialRecoveryResultType,
		ResultCounterRule:                        "must_echo_request",
		HubQuery:                                 "cell_assignment",
		HubMode:                                  "recover",
		CellQuery:                                "agent_credential_recovery",
		AuthenticatedIdentityProof:               "existing_agent_x25519_peer",
		TakeoverPolicy:                           "forbidden",
		RecoveryCredentialKind:                   "agent",
		RecoveryCredentialScope:                  "qurl:agent",
		MalformedRecoveryCredentialOutcome:       "invalid_request_52405_prelookup",
		CanonicalRecoveryCredentialRejectOutcome: "credential_rejected_52401",
		IssueSemanticFingerprintFields:           []string{"agent_id", "authenticated_peer_public_key_b64", "recovery_credential_key_id", "recovery_credential_hash", "recovery_credential_fence"},
		IssueReplayRule:                          "same_hub_request_id_and_semantic_fingerprint_returns_byte_identical_result_else_terminal_fingerprint_conflict",
		HubCookieContract:                        AgentCredentialRecoveryHubCookieProfile,
		MaxRecoveryGrantASCIIBytes:               AgentCredentialRecoveryMaxGrantBytes,
		RecoveryGrantLifetimeSeconds:             AgentCredentialRecoveryGrantLifetimeSeconds,
		NonemptyPacketOverheadBytes:              AgentCredentialRecoveryPacketOverheadBytes,
		RecoveryHorizonSeconds:                   AgentCredentialRecoveryHorizonSeconds,
		RecoveryHorizonAnchor:                    "first_authenticated_recovery_grant_expiry_per_episode",
		RecoveryEpisodeIdentity:                  "authority_owned_revoked_device_credential_fence",
		NewRecoveryEpisodeRule:                   "new_revoked_device_fence_may_establish_new_anchor",
		RecoveryDeadlineRule:                     "now_strictly_before_anchor_plus_horizon",
		LaterGrantOrLocalClockExtensionAllowed:   false,
		MaxPlaintextBodyBytes:                    AgentCredentialRecoveryMaxBodyBytes,
		MaxPacketBytes:                           AgentCredentialRecoveryMaxPacketBytes,
		RetryRule:                                "only_authenticated_retry_outcomes_within_one_bounded_explicit_operation",
		HTTPFallbackAllowed:                      false,
		RelayFallbackAllowed:                     false,
		ClientCellSelectionAllowed:               false,
	}
	if !reflect.DeepEqual(got, want) {
		return errors.New("conformance: agent credential recovery protocol drift")
	}
	if got.MaxPlaintextBodyBytes+got.NonemptyPacketOverheadBytes != got.MaxPacketBytes {
		return errors.New("conformance: agent credential recovery packet budget drift")
	}
	return nil
}

func validateAgentCredentialRecoveryFixtures(f AgentCredentialRecoveryFixtures) error {
	if !ValidateConnectorResourceLSTV1AgentID(f.AgentID) {
		return errors.New("conformance: recovery fixture agent_id is not canonical")
	}
	if _, err := DecodeRequestNonce(f.RequestNonce); err != nil {
		return fmt.Errorf("conformance: recovery fixture request nonce: %w", err)
	}
	if !isAgentCredentialRecoveryAPIKey(f.RecoveryCredential) || !isAgentCredentialRecoveryAPIKey(f.DeviceAPIKeyCandidate) || f.RecoveryCredential == f.DeviceAPIKeyCandidate {
		return errors.New("conformance: recovery fixture credentials are invalid")
	}
	if !validAgentCredentialRecoveryGrant(f.RecoveryGrant) || !isCanonicalAgentAPIKeyID(f.DeviceAPIKeyID) {
		return errors.New("conformance: recovery fixture grant or device key id is invalid")
	}
	grantIssuedAt, err := parseAgentCredentialRecoveryTimestamp(f.RecoveryGrantIssuedAt)
	if err != nil {
		return fmt.Errorf("conformance: recovery fixture grant issue time: %w", err)
	}
	grantExpiry, err := parseAgentCredentialRecoveryTimestamp(f.RecoveryGrantExpiresAt)
	if err != nil {
		return fmt.Errorf("conformance: recovery fixture grant expiry: %w", err)
	}
	if grantExpiry.Unix()-grantIssuedAt.Unix() != AgentCredentialRecoveryGrantLifetimeSeconds {
		return errors.New("conformance: recovery fixture grant lifetime drifted")
	}
	leaseExpiry, err := parseAgentCredentialRecoveryTimestamp(f.LeaseExpiresAt)
	if err != nil || !grantExpiry.Before(leaseExpiry) {
		return errors.New("conformance: recovery fixture lease must be canonical and outlive the grant")
	}
	if !agentCredentialRecoveryCellIDPattern.MatchString(f.CellID) || f.AssignmentGeneration < 1 || f.EndpointRevision < 1 ||
		!validAgentCredentialRecoveryHost(f.NHPHost) || f.NHPPort < 1 || f.NHPPort > 65535 {
		return errors.New("conformance: recovery fixture assignment is invalid")
	}
	if err := validateAgentCredentialRecoveryServerKey(f.ServerPublicKeyB64); err != nil {
		return fmt.Errorf("conformance: recovery fixture server key: %w", err)
	}
	return nil
}

func validateAgentCredentialRecoveryExchanges(exchanges map[string]AgentCredentialRecoveryExchange, f AgentCredentialRecoveryFixtures) error {
	want := map[string]string{
		"hub_issue_recovery":              AgentCredentialRecoveryHubPhase,
		"assigned_cell_complete_recovery": AgentCredentialRecoveryCellPhase,
	}
	if len(exchanges) != len(want) {
		return fmt.Errorf("conformance: recovery public exchange count = %d, want %d", len(exchanges), len(want))
	}
	for name, phase := range want {
		exchange, ok := exchanges[name]
		if !ok || exchange.Phase != phase {
			return fmt.Errorf("conformance: recovery public exchange %q is missing or misclassified", name)
		}
		if len(exchange.RequestBodyJSON) == 0 || len(exchange.RequestBodyJSON) > AgentCredentialRecoveryMaxBodyBytes ||
			len(exchange.SuccessBodyJSON) == 0 || len(exchange.SuccessBodyJSON) > AgentCredentialRecoveryMaxBodyBytes {
			return fmt.Errorf("conformance: recovery %s golden exceeds the plaintext body budget", phase)
		}
		if got := classifyAgentCredentialRecoveryRequest(phase, []byte(exchange.RequestBodyJSON)); got != "" {
			return fmt.Errorf("conformance: recovery %s request golden rejected as %s", phase, got)
		}
		if got := classifyAgentCredentialRecoveryResult(phase, []byte(exchange.SuccessBodyJSON)); got != "" {
			return fmt.Errorf("conformance: recovery %s result golden rejected as %s", phase, got)
		}
	}
	if err := validateAgentCredentialRecoveryGoldenBindings(exchanges, f); err != nil {
		return err
	}
	return nil
}

func validateAgentCredentialRecoveryGoldenBindings(exchanges map[string]AgentCredentialRecoveryExchange, f AgentCredentialRecoveryFixtures) error {
	var hubOuter agentCredentialRecoveryOuterRequest
	if err := strictDecodeArtifact([]byte(exchanges["hub_issue_recovery"].RequestBodyJSON), &hubOuter); err != nil {
		return err
	}
	var hubData agentCredentialRecoveryHubRequest
	if err := strictDecodeArtifact(hubOuter.Data, &hubData); err != nil {
		return err
	}
	if hubOuter.AgentID != f.AgentID || hubData.RequestNonce != f.RequestNonce || hubData.Credential != f.RecoveryCredential {
		return errors.New("conformance: recovery Hub request fixture bindings drifted")
	}
	var hubEnvelope agentCredentialRecoveryEnvelope
	if err := strictDecodeArtifact([]byte(exchanges["hub_issue_recovery"].SuccessBodyJSON), &hubEnvelope); err != nil {
		return err
	}
	var hubResult agentCredentialRecoveryHubResult
	if err := strictDecodeArtifact(hubEnvelope.List, &hubResult); err != nil {
		return err
	}
	if hubResult.AgentID != f.AgentID || hubResult.RecoveryGrant != f.RecoveryGrant ||
		hubResult.RecoveryGrantIssuedAt != f.RecoveryGrantIssuedAt || hubResult.RecoveryGrantExpiresAt != f.RecoveryGrantExpiresAt ||
		!agentCredentialRecoveryAssignmentMatchesFixture(hubResult.Assignment, f) {
		return errors.New("conformance: recovery Hub result fixture bindings drifted")
	}
	var cellOuter agentCredentialRecoveryOuterRequest
	if err := strictDecodeArtifact([]byte(exchanges["assigned_cell_complete_recovery"].RequestBodyJSON), &cellOuter); err != nil {
		return err
	}
	var cellData agentCredentialRecoveryCellRequest
	if err := strictDecodeArtifact(cellOuter.Data, &cellData); err != nil {
		return err
	}
	if cellOuter.AgentID != f.AgentID || cellData.RecoveryGrant != f.RecoveryGrant || cellData.DeviceAPIKey != f.DeviceAPIKeyCandidate {
		return errors.New("conformance: recovery cell request fixture bindings drifted")
	}
	var cellEnvelope agentCredentialRecoveryEnvelope
	if err := strictDecodeArtifact([]byte(exchanges["assigned_cell_complete_recovery"].SuccessBodyJSON), &cellEnvelope); err != nil {
		return err
	}
	var cellResult agentCredentialRecoveryCellResult
	if err := strictDecodeArtifact(cellEnvelope.List, &cellResult); err != nil {
		return err
	}
	if cellResult.DeviceAPIKeyID != f.DeviceAPIKeyID {
		return errors.New("conformance: recovery cell result fixture bindings drifted")
	}
	return nil
}

func validateAgentCredentialRecoveryHubCookie(composition AgentCredentialRecoveryHubCookieComposition, exchanges map[string]AgentCredentialRecoveryExchange, f AgentCredentialRecoveryFixtures) error {
	base, err := ConnectorHubLSTCookie()
	if err != nil {
		return fmt.Errorf("conformance: recovery Hub cookie base contract: %w", err)
	}
	if !slices.Contains(base.Contract.AdditiveApplicationProfiles, AgentCredentialRecoveryHubCookieProfile) {
		return errors.New("conformance: recovery Hub cookie composition is not allowed by the base primitive")
	}
	var cookieKAT ConnectorHubLSTCookieKAT
	for _, kat := range base.CookieKATs {
		if kat.Name == "ipv4" {
			cookieKAT = kat
			break
		}
	}
	cookie, err := base64.StdEncoding.Strict().DecodeString(cookieKAT.CookieB64)
	if err != nil || len(cookie) == 0 {
		return errors.New("conformance: recovery Hub cookie base KAT is missing")
	}
	unprovenCounter, err := strconv.ParseUint(composition.UnprovenCounter, 10, 64)
	if err != nil || strconv.FormatUint(unprovenCounter, 10) != composition.UnprovenCounter || composition.UnprovenCounter != "25" {
		return errors.New("conformance: recovery Hub cookie unproven counter is invalid")
	}
	proofCounter, err := strconv.ParseUint(composition.ProofCounter, 10, 64)
	if err != nil || strconv.FormatUint(proofCounter, 10) != composition.ProofCounter || proofCounter == unprovenCounter || composition.ProofCounter != "26" {
		return errors.New("conformance: recovery Hub cookie proof counter is not fresh")
	}
	challengeBody, err := ConnectorHubLSTChallengeBody(unprovenCounter, cookie)
	if err != nil {
		return err
	}
	requestBody := exchanges["hub_issue_recovery"].RequestBodyJSON
	successBody := exchanges["hub_issue_recovery"].SuccessBodyJSON
	maximumGrant := AgentCredentialRecoveryGrantPrefix + strings.Repeat("a", AgentCredentialRecoveryMaxGrantBytes-len(AgentCredentialRecoveryGrantPrefix))
	maximumGrantSuccess := strings.Replace(successBody, f.RecoveryGrant, maximumGrant, 1)
	if maximumGrantSuccess == successBody {
		return errors.New("conformance: recovery Hub cookie maximum-grant sizing fixture is unbound")
	}
	if composition.BaseContractArtifact != ConnectorHubLSTCookieArtifactID || composition.Phase != AgentCredentialRecoveryHubPhase ||
		composition.UnprovenBodyJSON != requestBody || composition.ProofBodyJSON != requestBody || composition.RequestNonce != f.RequestNonce ||
		composition.UnprovenHeaderFlagsHex != base.Contract.UnprovenHeaderFlagsHex || composition.ProofHeaderFlagsHex != base.Contract.ProofFlagHex ||
		composition.UnprovenRequestBodyBytes != len(requestBody) || composition.UnprovenRequestPacketBytes != len(requestBody)+base.Contract.NonemptyPacketOverheadBytes ||
		composition.ProofRequestPacketBytes != composition.UnprovenRequestPacketBytes || composition.ChallengeBodyJSON != challengeBody ||
		composition.ChallengeBodyBytes != len(challengeBody) || composition.ChallengePacketBytes != len(challengeBody)+base.Contract.NonemptyPacketOverheadBytes ||
		composition.ChallengePacketBytes >= composition.UnprovenRequestPacketBytes || composition.SuccessBodyBytes != len(successBody) ||
		composition.SuccessPacketBytes != len(successBody)+base.Contract.NonemptyPacketOverheadBytes ||
		composition.MaximumGrantSuccessBodyBytes != len(maximumGrantSuccess) ||
		composition.MaximumGrantSuccessPacketBytes != len(maximumGrantSuccess)+base.Contract.NonemptyPacketOverheadBytes ||
		composition.MaximumGrantSuccessPacketBytes > base.Contract.MaxPacketBytes ||
		composition.AuthorityInvocationsBeforeProof != 0 || composition.AuthorityInvocationsAfterProof != 1 {
		return errors.New("conformance: recovery Hub cookie composition drift")
	}
	expectedCases := map[string]struct{ mutation, outcome, reject string }{
		"accept_exact_recovery_cookie_flow":        {"none", ExpectAccept, ""},
		"reject_proof_body_change":                 {"proof_body_not_byte_identical", ExpectReject, "proof_body"},
		"reject_proof_nonce_change":                {"request_nonce_changed", ExpectReject, "proof_body"},
		"reject_nonexclusive_proof_flag":           {"proof_header_flags_0006", ExpectReject, "proof_flag"},
		"reject_reused_proof_counter":              {"proof_counter_equals_unproven", ExpectReject, "proof_freshness"},
		"reject_authority_before_proof":            {"authority_invocation_before_cookie_proof", ExpectReject, "return_routability"},
		"accept_challenge_strictly_smaller":        {"exact_packet_sizes", ExpectAccept, ""},
		"reject_challenge_equal_or_larger":         {"challenge_packet_not_strictly_smaller", ExpectReject, "amplification"},
		"accept_golden_success_after_proof":        {"exact_success_size", ExpectAccept, ""},
		"accept_maximum_grant_success_after_proof": {"exact_maximum_grant_success_size", ExpectAccept, ""},
	}
	return validateAgentCredentialRecoveryClosedCases(composition.Cases, expectedCases, "Hub cookie")
}

func agentCredentialRecoveryAssignmentMatchesFixture(assignment agentAssignmentWireAssignment, f AgentCredentialRecoveryFixtures) bool {
	return assignment.CellID == f.CellID && int64(assignment.AssignmentGeneration) == f.AssignmentGeneration && int64(assignment.EndpointRevision) == f.EndpointRevision &&
		assignment.LeaseExpiresAt == f.LeaseExpiresAt && assignment.NHPUDPEndpoint.Host == f.NHPHost && assignment.NHPUDPEndpoint.Port == f.NHPPort &&
		assignment.NHPUDPEndpoint.ServerPublicKeyB64 == f.ServerPublicKeyB64
}

func classifyAgentCredentialRecoveryRequest(phase string, body []byte) string {
	var outer agentCredentialRecoveryOuterRequest
	if err := strictDecodeArtifact(body, &outer); err != nil {
		return "body_parse"
	}
	if outer.UserID == nil || *outer.UserID != "" || !ValidateConnectorResourceLSTV1AgentID(outer.AgentID) || outer.AspID != "agent" {
		return "semantic"
	}
	switch phase {
	case AgentCredentialRecoveryHubPhase:
		var data agentCredentialRecoveryHubRequest
		if err := strictDecodeArtifact(outer.Data, &data); err != nil {
			return "body_parse"
		}
		if data.Query != "cell_assignment" || data.Version != 1 || data.Mode != "recover" || !isAgentCredentialRecoveryAPIKey(data.Credential) {
			return "semantic"
		}
		if _, err := DecodeRequestNonce(data.RequestNonce); err != nil {
			return "semantic"
		}
	case AgentCredentialRecoveryCellPhase:
		var data agentCredentialRecoveryCellRequest
		if err := strictDecodeArtifact(outer.Data, &data); err != nil {
			return "body_parse"
		}
		if data.Query != "agent_credential_recovery" || data.Version != 1 || !validAgentCredentialRecoveryGrant(data.RecoveryGrant) || !isAgentCredentialRecoveryAPIKey(data.DeviceAPIKey) {
			return "semantic"
		}
	default:
		return "semantic"
	}
	return ""
}

func classifyAgentCredentialRecoveryResult(phase string, body []byte) string {
	var envelope agentCredentialRecoveryEnvelope
	if err := strictDecodeArtifact(body, &envelope); err != nil {
		return "body_parse"
	}
	if envelope.ErrCode != "0" || envelope.ErrMsg != "" || envelope.Retry != nil || len(envelope.List) == 0 {
		return "semantic"
	}
	switch phase {
	case AgentCredentialRecoveryHubPhase:
		var result agentCredentialRecoveryHubResult
		if err := strictDecodeArtifact(envelope.List, &result); err != nil {
			return "body_parse"
		}
		if result.Query != "cell_assignment" || result.Version != 1 || result.Mode != "recover" || !ValidateConnectorResourceLSTV1AgentID(result.AgentID) ||
			!validAgentCredentialRecoveryGrant(result.RecoveryGrant) {
			return "semantic"
		}
		grantIssuedAt, err := parseAgentCredentialRecoveryTimestamp(result.RecoveryGrantIssuedAt)
		if err != nil {
			return "semantic"
		}
		grantExpiry, err := parseAgentCredentialRecoveryTimestamp(result.RecoveryGrantExpiresAt)
		if err != nil || grantExpiry.Unix()-grantIssuedAt.Unix() != AgentCredentialRecoveryGrantLifetimeSeconds ||
			validateAgentCredentialRecoveryAssignment(result.Assignment) != nil {
			return "semantic"
		}
		leaseExpiry, err := parseAgentCredentialRecoveryTimestamp(result.Assignment.LeaseExpiresAt)
		if err != nil || !grantExpiry.Before(leaseExpiry) {
			return "semantic"
		}
	case AgentCredentialRecoveryCellPhase:
		var result agentCredentialRecoveryCellResult
		if err := strictDecodeArtifact(envelope.List, &result); err != nil {
			return "body_parse"
		}
		if result.Query != "agent_credential_recovery" || result.Version != 1 || !isCanonicalAgentAPIKeyID(result.DeviceAPIKeyID) {
			return "semantic"
		}
	default:
		return "semantic"
	}
	return ""
}

func validateAgentCredentialRecoveryAssignment(a agentAssignmentWireAssignment) error {
	if !agentCredentialRecoveryCellIDPattern.MatchString(a.CellID) || a.AssignmentGeneration < 1 || a.EndpointRevision < 1 ||
		!validAgentCredentialRecoveryHost(a.NHPUDPEndpoint.Host) || a.NHPUDPEndpoint.Port < 1 || a.NHPUDPEndpoint.Port > 65535 {
		return errors.New("invalid assignment")
	}
	if _, err := parseAgentCredentialRecoveryTimestamp(a.LeaseExpiresAt); err != nil {
		return err
	}
	return validateAgentCredentialRecoveryServerKey(a.NHPUDPEndpoint.ServerPublicKeyB64)
}

func validateAgentCredentialRecoveryBodyCases(cases []AgentCredentialRecoveryBodyCase, request bool) error {
	want := recoveryResultRejects
	classifier := classifyAgentCredentialRecoveryResult
	label := "result"
	if request {
		want = recoveryRequestRejects
		classifier = classifyAgentCredentialRecoveryRequest
		label = "request"
	}
	if len(cases) != len(want) {
		return fmt.Errorf("conformance: recovery %s reject count = %d, want %d", label, len(cases), len(want))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		expected, ok := want[c.Name]
		if !ok || c.Phase != expected.phase || c.Outcome != ExpectReject || c.RejectClass != expected.class {
			return fmt.Errorf("conformance: recovery %s reject %q metadata drifted", label, c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate recovery %s reject %q", label, c.Name)
		}
		seen[c.Name] = struct{}{}
		if got := classifier(c.Phase, []byte(c.BodyJSON)); got != c.RejectClass {
			return fmt.Errorf("conformance: recovery %s reject %q classified %q, want %q", label, c.Name, got, c.RejectClass)
		}
	}
	return nil
}

var recoveryRequestRejects = map[string]struct{ phase, class string }{
	"reject_duplicate_hub_credential":  {AgentCredentialRecoveryHubPhase, "body_parse"},
	"reject_hub_takeover_field":        {AgentCredentialRecoveryHubPhase, "body_parse"},
	"reject_hub_cell_hint":             {AgentCredentialRecoveryHubPhase, "body_parse"},
	"reject_hub_resource_id":           {AgentCredentialRecoveryHubPhase, "body_parse"},
	"reject_hub_credential_in_user_id": {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_hub_request_wrong_mode":    {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_hub_padded_nonce":          {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_hub_noncanonical_agent_id": {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_hub_malformed_credential":  {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_hub_missing_user_id":       {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_cell_missing_grant":        {AgentCredentialRecoveryCellPhase, "semantic"},
	"reject_cell_noncanonical_grant":   {AgentCredentialRecoveryCellPhase, "semantic"},
	"reject_cell_duplicate_candidate":  {AgentCredentialRecoveryCellPhase, "body_parse"},
	"reject_cell_takeover_field":       {AgentCredentialRecoveryCellPhase, "body_parse"},
	"reject_cell_placement_hint":       {AgentCredentialRecoveryCellPhase, "body_parse"},
	"reject_cell_resource_id":          {AgentCredentialRecoveryCellPhase, "body_parse"},
}

var recoveryResultRejects = map[string]struct{ phase, class string }{
	"reject_hub_raw_aws_host":               {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_hub_missing_server_key":         {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_hub_result_wrong_mode":          {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_hub_grant_lifetime_901_seconds": {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_hub_grant_lifetime_899_seconds": {AgentCredentialRecoveryHubPhase, "semantic"},
	"reject_hub_unknown_field":              {AgentCredentialRecoveryHubPhase, "body_parse"},
	"reject_cell_secret_echo":               {AgentCredentialRecoveryCellPhase, "body_parse"},
	"reject_cell_missing_key_id":            {AgentCredentialRecoveryCellPhase, "semantic"},
	"reject_cell_wrong_query":               {AgentCredentialRecoveryCellPhase, "semantic"},
}

func validateAgentCredentialRecoveryErrors(cases []AgentCredentialRecoveryErrorCase) error {
	errorCase := func(name, phase, body, code, outcome string, retry int64) AgentCredentialRecoveryErrorCase {
		return AgentCredentialRecoveryErrorCase{Name: name, Phase: phase, BodyJSON: body, ErrCode: code, Outcome: outcome, RetryAfterSeconds: retry}
	}
	expected := map[string]AgentCredentialRecoveryErrorCase{
		"hub_unavailable":              errorCase("hub_unavailable", AgentCredentialRecoveryHubPhase, `{"errCode":"52400","errMsg":"credential recovery temporarily unavailable","retryAfterSeconds":5}`, "52400", "retry", 5),
		"recovery_credential_rejected": errorCase("recovery_credential_rejected", AgentCredentialRecoveryHubPhase, `{"errCode":"52401","errMsg":"recovery credential rejected"}`, "52401", "credential_rejected", 0),
		"hub_identity_rejected":        errorCase("hub_identity_rejected", AgentCredentialRecoveryHubPhase, `{"errCode":"52402","errMsg":"recovery identity rejected"}`, "52402", "identity_rejected", 0),
		"revoke_required":              errorCase("revoke_required", AgentCredentialRecoveryHubPhase, `{"errCode":"52403","errMsg":"revoke current device credential before recovery"}`, "52403", "revoke_required", 0),
		"hub_rate_limited":             errorCase("hub_rate_limited", AgentCredentialRecoveryHubPhase, `{"errCode":"52404","errMsg":"credential recovery rate limited","retryAfterSeconds":60}`, "52404", "rate_limited", 60),
		"invalid_hub_request":          errorCase("invalid_hub_request", AgentCredentialRecoveryHubPhase, `{"errCode":"52405","errMsg":"invalid credential recovery request"}`, "52405", "invalid_request", 0),
		"assignment_recovery_required": errorCase("assignment_recovery_required", AgentCredentialRecoveryHubPhase, `{"errCode":"52406","errMsg":"assignment requires operator recovery"}`, "52406", "assignment_recovery_required", 0),
		"cell_unavailable":             errorCase("cell_unavailable", AgentCredentialRecoveryCellPhase, `{"errCode":"52410","errMsg":"credential replacement temporarily unavailable","retryAfterSeconds":5}`, "52410", "retry", 5),
		"grant_rejected":               errorCase("grant_rejected", AgentCredentialRecoveryCellPhase, `{"errCode":"52411","errMsg":"credential recovery grant rejected"}`, "52411", "grant_rejected", 0),
		"cell_identity_rejected":       errorCase("cell_identity_rejected", AgentCredentialRecoveryCellPhase, `{"errCode":"52412","errMsg":"credential recovery identity rejected"}`, "52412", "identity_rejected", 0),
		"candidate_conflict":           errorCase("candidate_conflict", AgentCredentialRecoveryCellPhase, `{"errCode":"52413","errMsg":"different replacement credential candidate already recorded"}`, "52413", "credential_conflict", 0),
		"invalid_cell_request":         errorCase("invalid_cell_request", AgentCredentialRecoveryCellPhase, `{"errCode":"52414","errMsg":"invalid credential replacement request"}`, "52414", "invalid_request", 0),
	}
	if len(cases) != len(expected) {
		return fmt.Errorf("conformance: recovery error case count = %d, want %d", len(cases), len(expected))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		want, ok := expected[c.Name]
		if !ok || c.Phase != want.Phase || c.BodyJSON != want.BodyJSON || c.ErrCode != want.ErrCode || c.Outcome != want.Outcome || c.RetryAfterSeconds != want.RetryAfterSeconds {
			return fmt.Errorf("conformance: recovery error case %q metadata drifted", c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate recovery error case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		var envelope agentCredentialRecoveryEnvelope
		if err := strictDecodeArtifact([]byte(c.BodyJSON), &envelope); err != nil || envelope.ErrCode != c.ErrCode || envelope.ErrMsg == "" || len(envelope.List) != 0 {
			return fmt.Errorf("conformance: recovery error case %q body drifted", c.Name)
		}
		if c.RetryAfterSeconds > 0 {
			if envelope.Retry == nil || *envelope.Retry != c.RetryAfterSeconds {
				return fmt.Errorf("conformance: recovery error case %q retry delay drifted", c.Name)
			}
		} else if envelope.Retry != nil {
			return fmt.Errorf("conformance: recovery terminal error %q has a retry delay", c.Name)
		}
	}
	return nil
}

func validateAgentCredentialRecoveryIssueReplayCases(cases []AgentCredentialRecoveryBindingCase) error {
	expected := map[string]struct{ mutation, outcome, reject string }{
		"accept_first_issue":                          {"none", ExpectAccept, ""},
		"accept_exact_issue_replay":                   {"same_hub_request_id_and_semantic_fingerprint", ExpectAccept, ""},
		"reject_same_id_changed_credential":           {"same_hub_request_id_changed_recovery_credential", ExpectReject, "fingerprint_conflict"},
		"reject_same_id_changed_agent":                {"same_hub_request_id_changed_agent_id", ExpectReject, "fingerprint_conflict"},
		"reject_same_id_changed_peer":                 {"same_hub_request_id_changed_authenticated_peer", ExpectReject, "fingerprint_conflict"},
		"reject_transport_retry_remint":               {"same_nonce_and_body_returns_new_grant_or_times_or_assignment", ExpectReject, "replay_drift"},
		"reject_transport_retry_body_or_nonce_change": {"transport_retry_changes_nonce_or_serialized_body", ExpectReject, "logical_operation"},
	}
	return validateAgentCredentialRecoveryClosedCases(cases, expected, "issue replay")
}

func validateAgentCredentialRecoveryBindingCases(cases []AgentCredentialRecoveryBindingCase) error {
	expected := map[string]struct{ mutation, outcome, reject string }{
		"accept_exact_binding":                             {"none", ExpectAccept, ""},
		"reject_wrong_agent_id":                            {"agent_id", ExpectReject, "grant_binding"},
		"reject_wrong_authenticated_peer":                  {"authenticated_peer_public_key_b64", ExpectReject, "grant_binding"},
		"reject_wrong_recovery_credential_key":             {"recovery_credential_key_id", ExpectReject, "grant_binding"},
		"reject_wrong_recovery_credential_hash":            {"recovery_credential_hash", ExpectReject, "grant_binding"},
		"reject_wrong_recovery_credential_fence":           {"recovery_credential_fence", ExpectReject, "grant_binding"},
		"reject_non_agent_recovery_credential":             {"recovery_credential_kind_or_scope", ExpectReject, "grant_binding"},
		"reject_recovery_credential_inactive_after_issue":  {"bound_recovery_credential_becomes_inactive_revoked_or_expired_after_issue", ExpectReject, "grant_rejected"},
		"reject_wrong_environment":                         {"environment", ExpectReject, "grant_binding"},
		"reject_wrong_cell":                                {"cell_id", ExpectReject, "grant_binding"},
		"reject_wrong_assignment_generation":               {"assignment_generation", ExpectReject, "grant_binding"},
		"reject_current_device_credential_not_revoked":     {"current_device_credential_status", ExpectReject, "revoke_required"},
		"reject_wrong_revoked_device_credential_fence":     {"revoked_device_credential_fence", ExpectReject, "grant_binding"},
		"accept_exact_committed_replay_after_grant_expiry": {"expired_grant_with_exact_committed_candidate", ExpectAccept, ""},
		"reject_expired_uncommitted_grant":                 {"expired_grant_without_committed_result", ExpectReject, "grant_expired"},
		"accept_exact_replay_before_recovery_horizon":      {"exact_candidate_one_second_before_anchor_plus_7776000", ExpectAccept, ""},
		"reject_exact_replay_at_recovery_horizon":          {"exact_candidate_at_anchor_plus_7776000", ExpectReject, "recovery_expired"},
		"reject_later_grant_extending_recovery_horizon":    {"same_episode_later_grant_expiry_replaces_first_authenticated_anchor", ExpectReject, "recovery_anchor"},
		"accept_new_revoked_device_episode_anchor":         {"new_authority_owned_revoked_device_credential_fence", ExpectAccept, ""},
		"reject_local_clock_reanchoring":                   {"local_process_time_replaces_authenticated_grant_expiry", ExpectReject, "recovery_anchor"},
		"reject_short_grant_lifetime":                      {"recovery_grant_lifetime_seconds_899", ExpectReject, "grant_lifetime"},
		"reject_overlong_grant_lifetime":                   {"recovery_grant_lifetime_seconds_901", ExpectReject, "grant_lifetime"},
		"accept_exact_candidate_replay":                    {"same_candidate_after_commit", ExpectAccept, ""},
		"reject_changed_candidate_after_commit":            {"different_candidate_after_commit", ExpectReject, "credential_conflict"},
	}
	return validateAgentCredentialRecoveryClosedCases(cases, expected, "grant binding")
}

func validateAgentCredentialRecoveryFlowCases(cases []AgentCredentialRecoveryBindingCase) error {
	expected := map[string]struct{ mutation, outcome, reject string }{
		"accept_explicit_recovery":                    {"none", ExpectAccept, ""},
		"reject_implicit_recovery_after_resource_401": {"resource_401_triggers_recovery", ExpectReject, "operator_intent"},
		"reject_http_assignment":                      {"public_http_used_for_hub_or_cell", ExpectReject, "transport"},
		"reject_relay_path":                           {"browser_relay_used", ExpectReject, "transport"},
		"reject_client_cell_derivation":               {"client_derives_or_probes_cell", ExpectReject, "placement"},
		"reject_cross_cell_fallback":                  {"cell_exchange_falls_back_to_other_cell", ExpectReject, "placement"},
		"reject_authority_before_cookie_proof":        {"hub_invokes_authority_before_cookie_proof", ExpectReject, "return_routability"},
		"reject_takeover":                             {"different_authenticated_peer_for_same_agent", ExpectReject, "identity"},
		"reject_candidate_generated_after_first_send": {"candidate_not_durable_before_cell_send", ExpectReject, "persistence"},
		"reject_replacement_candidate_on_retry":       {"candidate_rotated_after_ambiguous_reply", ExpectReject, "persistence"},
	}
	return validateAgentCredentialRecoveryClosedCases(cases, expected, "flow")
}

func validateAgentCredentialRecoveryClosedCases(cases []AgentCredentialRecoveryBindingCase, expected map[string]struct{ mutation, outcome, reject string }, label string) error {
	if len(cases) != len(expected) {
		return fmt.Errorf("conformance: recovery %s case count = %d, want %d", label, len(cases), len(expected))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		want, ok := expected[c.Name]
		if !ok || c.Mutation != want.mutation || c.Outcome != want.outcome || c.RejectClass != want.reject {
			return fmt.Errorf("conformance: recovery %s case %q drifted", label, c.Name)
		}
		if _, duplicate := seen[c.Name]; duplicate {
			return fmt.Errorf("conformance: duplicate recovery %s case %q", label, c.Name)
		}
		seen[c.Name] = struct{}{}
	}
	return nil
}

func validAgentCredentialRecoveryGrant(value string) bool {
	return len(value) <= AgentCredentialRecoveryMaxGrantBytes && value == strings.TrimSpace(value) && agentCredentialRecoveryGrantPattern.MatchString(value)
}

// isAgentCredentialRecoveryAPIKey is the public device/agent API-key shape: a
// live or test prefix plus exactly 32 bytes of canonical unpadded base64url.
func isAgentCredentialRecoveryAPIKey(value string) bool {
	for _, prefix := range agentCredentialRecoveryAPIKeyPrefixes {
		if encoded, ok := strings.CutPrefix(value, prefix); ok {
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
			return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == encoded
		}
	}
	return false
}

// validAgentCredentialRecoveryHost accepts only a lowercase LayerV-owned DNS
// name. Raw IPs, trailing dots, reserved first labels, and third-party hosts
// (for example a raw cloud load-balancer name) are rejected.
func validAgentCredentialRecoveryHost(value string) bool {
	if value == "" || len(value) > 253 || value != strings.TrimSpace(value) || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if !agentCredentialRecoveryDNSLabelPattern.MatchString(label) {
			return false
		}
	}
	switch labels[0] {
	case "internal", "localhost", "metadata", "private":
		return false
	}
	for _, suffix := range agentCredentialRecoveryLayerVHostSuffixes {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

// validateAgentCredentialRecoveryServerKey requires canonical padded
// standard-base64 of a canonical, usable, non-low-order X25519 public key.
func validateAgentCredentialRecoveryServerKey(value string) error {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != value {
		return errors.New("key is not canonical padded standard-base64 X25519")
	}
	if !isCanonicalAgentCredentialRecoveryX25519U(raw) {
		return errors.New("key does not contain a canonical X25519 u-coordinate")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(raw)
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

// isCanonicalAgentCredentialRecoveryX25519U reports whether the little-endian
// u-coordinate is below the field prime 2^255-19.
func isCanonicalAgentCredentialRecoveryX25519U(raw []byte) bool {
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

// parseAgentCredentialRecoveryTimestamp accepts only canonical whole-second
// UTC RFC 3339 with an uppercase Z.
func parseAgentCredentialRecoveryTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || strings.Contains(value, ".") || parsed.Format(time.RFC3339) != value {
		return time.Time{}, errors.New("timestamp is not canonical whole-second UTC RFC3339")
	}
	return parsed, nil
}
