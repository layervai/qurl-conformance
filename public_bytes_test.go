package conformance

import (
	"strings"
	"testing"
)

// The public wire bodies must never carry a platform-private replay identity.
// hub_request_id and cell_request_id are derived server-side from the public
// request_nonce and stay inside the private conformance module; a public body
// may only reference the nonce. Assignment prose may name the private field
// to say it is never echoed, so that artifact is checked body by body.
func TestPublicBodiesNeverCarryPrivateReplayIdentities(t *testing.T) {
	private := []string{"hub_request_id", "cell_request_id"}
	assignment, err := AgentAssignmentGolden()
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"initial_assignment.request": assignment.InitialAssignment.Request.BodyJSON,
		"initial_assignment.result":  assignment.InitialAssignment.Result.BodyJSON,
		"refresh_assignment.request": assignment.RefreshAssignment.Request.BodyJSON,
		"refresh_assignment.result":  assignment.RefreshAssignment.Result.BodyJSON,
	} {
		for _, p := range private {
			if strings.Contains(body, p) {
				t.Errorf("agent_assignment_golden.json %s exposes private %s", name, p)
			}
		}
	}
	for name, raw := range map[string][]byte{
		"connector_resource_lst_v1_vectors.json":   ConnectorResourceLSTV1Vectors(),
		"agent_session_control_vectors.json":       AgentSessionControlVectors(),
		"connector_hub_lst_cookie_v1_vectors.json": ConnectorHubLSTCookieVectors(),
	} {
		for _, p := range private {
			if strings.Contains(string(raw), p) {
				t.Errorf("%s exposes private %s", name, p)
			}
		}
	}
}
