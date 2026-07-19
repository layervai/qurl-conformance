package conformance

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEmbeddedConnectorHubRequestIDLoadsAndDerives(t *testing.T) {
	file, err := ConnectorHubRequestID()
	if err != nil {
		t.Fatalf("ConnectorHubRequestID(): %v", err)
	}
	if file.Artifact != ConnectorHubRequestIDArtifactID || file.SchemaVersion != ConnectorHubRequestIDSchemaVersion {
		t.Fatalf("identity = %q/v%d, want %q/v%d", file.Artifact, file.SchemaVersion, ConnectorHubRequestIDArtifactID, ConnectorHubRequestIDSchemaVersion)
	}
	if len(file.Cases) != 5 {
		t.Fatalf("case count = %d, want 5", len(file.Cases))
	}
	baseline := file.Cases[0]
	peer, err := base64.StdEncoding.Strict().DecodeString(baseline.AuthenticatedPeerPublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := DecodeConnectorHubRequestNonce(baseline.RequestNonce)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DeriveConnectorHubRequestID(baseline.Environment, baseline.Operation, peer, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if got != baseline.HubRequestID {
		t.Fatalf("derived id = %q, want %q", got, baseline.HubRequestID)
	}
}

func TestConnectorHubRequestIDLinksAssignmentNonceWithoutExposingPrivateID(t *testing.T) {
	hub, err := ConnectorHubRequestID()
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := AgentAssignmentGolden()
	if err != nil {
		t.Fatal(err)
	}
	var request agentAssignmentListRequest
	if err := json.Unmarshal([]byte(assignment.RefreshAssignment.Request.BodyJSON), &request); err != nil {
		t.Fatal(err)
	}
	var data agentAssignmentRefreshRequestData
	if err := json.Unmarshal(request.UsrData, &data); err != nil {
		t.Fatal(err)
	}
	baseline := hub.Cases[0]
	if data.RequestNonce != baseline.RequestNonce || baseline.Operation != ConnectorHubRequestIDOperationRefresh {
		t.Fatalf("assignment/KAT linkage drifted: nonce %q/%q operation %q", data.RequestNonce, baseline.RequestNonce, baseline.Operation)
	}
	agentPublic, err := hex.DecodeString(assignment.Keys.Agent.StaticPubHex)
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(agentPublic) != baseline.AuthenticatedPeerPublicKeyB64 {
		t.Fatal("request-ID KAT peer does not match the assignment authenticated agent fixture")
	}
	for _, publicBody := range []string{
		assignment.InitialAssignment.Request.BodyJSON,
		assignment.InitialAssignment.Result.BodyJSON,
		assignment.RefreshAssignment.Request.BodyJSON,
		assignment.RefreshAssignment.Result.BodyJSON,
	} {
		if strings.Contains(publicBody, "hub_request_id") || strings.Contains(publicBody, baseline.HubRequestID) {
			t.Fatal("public assignment body exposes private hub_request_id")
		}
	}
}

func TestOpenConnectorHubRequestIDArtifact(t *testing.T) {
	want := ConnectorHubRequestIDVectors()
	for _, name := range []string{"connector_hub_request_id_v1_vectors.json", "vectors/connector_hub_request_id_v1_vectors.json"} {
		got, err := Open(name)
		if err != nil {
			t.Fatalf("Open(%q): %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Open(%q) does not match embedded Connector Hub request-ID vectors", name)
		}
	}
}

func TestDeriveConnectorHubRequestIDRejectsInvalidInputs(t *testing.T) {
	peer := bytes.Repeat([]byte{1}, ConnectorHubRequestIDPeerBytes)
	nonce := bytes.Repeat([]byte{2}, ConnectorHubRequestIDNonceBytes)
	for _, test := range []struct {
		name        string
		environment string
		operation   string
		peer        []byte
		nonce       []byte
		want        error
	}{
		{name: "environment", environment: "Sandbox", operation: ConnectorHubRequestIDOperationIssue, peer: peer, nonce: nonce, want: ErrConnectorHubRequestIDEnvironment},
		{name: "operation", environment: "sandbox", operation: "CompleteRegistration", peer: peer, nonce: nonce, want: ErrConnectorHubRequestIDOperation},
		{name: "peer", environment: "sandbox", operation: ConnectorHubRequestIDOperationIssue, peer: peer[:31], nonce: nonce, want: ErrConnectorHubRequestIDPeer},
		{name: "nonce", environment: "sandbox", operation: ConnectorHubRequestIDOperationIssue, peer: peer, nonce: nonce[:31], want: ErrConnectorHubRequestIDNonce},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DeriveConnectorHubRequestID(test.environment, test.operation, test.peer, test.nonce); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDecodeConnectorHubRequestNonceIsCanonical(t *testing.T) {
	if nonce, err := DecodeConnectorHubRequestNonce(AgentAssignmentRefreshRequestNonceFixture); err != nil || len(nonce) != ConnectorHubRequestIDNonceBytes {
		t.Fatalf("valid nonce = %x, %v", nonce, err)
	}
	nonCanonicalTailBits := AgentAssignmentRefreshRequestNonceFixture[:len(AgentAssignmentRefreshRequestNonceFixture)-1] + "9"
	canonicalBytes, err := base64.RawURLEncoding.DecodeString(AgentAssignmentRefreshRequestNonceFixture)
	if err != nil {
		t.Fatal(err)
	}
	nonCanonicalBytes, err := base64.RawURLEncoding.DecodeString(nonCanonicalTailBits)
	if err != nil || !bytes.Equal(nonCanonicalBytes, canonicalBytes) {
		t.Fatalf("non-canonical tail-bit fixture = %x, %v; want same decoded bytes %x", nonCanonicalBytes, err, canonicalBytes)
	}
	if _, err := DecodeConnectorHubRequestNonce(nonCanonicalTailBits); !errors.Is(err, ErrConnectorHubRequestIDNonce) {
		t.Fatalf("DecodeConnectorHubRequestNonce(non-canonical tail bits) = %v, want nonce reject", err)
	}
	for _, invalid := range []string{
		"",
		AgentAssignmentRefreshRequestNonceFixture + "=",
		strings.Repeat("A", 42),
		strings.Repeat("A", 44),
		strings.Repeat("+", 43),
	} {
		if _, err := DecodeConnectorHubRequestNonce(invalid); !errors.Is(err, ErrConnectorHubRequestIDNonce) {
			t.Fatalf("DecodeConnectorHubRequestNonce(%q) = %v, want nonce reject", invalid, err)
		}
	}
}

func TestParseConnectorHubRequestIDFileFailsClosed(t *testing.T) {
	raw := ConnectorHubRequestIDVectors()
	for name, invalid := range map[string][]byte{
		"duplicate key":  bytes.Replace(raw, []byte(`"artifact":`), []byte(`"artifact":"duplicate","artifact":`), 1),
		"unknown field":  bytes.Replace(raw, []byte("{"), []byte(`{"future":true,`), 1),
		"trailing value": append(append([]byte(nil), raw...), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConnectorHubRequestIDFile(invalid); err == nil {
				t.Fatal("invalid artifact unexpectedly accepted")
			}
		})
	}

	mutate := func(t *testing.T, change func(*ConnectorHubRequestIDFile)) []byte {
		t.Helper()
		var file ConnectorHubRequestIDFile
		if err := json.Unmarshal(raw, &file); err != nil {
			t.Fatal(err)
		}
		change(&file)
		body, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, test := range []struct {
		name   string
		change func(*ConnectorHubRequestIDFile)
	}{
		{name: "contract", change: func(file *ConnectorHubRequestIDFile) { file.Contract.ExcludedInputs = nil }},
		{name: "preimage", change: func(file *ConnectorHubRequestIDFile) {
			file.Cases[0].PreimageHex = strings.Repeat("0", len(file.Cases[0].PreimageHex))
		}},
		{name: "id", change: func(file *ConnectorHubRequestIDFile) { file.Cases[0].HubRequestID = strings.Repeat("0", 64) }},
		{name: "not equal", change: func(file *ConnectorHubRequestIDFile) { file.Cases[1].NotEqualTo = "environment_substitution" }},
		{name: "two fields", change: func(file *ConnectorHubRequestIDFile) { file.Cases[1].RequestNonce = file.Cases[4].RequestNonce }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseConnectorHubRequestIDFile(mutate(t, test.change)); err == nil {
				t.Fatal("mutated artifact unexpectedly accepted")
			}
		})
	}
}
