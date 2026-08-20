package conformance

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEmbeddedConnectorResourceLSTV1Loads(t *testing.T) {
	file, err := ConnectorResourceLSTV1()
	if err != nil {
		t.Fatalf("ConnectorResourceLSTV1(): %v", err)
	}
	if file.Artifact != ConnectorResourceLSTV1ArtifactID || file.SchemaVersion != ConnectorResourceLSTV1SchemaVersion {
		t.Fatalf("identity = %q/v%d", file.Artifact, file.SchemaVersion)
	}
	if file.Contract.Query != ConnectorResourceLSTV1Query || file.Contract.HTTPFallbackAllowed || !file.Contract.OneResourcePerExchange {
		t.Fatalf("contract discriminator/transport drift: %+v", file.Contract)
	}
	if got, want := file.Contract.MaxPlaintextBodyBytes, ConnectorResourceLSTV1MaxPlaintextBodyBytes; got != want {
		t.Fatalf("max plaintext bytes = %d, want %d", got, want)
	}
	for _, exchange := range file.SuccessExchanges {
		request, err := ParseConnectorResourceLSTV1RequestBody([]byte(exchange.Request.BodyJSON), file.Fixtures.AgentID)
		if err != nil {
			t.Fatalf("%s request: %v", exchange.Name, err)
		}
		result, err := ParseConnectorResourceLSTV1ResultBody([]byte(exchange.Result.BodyJSON), request)
		if err != nil {
			t.Fatalf("%s result: %v", exchange.Name, err)
		}
		if result.List == nil || result.List.FoundExisting != exchange.ExpectedFoundExisting {
			t.Fatalf("%s found_existing/result drift", exchange.Name)
		}
	}
	for _, errorCase := range file.ErrorCases {
		result, err := ParseConnectorResourceLSTV1ResultBody([]byte(errorCase.BodyJSON), nil)
		if err != nil {
			t.Fatalf("%s error: %v", errorCase.Name, err)
		}
		if result.ErrCode != errorCase.ErrorCode || result.List != nil {
			t.Fatalf("%s error result drift", errorCase.Name)
		}
	}
}

func TestOpenConnectorResourceLSTV1Artifact(t *testing.T) {
	want := ConnectorResourceLSTV1Vectors()
	for _, name := range []string{"connector_resource_lst_v1_vectors.json", connectorResourceLSTV1Name} {
		got, err := Open(name)
		if err != nil {
			t.Fatalf("Open(%q): %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Open(%q) returned different bytes", name)
		}
	}
}

func TestConnectorResourceLSTV1CellRequestIDKAT(t *testing.T) {
	file, err := ConnectorResourceLSTV1()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := base64.StdEncoding.Strict().DecodeString(file.Fixtures.AuthenticatedPeerPublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(file.Fixtures.CreateRequestNonce)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DeriveConnectorResourceLSTV1CellRequestID("sandbox", peer, nonce)
	if err != nil {
		t.Fatal(err)
	}
	const want = "57b3dac2005f8c49f56e9b23bda0f5f17f0be91bf5f8e853155f53d0ed9f1e4a"
	if got != want {
		t.Fatalf("cell_request_id = %s, want %s", got, want)
	}
	if err := ValidateConnectorResourceLSTV1CellRequestID(got); err != nil {
		t.Fatalf("ValidateConnectorResourceLSTV1CellRequestID: %v", err)
	}
	for _, test := range []struct {
		environment string
		peer        []byte
		nonce       []byte
	}{
		{"Sandbox", peer, nonce},
		{"sandbox", peer[:31], nonce},
		{"sandbox", peer, nonce[:31]},
	} {
		if _, err := DeriveConnectorResourceLSTV1CellRequestID(test.environment, test.peer, test.nonce); err == nil {
			t.Fatalf("invalid request-id input accepted: %+v", test)
		}
	}
}

func TestConnectorResourceLSTV1PublicParsersFailClosed(t *testing.T) {
	file, err := ConnectorResourceLSTV1()
	if err != nil {
		t.Fatal(err)
	}
	requestJSON := file.SuccessExchanges[0].Request.BodyJSON
	request, err := ParseConnectorResourceLSTV1RequestBody([]byte(requestJSON), file.Fixtures.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConnectorResourceLSTV1RequestBody([]byte(requestJSON), "different-agent"); rejectClass(t, err) != ConnectorResourceLSTV1RejectAgentBinding {
		t.Fatalf("agent mismatch = %v", err)
	}
	if _, err := ParseConnectorResourceLSTV1RequestBody([]byte(requestJSON+"{}"), file.Fixtures.AgentID); rejectClass(t, err) != ConnectorResourceLSTV1RejectBodyParse {
		t.Fatalf("trailing request = %v", err)
	}
	invalidUTF8 := append([]byte(requestJSON[:len(requestJSON)-2]), 0xff, '}', '}')
	if _, err := ParseConnectorResourceLSTV1RequestBody(invalidUTF8, file.Fixtures.AgentID); rejectClass(t, err) != ConnectorResourceLSTV1RejectBodyParse {
		t.Fatalf("invalid-UTF8 request = %v", err)
	}
	if _, err := ParseConnectorResourceLSTV1RequestBody([]byte(strings.Replace(requestJSON, `"usrId"`, `"usrId":"smuggled","usrId"`, 1)), file.Fixtures.AgentID); rejectClass(t, err) != ConnectorResourceLSTV1RejectBodyParse {
		t.Fatalf("duplicate request = %v", err)
	}

	resultJSON := file.SuccessExchanges[0].Result.BodyJSON
	wrongExpected := file.Fixtures.ResourceID[:len(file.Fixtures.ResourceID)-1] + "A"
	request.UsrData.ExpectedResourceID = &wrongExpected
	if _, err := ParseConnectorResourceLSTV1ResultBody([]byte(resultJSON), request); rejectClass(t, err) != ConnectorResourceLSTV1RejectResourceBinding {
		t.Fatalf("expected-resource mismatch = %v", err)
	}
	if _, err := ParseConnectorResourceLSTV1ResultBody([]byte(resultJSON), nil); rejectClass(t, err) != ConnectorResourceLSTV1RejectRequestBinding {
		t.Fatalf("uncorrelated success = %v", err)
	}
	tooLarge := bytes.Repeat([]byte{' '}, ConnectorResourceLSTV1MaxPlaintextBodyBytes+1)
	if _, err := ParseConnectorResourceLSTV1ResultBody(tooLarge, nil); rejectClass(t, err) != ConnectorResourceLSTV1RejectPacketSize {
		t.Fatalf("oversize result = %v", err)
	}
}

func TestParseConnectorResourceLSTV1FileFailsClosed(t *testing.T) {
	if _, err := ConnectorResourceLSTV1(); err != nil {
		t.Fatal(err)
	}
	mutate := func(change func(*ConnectorResourceLSTV1File)) []byte {
		var copy ConnectorResourceLSTV1File
		if err := json.Unmarshal(ConnectorResourceLSTV1Vectors(), &copy); err != nil {
			t.Fatal(err)
		}
		change(&copy)
		body, err := json.Marshal(&copy)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, test := range []struct {
		name   string
		body   []byte
		needle string
	}{
		{"schema", mutate(func(f *ConnectorResourceLSTV1File) { f.SchemaVersion++ }), "identity"},
		{"transport", mutate(func(f *ConnectorResourceLSTV1File) { f.Contract.HTTPFallbackAllowed = true }), "contract drift"},
		{"continuity", mutate(func(f *ConnectorResourceLSTV1File) { f.Contract.ExpectedResourceIDRule = "create_if_absent" }), "contract drift"},
		{"replay", mutate(func(f *ConnectorResourceLSTV1File) { f.ReplayCases[0].MutationAllowed = true }), "expectation drift"},
		{"size", mutate(func(f *ConnectorResourceLSTV1File) { f.SizeCases[0].SizeBudgetBytes++ }), "size/outcome drift"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseConnectorResourceLSTV1File(test.body); err == nil || !strings.Contains(err.Error(), test.needle) {
				t.Fatalf("error = %v, want containing %q", err, test.needle)
			}
		})
	}
	if _, err := ParseConnectorResourceLSTV1File(append(ConnectorResourceLSTV1Vectors(), []byte("{}")...)); err == nil {
		t.Fatal("artifact trailing data accepted")
	}
	duplicate := bytes.Replace(ConnectorResourceLSTV1Vectors(), []byte(`  "artifact":`), []byte(`  "artifact":"duplicate",\n  "artifact":`), 1)
	if _, err := ParseConnectorResourceLSTV1File(duplicate); err == nil {
		t.Fatal("artifact duplicate key accepted")
	}
}

func rejectClass(t *testing.T, err error) string {
	t.Helper()
	var validation *ConnectorResourceLSTV1ValidationError
	if !errors.As(err, &validation) {
		return ""
	}
	return validation.RejectClass
}
