package conformance

import (
	"bytes"
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

	for _, oldRequest := range []string{
		strings.Replace(requestJSON, `"connector_id":`, `"expected_resource_id":"legacy-key","connector_id":`, 1),
		strings.Replace(requestJSON, `"connector_id":`, `"expected_crid":"`+file.Fixtures.ResourcePublicKey+`","connector_id":`, 1),
	} {
		if _, err := ParseConnectorResourceLSTV1RequestBody([]byte(oldRequest), file.Fixtures.AgentID); err == nil {
			t.Fatal("accepted a public-key continuity request")
		}
	}
	goodResult := file.SuccessExchanges[0].Result.BodyJSON
	for _, oldResult := range []string{
		strings.Replace(goodResult, `"resource_public_key":`, `"resource_id":`, 1),
		strings.Replace(goodResult, `,"crid":"`+file.Fixtures.CRID+`"`, "", 1),
		strings.Replace(goodResult, `"crid":"`+file.Fixtures.CRID+`"`, `"crid":null`, 1),
	} {
		if oldResult == goodResult {
			t.Fatal("old-field fixture did not change")
		}
		if _, err := ParseConnectorResourceLSTV1ResultBody([]byte(oldResult), request); err == nil {
			t.Fatal("accepted a resource-ID or CRID-less result")
		}
	}
	wrongExpected := cridV1IssuerProdCRID
	request.UsrData.ExpectedCRID = &wrongExpected
	if _, err := ParseConnectorResourceLSTV1ResultBody([]byte(goodResult), request); rejectClass(t, err) != ConnectorResourceLSTV1RejectResourceBinding {
		t.Fatalf("expected-resource mismatch = %v", err)
	}
	if _, err := ParseConnectorResourceLSTV1ResultBody([]byte(goodResult), nil); rejectClass(t, err) != ConnectorResourceLSTV1RejectRequestBinding {
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
		{"create nonce", mutate(func(f *ConnectorResourceLSTV1File) { f.SuccessExchanges[0].Request = f.SuccessExchanges[2].Request }), "fresh_create requires"},
		{"existing nonce", mutate(func(f *ConnectorResourceLSTV1File) {
			f.SuccessExchanges[1].Request.BodyJSON = strings.Replace(f.SuccessExchanges[1].Request.BodyJSON, f.Fixtures.ExistingRequestNonce, f.Fixtures.CreateRequestNonce, 1)
		}), "existing_with_continuity requires"},
		{"unpinned request", mutate(func(f *ConnectorResourceLSTV1File) { f.SuccessExchanges[2].Request = f.SuccessExchanges[1].Request }), "unpinned exchange"},
		{"trailing crid", mutate(func(f *ConnectorResourceLSTV1File) { f.SuccessExchanges[2].Result = f.SuccessExchanges[1].Result }), "trailing crid"},
		{"schema", mutate(func(f *ConnectorResourceLSTV1File) { f.SchemaVersion++ }), "identity"},
		{"transport", mutate(func(f *ConnectorResourceLSTV1File) { f.Contract.HTTPFallbackAllowed = true }), "contract drift"},
		{"continuity", mutate(func(f *ConnectorResourceLSTV1File) { f.Contract.ExpectedCRIDRule = "create_if_absent" }), "contract drift"},
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
