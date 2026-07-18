package conformance

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestEmbeddedConnectorAuthorityLambdaLoads(t *testing.T) {
	file, err := ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda(): %v", err)
	}
	if file.Artifact != ConnectorAuthorityLambdaArtifactID || file.SchemaVersion != ConnectorAuthorityLambdaSchemaVersion {
		t.Fatalf("identity = %q/v%d, want %q/v%d", file.Artifact, file.SchemaVersion, ConnectorAuthorityLambdaArtifactID, ConnectorAuthorityLambdaSchemaVersion)
	}
	if len(file.Operations) != 5 {
		t.Fatalf("operation count = %d, want 5", len(file.Operations))
	}
	for _, operation := range connectorAuthorityOperationNames {
		op := file.Operations[operation]
		if err := validateConnectorAuthorityRequest(operation, []byte(op.RequestGolden.BodyJSON)); err != nil {
			t.Errorf("%s request golden: %v", operation, err)
		}
		if outcome, err := validateConnectorAuthorityResponse(operation, []byte(op.SuccessGolden.BodyJSON)); err != nil || outcome != "success" {
			t.Errorf("%s success golden = %q, %v", operation, outcome, err)
		}
		assertConnectorAuthorityRequestHasNoCallerAuthority(t, operation, op.RequestGolden.BodyJSON)
	}
}

func TestConnectorAuthorityPublicMappingsFreezeCriticalDispositions(t *testing.T) {
	file, err := ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda(): %v", err)
	}
	assertMapping := func(operation, name, source, action, bodyPart, recovery string) {
		t.Helper()
		for _, mapping := range file.Operations[operation].PublicMappingCases {
			if mapping.Name != name {
				continue
			}
			bodyMatches := bodyPart == "" && mapping.NHPBodyJSON == "" || bodyPart != "" && strings.Contains(mapping.NHPBodyJSON, bodyPart)
			if mapping.MappingSource != source || mapping.NHPAction != action || !bodyMatches || mapping.RecoveryAction != recovery {
				t.Fatalf("%s/%s mapping = %+v", operation, name, mapping)
			}
			return
		}
		t.Fatalf("%s/%s mapping is missing", operation, name)
	}

	assertMapping(ConnectorAuthorityOperationIssueAssignment, "credential_consumed", ConnectorAuthorityMappingSourceResponse, ConnectorAuthorityNHPActionEmitLRT, `"52108"`, ConnectorAuthorityRecoveryNone)
	assertMapping(ConnectorAuthorityOperationIssueAssignment, "registration_disabled", ConnectorAuthorityMappingSourcePreInvoke, ConnectorAuthorityNHPActionEmitLRT, `"52107"`, ConnectorAuthorityRecoveryNone)
	assertMapping(ConnectorAuthorityOperationIssueAssignment, "assignment_rate_limited", ConnectorAuthorityMappingSourcePreInvoke, ConnectorAuthorityNHPActionEmitLRT, `"52204"`, ConnectorAuthorityRecoveryNone)
	assertMapping(ConnectorAuthorityOperationRefreshAssignment, "assignment_rate_limited", ConnectorAuthorityMappingSourcePreInvoke, ConnectorAuthorityNHPActionEmitLRT, `"52204"`, ConnectorAuthorityRecoveryNone)
	assertMapping(ConnectorAuthorityOperationActivateRegistration, "ticket_expired", ConnectorAuthorityMappingSourceResponse, ConnectorAuthorityNHPActionEmitRAK, `"52111"`, ConnectorAuthorityRecoveryNone)
	assertMapping(ConnectorAuthorityOperationActivateRegistration, "unavailable", ConnectorAuthorityMappingSourceResponse, ConnectorAuthorityNHPActionDropNoReply, "", ConnectorAuthorityRecoveryPendingExact)
}

func TestParseConnectorAuthorityLambdaFileFailsClosed(t *testing.T) {
	raw := ConnectorAuthorityLambdaVectors()
	mutate := func(t *testing.T, change func(*ConnectorAuthorityLambdaFile)) []byte {
		t.Helper()
		var file ConnectorAuthorityLambdaFile
		if err := json.Unmarshal(raw, &file); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		change(&file)
		body, err := json.Marshal(file)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		return body
	}
	assertRejects := func(t *testing.T, body []byte, contains string) {
		t.Helper()
		if _, err := ParseConnectorAuthorityLambdaFile(body); err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("error = %v, want rejection containing %q", err, contains)
		}
	}

	t.Run("artifact", func(t *testing.T) {
		assertRejects(t, mutate(t, func(file *ConnectorAuthorityLambdaFile) { file.Artifact = "other" }), "artifact")
	})
	t.Run("protocol", func(t *testing.T) {
		assertRejects(t, mutate(t, func(file *ConnectorAuthorityLambdaFile) { file.Protocol.MaxRequestBytes++ }), "protocol")
	})
	t.Run("fixture secrets differ", func(t *testing.T) {
		assertRejects(t, mutate(t, func(file *ConnectorAuthorityLambdaFile) {
			file.Fixtures.DeviceAPIKey = file.Fixtures.Credential
		}), "must differ")
	})
	t.Run("missing operation", func(t *testing.T) {
		assertRejects(t, mutate(t, func(file *ConnectorAuthorityLambdaFile) {
			delete(file.Operations, ConnectorAuthorityOperationRefreshAssignment)
		}), "operation count")
	})
	t.Run("golden request", func(t *testing.T) {
		assertRejects(t, mutate(t, func(file *ConnectorAuthorityLambdaFile) {
			op := file.Operations[ConnectorAuthorityOperationActivateRegistration]
			op.RequestGolden.BodyJSON = strings.Replace(op.RequestGolden.BodyJSON, `"registration_credential":"01234567"`, `"registration_credential":null`, 1)
			file.Operations[ConnectorAuthorityOperationActivateRegistration] = op
		}), "request golden")
	})
	t.Run("semantic code", func(t *testing.T) {
		assertRejects(t, mutate(t, func(file *ConnectorAuthorityLambdaFile) {
			op := file.Operations[ConnectorAuthorityOperationCompleteRegistration]
			op.SemanticErrors[0].Code = "future_error"
			file.Operations[ConnectorAuthorityOperationCompleteRegistration] = op
		}), "semantic error")
	})
	t.Run("semantic body canonical bytes", func(t *testing.T) {
		assertRejects(t, mutate(t, func(file *ConnectorAuthorityLambdaFile) {
			op := file.Operations[ConnectorAuthorityOperationRefreshAssignment]
			op.SemanticErrors[0].BodyJSON = strings.Replace(op.SemanticErrors[0].BodyJSON, `{"version":1,`, `{ "version":1,`, 1)
			file.Operations[ConnectorAuthorityOperationRefreshAssignment] = op
		}), "not canonical")
	})
	t.Run("reject body must prove claimed class", func(t *testing.T) {
		assertRejects(t, mutate(t, func(file *ConnectorAuthorityLambdaFile) {
			op := file.Operations[ConnectorAuthorityOperationCompleteRegistration]
			var missingBody string
			for _, reject := range op.RequestRejects {
				if reject.Name == "reject_missing_field" {
					missingBody = reject.BodyJSON
				}
			}
			for index := range op.RequestRejects {
				if op.RequestRejects[index].Name == "reject_null_field" {
					op.RequestRejects[index].BodyJSON = missingBody
				}
			}
			file.Operations[ConnectorAuthorityOperationCompleteRegistration] = op
		}), "class")
	})
	t.Run("malformed reject cannot alias missing field", func(t *testing.T) {
		assertRejects(t, mutate(t, func(file *ConnectorAuthorityLambdaFile) {
			op := file.Operations[ConnectorAuthorityOperationRefreshAssignment]
			for index := range op.RequestRejects {
				if op.RequestRejects[index].Name == "reject_missing_field" {
					op.RequestRejects[index].BodyJSON = `{"version":1`
				}
			}
			file.Operations[ConnectorAuthorityOperationRefreshAssignment] = op
		}), "class")
	})
	t.Run("mapping", func(t *testing.T) {
		assertRejects(t, mutate(t, func(file *ConnectorAuthorityLambdaFile) {
			op := file.Operations[ConnectorAuthorityOperationActivateRegistration]
			op.PublicMappingCases[len(op.PublicMappingCases)-1].NHPAction = ConnectorAuthorityNHPActionEmitRAK
			file.Operations[ConnectorAuthorityOperationActivateRegistration] = op
		}), "public disposition")
	})
	t.Run("duplicate top-level key", func(t *testing.T) {
		body := bytes.Replace(raw, []byte("{\n"), []byte("{\n  \"artifact\": \"duplicate\",\n"), 1)
		assertRejects(t, body, "duplicate")
	})
	t.Run("malformed UTF-8 artifact", func(t *testing.T) {
		body := bytes.Clone(raw)
		index := bytes.Index(body, []byte("Strict private"))
		if index < 0 {
			t.Fatal("artifact description marker missing")
		}
		body[index] = 0xff
		assertRejects(t, body, "UTF-8")
	})
}

func TestConnectorAuthorityResponsePresenceAndNullPolicy(t *testing.T) {
	cases := []string{
		`{"version":1,"result":null,"error":{"code":"unavailable"}}`,
		`{"version":1,"result":{},"error":null}`,
		`{"version":1,"error":{"code":"unavailable","retry_after_seconds":null}}`,
		`{"version":1,"error":{"code":"rate_limited","retry_after_seconds":null}}`,
	}
	for _, body := range cases {
		if _, err := validateConnectorAuthorityResponse(ConnectorAuthorityOperationIssueRegistrationOTP, []byte(body)); err == nil {
			t.Errorf("response with ambiguous/null presence unexpectedly accepted: %s", body)
		}
	}
	for _, body := range cases[:2] {
		if got := classifyConnectorAuthorityResponseReject(ConnectorAuthorityOperationIssueRegistrationOTP, []byte(body)); got != "response_xor" {
			t.Errorf("both-present response class = %q, want response_xor: %s", got, body)
		}
	}
	for _, body := range cases[2:] {
		if got := classifyConnectorAuthorityResponseReject(ConnectorAuthorityOperationIssueRegistrationOTP, []byte(body)); got != "null_field" {
			t.Errorf("null retry_after_seconds class = %q, want null_field: %s", got, body)
		}
	}
}

func TestConnectorAuthorityVersionClassifierHandlesAbsentRawMessage(t *testing.T) {
	if got := classifyConnectorAuthorityVersionLexeme(nil); got != "missing_field" {
		t.Fatalf("absent version class = %q, want missing_field", got)
	}
}

func TestConnectorAuthorityRejectsMalformedUTF8BeforeJSONDecode(t *testing.T) {
	file, err := ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda(): %v", err)
	}
	request := []byte(file.Operations[ConnectorAuthorityOperationIssueAssignment].RequestGolden.BodyJSON)
	requestIndex := bytes.Index(request, []byte(file.Fixtures.AgentID))
	if requestIndex < 0 {
		t.Fatal("request agent_id marker missing")
	}
	request[requestIndex] = 0xff
	if err := validateConnectorAuthorityRequest(ConnectorAuthorityOperationIssueAssignment, request); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("malformed UTF-8 request error = %v", err)
	}
	response := []byte(file.Operations[ConnectorAuthorityOperationIssueAssignment].SuccessGolden.BodyJSON)
	responseIndex := bytes.Index(response, []byte(file.Fixtures.AgentID))
	if responseIndex < 0 {
		t.Fatal("response agent_id marker missing")
	}
	response[responseIndex] = 0xff
	if _, err := validateConnectorAuthorityResponse(ConnectorAuthorityOperationIssueAssignment, response); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("malformed UTF-8 response error = %v", err)
	}
}

func TestConnectorAuthorityIssueAssignmentTicketExpiresBeforeLease(t *testing.T) {
	file, err := ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda(): %v", err)
	}
	response := file.Operations[ConnectorAuthorityOperationIssueAssignment].SuccessGolden.BodyJSON
	response = strings.Replace(response, file.Fixtures.AssignmentTicketExpiresAt, file.Fixtures.LeaseExpiresAt, 1)
	if _, err := validateConnectorAuthorityResponse(ConnectorAuthorityOperationIssueAssignment, []byte(response)); err == nil {
		t.Fatal("assignment ticket expiry equal to lease expiry unexpectedly accepted")
	}
}

func TestConnectorAuthorityDeviceSecretIsDistinctAndNeverPublic(t *testing.T) {
	file, err := ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda(): %v", err)
	}
	if file.Fixtures.DeviceAPIKey == file.Fixtures.Credential {
		t.Fatal("device API key reuses the initial credential")
	}
	for operation, contract := range file.Operations {
		for _, mapping := range contract.PublicMappingCases {
			if strings.Contains(mapping.NHPBodyJSON, file.Fixtures.DeviceAPIKey) {
				t.Errorf("%s/%s public body exposes the device API key", operation, mapping.Name)
			}
		}
	}
}

func TestConnectorAuthorityAssignmentTicketLimitMatchesQAT1(t *testing.T) {
	authority, err := ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda(): %v", err)
	}
	assignmentTicket, err := AssignmentTicket()
	if err != nil {
		t.Fatalf("AssignmentTicket(): %v", err)
	}
	if got, want := authority.Protocol.MaxAssignmentTicketASCIIBytes, assignmentTicket.Contract.MaxTicketASCIIBytes; got != want || got != ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes {
		t.Fatalf("private max ticket bytes = %d, qat1 = %d, constant = %d", got, want, ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes)
	}

	request := authority.Operations[ConnectorAuthorityOperationIssueRegistrationOTP].RequestGolden.BodyJSON
	request = strings.Replace(request, authority.Fixtures.AssignmentTicket, strings.Repeat("a", ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes), 1)
	if err := validateConnectorAuthorityRequest(ConnectorAuthorityOperationIssueRegistrationOTP, []byte(request)); err != nil {
		t.Fatalf("shared ticket limit unexpectedly rejected: %v", err)
	}
	overLimit := strings.Replace(request, strings.Repeat("a", ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes), strings.Repeat("a", ConnectorAuthorityLambdaMaxAssignmentTicketASCIIBytes+1), 1)
	if err := validateConnectorAuthorityRequest(ConnectorAuthorityOperationIssueRegistrationOTP, []byte(overLimit)); err == nil {
		t.Fatal("ticket above shared qat1 limit unexpectedly accepted")
	}
}

func TestConnectorAuthorityPlacementValidationMatchesProducer(t *testing.T) {
	validHosts := []string{"cell0.nhp.layerv.ai", "cell-123.nhp.layerv.xyz"}
	for _, host := range validHosts {
		if !validConnectorAuthorityHost(host) {
			t.Errorf("valid host %q rejected", host)
		}
	}
	invalidHosts := []string{
		".layerv.ai",
		"cell..nhp.layerv.ai",
		strings.Repeat("a", 64) + ".nhp.layerv.ai",
		strings.Repeat("a.", 126) + "layerv.ai",
		"internal.nhp.layerv.ai",
		"localhost.nhp.layerv.ai",
		"metadata.nhp.layerv.ai",
		"private.nhp.layerv.ai",
		"Cell0.nhp.layerv.ai",
		"cell0.nhp.layerv.ai.",
		"cell0.nhp.amazonaws.com",
	}
	for _, host := range invalidHosts {
		if validConnectorAuthorityHost(host) {
			t.Errorf("invalid host %q accepted", host)
		}
	}

	validCellIDs := []string{"a", "cell0", "a-1", "a" + strings.Repeat("1", 63)}
	for _, cellID := range validCellIDs {
		if !connectorAuthorityCellIDPattern.MatchString(cellID) {
			t.Errorf("valid cell_id %q rejected", cellID)
		}
	}
	invalidCellIDs := []string{"", "0cell", "Cell0", "cell_0", "cell-", "a" + strings.Repeat("1", 64)}
	for _, cellID := range invalidCellIDs {
		if connectorAuthorityCellIDPattern.MatchString(cellID) {
			t.Errorf("invalid cell_id %q accepted", cellID)
		}
	}
}

func TestConnectorAuthorityServerKeyRejectsNoncanonicalAndLowOrderX25519(t *testing.T) {
	noncanonicalPrime := bytes.Repeat([]byte{0xff}, 32)
	noncanonicalPrime[0] = 0xed
	noncanonicalPrime[31] = 0x7f
	cases := map[string][]byte{
		"field prime": noncanonicalPrime,
		"high bit":    append(bytes.Repeat([]byte{0}, 31), 0x80),
		"low order":   make([]byte, 32),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString(raw)
			if err := validateConnectorAuthorityX25519ServerKey(encoded); err == nil {
				t.Fatalf("server key %s unexpectedly accepted", encoded)
			}
		})
	}
}

func TestConnectorAuthorityPublicBodiesMatchAgentAssignmentArtifact(t *testing.T) {
	authority, err := ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda(): %v", err)
	}
	assignment, err := AgentAssignmentGolden()
	if err != nil {
		t.Fatalf("AgentAssignmentGolden(): %v", err)
	}

	publicErrors := make(map[string]string)
	for _, cases := range [][]AgentAssignmentErrorCase{
		assignment.ErrorContract.AssignmentCases,
		assignment.ErrorContract.InitialCredentialCases,
		assignment.ErrorContract.CompletionCases,
		assignment.ErrorContract.RegistrationCases,
	} {
		for _, publicCase := range cases {
			publicErrors[publicCase.ErrCode] = publicCase.BodyJSON
		}
	}
	privateBody := func(operation, name string) string {
		t.Helper()
		for _, mapping := range authority.Operations[operation].PublicMappingCases {
			if mapping.Name == name {
				return mapping.NHPBodyJSON
			}
		}
		t.Fatalf("private mapping %s/%s missing", operation, name)
		return ""
	}
	errorBody := func(code string) string {
		t.Helper()
		body, ok := publicErrors[code]
		if !ok {
			t.Fatalf("public agent-assignment error %s missing", code)
		}
		return body
	}

	cases := []struct {
		name      string
		operation string
		outcome   string
		want      string
	}{
		{name: "initial invalid request", operation: ConnectorAuthorityOperationIssueAssignment, outcome: "invalid_request", want: errorBody("52109")},
		{name: "initial credential invalid", operation: ConnectorAuthorityOperationIssueAssignment, outcome: "credential_invalid", want: errorBody("52106")},
		{name: "initial credential consumed", operation: ConnectorAuthorityOperationIssueAssignment, outcome: "credential_consumed", want: errorBody("52108")},
		{name: "initial unavailable", operation: ConnectorAuthorityOperationIssueAssignment, outcome: "unavailable", want: errorBody("52200")},
		{name: "initial registration disabled", operation: ConnectorAuthorityOperationIssueAssignment, outcome: "registration_disabled", want: errorBody("52107")},
		{name: "initial rate limited", operation: ConnectorAuthorityOperationIssueAssignment, outcome: "assignment_rate_limited", want: errorBody("52204")},
		{name: "refresh success", operation: ConnectorAuthorityOperationRefreshAssignment, outcome: "success", want: assignment.RefreshAssignment.Result.BodyJSON},
		{name: "refresh invalid request", operation: ConnectorAuthorityOperationRefreshAssignment, outcome: "invalid_request", want: errorBody("52205")},
		{name: "refresh identity rejected", operation: ConnectorAuthorityOperationRefreshAssignment, outcome: "identity_rejected", want: errorBody("52201")},
		{name: "refresh reassignment", operation: ConnectorAuthorityOperationRefreshAssignment, outcome: "reassignment_in_progress", want: errorBody("52202")},
		{name: "refresh unavailable", operation: ConnectorAuthorityOperationRefreshAssignment, outcome: "unavailable", want: errorBody("52200")},
		{name: "refresh rate limited", operation: ConnectorAuthorityOperationRefreshAssignment, outcome: "assignment_rate_limited", want: errorBody("52204")},
		{name: "activation success", operation: ConnectorAuthorityOperationActivateRegistration, outcome: "success", want: assignment.AssignedCellRegistration.Result.BodyJSON},
		{name: "activation identity conflict", operation: ConnectorAuthorityOperationActivateRegistration, outcome: "identity_conflict", want: errorBody("52103")},
		{name: "activation ticket invalid", operation: ConnectorAuthorityOperationActivateRegistration, outcome: "ticket_invalid", want: errorBody("52110")},
		{name: "activation not yet valid", operation: ConnectorAuthorityOperationActivateRegistration, outcome: "not_yet_valid", want: errorBody("52110")},
		{name: "activation ticket expired", operation: ConnectorAuthorityOperationActivateRegistration, outcome: "ticket_expired", want: errorBody("52111")},
		{name: "activation quota", operation: ConnectorAuthorityOperationActivateRegistration, outcome: "quota", want: errorBody("52112")},
		{name: "completion success", operation: ConnectorAuthorityOperationCompleteRegistration, outcome: "success", want: assignment.RegistrationCompletion.Result.BodyJSON},
		{name: "completion invalid request", operation: ConnectorAuthorityOperationCompleteRegistration, outcome: "invalid_request", want: errorBody("52304")},
		{name: "completion identity rejected", operation: ConnectorAuthorityOperationCompleteRegistration, outcome: "identity_rejected", want: errorBody("52301")},
		{name: "completion quota", operation: ConnectorAuthorityOperationCompleteRegistration, outcome: "quota", want: errorBody("52302")},
		{name: "completion conflict", operation: ConnectorAuthorityOperationCompleteRegistration, outcome: "conflict", want: errorBody("52303")},
		{name: "completion unavailable", operation: ConnectorAuthorityOperationCompleteRegistration, outcome: "unavailable", want: errorBody("52300")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := privateBody(testCase.operation, testCase.outcome); got != testCase.want {
				t.Fatalf("private public body = %s, agent_assignment_golden = %s", got, testCase.want)
			}
		})
	}

	// The IssueAssignment success fixtures intentionally do not overlap: this
	// private artifact exercises an account credential, while the public
	// artifact's positive initial exchange exercises a bootstrap credential.
}

func TestConnectorAuthorityActivateExplicitEmptyMetadataStillRequiresMembers(t *testing.T) {
	file, err := ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda(): %v", err)
	}
	request := file.Operations[ConnectorAuthorityOperationActivateRegistration].RequestGolden.BodyJSON
	request = strings.Replace(request, `"hostname":"builder-01"`, `"hostname":""`, 1)
	request = strings.Replace(request, `"agent_version":"0.1.0"`, `"agent_version":""`, 1)
	if err := validateConnectorAuthorityRequest(ConnectorAuthorityOperationActivateRegistration, []byte(request)); err != nil {
		t.Fatalf("explicit empty metadata values: %v", err)
	}
	for _, field := range []string{"hostname", "agent_version"} {
		missing := removeConnectorAuthorityJSONField(t, request, field)
		if err := validateConnectorAuthorityRequest(ConnectorAuthorityOperationActivateRegistration, []byte(missing)); err == nil {
			t.Errorf("missing %s unexpectedly accepts", field)
		}
		null := strings.Replace(request, `"`+field+`":""`, `"`+field+`":null`, 1)
		if err := validateConnectorAuthorityRequest(ConnectorAuthorityOperationActivateRegistration, []byte(null)); err == nil {
			t.Errorf("null %s unexpectedly accepts", field)
		}
	}
}

func TestConnectorAuthorityActivateEmptyProofIsReplayCandidateButMemberRequired(t *testing.T) {
	file, err := ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda(): %v", err)
	}
	request := file.Operations[ConnectorAuthorityOperationActivateRegistration].RequestGolden.BodyJSON
	empty := strings.Replace(request, `"registration_credential":"01234567"`, `"registration_credential":""`, 1)
	// Shape validation cannot know replay state. The service may accept this only
	// after replay-first lookup finds a durable committed activation; an empty
	// proof never authorizes first use.
	if err := validateConnectorAuthorityRequest(ConnectorAuthorityOperationActivateRegistration, []byte(empty)); err != nil {
		t.Fatalf("explicit empty replay candidate: %v", err)
	}
	missing := removeConnectorAuthorityJSONField(t, request, "registration_credential")
	if err := validateConnectorAuthorityRequest(ConnectorAuthorityOperationActivateRegistration, []byte(missing)); err == nil {
		t.Fatal("missing registration proof unexpectedly accepted")
	}
	null := strings.Replace(request, `"registration_credential":"01234567"`, `"registration_credential":null`, 1)
	if err := validateConnectorAuthorityRequest(ConnectorAuthorityOperationActivateRegistration, []byte(null)); err == nil {
		t.Fatal("null registration proof unexpectedly accepted")
	}
}

func TestConnectorAuthorityRejectsCaseAliasSmugglingAtEveryObjectBoundary(t *testing.T) {
	file, err := ConnectorAuthorityLambda()
	if err != nil {
		t.Fatalf("ConnectorAuthorityLambda(): %v", err)
	}
	request := file.Operations[ConnectorAuthorityOperationIssueAssignment].RequestGolden.BodyJSON
	request = strings.Replace(request, `"agent_id":"agent-conform"`, `"agent_id":"agent-conform","Agent_ID":"smuggled-agent"`, 1)
	if err := validateConnectorAuthorityRequest(ConnectorAuthorityOperationIssueAssignment, []byte(request)); err == nil {
		t.Fatal("request canonical-plus-alias smuggling unexpectedly accepted")
	}

	errorResponse := `{"version":1,"error":{"code":"unavailable","Code":"invalid_request"}}`
	if _, err := validateConnectorAuthorityResponse(ConnectorAuthorityOperationIssueAssignment, []byte(errorResponse)); err == nil {
		t.Fatal("nested error canonical-plus-alias smuggling unexpectedly accepted")
	}

	success := file.Operations[ConnectorAuthorityOperationIssueAssignment].SuccessGolden.BodyJSON
	mutations := map[string][2]string{
		"response envelope": {`"result":{`, `"result":{},"Result":{`},
		"result":            {`"agent_id":"agent-conform"`, `"agent_id":"agent-conform","Agent_ID":"smuggled-agent"`},
		"registration":      {`"key_id":"key_A1b2C3d4E5f6"`, `"key_id":"key_A1b2C3d4E5f6","Key_ID":"smuggled"`},
		"assignment":        {`"cell_id":"cell0"`, `"cell_id":"cell0","Cell_ID":"smuggled"`},
		"endpoint":          {`"host":"cell0.nhp.layerv.ai"`, `"host":"cell0.nhp.layerv.ai","Host":"private.nhp.layerv.ai"`},
	}
	for name, replacement := range mutations {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(success, replacement[0], replacement[1], 1)
			if _, err := validateConnectorAuthorityResponse(ConnectorAuthorityOperationIssueAssignment, []byte(body)); err == nil {
				t.Fatal("canonical-plus-alias smuggling unexpectedly accepted")
			}
		})
	}
}

func assertConnectorAuthorityRequestHasNoCallerAuthority(t *testing.T, operation, body string) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &object); err != nil {
		t.Fatalf("%s request JSON: %v", operation, err)
	}
	for _, forbidden := range []string{"operation", "environment", "environment_id", "cell", "cell_id", "owner", "owner_id", "assignment_generation", "completion_generation"} {
		if _, ok := object[forbidden]; ok {
			t.Errorf("%s request contains caller-authority field %q", operation, forbidden)
		}
	}
}

func removeConnectorAuthorityJSONField(t *testing.T, body, field string) string {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &object); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	delete(object, field)
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(encoded)
}
