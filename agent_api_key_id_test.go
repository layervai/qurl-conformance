package conformance

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEmbeddedAgentAPIKeyIDsLoad(t *testing.T) {
	af, err := AgentAPIKeyIDs()
	if err != nil {
		t.Fatalf("AgentAPIKeyIDs(): %v", err)
	}
	if af.Artifact != AgentAPIKeyIDArtifactID || af.SchemaVersion != AgentAPIKeyIDSchemaVersion {
		t.Fatalf("identity = %q/v%d, want %q/v%d", af.Artifact, af.SchemaVersion, AgentAPIKeyIDArtifactID, AgentAPIKeyIDSchemaVersion)
	}
	if af.Contract.Pattern != AgentAPIKeyIDPattern || af.Contract.TotalLength != AgentAPIKeyIDTotalLength {
		t.Fatalf("contract = %+v, want pattern %q and length %d", af.Contract, AgentAPIKeyIDPattern, AgentAPIKeyIDTotalLength)
	}
	if len(af.Surfaces) != 2 || len(af.ProducerCases) != 4 || len(af.ConsumerValueCases) != 13 || len(af.ConsumerResponseCases) != 22 {
		t.Fatalf("fixture counts = surfaces:%d producer:%d values:%d responses:%d", len(af.Surfaces), len(af.ProducerCases), len(af.ConsumerValueCases), len(af.ConsumerResponseCases))
	}

	for _, c := range af.ProducerCases {
		if got := AgentAPIKeyIDPrefix + c.Suffix; got != c.ExpectedID || !isCanonicalAgentAPIKeyID(got) {
			t.Errorf("producer %q = %q, want canonical %q", c.Name, got, c.ExpectedID)
		}
	}
	for _, c := range af.ConsumerValueCases {
		got := ExpectReject
		if isCanonicalAgentAPIKeyID(c.Value) {
			got = ExpectAccept
		}
		if got != c.Outcome {
			t.Errorf("value %q derived outcome = %q, want %q", c.Name, got, c.Outcome)
		}
	}
	for _, c := range af.ConsumerResponseCases {
		outcome, id, rejectClass := deriveAgentAPIKeyIDResponse(c.Surface, []byte(c.BodyJSON))
		if outcome != c.Outcome || id != c.ExpectedID || rejectClass != c.RejectClass {
			t.Errorf("response %q derived = %q/%q/%q, want %q/%q/%q", c.Name, outcome, id, rejectClass, c.Outcome, c.ExpectedID, c.RejectClass)
		}
	}
}

func TestParseAgentAPIKeyIDFileFailsClosed(t *testing.T) {
	raw := AgentAPIKeyIDVectors()
	mutate := func(t *testing.T, change func(*AgentAPIKeyIDFile)) []byte {
		t.Helper()
		var af AgentAPIKeyIDFile
		if err := json.Unmarshal(raw, &af); err != nil {
			t.Fatal(err)
		}
		change(&af)
		b, err := json.Marshal(af)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	assertRejects := func(t *testing.T, body []byte, contains string) {
		t.Helper()
		if _, err := ParseAgentAPIKeyIDFile(body); err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("error = %v, want text %q", err, contains)
		}
	}

	t.Run("artifact", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.Artifact = "other" }), "artifact")
	})
	t.Run("schema", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.SchemaVersion++ }), "schema_version")
	})
	t.Run("contract", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.Contract.SuffixLength++ }), "contract")
	})
	t.Run("surface", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.Surfaces[0].WireField = "keyId" }), "wire_field")
	})
	t.Run("producer expected id", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.ProducerCases[0].ExpectedID = "key_012345678901" }), "producer case")
	})
	t.Run("value", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.ConsumerValueCases[0].Value = "key_short" }), "consumer value case")
	})
	t.Run("value expectation", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.ConsumerValueCases[0].Outcome = ExpectReject }), "expectation")
	})
	t.Run("response body", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.ConsumerResponseCases[0].BodyJSON = `{}` }), "consumer response case")
	})
	t.Run("response expectation", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.ConsumerResponseCases[0].ExpectedID = "key_012345678901" }), "expectation")
	})
	t.Run("duplicate response case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.ConsumerResponseCases[1] = af.ConsumerResponseCases[0] }), "duplicate")
	})
	t.Run("unknown response case", func(t *testing.T) {
		assertRejects(t, mutate(t, func(af *AgentAPIKeyIDFile) { af.ConsumerResponseCases[0].Name = "future_case" }), "unknown")
	})
}
