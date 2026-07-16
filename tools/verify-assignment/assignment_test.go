package verifyassignment

import (
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

func TestQURLGoProducerRevisionPin(t *testing.T) {
	module, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	want := "github.com/layervai/qurl-go v0.0.0-20260716040040-" + conformance.AgentAssignmentQURLGoProducerRevision[:12]
	if !strings.Contains(string(module), want) {
		t.Fatalf("go.mod is missing qurl-go producer pin %q", want)
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return decoded
}

func parseUint(t *testing.T, value string, base int) uint64 {
	t.Helper()
	parsed, err := strconv.ParseUint(value, base, 64)
	if err != nil {
		t.Fatalf("parse uint %q base %d: %v", value, base, err)
	}
	return parsed
}

// TestAgentAssignmentClass rebuilds every assignment-lifecycle packet exactly
// and then opens it in the opposite role. This fences deterministic wire
// production and authenticated recovery through qurl-go's exported APIs.
func TestAgentAssignmentClass(t *testing.T) {
	af, err := conformance.AgentAssignmentGolden()
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]conformance.AgentAssignmentKey{
		"hub": af.Keys.Hub, "assigned_cell": af.Keys.AssignedCell, "agent": af.Keys.Agent,
	}

	for _, tc := range []struct {
		name     string
		packet   conformance.AgentAssignmentPacket
		wantType int
		request  bool
	}{
		{"initial_assignment/request", af.InitialAssignment.Request, relayknock.TypeListRequest, true},
		{"initial_assignment/result", af.InitialAssignment.Result, relayknock.TypeListResult, false},
		{"refresh_assignment/request", af.RefreshAssignment.Request, relayknock.TypeListRequest, true},
		{"refresh_assignment/result", af.RefreshAssignment.Result, relayknock.TypeListResult, false},
		{"assigned_cell_registration/request", af.AssignedCellRegistration.Request, relayknock.TypeRegister, true},
		{"assigned_cell_registration/result", af.AssignedCellRegistration.Result, relayknock.TypeRegisterAck, false},
		{"registration_completion/request", af.RegistrationCompletion.Request, relayknock.TypeListRequest, true},
		{"registration_completion/result", af.RegistrationCompletion.Result, relayknock.TypeListResult, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender, senderOK := keys[tc.packet.SenderKey]
			receiver, receiverOK := keys[tc.packet.ReceiverKey]
			if !senderOK || !receiverOK {
				t.Fatalf("unknown key roles %q -> %q", tc.packet.SenderKey, tc.packet.ReceiverKey)
			}
			inputs := &relayknock.KnockInputs{
				DeviceStaticPriv: decodeHex(t, sender.StaticPrivHex),
				ServerStaticPub:  decodeHex(t, receiver.StaticPubHex),
				EphemeralPriv:    decodeHex(t, tc.packet.EphemeralPrivHex),
				TimestampNanos:   parseUint(t, tc.packet.TimestampNanos, 10),
				Counter:          parseUint(t, tc.packet.Counter, 10),
				Preamble:         uint32(parseUint(t, tc.packet.PreambleHex, 16)),
				Body:             []byte(tc.packet.BodyJSON),
			}
			var rebuilt []byte
			var buildErr error
			if tc.request {
				rebuilt, buildErr = relayknock.BuildMessage(tc.wantType, inputs)
			} else {
				rebuilt, buildErr = relayknocktest.BuildReply(tc.wantType, inputs)
			}
			if buildErr != nil {
				t.Fatalf("rebuild: %v", buildErr)
			}
			packet := decodeHex(t, tc.packet.PacketHex)
			if !bytes.Equal(rebuilt, packet) {
				t.Fatalf("rebuilt packet does not match packet_hex:\n got  %x\n want %x", rebuilt, packet)
			}

			var opened *relayknock.Reply
			var openErr error
			if tc.request {
				opened, openErr = relayknocktest.OpenInitiatorMessage(decodeHex(t, receiver.StaticPrivHex), decodeHex(t, sender.StaticPubHex), packet)
			} else {
				opened, openErr = relayknock.DecryptReply(decodeHex(t, receiver.StaticPrivHex), decodeHex(t, sender.StaticPubHex), packet)
			}
			if openErr != nil {
				t.Fatalf("open: %v", openErr)
			}
			if opened.Type != tc.wantType || opened.Counter != inputs.Counter || opened.TimestampNanos != inputs.TimestampNanos {
				t.Fatalf("recovered header = type %d counter %d timestamp %d, want %d/%d/%d", opened.Type, opened.Counter, opened.TimestampNanos, tc.wantType, inputs.Counter, inputs.TimestampNanos)
			}
			if got := string(opened.Body); got != tc.packet.BodyJSON {
				t.Fatalf("recovered body mismatch:\n got  %s\n want %s", got, tc.packet.BodyJSON)
			}
			if got := hex.EncodeToString(opened.Body); got != tc.packet.BodyHex {
				t.Fatalf("recovered body hex mismatch:\n got  %s\n want %s", got, tc.packet.BodyHex)
			}
		})
	}
}
