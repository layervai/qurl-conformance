package verifysdk

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
	"github.com/layervai/qurl-go/relayknock"
)

// NHP header-type values the agent-registration wire uses. qurl-go's exported
// relayknock constants today cover only the reply types a single resolve sees
// (TypeACK / TypeCookieChallenge); the registration types are not yet named in
// the exported API, so we assert the numeric header values the golden artifact
// documents (OTP=12, REG=13, RAK=14). When qurl-go exports TypeOTP/TypeRegister/
// TypeRegisterAck, swap these literals for the named constants.
const (
	nhpTypeOTP         = 12
	nhpTypeRegister    = 13
	nhpTypeRegisterAck = 14
)

// TestAgentRegistrationClass closes the in-repo behavioral loop for the
// agent-registration golden artifact, mirroring TestRelayKnockClass. For every
// packet it runs a real crypto round-trip through the qurl-go SDK's exported
// relayknock.DecryptReply and asserts the recovered header type, transaction
// counter, timestamp, and plaintext body against the stored fields — so a
// hand-edit of any packet_hex (or a drift in the wire format) fails here rather
// than passing silently.
//
// The five packets split into two roles, both openable with the one exported
// primitive (DecryptReply) because the NHP initiator and reply packets share an
// identical Noise sealing structure — ephemeral pub, a static field sealed under
// the es DH, a timestamp sealed under the ss DH, then the body — differing only
// in the header type:
//
//   - RAK replies (rak_success/rak_error) are opened as replies: the agent's
//     static private key is the recipient, the server's static public key the
//     expected peer. This is the exact ack decrypt the relay-knock set performs.
//
//   - OTP/REG requests (otp/reg_emailed/reg_preissued) are initiator packets
//     sealed TO the server, so they open with the key roles swapped: the
//     server's static private key is the recipient and the device's static
//     public key the expected peer. A successful open proves the packet's
//     ephemeral, sealed device-static, sealed timestamp, and sealed body are all
//     internally consistent and bound to the right static keys, and recovers the
//     header type / counter / timestamp / body for assertion.
//
// Coverage vs. limitation. This fence recovers and checks every field an
// external consumer must derive from packet_hex, giving the artifact an in-repo
// decrypt round-trip on top of the authoritative independent cross-language
// fence. It does NOT assert the deterministic OTP/REG packet_hex is byte-for-byte
// REPRODUCIBLE from its inputs (a fixed-ephemeral rebuild-and-compare, as
// TestRelayKnockClass's knock leg does): a re-seal of the same body under a
// different valid ephemeral would still open. The byte-exact rebuild needs a
// type-parameterized single-message initiator builder, which qurl-go does not
// yet export to this module; until it does, the header type is also asserted
// structurally straight off the wire (below) so a header-type edit is caught by
// a clear diagnostic even before the crypto, and the byte-exact rebuild remains
// tracked in layervai/qurl-conformance#21.
func TestAgentRegistrationClass(t *testing.T) {
	af, err := conformance.AgentRegistrationGolden()
	if err != nil {
		t.Fatal(err)
	}

	// OTP/REG initiator requests: open with swapped key roles (server priv is the
	// recipient, device pub the expected peer).
	for _, tc := range []struct {
		name     string
		c        conformance.AgentRegistrationCase
		wantType int
	}{
		{"otp", af.OTP, nhpTypeOTP},
		{"reg_emailed", af.RegEmailed, nhpTypeRegister},
		{"reg_preissued", af.RegPreissued, nhpTypeRegister},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := hexd(t, tc.c.PacketHex)

			// Structural: the wire header decodes to the expected type before any
			// crypto, so a header-type edit fails here with a clear message. (The
			// counter, timestamp, and body are recovered and asserted by the
			// decrypt below.)
			assertHeaderType(t, packet, tc.wantType)

			reply, err := relayknock.DecryptReply(
				hexd(t, tc.c.ServerStaticPrivHex),
				hexd(t, tc.c.DeviceStaticPubHex),
				packet,
			)
			if err != nil {
				t.Fatalf("%s decrypt: %v", tc.name, err)
			}
			if reply.Type != tc.wantType {
				t.Fatalf("%s recovered type: got %d want %d", tc.name, reply.Type, tc.wantType)
			}
			if want := u64(t, tc.c.Counter, 10); reply.Counter != want {
				t.Fatalf("%s recovered counter: got %d want %d", tc.name, reply.Counter, want)
			}
			if want := u64(t, tc.c.TimestampNanos, 10); reply.TimestampNanos != want {
				t.Fatalf("%s recovered timestamp_nanos: got %d want %d", tc.name, reply.TimestampNanos, want)
			}
			if got := hex.EncodeToString(reply.Body); got != tc.c.BodyHex {
				t.Fatalf("%s recovered body mismatch:\n got  %s\n want %s", tc.name, got, tc.c.BodyHex)
			}
		})
	}

	// RAK replies: open as replies (agent priv is the recipient, server pub the
	// expected peer). Frozen at origin, so decrypt-only.
	regCounter := u64(t, af.RegEmailed.Counter, 10)
	for _, tc := range []struct {
		name        string
		c           conformance.AgentRegistrationCase
		wantErrCode string
	}{
		{"rak_success", af.RakSuccess, "0"},
		{"rak_error", af.RakError, "52100"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply, err := relayknock.DecryptReply(
				hexd(t, tc.c.AgentStaticPrivHex),
				hexd(t, tc.c.ServerStaticPubHex),
				hexd(t, tc.c.PacketHex),
			)
			if err != nil {
				t.Fatalf("%s decrypt: %v", tc.name, err)
			}
			if reply.Type != nhpTypeRegisterAck {
				t.Fatalf("%s recovered type: got %d want %d (RAK)", tc.name, reply.Type, nhpTypeRegisterAck)
			}
			// conformance#19: the RAK echoes its REG's transaction counter. Both RAK
			// cases carry counter_hex, and both must equal reg_emailed's counter.
			if want := u64(t, tc.c.CounterHex, 16); reply.Counter != want {
				t.Fatalf("%s recovered counter: got %d want %d", tc.name, reply.Counter, want)
			}
			if reply.Counter != regCounter {
				t.Fatalf("%s counter %d must echo reg_emailed.counter %d", tc.name, reply.Counter, regCounter)
			}
			if want := u64(t, tc.c.TimestampNanos, 10); reply.TimestampNanos != want {
				t.Fatalf("%s recovered timestamp_nanos: got %d want %d", tc.name, reply.TimestampNanos, want)
			}
			if got := hex.EncodeToString(reply.Body); got != tc.c.BodyHex {
				t.Fatalf("%s recovered body mismatch:\n got  %s\n want %s", tc.name, got, tc.c.BodyHex)
			}
			// The recovered body carries the typed accept/deny code: errCode "0"
			// (success) or a "521xx" denial. Assert it to pin the success/error split.
			if got := errCodeOf(t, reply.Body); got != tc.wantErrCode {
				t.Fatalf("%s errCode: got %q want %q", tc.name, got, tc.wantErrCode)
			}
		})
	}
}

// assertHeaderType decodes the NHP header type from the wire packet and fails if
// it is not want. The type+size word is HeaderCommon[0:8]: [0:4] = preamble,
// [4:8] = (type<<16 | size) XOR preamble; the type is the high 16 bits of the
// de-obfuscated word.
func assertHeaderType(t *testing.T, packet []byte, want int) {
	t.Helper()
	if len(packet) < 8 {
		t.Fatalf("packet too short for header type: %d bytes", len(packet))
	}
	preamble := binary.BigEndian.Uint32(packet[0:4])
	tns := preamble ^ binary.BigEndian.Uint32(packet[4:8])
	if got := int((tns >> 16) & 0xffff); got != want {
		t.Fatalf("header type: got %d want %d", got, want)
	}
}

// errCodeOf extracts the errCode field from a decrypted RAK body. The body is
// {errCode, errMsg?, aspId} JSON; errCode is a string ("0"/"" = success, "521xx"
// = a typed denial).
func errCodeOf(t *testing.T, body []byte) string {
	t.Helper()
	var m struct {
		ErrCode string `json:"errCode"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal RAK body: %v", err)
	}
	return m.ErrCode
}
