package verifysdk

import (
	"encoding/hex"
	"strconv"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
	"github.com/layervai/qurl-go/relayknock"
)

func hexd(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex-decode %q: %v", s, err)
	}
	return b
}

func u64(t *testing.T, s string, base int) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		t.Fatalf("parse uint %q (base %d): %v", s, base, err)
	}
	return v
}

// TestRelayKnockClass closes the behavioral loop for the relay-knock golden
// artifact INSIDE this repo: it rebuilds the knock packet through the real
// relayknock.BuildKnock and asserts it equals the stored packet_hex byte-for-byte,
// then DecryptReply's the frozen ack and asserts the recovered type/counter/
// timestamp/body. A typo in either packet_hex (or a drift in the wire format)
// fails here rather than passing silently.
func TestRelayKnockClass(t *testing.T) {
	rf, err := conformance.RelayKnockGolden()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("knock", func(t *testing.T) {
		k := rf.Knock
		packet, err := relayknock.BuildKnock(&relayknock.KnockInputs{
			DeviceStaticPriv: hexd(t, k.DeviceStaticPrivHex),
			ServerStaticPub:  hexd(t, k.ServerStaticPubHex),
			EphemeralPriv:    hexd(t, k.EphemeralPrivHex),
			TimestampNanos:   u64(t, k.TimestampNanos, 10),
			Counter:          u64(t, k.Counter, 10),
			Preamble:         uint32(u64(t, k.PreambleHex, 16)),
			Body:             hexd(t, k.BodyHex),
		})
		if err != nil {
			t.Fatalf("BuildKnock: %v", err)
		}
		if got := hex.EncodeToString(packet); got != k.PacketHex {
			t.Fatalf("knock packet mismatch:\n got  %s\n want %s", got, k.PacketHex)
		}
	})

	t.Run("ack", func(t *testing.T) {
		a := rf.Ack
		reply, err := relayknock.DecryptReply(
			hexd(t, a.AgentStaticPrivHex),
			hexd(t, a.ServerStaticPubHex),
			hexd(t, a.PacketHex),
		)
		if err != nil {
			t.Fatalf("DecryptReply: %v", err)
		}
		if reply.Type != relayknock.TypeACK {
			t.Fatalf("reply type: got %d want %d (TypeACK)", reply.Type, relayknock.TypeACK)
		}
		if want := u64(t, a.CounterHex, 16); reply.Counter != want {
			t.Fatalf("reply counter: got %d want %d", reply.Counter, want)
		}
		if want := u64(t, a.TimestampNanos, 10); reply.TimestampNanos != want {
			t.Fatalf("reply timestamp_nanos: got %d want %d", reply.TimestampNanos, want)
		}
		if got := hex.EncodeToString(reply.Body); got != a.BodyHex {
			t.Fatalf("reply body mismatch:\n got  %s\n want %s", got, a.BodyHex)
		}
	})
}
