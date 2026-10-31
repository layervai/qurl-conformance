package conformance

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRelayMatchedCounterRejectsDrift(t *testing.T) {
	tests := []struct {
		name   string
		change func(*RelayKnockFile)
	}{
		{"unknown_schema", func(f *RelayKnockFile) { f.SchemaVersion = 3 }},
		{"matched_in_v1", func(f *RelayKnockFile) { f.SchemaVersion = 1 }},
		{"missing_match", func(f *RelayKnockFile) { f.MatchedAck = nil }},
		{"empty_packet", func(f *RelayKnockFile) { f.MatchedAck.PacketHex = "" }},
		{"empty_body", func(f *RelayKnockFile) { f.MatchedAck.BodyHex = "" }},
		{"bad_request_counter", func(f *RelayKnockFile) { f.Knock.Counter = "18446744073709551616" }},
		{"noncanonical_request_counter", func(f *RelayKnockFile) { f.Knock.Counter = "01" }},
		{"bad_reply_counter", func(f *RelayKnockFile) { f.MatchedAck.CounterHex = "10000000000000000" }},
		{"noncanonical_reply_counter", func(f *RelayKnockFile) { f.MatchedAck.CounterHex = "01" }},
		{"unequal_counters", func(f *RelayKnockFile) { f.MatchedAck.CounterHex = "2" }},
		{"different_server", func(f *RelayKnockFile) { f.MatchedAck.ServerStaticPubHex = "00" }},
		{"different_agent", func(f *RelayKnockFile) { f.MatchedAck.AgentStaticPrivHex = "00" }},
		{"wrong_wire_counter", func(f *RelayKnockFile) {
			b, _ := hex.DecodeString(f.MatchedAck.PacketHex)
			b[23] ^= 1
			f.MatchedAck.PacketHex = hex.EncodeToString(b)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := RelayKnockGolden()
			if err != nil {
				t.Fatal(err)
			}
			tc.change(f)
			b, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRelayKnockFile(b); err == nil {
				t.Fatal("accepted corrupted matched-pair contract")
			}
		})
	}
}

func TestRelayMatchedRejectsWrongHeaderType(t *testing.T) {
	for _, name := range []string{"knock", "matched_ack"} {
		t.Run(name, func(t *testing.T) {
			f, err := RelayKnockGolden()
			if err != nil {
				t.Fatal(err)
			}
			c := &f.Knock
			if name == "matched_ack" {
				c = f.MatchedAck
			}
			packet, err := hex.DecodeString(c.PacketHex)
			if err != nil {
				t.Fatal(err)
			}
			packet[5] ^= 3
			c.PacketHex = hex.EncodeToString(packet)
			b, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRelayKnockFile(b); err == nil || !strings.Contains(err.Error(), "packet header type") {
				t.Fatalf("want header-type rejection, got %v", err)
			}
		})
	}
}

func TestRelayMatchedCounterRejectsShortHeader(t *testing.T) {
	for size := 10; size < 24; size++ {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			f, err := RelayKnockGolden()
			if err != nil {
				t.Fatal(err)
			}
			f.MatchedAck.PacketHex = f.MatchedAck.PacketHex[:size*2]
			b, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRelayKnockFile(b); err == nil || !strings.Contains(err.Error(), "packet lacks a complete counter") {
				t.Fatalf("want incomplete-counter rejection, got %v", err)
			}
		})
	}
}

func TestRelayKnockLegacySchemaCompatibility(t *testing.T) {
	f, err := RelayKnockGolden()
	if err != nil {
		t.Fatal(err)
	}
	if f.SchemaVersion != 2 || f.MatchedAck == nil {
		t.Fatal("embedded corpus must require the matched pair")
	}
	f.SchemaVersion = 1
	f.MatchedAck = nil
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRelayKnockFile(b); err != nil {
		t.Fatalf("legacy corpus must still load: %v", err)
	}
}

func TestRelayMatchedAckRejectsInvalidTimestamp(t *testing.T) {
	for _, timestamp := range []string{"", "0", "-1", "+1", "01", "9223372036854775808"} {
		t.Run(timestamp, func(t *testing.T) {
			f, err := RelayKnockGolden()
			if err != nil {
				t.Fatal(err)
			}
			f.MatchedAck.TimestampNanos = timestamp
			b, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRelayKnockFile(b); err == nil || !strings.Contains(err.Error(), "timestamp_nanos must be canonical positive int64") {
				t.Fatalf("want timestamp rejection, got %v", err)
			}
		})
	}
}
