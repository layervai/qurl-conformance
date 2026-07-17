package verifysdk

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
	"github.com/layervai/qurl-go/relayknock"
	"golang.org/x/crypto/blake2s"
)

var sessionInitialHash = []byte("NHP hashgen v.20230421@deepcloudsdp.com")

func TestAgentSessionControlGolden(t *testing.T) {
	af, err := conformance.AgentSessionControl()
	if err != nil {
		t.Fatal(err)
	}
	agentPrivate := hexd(t, af.Keys.Agent.StaticPrivateHex)
	agentPublic := hexd(t, af.Keys.Agent.StaticPublicHex)
	cellPrivate := hexd(t, af.Keys.AssignedCell.StaticPrivateHex)
	cellPublic := hexd(t, af.Keys.AssignedCell.StaticPublicHex)
	cookie := hexd(t, af.OverloadReknock.CookieHex)

	requests := []struct {
		name   string
		packet conformance.AgentSessionPacket
		cookie []byte
	}{
		{"knock", af.OverloadReknock.KnockRequest, nil},
		{"reknock", af.OverloadReknock.ReknockRequest, cookie},
		{"exit", af.CleanExit.Request, nil},
	}
	for _, tc := range requests {
		t.Run(tc.name+"_rebuild", func(t *testing.T) {
			got, err := relayknock.BuildKnock(&relayknock.KnockInputs{
				DeviceStaticPriv: agentPrivate,
				ServerStaticPub:  cellPublic,
				EphemeralPriv:    hexd(t, tc.packet.EphemeralPrivateHex),
				TimestampNanos:   u64(t, tc.packet.TimestampNanos, 10),
				Counter:          u64(t, tc.packet.Counter, 10),
				Preamble:         uint32(u64(t, tc.packet.PreambleHex, 16)),
				Body:             []byte(tc.packet.BodyJSON),
			})
			if err != nil {
				t.Fatalf("BuildKnock: %v", err)
			}
			got = retagSessionRequest(t, got, tc.packet.HeaderType, cellPublic, tc.cookie)
			want := hexd(t, tc.packet.PacketHex)
			if !bytes.Equal(got, want) {
				t.Fatalf("packet mismatch:\n got  %x\n want %x", got, want)
			}
			if gotDigest := fmt.Sprintf("%x", got[208:240]); gotDigest != tc.packet.HeaderDigestHex {
				t.Fatalf("digest = %s, want %s", gotDigest, tc.packet.HeaderDigestHex)
			}

			// The released qurl-go verifier predates RKN's cookie-extended digest.
			// We prove that digest independently above, then restore the ordinary
			// digest solely to exercise its exported Noise opener and peer pinning.
			openedPacket := append([]byte(nil), got...)
			copy(openedPacket[208:240], sessionHeaderDigest(cellPublic, openedPacket, nil))
			opened, err := relayknock.DecryptReply(cellPrivate, agentPublic, openedPacket)
			if err != nil {
				t.Fatalf("open request: %v", err)
			}
			if opened.Type != tc.packet.HeaderType || opened.Counter != u64(t, tc.packet.Counter, 10) || opened.TimestampNanos != u64(t, tc.packet.TimestampNanos, 10) || !bytes.Equal(opened.Body, []byte(tc.packet.BodyJSON)) {
				t.Fatalf("opened request drifted: %+v", opened)
			}
		})
	}

	replies := []struct {
		name           string
		packet         conformance.AgentSessionPacket
		wantType       int
		requestCounter string
	}{
		{"cookie", af.OverloadReknock.CookieReply, conformance.AgentSessionHeaderCOK, af.OverloadReknock.KnockRequest.Counter},
		{"reknock_ack", af.OverloadReknock.ACK, conformance.AgentSessionHeaderACK, af.OverloadReknock.ReknockRequest.Counter},
		{"exit_ack", af.CleanExit.ACK, conformance.AgentSessionHeaderACK, af.CleanExit.Request.Counter},
	}
	for _, tc := range replies {
		t.Run(tc.name+"_authentication", func(t *testing.T) {
			opened, err := relayknock.DecryptReply(agentPrivate, cellPublic, hexd(t, tc.packet.PacketHex))
			if err != nil {
				t.Fatalf("DecryptReply: %v", err)
			}
			if opened.Type != tc.wantType || opened.TimestampNanos != u64(t, tc.packet.TimestampNanos, 10) || !bytes.Equal(opened.Body, []byte(tc.packet.BodyJSON)) {
				t.Fatalf("opened reply drifted: %+v", opened)
			}
			if tc.wantType == conformance.AgentSessionHeaderACK && opened.Counter != u64(t, tc.requestCounter, 10) {
				t.Fatalf("ACK counter = %d, want request counter %s", opened.Counter, tc.requestCounter)
			}
		})
	}

	t.Run("cookie_body_transaction", func(t *testing.T) {
		var body struct {
			TransactionID uint64 `json:"trxId"`
			Cookie        string `json:"cookie"`
		}
		if err := json.Unmarshal([]byte(af.OverloadReknock.CookieReply.BodyJSON), &body); err != nil {
			t.Fatal(err)
		}
		if body.TransactionID != u64(t, af.OverloadReknock.KnockRequest.Counter, 10) || body.Cookie != af.OverloadReknock.CookieB64 {
			t.Fatalf("cookie correlation drifted: %+v", body)
		}
	})
}

func TestAgentSessionControlRejects(t *testing.T) {
	af, err := conformance.AgentSessionControl()
	if err != nil {
		t.Fatal(err)
	}
	agentPrivate := hexd(t, af.Keys.Agent.StaticPrivateHex)
	cellPrivate := hexd(t, af.Keys.AssignedCell.StaticPrivateHex)
	cellPublic := hexd(t, af.Keys.AssignedCell.StaticPublicHex)
	rkn := hexd(t, af.OverloadReknock.ReknockRequest.PacketHex)
	cookie := hexd(t, af.OverloadReknock.CookieHex)

	t.Run("wrong_server_key", func(t *testing.T) {
		wrongPublic := x25519Public(t, bytes.Repeat([]byte{0x61}, 32))
		if _, err := relayknock.DecryptReply(agentPrivate, wrongPublic, hexd(t, af.OverloadReknock.ACK.PacketHex)); err == nil {
			t.Fatal("reply authenticated under the wrong server key")
		}
	})
	t.Run("wrong_agent_key", func(t *testing.T) {
		wrongPublic := x25519Public(t, bytes.Repeat([]byte{0x62}, 32))
		if _, err := relayknock.DecryptReply(cellPrivate, wrongPublic, hexd(t, af.OverloadReknock.KnockRequest.PacketHex)); err == nil {
			t.Fatal("request authenticated under the wrong agent key")
		}
	})
	t.Run("wrong_cookie_digest", func(t *testing.T) {
		wrongCookie := append([]byte(nil), cookie...)
		wrongCookie[0] ^= 1
		if bytes.Equal(rkn[208:240], sessionHeaderDigest(cellPublic, rkn, wrongCookie)) {
			t.Fatal("RKN digest authenticated a different cookie")
		}
	})
	t.Run("tampered_digest", func(t *testing.T) {
		tampered := append([]byte(nil), rkn...)
		tampered[208] ^= 1
		if bytes.Equal(tampered[208:240], sessionHeaderDigest(cellPublic, tampered, cookie)) {
			t.Fatal("RKN accepted a tampered digest")
		}
	})

	requestCounter := u64(t, af.OverloadReknock.KnockRequest.Counter, 10)
	for _, tc := range af.CookieBodyCases {
		t.Run("cookie_"+tc.Name, func(t *testing.T) {
			class := classifySessionCookieBody([]byte(tc.BodyJSON), requestCounter)
			outcome := conformance.AgentSessionOutcomeAccept
			if class != "" {
				outcome = conformance.AgentSessionOutcomeReject
			}
			if outcome != tc.Outcome || class != tc.RejectClass {
				t.Fatalf("classified as %q/%q, want %q/%q", outcome, class, tc.Outcome, tc.RejectClass)
			}
		})
	}
}

func retagSessionRequest(t *testing.T, packet []byte, typ int, serverPublic, cookie []byte) []byte {
	t.Helper()
	if len(packet) < conformance.AgentSessionHeaderSize {
		t.Fatalf("packet too short: %d", len(packet))
	}
	got := append([]byte(nil), packet...)
	preamble := binary.BigEndian.Uint32(got[0:4])
	payloadSize := len(got) - conformance.AgentSessionHeaderSize
	binary.BigEndian.PutUint32(got[4:8], preamble^((uint32(typ)&0xffff)<<16|uint32(payloadSize)))
	copy(got[208:240], sessionHeaderDigest(serverPublic, got, cookie))
	return got
}

func sessionHeaderDigest(serverPublic, packet, cookie []byte) []byte {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	_, _ = h.Write(sessionInitialHash)
	_, _ = h.Write(serverPublic)
	_, _ = h.Write(packet[:208])
	_, _ = h.Write(cookie)
	return h.Sum(nil)
}

func x25519Public(t *testing.T, private []byte) []byte {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey().Bytes()
}

// classifySessionCookieBody deliberately does not call the root classifier;
// both implementations must execute every closed cookie_body_cases entry.
func classifySessionCookieBody(body []byte, requestCounter uint64) string {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return conformance.AgentSessionRejectBodyParse
	}
	fields := make(map[string]json.RawMessage, 2)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || (key != "trxId" && key != "cookie") {
			return conformance.AgentSessionRejectBodyParse
		}
		if _, duplicate := fields[key]; duplicate {
			return conformance.AgentSessionRejectBodyParse
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return conformance.AgentSessionRejectBodyParse
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || len(fields) != 2 {
		return conformance.AgentSessionRejectBodyParse
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return conformance.AgentSessionRejectBodyParse
	}

	var transactionID uint64
	var cookie string
	if bytes.Equal(fields["trxId"], []byte("null")) || bytes.Equal(fields["cookie"], []byte("null")) ||
		json.Unmarshal(fields["trxId"], &transactionID) != nil || json.Unmarshal(fields["cookie"], &cookie) != nil || cookie == "" {
		return conformance.AgentSessionRejectBodyParse
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(cookie)
	if err != nil {
		if raw, rawErr := base64.RawStdEncoding.Strict().DecodeString(cookie); rawErr == nil && len(raw) == conformance.AgentSessionCookieSize {
			return conformance.AgentSessionRejectCookieCanonical
		}
		return conformance.AgentSessionRejectCookieEncoding
	}
	if len(decoded) != conformance.AgentSessionCookieSize {
		return conformance.AgentSessionRejectCookieLength
	}
	if base64.StdEncoding.EncodeToString(decoded) != cookie {
		return conformance.AgentSessionRejectCookieCanonical
	}
	if transactionID != requestCounter {
		return conformance.AgentSessionRejectCounter
	}
	return ""
}
