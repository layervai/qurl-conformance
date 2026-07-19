package verifysdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
	"golang.org/x/crypto/blake2s"
)

func TestConnectorHubLSTCookieKATsIndependent(t *testing.T) {
	file, err := conformance.ConnectorHubLSTCookie()
	if err != nil {
		t.Fatal(err)
	}
	for _, kat := range file.CookieKATs {
		t.Run(kat.Name, func(t *testing.T) {
			key := decodeHex(t, kat.SigningKeyHex)
			peer, err := base64.StdEncoding.Strict().DecodeString(kat.AuthenticatedPeerPublicKeyB64)
			if err != nil {
				t.Fatal(err)
			}
			window, err := strconv.ParseUint(kat.WindowIndex, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			addr, err := netip.ParseAddr(kat.SourceIP)
			if err != nil {
				t.Fatal(err)
			}
			addr = addr.Unmap()
			rawIP := addr.AsSlice()
			family := byte(0x06)
			if addr.Is4() {
				family = 0x04
			}
			preimage := append([]byte("nhp-connector-hub-lst-cookie-v1\x00"), family)
			var frame [8]byte
			binary.BigEndian.PutUint32(frame[:4], uint32(len(rawIP)))
			preimage = append(preimage, frame[:4]...)
			preimage = append(preimage, rawIP...)
			binary.BigEndian.PutUint32(frame[:4], uint32(len(peer)))
			preimage = append(preimage, frame[:4]...)
			preimage = append(preimage, peer...)
			binary.BigEndian.PutUint64(frame[:], window)
			preimage = append(preimage, frame[:]...)
			if got := hex.EncodeToString(preimage); got != kat.PreimageHex {
				t.Fatalf("preimage = %s, want %s", got, kat.PreimageHex)
			}
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write(preimage)
			cookie := mac.Sum(nil)
			if got := hex.EncodeToString(cookie); got != kat.CookieHex {
				t.Fatalf("cookie = %s, want %s", got, kat.CookieHex)
			}
			if got := base64.StdEncoding.EncodeToString(cookie); got != kat.CookieB64 {
				t.Fatalf("cookie b64 = %s, want %s", got, kat.CookieB64)
			}
		})
	}
	if !bytes.Equal(decodeHex(t, file.CookieKATs[0].CookieHex), decodeHex(t, file.CookieKATs[1].CookieHex)) {
		t.Fatal("IPv4-mapped KAT does not equal IPv4")
	}
}

func TestConnectorHubLSTProofDigestKATIndependent(t *testing.T) {
	file, err := conformance.ConnectorHubLSTCookie()
	if err != nil {
		t.Fatal(err)
	}
	kat := file.ProofDigestKAT
	h, err := blake2s.New256(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{kat.InitialHashHex, kat.HubServerStaticPublicKeyHex, kat.HeaderPrefixHex, kat.RawCookieHex} {
		_, _ = h.Write(decodeHex(t, input))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != kat.ExpectedDigestHex {
		t.Fatalf("proof digest = %s, want %s", got, kat.ExpectedDigestHex)
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
