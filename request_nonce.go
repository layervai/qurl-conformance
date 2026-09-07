package conformance

import (
	"encoding/base64"
	"errors"
)

// RequestNonceBytes is the exact decoded length of the public LST
// request_nonce that a registered agent mints per logical request.
const RequestNonceBytes = 32

// ErrRequestNonce identifies a logical-request nonce that is not
// exactly RequestNonceBytes of canonical unpadded base64url.
var ErrRequestNonce = errors.New("conformance: invalid Connector Hub request nonce")

// DecodeRequestNonce strictly decodes the public LST request_nonce grammar:
// an SDK mints it once per logical request and the platform consumes it as exactly RequestNonceBytes of
// canonical unpadded base64url. Strict raw-url decoding rejects padding,
// out-of-alphabet bytes, and non-zero trailing bits, but Go's decoder still
// skips embedded CR and LF, so the re-encode comparison is what pins one wire
// string per nonce. The returned raw bytes are what the Hub binds its private
// replay identifier to.
func DecodeRequestNonce(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != RequestNonceBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrRequestNonce
	}
	return decoded, nil
}
