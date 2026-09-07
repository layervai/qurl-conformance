package conformance

import (
	"encoding/base64"
	"errors"
)

// ConnectorHubRequestNonceBytes is the exact decoded length of the public
// LST request_nonce that a registered agent mints per logical request.
const ConnectorHubRequestNonceBytes = 32

// ErrConnectorHubRequestNonce identifies a logical-request nonce that is not
// exactly ConnectorHubRequestNonceBytes of canonical unpadded base64url.
var ErrConnectorHubRequestNonce = errors.New("conformance: invalid Connector Hub request nonce")

// DecodeConnectorHubRequestNonce strictly decodes the public LST request_nonce
// grammar shared by SDKs and the Hub: exactly ConnectorHubRequestNonceBytes of
// canonical unpadded base64url. Strict raw-url decoding rejects padding,
// out-of-alphabet bytes, and non-zero trailing bits, but Go's decoder still
// skips embedded CR and LF, so the re-encode comparison is what pins one wire
// string per nonce. The returned raw bytes are what the Hub binds its private
// replay identifier to.
func DecodeConnectorHubRequestNonce(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != ConnectorHubRequestNonceBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrConnectorHubRequestNonce
	}
	return decoded, nil
}
