package conformance

import (
	"encoding/base64"
	"errors"
)

// ConnectorHubRequestIDNonceBytes is the exact decoded length of the public
// LST request_nonce that a registered agent mints per logical request.
const ConnectorHubRequestIDNonceBytes = 32

// ErrConnectorHubRequestIDNonce identifies a logical-request nonce that is
// not exactly ConnectorHubRequestIDNonceBytes of canonical unpadded base64url.
var ErrConnectorHubRequestIDNonce = errors.New("conformance: invalid Connector Hub request-ID nonce")

// DecodeConnectorHubRequestNonce strictly decodes the public LST request_nonce
// grammar shared by SDKs and the Hub: exactly ConnectorHubRequestIDNonceBytes
// of canonical unpadded base64url. The returned raw bytes are what the Hub
// binds its private replay identifier to.
func DecodeConnectorHubRequestNonce(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != ConnectorHubRequestIDNonceBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrConnectorHubRequestIDNonce
	}
	return decoded, nil
}
