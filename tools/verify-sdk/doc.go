// Package verifysdk re-runs the public qURL v2 conformance vectors through the
// qurl-go SDK's EXPORTED API, as a producer-side cross-language compatibility
// check. It covers exactly the classes reachable through exported entry points
// (signature, fragment, relay_allowlist, server_id). The claims_parse,
// secret_parse, and strict_base64 classes use qurl-go's UNEXPORTED parsers
// (parseClaims/parseSecret/decodeB64) and are fully exercised by qurl-go's own
// in-package conformance test, not here. The agent API-key ID artifact is also
// outside this module until qurl-go exposes the registration-info and completion
// consumers that can run it; qurl-conformance#28 remains open until that
// downstream adoption is released and passing.
package verifysdk
