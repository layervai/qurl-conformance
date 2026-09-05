# Delegated-mint capability issue v1

This artifact freezes the private request signature used when a trusted
Connector asks qurl-service to issue an opaque delegated-mint capability. It
does not expose capability claims to an SDK and it does not authorize a public
batch redemption.

The signature input is the ASCII domain `LV-QURL-CAPABILITY-ISSUE-V1`, one zero
byte, then nine fields in the listed order. Each field has a four-byte unsigned
big-endian byte length followed by its exact UTF-8 bytes. The body field is the
lowercase hexadecimal SHA-256 of the exact HTTP request body bytes. A consumer
must not parse and reserialize JSON before it computes this digest.

The signed headers are `Idempotency-Key`, `X-LayerV-Issuer-ID`,
`X-LayerV-Issuer-KID`, `X-LayerV-Timestamp`, and `X-LayerV-Nonce`.
`X-LayerV-Signature` carries the result. `X-LayerV-Nonce` is exactly 16 random
bytes in canonical unpadded base64url. `Idempotency-Key` is 1 to 128 bytes from
the listed unreserved ASCII alphabet. The golden uses the Connector form
`uci_<base64url SHA-256>`. The endpoint must bind the idempotency key and nonce
to the same authenticated issuer operation. The exact request body is limited
to 8,192 bytes before parsing or signature verification.

The service accepts a signed request timestamp only within 300 seconds of its
current UTC time. It stores an accepted nonce for at least 600 seconds from
first acceptance. An exact idempotent replay can return its durable result, but
the same issuer and key cannot use that nonce for a different operation. These
two bounds are part of v1 and are not local producer retry settings.

The signed authority is a lowercase ASCII DNS name without a port or trailing
dot. It has at least two labels and at most 253 bytes. Each label is 1 to 63
bytes, starts and ends with a lowercase letter or digit, and otherwise contains
only lowercase letters, digits, or hyphens. IP literals, underscores, empty
labels, controls, and non-ASCII input are invalid.

The Connector derives `Idempotency-Key` as `uci_` plus unpadded base64url of
SHA-256 over `LV-QURL-CAPABILITY-ISSUE-IDEMPOTENCY-V1`, one zero byte, then the
issuer ID, upload handle, and canonical decimal issue generation. Each value
has a four-byte unsigned big-endian byte length. Generation has no leading
zero. A refresh increments the generation and gets a different durable replay
key.

The signature is canonical ASN.1 DER ECDSA P-256 with low S, encoded as
canonical unpadded base64url. A verifier must reject padded or non-canonical
base64url, non-canonical DER, an out-of-range scalar, and a high-S malleability
twin. It must not normalize an untrusted signature.

The Connector selects neither the service-owned resource nor an arbitrary path
namespace. qurl-service loads both from issuer policy. The signed body carries
the exact issuer-produced object path and the authenticated caller's public
`audience_key_id`. Capability issuance is separate from later redemption with
that caller's normal qURL API credential.

The Connector supplies the two expiry fields so its signed upload record and a
lost-response retry name one deterministic authority. qurl-service does not
trust those times. It requires `capability_expires_at` to be exactly 900 seconds
after the signed request timestamp. It requires the initial
`authority_expires_at` to be no later than 86,400 seconds after that timestamp.
A signed refresh uses this same route with a higher issue generation. It can
move only the capability expiry forward, and never after the original authority
expiry. It must not change the issuer, audience, upload, resource policy,
target path, batch limit, link TTL limit, or signed upload metadata. The service
checks its own policy maximum when it stores the first authority; the Connector
cannot increase it by signing a later request.

A successful first issue, exact replay, reconciliation, or refresh returns
HTTP 200 and `Content-Type: application/json` without a charset parameter. The
response data has opaque `capability`, `capability_expires_at`, and
`authority_expires_at` fields. The Connector does not inspect the capability.
