# Delegated-mint capability issue v1

This artifact freezes the private request signature used when a trusted
Connector asks an issuer service to issue an opaque delegated-mint capability.
It does not expose capability claims to an SDK and it does not authorize a
public batch redemption.

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

`X-LayerV-Timestamp` is the canonical base-10 Unix-second value in the signed
`timestamp_unix_decimal` field. The receiver must also require the signed
method, route, and authority to equal its configured endpoint. A valid signature
for a different service authority is not valid for this receiver.

The service accepts a signed request timestamp only within 300 seconds of its
current UTC time. It stores an accepted nonce for at least 600 seconds from
first acceptance. This retention covers the full symmetric timestamp window:
one request can arrive 300 seconds early and a replay can arrive 300 seconds
late. An exact idempotent replay can return its durable result, but the same
issuer and key cannot use that nonce for a different operation. These two
bounds are part of v1 and are not local producer retry settings.

The service first validates request shape and verifies the signature. It then
does a durable operation lookup before it applies timestamp freshness. A
byte-exact transport envelope that was already accepted can return its original
result after the 300-second freshness window. A different envelope for the same
operation must have a fresh timestamp and must bind its nonce to that operation
before the service returns the stored result. A different stale envelope rejects
without mutation. A stored result can contain an expired capability; the
Connector uses the signed next generation to refresh it. The same idempotency
key with different operation bytes is a conflict.

Operation identity consists of the issuer ID, upload handle, issue
generation, derived idempotency key, exact body SHA-256, and the service's
immutable authority fingerprint. Nonce, signature, timestamp, and key ID are
transport authentication, not operation identity. A retry can replay the exact
accepted envelope or use a fresh valid envelope. The configured issuer key ID
can rotate. The service binds each accepted nonce to the same issuer operation,
so that nonce cannot authenticate a different operation later.

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

`reject_cases` publishes concrete cross-language rejection inputs. `replace`
sets the named golden field to `value`. `ascii_repeat` sets it to `value`
repeated `repeat` times; v1 uses that recipe to keep the 8,193-byte body case
compact. Each case uses the `golden` object as its base. A consumer must reject
each result with the listed closed `reject_class`; it must not repair the input.

The Connector selects neither the service-owned resource nor an arbitrary path
namespace. The issuer service loads both from issuer policy. The signed body
carries the exact issuer-produced object path and the authenticated caller's
public `audience_key_id`. Capability issuance is separate from later redemption
with that caller's normal qURL API credential.

The Connector supplies the two expiry fields so its signed upload record and a
lost-response retry name one deterministic authority. The issuer service does
not trust those times. It requires `capability_expires_at` to be exactly 900
seconds after the signed request timestamp. It requires the initial
`authority_expires_at` to be no later than 86,400 seconds after that timestamp.
A signed refresh uses this same route with a higher issue generation. It can
move only the capability expiry forward, and never after the original authority
expiry. It must not change the issuer, audience, upload, resource policy,
target path, batch limit, link TTL limit, or signed upload metadata. The service
checks its own policy maximum when it stores the first authority; the Connector
cannot increase it by signing a later request.

Both expiry fields use RFC 3339 UTC at exact second precision, with an uppercase
literal `Z`: `YYYY-MM-DDTHH:MM:SSZ`. Offsets, fractional seconds, and lowercase
`z` are not canonical even when they name the same instant.

The sequential nonces and the public keys in this artifact are fixed test data.
Production producers must create each nonce with a cryptographically secure
random source. The illustrative `issuer-2026-09` and `issuer-2026-10`
identifiers and test public keys are not operational sandbox issuers. The
refresh golden rotates the test key to prove that key ID is transport
authentication, not operation identity. Consumers verify these committed bytes;
they do not need either matching test private key.

`make gen-delegated-mint-vectors` creates fresh throwaway P-256 test keys,
rebuilds the canonical bytes and low-S signatures, derives the reject cases,
and verifies the complete artifact before it writes it. The private keys are
discarded. Run it only for an intentional test-key rotation and then sync the
three published mirrors.

Because signature verification happens before operation lookup, the issuer
service retains the verifier for each accepted key ID until that operation's
authority expires. A rotation can use a new key ID for a fresh envelope, but it
cannot make an accepted old envelope unverifiable during its replay lifetime.

A successful first issue, exact replay, reconciliation, or refresh returns
HTTP 200 and `Content-Type: application/json` without a charset parameter. The
response data has opaque `capability`, `capability_expires_at`, and
`authority_expires_at` fields. The Connector does not inspect the capability.
