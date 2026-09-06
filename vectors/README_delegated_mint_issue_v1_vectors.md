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
current UTC time. It stores an accepted nonce for 900 seconds from first
acceptance. The nonce retention must be strictly greater than twice the
timestamp skew. An exact idempotent replay can return its durable result after
nonce retention ends, but the same issuer cannot use a retained nonce for a
different operation. These bounds are part of v1 and are not local producer
retry settings.

The service first validates request shape and verifies the signature. It then
does a durable operation lookup before it applies timestamp freshness. A
byte-exact transport envelope that was already accepted can return its original
result after the 300-second freshness window. A different envelope for the same
operation must have a fresh timestamp and must bind its nonce to that operation
before the service returns the stored result. A different stale envelope rejects
without mutation. A stored result can contain an expired capability; the
Connector uses the signed next generation to refresh it. The same idempotency
key with different operation bytes is a conflict.

The durable operation key consists of issuer ID, upload handle, issue
generation, and the derived idempotency key. A separate immutable authority
fingerprint binds the upload request digest, content digest and size, media type,
display filename, audience, target path, batch and link limits, original
authority expiry, and the service-owned issuer policy fingerprint.
`capability_expires_at` is not part of that authority fingerprint. A fresh retry
must move it with the new signed request timestamp without changing the durable
operation or its maximum authority.

The accepted-envelope fingerprint binds the exact method, authority, route,
issuer ID, key ID, idempotency key, timestamp, nonce, body SHA-256, and signature
encoding. Nonce, signature, timestamp, key ID, and exact body digest are
transport authentication, not operation identity. A retry can replay an exact
accepted envelope or use a fresh valid envelope for the same operation and
authority. The configured issuer key ID can rotate. The service binds each
accepted nonce to the same issuer operation, so that nonce cannot authenticate
a different operation later.

If a valid signed stale request has no operation after a strongly consistent
lookup, the service returns HTTP 404 with code `issue_operation_not_found` and
does not mutate state. Only this authenticated stale-miss result lets the
Connector sign a fresh envelope for the same generation. The Connector persists
the fresh envelope before it sends it and retains earlier envelopes until one
reconciles. If an earlier request commits after the miss, a fresh envelope with
the same authority fingerprint returns that stored result. A changed authority
fingerprint is a conflict.

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
compact. `append` adds `value` to the named field. The changed-body case adds
valid JSON whitespace but retains the old signature. Each case uses the
`golden` object as its base. All derived fields in a mutated input, including
the body hash, canonical bytes, signing digest, and signature result, cease to
be assertions after a recipe is applied. A consumer recomputes them from the
mutated request and returns the listed closed `reject_class`. It must not repair
the input.

`wrong_endpoint_signed` and `nonce_reuse_signed` are complete inputs with valid
canonical low-S signatures. The first is signed for another authority, so it is
not valid at the configured receiver. The second uses the initial operation's
nonce for the distinct generation-two operation. Signature success alone does
not authorize either request.

`state_cases` publishes the seven required receiver transitions. It covers a
first issue, an exact stale replay after nonce expiry, a fresh reconciliation,
an authenticated stale strong miss, an alternate endpoint, a nonce reused by a
different operation, and a stale non-exact retry. Each case names its complete
signed input, prior durable operation and nonce state, receiver time, status,
public error code, state mutation, and response source. The `outcome` and
`mutation` values are closed by the contract lists. A receiver must not replace
a listed rejection with a state write.

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
A caller signs `authority_expires_at` as its immutable maximum; it does not
select the short internal capability expiry. The Connector copies that maximum
without change and computes each internal capability expiry from its request
timestamp. If fewer than 900 seconds remain, it cannot widen the maximum and
must end that external operation.
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
rebuilds the initial, stale-miss retry, and refresh canonical bytes and low-S
signatures, derives the reject cases, and verifies the complete artifact before
it writes it. The private keys are discarded. Run it only for an intentional
test-key rotation and then sync the three published mirrors.

Because signature verification happens before operation lookup, the issuer
service retains the verifier for each accepted key ID until that operation's
authority expires. A rotation can use a new key ID for a fresh envelope, but it
cannot make an accepted old envelope unverifiable during its replay lifetime.

A successful first issue, exact replay, reconciliation, or refresh returns
HTTP 200 and `Content-Type: application/json` without a charset parameter. The
response data has opaque `capability`, `capability_expires_at`, and
`authority_expires_at` fields. Reconciliation returns the one durable stored
result, so its capability expiry does not have to equal the current request's
proposed expiry. The Connector requires a canonical capability expiry that is
not after the exact immutable authority expiry. If the stored capability is no
longer usable, it advances to the next generation. The Connector does not
inspect the capability.

Issue generation is internal to the Connector-to-issuer-service operation. An
external Connector operation that has not committed its response can advance
the internal issue generation under the same immutable signed authority. After
the Connector commits an external response, exact replay returns those bytes,
even if the embedded capability has expired. A new outward capability requires
a new signed external request and request ID.
