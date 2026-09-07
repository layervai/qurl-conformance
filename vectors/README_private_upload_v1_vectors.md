# Private upload v1 vectors

`private_upload_v1_vectors.json` is the byte-exact application-signing contract
for private file upload and delegated-capability refresh. Both requests run
through one cached NHP 1.1 session. This artifact starts after the authenticated
ACK gives the client its protected URL. It contains no NHP packet bytes.

The committed, signed, self-verifying artifact is the public authority. The Go
loader rebuilds every canonical value, digest, and P-256 verification result.

## Trust boundary

The client signs the exact authority from the authenticated ACK URL. It must not
derive that authority from a public resource ID, a Connector routing ID, or an
HTTP forwarding header. The request has no `Authorization` header. The
application signature is the only HTTP-layer client credential. Executable
reject cases require both upload and refresh to reject `Authorization`.

The authority has lowercase DNS-label syntax. Each label contains only `a-z`,
`0-9`, or `-`, is 1 to 63 bytes, and has no edge hyphen. The host is at most
253 bytes. IPv4 text follows the same label syntax. IPv6 literals and trailing
dots are invalid. A colon without a port is invalid. An optional port is
canonical nonzero decimal in the range 1 to 65535, with no leading zero.

The upload audience is the API-key ID that can use the returned delegated mint
capability. Its exact form is `key_` plus 12 alphanumeric characters. It is
signed on upload. Refresh cannot change it and must omit the audience header.
`contract.audience_key_id_rule`, `contract.client_id_rule`, and
`contract.key_id_rule` publish the closed regular-expression grammars for all
three identifiers. Consumers must enforce those expressions exactly.
`contract.upload_request_id_rule` requires a lowercase UUIDv4.
`contract.upload_handle_rule` requires `upl_` followed by 43 canonical
base64url characters. `contract.authority_expires_at_rule` requires RFC 3339
UTC text with whole seconds and an uppercase `Z`. `contract.body_length_rule`
requires positive canonical decimal text equal to the exact body byte length.

The synthetic private key in `fixture_key` has scalar `d=1`. It exists only so
consumer SDKs can run their real signer in conformance tests. Never admit that
key or its public key to a production trust store.

## Shared signature encoding

Both operations use SHA-256 and ECDSA P-256. The signature is strict ASN.1 DER
`(r,s)`, encoded as canonical base64url without padding. `s` must be in the low
half of the P-256 group order. Receivers reject a high-S twin, padded base64url,
nonminimal DER, trailing DER bytes, invalid scalars, and a validly encoded
signature that does not match the canonical request bytes.

Canonical input starts with the operation's ASCII domain and one zero byte.
Each listed field follows as:

```text
U32BE(byte_length) || exact UTF-8 bytes
```

There is no final byte. Decimal fields have no sign or leading zero. Hex digests
use lowercase. A nonce is canonical unpadded base64url for exactly 32 random
bytes. `Content-Digest` uses canonical padded standard base64 in
`sha-256=:<digest>:` form.

## Upload

Upload uses `POST /internal/v1/uploads`. The body is the exact file bytes. It is
not multipart data. The signing domain is `LV-QURL-UPLOAD-AUTH-V1`. The field
order in `contract.upload.field_order` is closed and normative. `Content-Type`
must equal the signed `media_type` byte for byte, as stated by
`contract.upload.content_type_rule`. The media type must also match
`contract.upload.media_type_rule`: one lowercase type and subtype. The subtype
must not be exactly `*`, as stated by
`contract.upload.media_type_subtype_rule`. The type token has no separate
wildcard exclusion.

The display filename is NFC-normalized UTF-8 from 1 to 180 bytes. It cannot
have leading or trailing Unicode whitespace, equal `.` or `..`, contain `/` or
`\`, or contain a Unicode control, format, private-use, line-separator, or
paragraph-separator code point. The header is that exact UTF-8 text encoded as
canonical unpadded base64url. The two machine-readable filename rules publish
this contract.

The stable request digest uses domain `LV-QURL-UPLOAD-REQUEST-V1` and the stable
field order in the artifact. It excludes timestamp, nonce, and signing-key ID.
It also excludes method, path, and authority. A transport retry can use a fresh
nonce or a rotated signer, but the per-request signature still binds the exact
method, path, and protected authority. A receiver must scope the stable digest
to its authenticated client and request state. It must not use the digest as a
global authority-independent idempotency key.

`upload_golden` freezes all request values, canonical bytes, signing digest,
signature, stable request bytes, and stable request digest.

## Refresh

Refresh uses `PATCH /internal/v1/uploads` through the same protected ACK URL. Its
body is the exact canonical JSON bytes in `refresh_golden.body_hex`.
`Content-Type` is exactly `application/json`. The audience and filename headers
are forbidden. Executable reject cases also require refresh to reject both of
these headers and `Authorization`.

`contract.refresh.body_key_order` is the exact JSON key order. There is no
whitespace between JSON tokens. String values use RFC 8259 UTF-8 JSON escaping:
use the short escapes for quote, backslash, backspace, tab, newline, form feed,
and carriage return; use lowercase `\u00xx` for the other U+0000 through U+001F
controls; and also escape `<`, `>`, `&`, U+2028, and U+2029 as lowercase
`\u003c`, `\u003e`, `\u0026`, `\u2028`, and `\u2029`. The three
`contract.refresh.body_*` fields publish these rules in machine-readable form.

The signature domain is `LV-QURL-UPLOAD-REFRESH-AUTH-V1`. The stable request
domain is `LV-QURL-UPLOAD-REFRESH-REQUEST-V1`. The signature binds the body hash
and length. The stable request digest uses the explicit string fields
`upload_handle`, `max_batch_size_decimal`, `max_link_ttl_seconds_decimal`,
`authority_expires_at`, and `upload_request_id` in `refresh_golden`. Consumers
must not parse JSON numbers to build this stable digest. The exact body must
match those explicit fields under the canonical JSON rules above. This design
keeps the digest exact when a JSON runtime cannot represent a large integer.
Refresh cannot change the stored audience, object, route, media type, filename,
or authority horizon.

## Reject classes

- `authority`: the presented authority is not a canonical lowercase authority.
- `audience_key_id`: the upload audience is invalid.
- `body_digest`: the exact body bytes do not match the signed digest.
- `forbidden_header`: the request presents a header forbidden for that
  operation.
- `method_path`: method or path differs from the operation contract.
- `nonce`: the nonce is not canonical unpadded base64url for 32 bytes.
- `signature_encoding`: base64url or DER is not canonical.
- `signature_malleability`: the DER signature is a high-S twin.
- `signature_mismatch`: canonical fields changed after signing.
- `signature_scalar`: `r` or `s` is outside the P-256 scalar range.

`contract.reject_class_precedence` is normative. A request that violates more
than one rule must use the first matching class in that list. This order makes
each mutation deterministic even when it also invalidates the signature.

Each reject case contains an ordered, nonempty `mutations` array. Each mutation
states a `target`. `request_field` replaces the named golden field. `body`
replaces the exact request body. `request_header` adds or replaces the named
HTTP header. Every header in an operation's closed `forbidden_headers` list
maps to `forbidden_header`; this includes the refresh audience header. The
dual-invalid case pins `method_path` before `authority`.

All published rejects map to HTTP 401 `invalid_upload_auth`. This uniform result
does not disclose which authentication field failed.

The closed `reject_classes` vocabulary covers the executable stateless
classifier cases in this artifact. The content-type rules, identifier grammars,
and required-header list are also normative. A consumer must add local negative
tests for construction and preflight rules that have no separate reject case.

## Construction rejects

`construction_reject_cases` is a small client-preflight suite. Each case starts
from `upload_golden`, replaces one named construction input, and must reject
under the named contract rule before a request is signed or sent. The cases
cover a `Content-Type` value that differs from the signed media type, filename
containment, decomposed non-NFC input, uppercase media type input, and an exact
wildcard subtype. The Go loader pins the decomposed NFC input structurally
because this public module is dependency-free; the Node and Python gates execute
Unicode NFC normalization. These cases have no HTTP status or application error
because a conforming client does not put these requests on the wire.

## Consumer algorithm

1. Load the artifact with a strict JSON parser. Reject duplicate keys, unknown
   fields, trailing values, and an unknown artifact or schema version.
2. Import the synthetic PKCS8 key only in the conformance test process. Confirm
   that its public key equals `public_key_der_b64url`.
3. Inject the golden timestamp and nonce into the signer. Build the upload
   request with the real SDK signer. Assert the exact canonical bytes, body
   digest header, stable request digest, required headers, forbidden headers,
   and a canonical low-S signature that verifies with the fixture key.
4. Build the refresh request with the real SDK signer and make the same checks.
   Assert that its body bytes equal the committed canonical JSON.
5. Apply every construction reject to the real SDK preflight path. It must fail
   before signing or dispatch.
6. Apply every reject mutation to its named golden request. Feed it through the
   production preflight or receiver verifier. Inject a clock at the golden
   timestamp and use an empty replay store so skew or prior state cannot hide
   the declared stateless reject class. A missing vector is a test failure, not
   a skip.

The timestamps and nonces are frozen test inputs. Production code must still
use its real clock, fresh random nonces, the 30-second skew limit, and replay
state. Timestamp freshness and nonce replay are receiver-state checks. They are
not stateless signer mutations in this artifact.

This artifact has no in-repo generator. To update it, edit the public contract,
update the synthetic fixture and signatures only when required, and run the
loader and `RELEASE_CHECKLIST.md` checks. Do not rotate the fixture on an
unrelated edit.

This artifact defines only HTTP application signing after NHP 1.1 authorization.
It does not define NHP negotiation, OAuth, Auth0, a CLI, qURL minting, or the
delegated capability format.
