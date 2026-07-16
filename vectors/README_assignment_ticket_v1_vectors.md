# Assignment ticket v1 vectors

`assignment_ticket_v1_vectors.json` is the standalone cryptographic source of
truth for the opaque qURL agent-assignment ticket. It is intentionally separate
from the NHP LST/LRT packet artifact: NHP carries the ticket as an opaque string
and must not gain a second ticket parser.

All credentials, keys, identifiers, signatures, and endpoints in this document
are synthetic. The committed private scalar exists only so an independent
consumer can prove the public key fixture; never use it outside conformance
tests.

## Positive vector

The wire is exactly `qat1.<claims_b64url>.<signature_b64url>`. Both encoded
segments are canonical unpadded base64url. The JSON text in `golden.claims_json`
is the exact UTF-8 byte sequence signed by the producer; consumers must verify
the transmitted `claims_b64url` string without decoding and reserializing it.
The final optional `assignment_fence_b64` claim is omitted for the positive
`placement_mode=new` vector.

The signing digest is:

```text
SHA-256("qurl-agent-assignment-ticket-v1" || 0x00 || claims_b64url ASCII)
```

The fixture models AWS KMS `ECDSA_SHA_256` with `MessageType=DIGEST`:
`kms_signature_der_hex` is a valid high-S ASN.1 DER ECDSA result. A producer
must parse it strictly, range-check `r` and `s`, normalize `s` to low-S, encode
both integers as fixed-width 32-byte values, and concatenate `r || s`.
`raw_low_s_signature_hex`, its exact 86-character base64url encoding, and the
complete ticket pin every byte of that conversion.
The synthetic private scalar, ECDSA nonce, UTC clock, and 16 JTI random bytes
are all fixed so the independent verifier can reproduce the DER output and
claims bytes exactly. Production KMS signatures remain nondeterministic.

The positive ticket uses public `credential_kind=connector_bootstrap`. The
private qurl-service row spelling `tunnel_bootstrap` appears only as the raw
storage input to the credential fence and in the explicit public-wire reject.
It is never an accepted ticket value. No assignment ticket contains an OTP:
account registration obtains the user-entered OTP out of band and carries that
OTP with the ticket in the single REG call.

`lrt_body_template` composes the complete positive ticket into the exact LRT
JSON shape. The derived body and complete encrypted NHP packet sizes prove the
fixture stays below the frozen 3856-byte body and 4096-byte packet limits.

## Fences

Every fence is:

```text
SHA-256(domain || 0x00 || uint64be(len(part1)) || part1 || ...)
```

The three vectors freeze the exact domains, ordered parts, semantic values,
encoded bytes, complete preimages, and digests for credential, cell, and
existing-assignment snapshots. Part encodings are closed:

- `raw_bytes_b64url`: decode canonical unpadded base64url to raw bytes;
- `utf8`: the exact stored UTF-8 bytes, including an empty string;
- `uint64_be`: parse the unsigned decimal value and encode exactly eight bytes;
- `bool_byte`: `false` is `00`, `true` is `01`.

Scopes are represented by a count followed by their unique lexical byte-order
members. Exact number and timestamp storage spellings remain strings where the
contract requires storage-level optimistic fencing.

## Reject suites

`verify_rejects` drives the complete verifier. An omitted claims or signature
field inherits the positive vector; otherwise the supplied value is verbatim.
`ResolveToken` implements the same rule for Go consumers. A `derivation` is an
exact repeated-ASCII input used only for limit+1 cases, avoiding three large
duplicate package copies.

`claims_rejects` drives the strict claims parser before signing or verification.
It covers duplicate, unknown, trailing and null JSON; exact time relations;
new/existing assignment-fence presence; private and unknown credential kinds;
and key, digest, fence, JTI, KID, and decoded-claims bounds.

`kms_der_cases` drives the producer's KMS DER converter. The accept case proves
high-S normalization; the reject cases cover truncated/trailing DER, zero `r`,
and an out-of-range `s`. `fence_rejects` and `trust_key_rejects` freeze the
remaining typed-input and P-256 trust-store boundaries.

Reject classes are a closed, coarse consumer vocabulary:

- `claims`, `time`, `size`, `encoding`;
- `signature`, `high_s`, `wrong_length`;
- `unknown_kid`, `environment`, `key_length`;
- `der`, `fence_input`.

A consumer may expose more specific internal errors, but it must reject every
fixture at the named boundary and must not silently reinterpret a reject as an
accepted future extension.
