# Assignment ticket v1 vectors

`assignment_ticket_v1_vectors.json` is the standalone cryptographic source of
truth for the opaque qURL agent-assignment ticket. It is intentionally separate
from the NHP LST/LRT packet artifact: NHP carries the ticket as an opaque string
and must not gain a second ticket parser.

All credentials, keys, identifiers, signatures, and endpoints in this document
are synthetic. The committed private scalar exists only so an independent
consumer can prove the public key fixture; never use it outside conformance
tests.
`cell0.nhp.layerv.ai` is likewise a synthetic, non-production fixture hostname;
consumers must not treat it as a deployable or discoverable endpoint.

## Positive vector

The wire is exactly `qat1.<claims_b64url>.<signature_b64url>`. Both encoded
segments are canonical unpadded base64url. The JSON text in `golden.claims_json`
is the exact UTF-8 byte sequence signed by the producer; consumers must verify
the transmitted `claims_b64url` string without decoding and reserializing it.
The final optional `assignment_fence_b64` claim is omitted for the positive
`placement_mode=new` vector.

Inside the claims, `agent_public_key_b64` is the deliberate exception: it is
canonical padded standard base64 (44 characters for the 32-byte key). The JTI
payload, credential hash, and fence digests are canonical unpadded base64url;
the JTI additionally carries the literal `atj_` prefix.

The signing digest is:

```text
SHA-256("qurl-agent-assignment-ticket-v1" || 0x00 || claims_b64url ASCII)
```

The fixture models an ASN.1-DER ECDSA signer that receives a precomputed SHA-256
digest and may emit high-S: `kms_signature_der_hex` is one valid high-S result.
A producer must parse it strictly, range-check `r` and `s`, normalize `s` to
low-S, encode both integers as fixed-width 32-byte values, and concatenate
`r || s`.
`raw_low_s_signature_hex`, its exact 86-character base64url encoding, and the
complete ticket pin every byte of that conversion.
The synthetic private scalar, ECDSA nonce, UTC clock, and 16 JTI random bytes
are all fixed so the independent verifier can reproduce the DER output and
claims bytes exactly. Production signer output remains nondeterministic.

The positive ticket uses public `credential_kind=connector_bootstrap`. The
private storage discriminator `tunnel_bootstrap` appears only as the raw input
to the credential fence and in the explicit public-wire reject. It is never an
accepted ticket value. No assignment ticket contains an OTP: account
registration obtains the user-entered OTP out of band and carries that OTP with
the ticket in the single REG call.

`lrt_body_template` composes the complete positive ticket into the exact LRT
JSON shape. The derived body size and conservative assumed NHP packet size
prove the fixture stays below the frozen 3856-byte body and 4096-byte packet
limits.
`nhp_packet_overhead_bytes=256` is a deliberately conservative envelope
reservation, not a claim that one current serializer always emits exactly 256
bytes of framing. With that reservation, the 1521-byte body produces a
1777-byte assumed packet, leaving 2335 bytes of body headroom and 2319 bytes of
packet headroom. Any future NHP envelope that can exceed the reservation must
update this artifact before the larger ticket path ships.

The independent assignment-ticket verifier is deliberately separate from
exported-SDK coverage: SDK and NHP transport layers carry qat1 opaquely, while
only the assignment authority produces and verifies it. The verifier therefore
exercises qat1 cryptography without adding a ticket parser to either transport
layer. It deliberately remains in the root Go module so `go test ./...` runs
its tests in the standard root-module CI gate; publishing the command is an
accepted tradeoff for automatically guarding every committed cryptographic
byte.
Behavioral and cryptographic conformance currently run in that Go verifier;
the npm and Python surfaces are byte-delivery accessors whose CI coverage is
structural and whose exact bytes are protected by the three-copy identity gate.

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

`fence_rejects` are deliberately advisory typed-mutation recipes, not alternate
golden byte strings: consumers apply each recipe to their own fence builder and
assert rejection before hashing. The `fence_kind=all` recipe is a cross-cutting
integer-encoding boundary rather than the name of a fourth fence. By contrast,
`claims_rejects` carry executable parser inputs. The `wrong_audience` complete-
verifier case includes a valid signature for its altered claims, so it isolates
the claims boundary without depending on claims-before-signature check order.
Trust-key rejects also carry concrete SPKI bytes: the independent verifier
parses each input and proves the empty, malformed, and non-P256 cases reject.

Reject classes are a closed, coarse consumer vocabulary:

- `claims`, `time`, `size`, `encoding`;
- `signature`, `high_s`, `wrong_length`;
- `unknown_kid`, `environment`, `key_length`;
- `der`, `fence_input`.

The coarse `key_length` trust class deliberately includes a well-formed EC key
on the wrong curve: the trust profile accepts only the fixed-width P-256 key
shape. Malformed and empty SPKI inputs use the separate `der` class.

A consumer may expose more specific internal errors, but it must reject every
fixture at the named boundary and must not silently reinterpret a reject as an
accepted future extension.
