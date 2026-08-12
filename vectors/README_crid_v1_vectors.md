# CRID v1 vectors

`crid_v1_vectors.json` is the public contract for CRID v1, the Cryptographic
Resource ID: a self-checking identifier derived from a resource public key. A
CRID commits to the exact DER `SubjectPublicKeyInfo` bytes, so any party that
later receives the key can re-derive the identifier and detect substitution
without trusting the channel that delivered the key.

## Derivation

```text
digest  = SHA-256( "NHP-QURL-CRID-V1" || 0x00 || der_spki_bytes )
payload = version_byte(1) || digest[:digest_length]
crc     = CRC32C(payload)            # Castagnoli; serialized big-endian, 4 bytes
CRID    = base32(payload || crc)     # RFC 4648 alphabet, lowercase, no padding
```

`checksum_polynomial_hex` is the Castagnoli polynomial in normal
(non-reflected) form, `1edc6f41`; implementations that take the reversed form
(for example Go's `crc32.Castagnoli` table constant) use `82f63b78` for the
same checksum. The checksum is an integrity aid, not a security boundary — the
security property is the digest.

In `producer_cases`, `digest_hex` is the full 32-byte digest, `crc_hex` is the
serialized checksum, and `payload_hex` is the **complete pre-encoding byte
string** `version_byte || digest[:digest_length] || crc` — exactly the bytes
the base32 stage consumes, so `expected_crid` is its direct encoding and
`crc_hex` is its final four bytes, computed over everything before them.

## Version registry

| `version_hex` | Digest length | Environment | Status |
| --- | --- | --- | --- |
| `01` | 32 | production | active |
| `81` | 32 | test | active |
| `02` | 24 | production | reserved |
| `82` | 24 | test | reserved |

The `80` bit means non-production. Version `00` is permanently forbidden and
must reject locally. The reserved truncated versions are registered but not
minted; consumers must not treat them as errors if they ever appear with a
valid checksum — they are unknown-but-forwardable like any other unregistered
version until a schema revision activates them.

Structural facts every implementation can (and the strict loader does)
enforce:

- A full CRID is exactly 60 characters; 37 bytes leave 4 zero pad bits, so its
  final character is `a` or `q`.
- A truncated CRID is exactly 47 characters; 29 bytes leave 3 zero pad bits,
  so its final character is one of `a`, `i`, `q`, `y`.
- The first character encodes the top five bits of the version byte:
  production full CRIDs start with `a`, test full CRIDs with `q`.

## Fixture roles

- `producer_cases` feed a frozen DER `SubjectPublicKeyInfo` and version byte
  through a producer's real derivation and compare every intermediate:
  `digest_hex`, `payload_hex`, `crc_hex`, and the exact `expected_crid`.
- `consumer_value_cases` feed the listed string through the consumer's local
  validation gate and assert `outcome`.
- `version_cases` pin what a consumer reports for a locally valid CRID:
  `version_hex`, whether the version is `known` (registered), the
  `environment` (`unknown` for unregistered versions), and the
  `digest_length` implied by the value's length.
- `key_match_cases` pin the delivered-key rule below.

## The local gate

`consumer_value_cases` pin the **local validation gate only**. An `accept`
outcome means the value passed every local check and **must be forwarded to
the authoritative validator**; it asserts nothing about whether the resource
exists. Only permanently invalid inputs — bad charset, wrong length, checksum
failure, non-canonical encoding, or version `00` — reject locally. A CRID
whose version byte is merely unregistered **must be forwarded** (warn-only at
most): rejecting unknown versions locally would turn every future version
activation into a breaking change.

A rejected case carries one of five stable classes:

- `charset`: a character outside the lowercase RFC 4648 alphabet (this
  includes surrounding whitespace — nothing is trimmed).
- `length`: not exactly 60 or 47 characters (checked after charset, so a
  61-character value containing a space is `charset`).
- `checksum`: the decoded CRC32C does not match the payload.
- `non_canonical`: the trailing pad bits are not zero. Such a value decodes to
  the same bytes as its canonical spelling, so it must be caught by
  re-encoding the decoded bytes (or checking the pad bits directly), never by
  the checksum.
- `version`: the payload's version byte is the forbidden `00`.

This vocabulary is closed: adding a class requires a new `schema_version` and
a coordinated release, and these classes do not extend the qv2 `reject_class`
vocabulary documented in
[`README_qv2_conformance_vectors.md`](README_qv2_conformance_vectors.md).
Internal error names are not part of this artifact; each implementation maps
the outcomes into its own typed errors while preserving fail-closed behavior.

## Key matching

`key_match_cases` pin the consumer MUST-rule: when a public key is delivered
for a CRID the consumer already holds, the key is used **only if** the CRID
re-derived from the delivered key — under the held CRID's version byte and
digest length — equals the held CRID exactly. On any mismatch the consumer
fails closed: no fallback to the delivered key, no partial trust. The
`mismatch_*` fixtures deliver a real, well-formed key that is simply not the
committed one, which is precisely the substitution the identifier exists to
detect.

The dependency-free Go loader in this repository is the artifact's strict
reference validator: it re-derives every producer intermediate from the DER
bytes, re-classifies every consumer value with a reference gate, re-derives
every version and key-match expectation, and enforces the structural facts
above. The npm and Python packages carry byte-identical artifact copies and
expose data accessors, so their in-repository gates check package shape and
copy parity rather than reimplementing that parser. Downstream producers and
consumers still run every applicable case through their real implementation,
as required by the lockstep rule below.

## Lockstep rule

This artifact is not satisfied merely by copying its constants into local
tests. The issuing producer consumes `producer_cases` through its real
derivation; every parser that accepts a CRID consumes `consumer_value_cases`,
`version_cases`, and `key_match_cases` through its real gate. CI in each
repository pins one released artifact version, so a derivation, registry, or
gate change cannot land independently.

Schema changes require a new `schema_version` and a coordinated producer-first
release. Existing vectors change only deliberately; additions that broaden the
accepted grammar are breaking changes for fail-closed consumers.
