# qurl-conformance

The single public source of truth for **qURL v2 conformance vectors**: the
language-agnostic wire-truth that every qURL v2 verifier re-runs against its own
implementation.

The vectors are **behavioral**. Each class names the verifier operation it targets
and the input shape it consumes; a consumer feeds that input through its real
parser/validator and asserts the declared accept/reject outcome (and, where the
class is about the distinction, the `reject_class`). A verifier that drifts from
the contract fails its own run — there are no stored booleans to trust.

## Layout

| Path | What it is |
| --- | --- |
| `vectors/qv2_conformance_vectors.json` | the conformance classes: claims/secret parse, strict base64url, fragment shape, relay allowlist, server-id, and the composed signature class |
| `vectors/issuer_signature_vectors.json` | the issuer-signature golden vectors (P-256 raw r\|\|s low-S) the signature class composes by reference |
| `vectors/README_qv2_conformance_vectors.md` | the schema, `reject_class` vocabulary, class-to-entry-point map, and the derived tamper case |
| `schema.go`, `embed.go` | a stdlib-only Go module that embeds the artifacts and exposes strict, typed loaders |

## Using it from Go

```go
import conformance "github.com/layervai/qurl-conformance"

cf, err := conformance.ConformanceVectors()   // strict-parsed conformance artifact
vf, err := conformance.SignatureVectors()     // strict-parsed issuer-signature vectors
raw := conformance.QV2Vectors()               // raw bytes, if you drive your own parser
```

The loaders fail (never return an empty document) on a malformed or unexpected
artifact, so the contract can never silently drop out of a test suite.

## Using it from another language

Copy `qv2_conformance_vectors.json` **and** `issuer_signature_vectors.json`
verbatim (same bytes, no reformatting), load them with a strict JSON reader that
rejects duplicate keys and unknown fields, route each class's input to your real
entry point, and assert the declared outcome. Treat a missing fixture as a hard
failure, not a skip. See `vectors/README_qv2_conformance_vectors.md` for the full
schema and vocabulary.

## Scope

This module is intentionally dependency-free (stdlib only). The generator that
produces the vectors is not part of this repo and is never run in CI; the
committed JSON is the artifact. Vectors are edited under `vectors/`.

## License

MIT — see [LICENSE](LICENSE).
