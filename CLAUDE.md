# qurl-conformance — working notes

This repo is the single public source of truth for the qURL v2 cross-language
conformance vectors. Keep it small, stdlib-only, and stable.

## Editing the vectors

- The vectors live under `vectors/` as JSON. Edit them there, by hand, with a
  JSON-aware edit. Treat every per-vector field as wire-truth: change vector data
  only deliberately, and re-run `go test ./...` after any edit.
- `qv2_conformance_vectors.json` is the conformance classes; it composes
  `issuer_signature_vectors.json` (the signature golden bytes) by reference.
- `vectors/README_qv2_conformance_vectors.md` is the schema + `reject_class`
  vocabulary + class-to-entry-point map. Keep it in sync with any schema change.

## Hard rules

- The generator that produces the vectors lives at `tools/gen` and is run via
  `make gen-vectors` ONCE per issuer-key rotation. It is NEVER run in CI (the
  accept signature uses a random nonce, so it is not reproducible). The committed
  JSON is the artifact.
- Do not regenerate keys or signatures here; the committed key/signature bytes are
  the contract.
- Keep the module dependency-free (stdlib only): no `require` lines in `go.mod`.
- Keep the description/README consumer-neutral: this artifact is consumed by
  verifiers in multiple languages, so prose must not name any one implementation's
  private internals.
