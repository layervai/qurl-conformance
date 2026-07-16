# qurl-conformance — working notes

This repo is the single public source of truth for the qURL v2 cross-language
conformance vectors. Keep it small, stdlib-only, and stable.

## Editing the vectors

- The vectors live under `vectors/` as JSON. Edit them there, by hand, with a
  JSON-aware edit. Treat every per-vector field as wire-truth: change vector data
  only deliberately, and re-run `go test ./...` after any edit.
- `qv2_conformance_vectors.json` is the conformance classes; it composes
  `issuer_signature_vectors.json` (the signature golden bytes) by reference.
- `agent_knock_application_vectors.json` starts after Noise decryption. Keep it
  consumer-neutral and do not add packet/key/ciphertext fields already covered
  by `relay_knock_golden.json`.
- Keep its raw RunID request cases at the application-body layer. The generic
  parser and native qURL Connector expectations are separate entry points; do
  not turn either into a second full packet artifact.
- `vectors/README_qv2_conformance_vectors.md` is the schema + `reject_class`
  vocabulary + class-to-entry-point map. Keep it in sync with any schema change.

## Hard rules

- The generator that produces the vectors lives at `tools/gen` and is run via
  `make gen-vectors` ONCE per issuer-key rotation. It is NEVER run in CI (the
  accept signature uses a random nonce, so it is not reproducible). The committed
  JSON is the artifact.
- `tools/gen` owns only the issuer-signature and qv2 verify-path artifacts. It
  does not rewrite the frozen NHP packet families: agent-registration packets
  are checked by `tools/verify-sdk`, and agent-assignment packets are checked by
  `tools/verify-assignment` against their pinned producers.
- Do not regenerate keys or signatures here; the committed key/signature bytes are
  the contract.
- Keep the module dependency-free (stdlib only): no `require` lines in `go.mod`.
- Keep the description/README consumer-neutral: this artifact is consumed by
  verifiers in multiple languages, so prose must not name any one implementation's
  private internals.

## Releases

- Versioning is automated by Release Please in manifest mode (`release-please-config.json`,
  `.release-please-manifest.json`, `.github/workflows/release-please.yml`). The Go
  module, npm package, and Python package share one linked version.
- Merging the release PR tags the repo and thereby releases the Go module.
- npm/PyPI registry publishing on release is a token-gated follow-up (needs
  `NPM_TOKEN` / PyPI trusted publishing); Release Please currently automates only
  the version PRs + the Go tag.
