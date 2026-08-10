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
  does not rewrite the frozen NHP packet families.
- This repo does NOT verify its vectors by rebuilding them with a consumer SDK.
  Doing so made the vector artifact depend on its own consumers, and every wire
  change deadlocked: the cross-check could not pass until a consumer spoke the
  new protocol, and no consumer could adopt it until the vectors shipped.
  Consumers verify themselves against the published vectors in their own CI.
- Because the module is stdlib-only there is no BLAKE2s/AEAD primitive here, so
  nothing in this repo can recompute a packet, header digest, or proof digest.
  The in-repo gates are structural only and a transcription error inside a
  well-formed `packet_hex` would pass CI. Regenerating packet bytes hands
  verification to `RELEASE_CHECKLIST.md`; work through it and keep it current
  rather than adding a crypto check here.
- Producer-revision pins name the commit that emitted the committed bytes. Never
  leave one pointing at a pre-change commit — the self-consistency tests pass
  when the pins agree with each other, not when they are true.
- Do not regenerate keys or signatures here; the committed key/signature bytes are
  the contract.
- Keep the module dependency-free (stdlib only): no `require` lines in `go.mod`.
- Keep the description/README consumer-neutral: this artifact is consumed by
  verifiers in multiple languages, so prose must not name any one implementation's
  private internals.

## Releases

- Versioning is automated by Release Please in manifest mode (`release-please-config.json`,
  `.release-please-manifest.json`, `.github/workflows/release-please.yml`). The npm
  and Python packages share one linked version. The Go module's version tracks
  them whenever a change touches the vectors — which is every change to the wire
  artifact, since the three mirrors are byte-identical — but floats ahead on a
  release driven only by root-path commits (a `build:` toolchain bump, a `ci:`
  change), because `npm/` and `python/` have nothing to publish for those. That
  is why `.release-please-manifest.json` can legitimately read `".": 0.12.3`
  against `npm`/`python` at `0.12.2`; it is not drift to be "corrected".
- Merging the release PR tags the repo and thereby releases the Go module.
- npm/PyPI registry publishing on release is a token-gated follow-up (needs
  `NPM_TOKEN` / PyPI trusted publishing); Release Please currently automates only
  the version PRs + the Go tag.
