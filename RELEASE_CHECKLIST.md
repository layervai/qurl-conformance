# Release checklist

This file is the gate that carries what this repository's CI structurally cannot.
Work through it before merging a PR that regenerates packet bytes, and before
tagging the release that publishes them.

## What CI here does and does not prove

The root module is stdlib-only by rule — `go.mod` carries no `require` line —
so **no BLAKE2s, X25519-AEAD or Noise primitive exists in this repository**, and
no test here can recompute a `packet_hex`, a `header_digest_hex`, or the Hub
`expected_digest_hex`. That is deliberate: a vectors artifact that imported a
codec to check itself would depend on its own consumers, and every wire change
would deadlock.

CI proves the artifacts are **structurally** sound: strict parsing, framing and
length bounds, canonical lowercase hex and base64, key roles, header type, flag
and protocol-version bytes, counter correlation, closed case vocabularies, and
byte-identity across `vectors/`, `npm/vectors/` and
`python/qurl_conformance/_data/`.

CI cannot prove the bytes are **authentic**. A transcription error inside an
otherwise well-formed regenerated `packet_hex` passes every check in this repo.
Authentication happens in the consumers, and the steps below are what makes that
handoff real rather than assumed.

## Every release

- [ ] `go build ./... && go vet ./... && go test -count=1 ./...`
- [ ] `gofmt -l .` is empty
- [ ] `bash scripts/check-sync.sh`
- [ ] `(cd tools/verify-assignment-ticket && go test ./...)`
- [ ] npm and Python package smokes green (CI job `vectors + go + cross-language`)
- [ ] `go.mod` still has no `require` line

## When a release regenerates NHP packet bytes

Applies whenever any `packet_hex`, `header_digest_hex`, `header_prefix_hex` or
`expected_digest_hex` changes — a protocol bump, a key rotation, a reseal.

- [ ] **Name the producer.** Record which repository and commit emitted the new
      bytes. Update `AgentSessionControlProducerRevision` (`agent_session.go`),
      `AgentAssignmentQURLGoProducerRevision` (`schema.go`), the
      `producer_revision` field in `agent_session_control_vectors.json` and its
      two mirrors, the two `producer_revision` assertions in
      `.github/workflows/ci.yml`, and the prose pins in `README.md` and
      `vectors/README_agent_session_control_vectors.md`. A pin that names a
      pre-change commit is worse than no pin: the self-consistency tests pass
      because the pins agree with each other, not because they are true.
- [ ] **Re-pin after the producer merges.** A pre-merge branch commit is a
      legitimate pin — it is pushed and immutable — but a squash-merge mints a
      different SHA and deleting the branch can make the original unreachable.
      Once the producing PR merges, open a follow-up PR that moves every pin
      above to the merged SHA. Do this before the next release, not eventually.
- [ ] **Move the version pins together.** If the protocol version moved, update
      `NHPProtocolVersionMajor` / `NHPProtocolVersionMinor` **and** the
      `nhpPacketProducerProtocolMajor` / `Minor` literals that sit above the
      producer pins in `schema.go`.
      `TestNHPPacketProducerPinsRecordVectorProtocolVersion` fails until they
      agree with the bytes the goldens actually carry; that failure is the
      forcing function that puts a reviewer in front of the producer pins.
- [ ] **Get the bytes cryptographically authenticated somewhere.** Before
      tagging, at least one consumer must rebuild the deterministic packets and
      open the frozen replies against these exact committed bytes, with its real
      codec, and report green. Today that is `layervai/qurl-go`
      (`TestBuildMessage_*Golden`, `TestDecryptReply_*Golden`,
      `TestBuildKnock_GoldenVector`) run against a `replace` directive or a
      pre-release pin pointing at this branch. Record where it ran in the PR.
      Until that has happened the bytes are unverified by anyone.
- [ ] **State the rollout order.** A 1.1 receiver rejects a 1.0 sender by
      design, so senders must never lead receivers. Vectors release first,
      servers next, clients last, and the 7-day dependency-age quarantine makes
      each step a separate pass roughly a week apart.

## After the release

- [ ] Consumers bump to the published version and adopt the new wire in their
      own CI. Until each has, its conformance run is asserting against the
      previous protocol and proves nothing about this release.
