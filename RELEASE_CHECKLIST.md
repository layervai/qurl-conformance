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

CI cannot prove the **NHP packet** bytes are authentic. A transcription error
inside an otherwise well-formed regenerated `packet_hex` passes every check in
this repo. Authentication happens in the NHP consumers, and the steps below make
that handoff real rather than assumed. The delegated-mint issue artifact is
different: its P-256 primitive is in the standard library, so the strict Go
loader rebuilds and verifies that golden signature here.

## Every release

- [ ] `go build ./... && go vet ./... && go test -count=1 ./...`
- [ ] `gofmt -l .` is empty
- [ ] `bash scripts/check-sync.sh`
- [ ] `python3 scripts/check-claude-model-lockstep.py`
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
- [ ] **Confirm every real ACK denial producer emits the strict lifetime.** At
      the pinned NHP producer revision, verify `ServerKnockAckMsg.OpenTime`
      remains a required (non-`omitempty`) uint32 `opnTime` field and exercise
      native UDP, relay/forwarded ACK, plugin, and early server-denial paths.
      Every serialized knock denial must contain typed `opnTime: 0`; every
      knock or exact-retirement denial must omit `cellId`, `sessId`,
      `sessIssuedAtMillis`, `runId`, `runAttempt`, `closeEventId`, and `state`.
      Missing, wrong-type, overflowing, or nonzero denial lifetimes and any
      denial-carried receipt authority are not conformant `server_deny` bodies.
      Record the producer tests in the PR or release handoff; consumer-only
      fixtures do not satisfy this gate.
- [ ] **State the rollout order.** A 1.1 receiver rejects a 1.0 sender by
      design, so senders must never lead receivers. Vectors release first,
      servers next, clients last, and the 7-day dependency-age quarantine makes
      each step a separate pass roughly a week apart.

## When a release rotates delegated-mint test keys

- [ ] Run `make gen-delegated-mint-vectors` once. Confirm that it self-verifies
      both low-S signatures and derives the published reject cases.
- [ ] Run `scripts/sync-vectors.sh`, then all gates in **Every release**. Confirm
      that the Node package verifies both signatures and that all three
      published JSON files are byte-identical.
- [ ] Run the real Connector producer tests against this exact artifact. They
      must rebuild the same canonical digest with a new private key and verify
      the result. Record the producing repository and exact commit in the PR.
- [ ] Confirm that the issuing service accepts both goldens, rejects every
      published reject case, retains accepted key verifiers through operation
      authority expiry, and permits a fresh-envelope key rotation.

## After the release

- [ ] Consumers bump to the published version and adopt the new wire in their
      own CI. Until each has, its conformance run is asserting against the
      previous protocol and proves nothing about this release.

## Why the root package declares no `component`

`release-please-config.json` gives `npm` and `python` a `component` and
deliberately gives the root Go package none. That asymmetry is load-bearing —
do not "tidy" it by adding `"component": "go"` back.

The root package sets `include-component-in-tag: false`, because a Go module
must be tagged `vX.Y.Z` at the module root; `go-v0.12.3` would be invisible to
the Go proxy. Inside release-please that flag makes `getComponent()` return the
empty string, which is what matches the *unlabeled* `<details><summary>0.12.3
</summary>` block the root package contributes to the grouped release PR body.

The trap is a second, separate accessor. When the release PR body has exactly
one section and that section is unlabeled — which is every release driven only
by root-path commits, since `npm/` and `python/` see no commits and get skipped
— release-please takes its "standalone release PR" path and matches on
`getBranchComponent()` instead. That accessor ignores `include-component-in-tag`
and returns the configured component verbatim. It then compares that against the
component parsed out of the *branch name*, and the grouped branch
`release-please--branches--main` carries no component at all. So `""` vs `"go"`
never matched, and release-please logged

    PR component: undefined does not match configured component: go

for all three paths, built zero releases, and exited 0.

That is what happened to v0.12.3: `#88` merged, `CHANGELOG.md` and
`.release-please-manifest.json` landed on `main`, both publish jobs skipped, no
tag was created, and nothing failed. The tag had to be created by hand and `#88`
relabelled `autorelease: tagged` to stop release-please aborting every
subsequent release PR with "There are untagged, merged release PRs outstanding".

With no `component` on the root package both accessors return the empty string,
the branch-name comparison matches, and a root-only release tags itself. Tag
names are unchanged — they are governed by `include-component-in-tag`, not by
this field.

The `linked-versions` plugin lists only `npm` and `python` for the same reason.
That plugin filters on `getComponent()`, which is the empty string for the root
package, so the Go module was never one of its group members — listing `"go"`
there was always a no-op. The real contract is: `npm` and `python` move
together, and the Go module's version tracks them on any change that touches the
vectors (which is every wire change, since the three are byte-identical) but
floats ahead on a release driven only by root-path commits. A manifest reading
`".": 0.12.3` against `npm`/`python` at `0.12.2` is correct, not drift.

This is now enforced rather than remembered. The `verify-root-tag` job in
`release-please.yml` fails the run when a release commit did not produce a
correct root tag. It treats HEAD as a release commit on either of two signals —
a `chore: release` subject, or a touched `.release-please-manifest.json` — so an
edited squash title or a customized release-commit-message cannot make the gate
silently no-op. It then requires `vX.Y.Z` for the manifest's root version to
exist *and* to resolve to that commit, since a stale tag of the right name left
by a partial recovery is as broken as a missing one.

It asserts the outcome rather than reading release-please's own outputs: the
whole bug was release-please believing it had nothing to release, so its outputs
are not a trustworthy witness. Verified against five cases — the real
post-recovery `main` passes; a missing tag fails; an edited subject with a
touched manifest still fails rather than skipping; a tag pointing at the wrong
commit fails; an ordinary commit skips.

- [ ] If `verify-root-tag` ever goes red, do not re-run it. Create the tag and
      GitHub Release at that commit, then relabel the merged release PR
      `autorelease: tagged` — otherwise release-please aborts every later
      release PR with "There are untagged, merged release PRs outstanding".
