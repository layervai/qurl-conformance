# Agent credential recovery v1 vectors

`agent_credential_recovery_v1_vectors.json` freezes the UDP-only, explicit
operator path for replacing a lost or revoked qURL Connector device API
credential while preserving the existing agent identity.

This artifact is the SDK-facing half of the recovery contract: the exact Hub
and assigned-cell NHP bodies an SDK sends and receives, the closed error
taxonomy it must classify, and the binding, replay, and flow rules it must
enforce. The platform's internal invocation bodies, its private replay-key
derivation, and the deployment inputs to that derivation are not published
here. Every fixture value appears in at least one public body.

## Security boundary

Recovery requires both a live, reusable credential of exact kind `agent` and
scope `qurl:agent`, and the authenticated X25519 initiator public key already
bound to the persisted `agent_id`. The recovery credential proves owner
authority. The authenticated peer proves continuity of the existing agent
identity. Neither proof is a placement hint.

Here `kind=agent` means the ordinary reusable `qurl:agent`-scoped credential
metadata already used by assignment. It does not mean, or compose with, a
distinct API-key type enum.

The platform chooses the current cell and the Hub returns its exact
LayerV-owned UDP host, port, and server public key. The client resolves and
dials only that endpoint and authenticates only that server key.

Version 1 deliberately has no key takeover. `takeover`, `cell_id`,
`resource_id`, and every other placement or qURL-resource selector are unknown
request fields. A caller that lost the agent X25519 private key must enroll a
new agent identity; an owner credential alone cannot seize an existing ID.

No lifecycle leg permits HTTP, the browser relay, client-derived cell names,
cell probing, or cross-cell fallback. Steady-state qURL resource CRUD remains a
separate API concern. This recovery wire carries no resource identity, so it
cannot accept either a public-key resource ID or a legacy `r_...` identifier.

## Public flow

Both exchanges use authenticated `NHP_LST` (5) -> `NHP_LRT` (6), and each LRT
must echo the request counter. `public_exchanges` holds the two exact golden
request and success bodies.

1. `hub_issue_recovery`: the explicit recovery operation sends a Hub
   `cell_assignment` request with `mode=recover`, one canonical 32-byte
   `request_nonce`, and the recovery credential inside `usrData`. `usrId`
   remains empty. The Hub applies this artifact's additive recovery LST-cookie
   composition (`hub_cookie_composition`) before doing any credential work.
   It reuses the base `connector_hub_lst_cookie_v1_vectors.json` cookie KAT,
   digest primitive, challenge parser, and strict-less-than size gate while
   keeping the recovery body's proof/size cases outside that artifact's closed
   two-flow set.
2. The Hub validates the credential, peer/agent binding, current assignment,
   and that the current device credential was deliberately revoked. It
   returns the complete assignment and one opaque, short-lived recovery grant
   plus authenticated whole-second UTC `recovery_grant_issued_at` and
   `recovery_grant_expires_at` values whose producer lifetime is exactly 900
   seconds. Consumers enforce the same difference without using local receipt
   time. The grant's canonical wire grammar is `qrg1.` plus one or more ASCII
   alphanumeric, `_`, or `-` characters, capped at 2,304 bytes; the restricted
   alphabet keeps the byte budget independent of JSON escaping. The grant is
   opaque to the SDK. The platform binds it to the environment, agent,
   authenticated peer, recovery-credential key/hash/fence/kind/scope,
   revoked-device fence, cell, and assignment generation. Endpoint revision is
   transport metadata and is not an authorization fence.
3. Before the first assigned-cell request, the SDK generates one CSPRNG device
   secret and durably seals that exact candidate with the grant and
   assignment.
4. `assigned_cell_complete_recovery`: the SDK sends
   `query=agent_credential_recovery` with the grant and candidate directly to
   the assigned cell. The cell checks the authenticated peer and every grant
   fence, and strongly rechecks that the exact bound recovery credential is
   still active and unexpired. A credential that becomes inactive, revoked, or
   expired after grant issuance makes completion fail terminally with grant
   rejection; this is the revocation kill switch for a stolen reusable
   recovery credential. The platform then atomically records the replacement
   and returns only `device_api_key_id`. It never returns the secret or a
   secret-derived value. An exact committed replay returns the same ID; a
   different candidate is a terminal conflict.

## Logical-request replay

One explicit recovery operation mints one `request_nonce` and reuses the exact
serialized Hub body through every nested transport retry. The platform keys its
replay record on that nonce, the authenticated peer, and the operation, so the
record is scoped to recovery. Reusing a nonce value across different
operations, such as an assignment refresh and a recovery, is not a replay and
not a conflict; this fixture nonce equals the refresh-assignment nonce used
by the assignment and base cookie artifacts. The platform fingerprints the recovery operation
over the fields named in `protocol.issue_semantic_fingerprint_fields` (the
agent ID, the authenticated peer, and the key ID, hash, and fence derived
from the recovery credential). The same nonce with the same fingerprint returns
the byte-identical assignment, grant, issued time, and expiry. The same nonce
with a changed credential, agent, or authenticated peer is a terminal
fingerprint conflict and surfaces as `52405`. A transport retry never remints
an outcome and never changes the nonce or body. An exact replay may return its
stored result after the bound credential is revoked, but the cell's live
credential-status check prevents that replay from completing. `issue_replay_cases`
freezes these outcomes.

## Crash and time contract

The first authenticated `recovery_grant_expires_at` anchors one immutable
90-day (`7,776,000` second) recovery horizon for the platform-owned recovery
episode identified by the revoked-device credential fence. Recovery is allowed
only while `now` is strictly before `anchor + horizon`; the exact boundary is
expired. A later grant in the same episode, process restart, local wall-clock
timestamp, response, or retry never moves the anchor. A genuinely new episode
with a new platform-owned revoked-device fence may establish a new anchor; a
client cannot declare that boundary itself.

The platform checks an exact durable completion outcome before ordinary grant
expiry. Therefore a committed response lost in transit can be replayed with the
same candidate after grant expiry but before the recovery horizon. An expired
grant with no committed result is rejected. The SDK fails closed before network
I/O after the horizon and never rotates the candidate to escape a conflict.

## Errors and retries

The closed `524xx` family is split by phase:

- Hub: `52400` unavailable, `52401` recovery credential rejected, `52402`
  identity rejected, `52403` current device credential must be revoked,
  `52404` rate limited, `52405` invalid request, `52406` assignment requires
  operator recovery.
- Assigned cell: `52410` unavailable, `52411` grant rejected, `52412` identity
  rejected, `52413` different candidate conflict, `52414` invalid request.

Only authenticated `52400`, `52404`, and `52410` are retry outcomes, within the
single caller-bounded explicit operation. `52400` and `52410` retry after five
seconds and `52404` after 60 seconds; all other codes are terminal. `errMsg`
is diagnostic text and never controls policy. Transport ambiguity retains the
exact pending candidate and grant; it does not trigger a new Hub request, HTTP
call, relay call, or another cell.

Malformed credential syntax is an invalid Hub request (`52405`) and is
rejected before a credential lookup. `52401` is reserved for a canonical
credential the platform rejects (including inactive, expired, wrong-secret,
wrong-kind, or missing `qurl:agent` scope), without disclosing which condition
failed. Public diagnostic text is exact and contains no credential, grant, or
candidate.

### Reject classes

Reject classes are consumer-neutral test categories, not public error strings:

- `body_parse` is invalid JSON shape; `semantic` is structurally valid but
  invalid recovery wire data. A duplicated, unknown, or mistyped field is
  `body_parse`; an absent required field is `semantic`.
- `proof_body`, `proof_flag`, and `proof_freshness` reject cookie-proof drift;
  `return_routability` rejects credential work before proof; `amplification`
  rejects a challenge that is not strictly smaller than its triggering packet.
- `fingerprint_conflict` rejects nonce reuse with changed semantics;
  `replay_drift` rejects a non-byte-identical stored result; `logical_operation`
  rejects retry behavior that starts a different logical request.
- `grant_binding` rejects a changed grant fence; `grant_rejected` rejects a
  no-longer-authorized bound credential; `revoke_required` requires deliberate
  revocation of the current device credential; `grant_expired` and
  `grant_lifetime` reject an unusable or non-900-second grant.
- `recovery_anchor` rejects horizon re-anchoring and `recovery_expired` rejects
  the exact horizon boundary; `credential_conflict` rejects a different
  replacement candidate.
- `identity`, `operator_intent`, `transport`, `placement`, and `persistence`
  respectively reject peer takeover, implicit recovery, HTTP/relay use,
  client-selected or fallback cells, and non-durable candidate handling.

`hub_cookie_composition.authority_invocations_before_proof` and
`authority_invocations_after_proof` count credential-checking calls the Hub may
make for one flow: zero before a valid cookie proof and exactly one after.

## Consumer algorithm

Consumers must strict-decode every object, rejecting duplicates, aliases,
unknown fields, wrong types, missing required fields, and trailing JSON. They
must run each raw request and result reject through the real parser and execute
every issue-replay, grant-binding, and flow mutation against the real SDK state
machine rather than trusting the stored outcome.

Some binding dimensions have no published fixture value. The environment is
deployment state that no public body carries. The authenticated peer is the
Noise-authenticated initiator key, not a body field. The credential key ID,
hash, and fence are derived server-side from the recovery credential. The
`reject_wrong_environment` and peer grant-binding cases, and the matching
entries in `issue_semantic_fingerprint_fields`, are therefore declarative in
this public half. An SDK exercises them against its own durable pending state,
for example the stored agent, public key, and credential fingerprint. Likewise,
`hub_cookie_composition.authority_invocations_before_proof` /
`authority_invocations_after_proof`, the cookie case
`reject_authority_before_proof`, and the flow case
`reject_authority_before_cookie_proof` describe Hub behavior. An SDK can only
check that it sends the byte-identical body in the proof and never treats an
unproven exchange as a result.

Consumers also validate the Hub cookie composition, result counter/type,
LayerV host, pinned server key, cell/generation binding, grant times, and
device-key ID grammar. The recovery credential, grant, and replacement
candidate never enter errors or logs. A missing fixture or unsupported case is
a test failure, never a skip.
