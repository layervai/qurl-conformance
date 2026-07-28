# Connector Authority Lambda v1 vectors

`connector_authority_lambda_v1_vectors.json` freezes the private synchronous
contract for five separately permissioned Connector Authority Lambda operations
called by authenticated NHP workers and one sandbox-only attended-proof
operation. These bodies are not a public API and never travel between an SDK
and LayerV. Native SDK traffic remains NHP over UDP.

Each operation has its own request schema; there is intentionally no generic
`operation` envelope. NHP runtime callers cannot choose environment, cell,
owner, or assignment generation. The authority derives those values from
authenticated identity, credential state, and the provisioned-cell catalog.
Only the separately permissioned sandbox proof controller may name the pinned
and target cells in its closed mutation request.

The global `IssueAssignment` and `RefreshAssignment` operations require a
canonical lowercase SHA-256 hex `hub_request_id`. The authenticated Hub worker
uses domain-separated framing over its deployment environment, the
Hub-selected exact operation, the authenticated initiator public key, and the
raw 32-byte logical `request_nonce` carried in the authenticated assignment
LST. NHP send timestamp, transaction id, source address, and body digest are
deliberately excluded so a fresh-packet retry retains the same logical ID. The
authority uses this private value as a cross-worker replay key: it
caches only a successful Issue/Refresh domain result for 15 minutes, and the
same id plus request fingerprint returns that result. The same id plus a
different semantic request fingerprint fails closed. Malformed,
rejected-credential or identity, pre-invoke/rate-limited, and transient
`unavailable` outcomes are not cached. Retries inside one logical operation
produce the same id even though their packet timestamps and counters change. A
later top-level operation generates a new request nonce and therefore a new id,
so replay handling does not suppress a fresh assignment read or reassignment.
This id is neither a
credential nor caller-selected authority, never appears in authority
responses or public NHP bodies, and is rejected by all three cell operations.
The exact private derivation and substitution KATs live in
`connector_hub_request_id_v1_vectors.json`.

The attended controller also supplies a canonical `hub_request_id` to
`MutateProofAgent` as its replay key. Its `grant_correlation_id` is the exact
controller dispatch identity:
`nhp-<run-id>-<run-attempt>-<client>-<proof-phase>-<32-lowercase-hex>`, where
client is `connector` or `qurl_go` and phase is `pre_removal` or
`post_removal`. Neither identifier appears in a move or lease-expiry receipt;
the arm receipt returns the correlation id so the controller can bind the
durable directive it just created to the dispatched proof.

The mutation replay contract is behavioral, not decorative. Its
domain-separated semantic fingerprint covers `version`, `mutation`,
`agent_id`, `grant_correlation_id`, and exactly the fields admitted by the
selected mutation; `hub_request_id` is the lookup key and is excluded from the
fingerprint. Every first mutation is atomically fenced by a conditional command
write carrying that exact fingerprint. The same live id and fingerprint returns
the byte-identical success; the same id with changed semantics loses the
condition and returns `invalid_request` without committing its mutation. An
expired or corrupt id returns `unavailable` and never starts a fresh mutation.

`arm` and `expire_lease` commit their mutation and exact success atomically.
`move` may use its required two assignment transitions: the active-to-moving
transition and pending command commit atomically, then the final
assignment/directive transition and exact success commit atomically. A pending
move resumes only from moving on the pinned cell. Once that state was accepted
before logical expiry, the exact pending command remains authorized for a
bounded 300-second recovery window after logical expiry. During that window
it either finishes with the exact success or atomically compensates to active
on the pinned cell at the same generation and records a terminal
`unavailable` tombstone. The compensation transaction changes pending to that
terminal tombstone in the same write that restores active-on-pinned; a durable
pending-plus-active pair is still corrupt. Every other pending-state mismatch
also fails closed. A completed command replays its stored bytes only while its
logical window is live. A first observation of an already-expired durable ID,
and every expired terminal replay, returns `unavailable` without mutation.
While a command is live or an accepted pending move is inside its recovery
window, a same-ID changed fingerprint remains `invalid_request` with zero
writes. The logical replay window is 900 seconds. The command row remains until
86,400 seconds after logical expiry. Because the recovery window ends earlier,
at least 86,100 seconds of terminal tombstone runway remains even when recovery
completes at its deadline; an expired request id therefore cannot be reused to
start a second mutation while background retention completes.

All identifiers, keys, credentials, addresses, timestamps, and endpoints in
the artifact are synthetic non-production fixtures. The completion device API
key is deliberately distinct from the initial credential, and no public result
or error body contains that secret.

## Framing and shared bounds

Requests and responses are UTF-8 JSON objects capped at 4,096 bytes. Duplicate
keys, case aliases, unknown members, trailing data, null required members, and
non-object roots reject. `version` is the exact JSON integer lexeme `1`, not a
string, float, exponent, or alternate numeric spelling. Timestamps are
canonical whole-second UTC RFC3339 values ending in `Z`.

Every `body_json` string is exact wire truth: compact member order is fixed as
well as values and whitespace. Reordering members is contract drift even when
the resulting JSON object would be semantically equivalent.

The frozen assignment-ticket ceiling is 2,304 printable ASCII bytes, exactly
matching `assignment_ticket_v1_vectors.json`. This private adapter must accept
every valid qat1 token within that shared limit when the complete request still
fits the 4,096-byte request cap.

Every response is exactly one of:

```json
{"version":1,"result":{}}
{"version":1,"error":{"code":"..."}}
```

Only `IssueRegistrationOTP/rate_limited` adds `retry_after_seconds`, and that
value must be a positive integer. No other success or error may add fields.

## Closed operations

| Operation | Request members after `version` | Success result | Closed semantic errors |
| --- | --- | --- | --- |
| `IssueAssignment` | `hub_request_id`, `agent_id`, `authenticated_peer_public_key_b64`, `credential` | agent id, registration metadata, assigned cell endpoint, opaque assignment ticket and expiry | `invalid_request`, `credential_invalid`, `credential_consumed`, `unavailable` |
| `RefreshAssignment` | `hub_request_id`, `agent_id`, `authenticated_peer_public_key_b64` | agent id and assigned cell endpoint | `invalid_request`, `identity_rejected`, `reassignment_in_progress`, `unavailable` |
| `IssueRegistrationOTP` | `assignment_ticket`, credential key id and secret, peer key, agent id, observed source address | `{}` | `invalid_request`, `rejected`, `email_unavailable`, `rate_limited`, `send_failed`, `unavailable` |
| `ActivateRegistration` | `assignment_ticket`, credential key id, registration credential, peer key, agent id, hostname, agent version | `{}` | `invalid_request`, `credential_rejected`, `ticket_invalid`, `not_yet_valid`, `ticket_expired`, `identity_conflict`, `quota`, `reenrollment_required`, `unavailable` |
| `CompleteRegistration` | peer key, agent id, device API key | `device_api_key_id` only | `invalid_request`, `identity_rejected`, `quota`, `conflict`, `unavailable` |
| `MutateProofAgent` | replay id, mutation, proof agent id, grant correlation id, and mutation-specific fields | strict result union described below | `invalid_request`, `identity_rejected`, `directive_absent`, `directive_expired`, `reassignment_in_progress`, `unavailable` |

`MutateProofAgent` is a proof-controller operation, not an NHP worker
operation. Its request union is exact:

- `arm` requires `pinned_cell_id`, `target_cell_id`, and positive
  `lease_seconds`;
- `move` requires only `target_cell_id`;
- `expire_lease` requires only positive `lease_seconds`.

Conditional members for a different mutation are unknown fields, not ignored
options. The move golden is the primary request/success pair;
`additional_request_goldens` and `additional_success_goldens` freeze the arm
and expiry pairs.

Each success result begins with its required `mutation` discriminator:

- `arm` returns the agent, pinned and target cells, lease seconds, grant
  correlation id, and mutation timestamp;
- `move` returns the agent, previous cell/generation, new cell/generation,
  lease expiry, and mutation timestamp. The cells differ and the new generation
  is exactly the previous generation plus one;
- `expire_lease` returns the agent, new lease expiry, and mutation timestamp.

All three results are closed exact-member objects. A mixed union rejects.
Mutation timestamps and lease expiries are canonical whole-second UTC values,
and mutation precedes expiry where an expiry is present.

The synthetic `IssueAssignment` success golden uses registration
`key_kind=account`. Consumers must accept the complete frozen public vocabulary:
`bootstrap`, `connector_bootstrap`, `account`, and `agent`.

`registration_credential`, `hostname`, and `agent_version` are required
members on activation. The registration proof may be explicitly empty only as
a replay candidate: this private shape gate cannot know replay state, and the
service accepts it only after replay-first lookup finds a durable committed
activation. Empty proof never authorizes first use, where the credential-kind
specific API secret or OTP must validate. Hostname and agent version may also
be explicitly empty, but missing and null are never equivalent to explicit
empty for any of these members.

Assignment results enforce the provisioned-cell producer contract: canonical
cell ids, positive generations and endpoint revisions, canonical LayerV-owned
public DNS endpoints, ports 1 through 65535, and a canonical usable X25519
server key. The public server key is the identity the native SDK authenticates;
the worker must not substitute an inferred endpoint or raw cloud load-balancer
hostname.

## Public NHP dispositions

`public_mapping_cases` freeze exact public bytes and name their provenance:

- `authority_response` maps a validated private success or semantic error;
- `nhp_preinvoke` maps a worker admission decision made before invocation.

`MutateProofAgent.public_mapping_cases` is exactly empty. The operation is
invoked only through its sandbox proof alias and must not enter an NHP
production dispatch table or numeric-code mapping.

Registration-disabled `52107` is Issue/enroll-only. Assignment admission
`52204` is a pre-invoke outcome for both Issue and Refresh and is not a private
authority error. Public assignment code `52203` remains reserved by
`agent_assignment_golden.json` but is deliberately not produced here: the Issue
and Refresh domain operations do not mutate assignments, although their
private adapter writes the 15-minute replay envelope; Activate atomically
enforces owner quota and maps it to RAK `52112`.

OTP issuance is fire-and-forget and uses `no_application_reply` for every
outcome. Activation is different: a validated `unavailable` authority response
uses `drop_no_reply`, carries no RAK body, and starts only the bounded
exact-pending-activation transport-recovery path. It must never be translated
to `52107`. This distinct action prevents a worker from treating a deliberately
dropped activation reply as the OTP protocol.

Activation `ticket_invalid` and `not_yet_valid` deliberately collapse to the
same public RAK `52110` body so ticket timing does not become a public oracle.

## Reject vocabulary

Request rejects use the closed classes `duplicate_key`, `case_alias`,
`unknown_field`, `null_field`, `wrong_type`, `missing_field`, `trailing_data`,
`version_encoding`, `non_object`, and `oversize`.

Response producer rejects add `response_xor`, `unknown_error_code`,
`retry_after_policy`, and `invalid_result`. Each committed reject body must fail
for its declared class and isolate exactly one anomaly; merely failing for some
other reason is not conformant, and combined defects have no class precedence.
Oversize cases derive exactly 4,097 bytes from the recorded fill byte.

## Consumer algorithm

For each operation, a consumer should:

1. enforce the byte cap before JSON decoding;
2. reject duplicate keys, trailing data, and non-object roots;
3. require exact member names, presence, null policy, types, and version lexeme;
4. validate operation-specific semantics and producer-domain fences;
5. accept the request and success goldens byte-for-byte, including every
   additional proof-mutation golden;
6. parse each semantic error and require its exact canonical response bytes;
7. prove every reject fails for the named reject class;
8. map every private or pre-invoke outcome to the exact NHP action, body, and
   recovery action in `public_mapping_cases`, except that the proof-only
   operation must have no mappings.

The Go loader performs these checks independently when loading the embedded
artifact. npm and Python expose byte-identical synchronized copies; their CI
smokes protect artifact identity and the operation/disposition inventory.
