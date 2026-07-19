# qurl-conformance

The single public source of truth for the **qURL cross-language conformance
vectors**: the language-agnostic wire-truth that every qURL verifier re-runs
against its own implementation. Separate artifact ids keep the qURL v2 verify
path, Noise-handshake packets, agent registration, NHP assignment/completion,
registered-agent knock application bodies, registered-agent session control,
control-plane API-key IDs, private Connector Authority invocations, private
Connector Hub replay identifiers, and Hub LST return-routability cookies
decoupled by layer.

The verify-path vectors are **behavioral**. Each class names the verifier
operation it targets and the input shape it consumes; a consumer feeds that input
through its real parser/validator and asserts the declared accept/reject outcome
(and, where the class is about the distinction, the `reject_class`). A verifier
that drifts from the contract fails its own run — there are no stored booleans to
trust.

## Layout

| Path | What it is |
| --- | --- |
| `vectors/qv2_conformance_vectors.json` | the conformance classes: claims/secret parse, strict base64url, fragment shape, relay allowlist, server-id, and the composed signature class |
| `vectors/issuer_signature_vectors.json` | the issuer-signature golden vectors (P-256 raw r\|\|s low-S) the signature class composes by reference |
| `vectors/relay_knock_golden.json` | the relay/NHP-handshake golden packets (X25519 / AES-256-GCM / BLAKE2s): a deterministic knock packet plus a frozen, server-sealed ack reply (see Scope) |
| `vectors/agent_registration_golden.json` | the NHP agent-registration golden packets (X25519 / AES-256-GCM / BLAKE2s): deterministic OTP/REG requests plus frozen, server-sealed RAK replies (see Scope) |
| `vectors/agent_assignment_golden.json` | deterministic hub LST/LRT assignment, account-only assigned-cell OTP, REG/RAK activation, completion LST/LRT packets, strict request/binding/size/result rejects, and the producer-pinned closed error-body taxonomy (see Scope) |
| `vectors/agent_knock_application_vectors.json` | registered-agent KNK body and RunID request-policy cases plus already-decrypted ACK/COK dispositions; no Noise packet duplication |
| `vectors/README_agent_knock_application_vectors.md` | application-vector schema, outcome/reject vocabulary, and consumer algorithm |
| `vectors/agent_session_control_vectors.json` | deterministic full-packet KNK/COK/RKN/ACK overload recovery and EXT/ACK clean exit, strict cookie parsing, authentication, and closed flow rejects |
| `vectors/README_agent_session_control_vectors.md` | session-control wire contract, correlation rules, digest formula, reject vocabulary, and consumer algorithm |
| `vectors/agent_api_key_id_vectors.json` | issuer and strict-consumer fixtures for agent registration `key_id` / `device_api_key_id` |
| `vectors/README_agent_api_key_id_vectors.md` | API-key ID grammar, fixture roles, reject classes, and lockstep rule |
| `vectors/assignment_ticket_v1_vectors.json` | standalone qat1 claims/signature golden bytes, three exact fences, and strict reject suites |
| `vectors/README_assignment_ticket_v1_vectors.md` | qat1 wire, signing, fence, size-budget, and reject-consumer contract |
| `vectors/connector_authority_lambda_v1_vectors.json` | strict private request/result/error bodies for the five separately permissioned Connector Authority Lambda operations plus NHP public mappings |
| `vectors/README_connector_authority_lambda_v1_vectors.md` | private schema, closed errors, reject vocabulary, mapping provenance, and consumer algorithm |
| `vectors/connector_hub_request_id_v1_vectors.json` | private Hub replay-key framing over environment, operation, authenticated peer, and client logical-request nonce |
| `vectors/README_connector_hub_request_id_v1_vectors.md` | request-nonce lifetime, exact derivation, excluded packet inputs, and consumer boundaries |
| `vectors/connector_hub_lst_cookie_v1_vectors.json` | Hub LST/COK/LST return-routability derivation, initial/refresh flows, amplification bounds, and closed rejects |
| `vectors/README_connector_hub_lst_cookie_v1_vectors.md` | cookie framing, proof flag/digest placement, replay boundaries, and consumer algorithm |
| `vectors/README_qv2_conformance_vectors.md` | the schema, `reject_class` vocabulary, class-to-entry-point map, and the derived tamper case |
| `schema.go`, `embed.go` | a stdlib-only Go module that embeds the artifacts and exposes strict, typed loaders |

## Using it from Go

```go
import conformance "github.com/layervai/qurl-conformance"

cf, err := conformance.ConformanceVectors()        // strict-parsed conformance artifact
vf, err := conformance.SignatureVectors()          // strict-parsed issuer-signature vectors
rk, err := conformance.RelayKnockGolden()          // strict-parsed relay-knock golden packets
ar, err := conformance.AgentRegistrationGolden()   // strict-parsed agent-registration golden packets
aa, err := conformance.AgentAssignmentGolden()     // strict-parsed assignment/REG/completion packets + errors
ka, err := conformance.AgentKnockApplication()      // strict-parsed agent KNK/ACK application vectors
sc, err := conformance.AgentSessionControl()        // strict-parsed RKN/EXT full-packet vectors
ki, err := conformance.AgentAPIKeyIDs()             // strict-parsed agent API-key ID vectors
at, err := conformance.AssignmentTicket()           // strict-parsed qat1 cryptographic/fence artifact
ca, err := conformance.ConnectorAuthorityLambda()   // strict-parsed private authority invocation artifact
hi, err := conformance.ConnectorHubRequestID()       // strict-parsed private Hub request-ID KATs
hc, err := conformance.ConnectorHubLSTCookie()       // strict-parsed Hub LST return-routability contract
raw := conformance.QV2Vectors()                    // raw bytes, if you drive your own parser
```

The loaders fail (never return an empty document) on a malformed or unexpected
artifact, so the contract can never silently drop out of a test suite.

## Using it from another language

Copy the artifact your implementation consumes (and, for qURL v2,
`qv2_conformance_vectors.json` **and** `issuer_signature_vectors.json`)
verbatim (same bytes, no reformatting), load them with a strict JSON reader that
rejects duplicate keys and unknown fields, route each class's input to your real
entry point, and assert the declared outcome. Treat a missing fixture as a hard
failure, not a skip. See `vectors/README_qv2_conformance_vectors.md` for the full
schema and vocabulary.

## Scope

This module hosts eleven artifact families, each under its own `artifact` id:

- **qURL v2 verify path** (`qurl-v2-conformance-vectors`, composing the
  issuer-signature golden bytes) — the claims/secret/base64/fragment/relay/
  server-id classes described above.
- **Relay/NHP handshake** (`qurl-relay-knock-golden-vectors`,
  `relay_knock_golden.json`) — the Noise-handshake golden packets, kept in a
  separate artifact because the qURL verify path does not import the handshake
  layer. The `knock` packet is **deterministic**: a conformant initiator must
  reproduce its `packet_hex` byte-for-byte from the listed inputs. The `ack`
  reply is sealed at origin with a **random** server ephemeral key, so it is
  **not** reproducible by a client — consumers can only decrypt it and assert the
  recovered fields. It is re-hosted here verbatim as a frozen golden value. These
  packets originate from the NHP cross-language handshake fixtures and are pinned
  here.
- **NHP agent registration** (`qurl-agent-registration-golden-vectors`,
  `agent_registration_golden.json`) — the OTP/REG/RAK Noise-handshake golden
  packets for agent enrollment, again a separate artifact from the verify path.
  The `otp`, `reg_emailed`, and `reg_preissued` requests are **deterministic**: a
  conformant initiator must reproduce each `packet_hex` byte-for-byte. The REG body
  is `{usrId, devId, aspId, otp, usrData}` with `usrData` =
  `{hostname, version, takeover}` (fields omitted when empty/false), matching the
  live agent implementations byte-for-byte. The two REG packets differ in the body
  `otp` value (an emailed code vs a pre-issued key secret) and in `usrData.takeover`
  (omitted vs `true`); the framing is identical. The `rak_success` / `rak_error`
  replies are
  sealed at origin with a **random** server ephemeral, so they are **frozen**
  decrypt-only, mirroring the relay-knock `ack`. The RAK cases echo
  `reg_emailed`'s counter, so a consumer can validate the RAK-must-echo-its-REG
  counter contract against a positive fixture. All keys/ids/secrets are synthetic.
- **NHP agent assignment and completion**
  (`qurl-agent-assignment-golden-vectors`, `agent_assignment_golden.json`) —
  complete deterministic NHP_LST (type 5) / NHP_LRT (type 6) exchanges for
  initial hub assignment, registered-agent assignment refresh, and assigned-cell
  registration completion, plus the intervening assigned-cell NHP_REG (type 13)
  / NHP_RAK (type 14) activation. Every result echoes its request counter.
  Initial and refresh packets authenticate the hub; REG and completion
  authenticate the distinct cell public key returned by assignment. The initial
  and refresh LST bodies are strictly parsed and require a canonical,
  CSPRNG-generated 32-byte `request_nonce`.
  An SDK mints it once per logical assignment operation and reuses the exact
  body through every nested retry, while a later operation mints a fresh nonce.
  It is never echoed in LRT and never exposes the Hub's private replay key. The
  separate Hub request-ID artifact freezes that private derivation.
  The opaque ticket returned by initial assignment appears byte-for-byte in REG `usrData`
  and is consumed there. Ordinary refresh returns only the current assignment
  binding and never issues a registration ticket, while completion deliberately
  carries no ticket. Public initial-assignment `registration.key_kind` is closed
  to `bootstrap`, `connector_bootstrap`, `account`, or `agent`;
  `tunnel_bootstrap` remains a private control-plane `key_type` and is rejected
  if it crosses the LRT wire. The `account_credential_otp` section
  freezes the exact one-way NHP_OTP (type 12) request bytes sent to the assigned
  cell: `{usrId,devId,aspId,pass,usrData:{query,version,assignment_ticket}}`.
  Its secret-bearing decrypted body must be consumed from the exact RawBody;
  the Noise-authenticated peer key is a separate trusted input, and no public
  key or placement field is allowed in the body. Only `key_kind=account` uses
  OTP. The `bootstrap`, `connector_bootstrap`, and `agent` paths are explicitly
  OTP-free and proceed directly to one REG. Binding cases isolate the exact
  ticket token, peer key, devId, credential id/hash/fence/kind, environment,
  cell, expiry, inclusive 630-second lifetime boundary, and 629-second reject.
  The challenge-store metadata freezes `ticket_jti` as its lookup key and binds
  that ticket to the authenticated peer key, devId, credential id, environment,
  and cell, with an exact one-field mismatch suite.
  `recomputed_credential_fence_b64` is the frozen expected result of the
  qat1/authority-owned strong-row derivation; this artifact freezes its compare
  inputs and mismatch outcome rather than locally reimplementing that derivation.
  Binding and challenge cases are declarative mutation recipes that authority
  consumers must execute against their own implementation. Packet-size
  cases drive the producer at the exact 3,840-byte plaintext / 4,096-byte packet
  limit and max+1. This remains contract data: it does not implement ticket
  verification, OTP state, rate limiting, email delivery, SDK callbacks, or a
  plugin. Schema v3 introduced the required assignment request nonce; schema v4
  adds the 52205 case's exact accepted request phases. Each is a deliberate
  breaking shape for strict consumers, which must update their typed loader
  before adopting the corresponding release. The completion request carries the
  synthetic SDK-generated device-key candidate
  that must be persisted before send; its result `list` contains exactly
  `query`, `version`, and `device_api_key_id`—no agent metadata, secret,
  secret-derived hash, or candidate commitment. The artifact also carries the
  closed 522xx/523xx LRT
  and ticket/quota 521xx RAK error taxonomy, including retry-delay rules and
  malformed-body rejects. The assignment-family 52205 response is explicitly
  accepted for both initial and refresh requests so a Hub can reject a
  malformed, unidentifiable mode without guessing the intended exchange. Its
  compact authenticated request/result case sets
  separately pin duplicate-aware JSON parsing, exact case-sensitive keys,
  unknown-field rejection, phase semantics, secret non-disclosure, and the rule
  that clients cannot supply owner identity or cell placement. The artifact
  notes define the consumer-neutral reject vocabulary so non-Go consumers do
  not need to infer meanings from Go constants. The loader
  verifies canonical lowercase hex, positive decimal transaction fields,
  canonical padded base64 endpoint keys, and each static X25519 keypair. The
  assignment wire verifier pins merged qurl-go packet-codec revision
  `8a69642957030b9ce0a1b8b356246d265a9f577d` and rebuilds and opens all nine
  deterministic packets through its exported low-level codec. That revision
  pin does not claim the higher-level qurl-go assignment request builder already
  supports the current artifact schema; the conformance artifact intentionally
  lands first. The
  error taxonomy is pinned to merged NHP revision
  `9653fcb185c77629b787ad046c13c760baba88f4`, which reserves 52110-52112 and
  the 522xx/523xx ranges and adds list-result `retryAfterSeconds`. Exact OTP
  RawBody preservation and the authenticated-peer plugin boundary are pinned
  separately to merged NHP revision
  `2072546e1fc76eb76bd7e5c22d37856019ba33e7`. All packets,
  identities, credentials, tickets, hosts,
  timestamps, and error messages are synthetic conformance values.
- **Registered-agent knock application contract**
  (`qurl-agent-knock-application-vectors`,
  `agent_knock_application_vectors.json`) — the exact compact six-field KNK
  body, authenticated RunID request-policy cases, and synthetic,
  already-decrypted reply dispositions for ACK success,
  authenticated deny, cookie challenge, wrong resource, malformed/missing maps,
  the complete current ACK producer envelope, required pre-access actions, and
  reply counter/type mismatch. Generic protocol parsing keeps RunID optional,
  while the native qURL Connector gate requires one canonical 16-character
  lowercase-hex value. Standard success includes exact-resource
  `preActions: null`; any non-null action requires NHP_ACC and fails closed until
  that phase is implemented. Optional `aspToken` / `redirectUrl` metadata never
  replaces the requested resource's `acTokens` / `resHost` authorization result.
  It contains no Noise packets or key material; consumers compose it with their
  real body serializer, request-policy gates, reply parser, and transport
  correlation gates. Its `resId` semantic is the placement-neutral NHP
  `knock_resource_id`, not the public-key management `resource_id`. See
  `vectors/README_agent_knock_application_vectors.md`.
- **Registered-agent session control**
  (`qurl-agent-session-control-vectors`,
  `agent_session_control_vectors.json`) — deterministic full packets for the
  overload path KNK -> COK -> RKN -> ACK and clean exit EXT -> ACK, pinned to
  merged producer revision `2a2a3d91adcf5a7930050db3561c8e00b8340a39`. The COK wire
  counter is deliberately unconstrained; its authenticated body `trxId` must
  equal the originating KNK counter. RKN authenticates a canonical padded
  standard-base64 32-byte cookie by extending the header digest with the raw
  cookie bytes. ACK counters echo RKN or EXT. EXT never accepts a cookie
  challenge. The artifact freezes both static X25519 identities, every
  deterministic ephemeral key, body byte, header digest, and packet byte, plus
  closed cookie and flow reject suites. Consumers must rebuild initiator
  packets, authenticate replies against the assigned cell key, and enforce the
  application-body and correlation gates after decryption. See
  `vectors/README_agent_session_control_vectors.md`.
- **Agent API-key ID contract** (`qurl-agent-api-key-id-vectors`,
  `agent_api_key_id_vectors.json`) — deterministic issuer suffix fixtures,
  direct string validation cases, and raw response-field cases for
  `registration-info.key_id` and completion `device_api_key_id`. It freezes the
  exact `key_` plus 12 ASCII-alphanumeric grammar without reinterpreting the
  synthetic NHP registration packet `usrId`. See
  `vectors/README_agent_api_key_id_vectors.md`.
- **Assignment ticket v1** (`qurl-assignment-ticket-v1-vectors`,
  `assignment_ticket_v1_vectors.json`) — exact qat1 claims bytes, signing digest,
  synthetic KMS DER-to-raw-low-S conversion, complete ticket, credential/cell/
  existing-assignment fences, NHP size budget, and closed reject suites. NHP
  carries this ticket opaquely. See
  `vectors/README_assignment_ticket_v1_vectors.md`.
- **Private Connector Authority Lambda v1**
  (`qurl-connector-authority-lambda-v1-vectors`,
  `connector_authority_lambda_v1_vectors.json`) — five distinct strict request
  schemas for `IssueAssignment`, `RefreshAssignment`,
  `IssueRegistrationOTP`, `ActivateRegistration`, and
  `CompleteRegistration`. There is no generic operation selector and callers
  cannot supply environment, cell, owner, or assignment generation. Each
  global `IssueAssignment` and `RefreshAssignment` request carries a required
  lowercase SHA-256 hex `hub_request_id`. The authenticated Hub worker uses
  domain-separated framing over its environment, the Hub-selected exact
  operation, authenticated initiator public key, and the raw 32-byte
  `request_nonce` from the strict authenticated LST. NHP timestamp, transaction
  id, source address, and body digest are deliberately excluded so fresh-packet
  retries retain one logical ID. This gives the private authority a
  cross-worker replay key without making it caller authority: a successful
  Issue/Refresh domain result is cached for 15 minutes and the same id plus
  request fingerprint reuses it, while the same id plus a different semantic
  request fingerprint fails closed. Malformed, rejected-credential or identity,
  pre-invoke/rate-limited, and transient-unavailable outcomes are not cached. A
  later top-level assignment operation has a newly generated request nonce and
  therefore a new id. Cell operations reject the field, and it never appears
  in a public NHP body or authority response. Each response is exactly
  `{version,result}` or `{version,error}` under a 4,096-byte
  cap; only OTP `rate_limited` may carry a positive `retry_after_seconds`.
  Private-to-NHP cases freeze whether the worker emits LRT, emits RAK, follows
  OTP's normal no-application-reply protocol, or deliberately drops an
  activation reply. In particular, activation `unavailable` is deliberately
  silent so the SDK's bounded exact-pending-activation transport recovery owns
  ambiguity; it is never translated to 52107. Initial-enrollment 52107 and
  Issue/Refresh assignment-admission 52204 are explicitly NHP pre-invoke
  outcomes, not authority errors. Public 52203 remains reserved by the public
  assignment artifact but is intentionally not produced here: the Issue and
  Refresh domain operations do not mutate assignments, although their private
  adapter writes the 15-minute replay envelope; activation atomically enforces
  owner quota as RAK 52112. See
  `vectors/README_connector_authority_lambda_v1_vectors.md`.
- **Private Connector Hub request-ID v1**
  (`qurl-connector-hub-request-id-v1-vectors`,
  `connector_hub_request_id_v1_vectors.json`) — exact tagged framing and KATs
  for the Hub-derived replay key. It also freezes the canonical public
  `request_nonce` encoding and the rule that same-nonce changed semantics must
  reach the Authority under the same operation-scoped ID and fail its semantic
  fingerprint check. See
  `vectors/README_connector_hub_request_id_v1_vectors.md`.
- **Connector Hub LST return-routability cookie v1**
  (`qurl-connector-hub-lst-cookie-v1-vectors`,
  `connector_hub_lst_cookie_v1_vectors.json`) — exact stateless HMAC framing,
  the Hub-LST-only `0x0004` proof flag and digest input, initial and refresh
  flows, strict COK parsing, dynamic no-amplification bounds, and silent
  pre-Authority rejects. It neither changes nor reuses the existing overload
  KNK/RKN cookie domain. See
  `vectors/README_connector_hub_lst_cookie_v1_vectors.md`.

This module is intentionally dependency-free (stdlib only). The generator that
produces the verify-path vectors lives at `tools/gen` and is run via
`make gen-vectors` once per issuer-key rotation; it is never run in CI (the accept
signature uses a random nonce, so it is not reproducible). The committed JSON is
the artifact. Vectors are edited under `vectors/`.

## Releases

Versioning is automated with [Release Please](https://github.com/googleapis/release-please)
in manifest mode: the Go module, the npm package, and the Python package are
released together under one linked version (see `release-please-config.json`).
Merging the release PR tags the repo, which is what releases the Go module.

npm and PyPI **registry publishing on release is a token-gated follow-up** (it needs
`NPM_TOKEN` / PyPI trusted publishing wired up); for now Release Please only
automates the version-bump PRs and the Go tag.

## License

MIT — see [LICENSE](LICENSE).
