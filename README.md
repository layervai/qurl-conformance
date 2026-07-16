# qurl-conformance

The single public source of truth for the **qURL cross-language conformance
vectors**: the language-agnostic wire-truth that every qURL verifier re-runs
against its own implementation. Separate artifact ids keep the qURL v2 verify
path, Noise-handshake packets, agent registration, registered-agent knock
application bodies, and control-plane API-key IDs decoupled by layer.

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
| `vectors/agent_knock_application_vectors.json` | registered-agent KNK body and RunID request-policy cases plus already-decrypted ACK/COK dispositions; no Noise packet duplication |
| `vectors/README_agent_knock_application_vectors.md` | application-vector schema, outcome/reject vocabulary, and consumer algorithm |
| `vectors/agent_api_key_id_vectors.json` | issuer and strict-consumer fixtures for agent registration `key_id` / `device_api_key_id` |
| `vectors/README_agent_api_key_id_vectors.md` | API-key ID grammar, fixture roles, reject classes, and lockstep rule |
| `vectors/README_qv2_conformance_vectors.md` | the schema, `reject_class` vocabulary, class-to-entry-point map, and the derived tamper case |
| `schema.go`, `embed.go` | a stdlib-only Go module that embeds the artifacts and exposes strict, typed loaders |

## Using it from Go

```go
import conformance "github.com/layervai/qurl-conformance"

cf, err := conformance.ConformanceVectors()        // strict-parsed conformance artifact
vf, err := conformance.SignatureVectors()          // strict-parsed issuer-signature vectors
rk, err := conformance.RelayKnockGolden()          // strict-parsed relay-knock golden packets
ar, err := conformance.AgentRegistrationGolden()   // strict-parsed agent-registration golden packets
ka, err := conformance.AgentKnockApplication()      // strict-parsed agent KNK/ACK application vectors
ki, err := conformance.AgentAPIKeyIDs()             // strict-parsed agent API-key ID vectors
raw := conformance.QV2Vectors()                    // raw bytes, if you drive your own parser
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

This module hosts five artifact families, each under its own `artifact` id:

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
- **Agent API-key ID contract** (`qurl-agent-api-key-id-vectors`,
  `agent_api_key_id_vectors.json`) — deterministic issuer suffix fixtures,
  direct string validation cases, and raw response-field cases for
  `registration-info.key_id` and completion `device_api_key_id`. It freezes the
  exact `key_` plus 12 ASCII-alphanumeric grammar without reinterpreting the
  synthetic NHP registration packet `usrId`. See
  `vectors/README_agent_api_key_id_vectors.md`.

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
