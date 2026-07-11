# Registered-agent knock application vectors

`agent_knock_application_vectors.json` is the versioned, language-agnostic
application contract for a registered agent knock. It begins after Noise
decryption and deliberately contains no packet bytes, keys, nonces, or
ciphertext. `relay_knock_golden.json` remains the only artifact for the KNK/ACK
Noise packet format.

All identifiers, addresses, hosts, cookies, and tokens are synthetic. The
artifact id is `qurl-agent-knock-application-vectors`; `schema_version` is `1`.
A breaking shape or semantic change requires a schema-version bump.

## Request golden

`request.fields` carries semantic inputs. A consumer must pass those inputs
through its real registered-agent request serializer and compare the result
byte-for-byte with `request.body_json`. The canonical form is compact JSON with
no insignificant whitespace and keys in this exact order:
`headerType`, `usrId`, `devId`, `aspId`, `resId`. The body contains exactly:

| Wire field | Meaning |
| --- | --- |
| `headerType` | authenticated body copy of the outer NHP type; must equal `wire_type` (`NHP_KNK`, value `1`) |
| `usrId` | registered agent identity label |
| `devId` | registered device identity |
| `aspId` | authorization handler id (`agent`) |
| `resId` | requested NHP resource id |

Optional generic-agent fields are intentionally absent. This artifact pins the
connector-ready registered-agent body, not every body shape the generic protocol
can carry.

## Reply cases

Each `reply_cases` entry represents a decrypted reply plus the request/reply
correlation metadata that remains outside the application JSON:

```jsonc
{
  "name": "ack_success",
  "reply_type": 2,
  "request_counter": "42",
  "reply_counter": "42",
  "body_json": "{...}",
  "outcome": "success",
  "reject_class": "..."
}
```

Counters are decimal strings so uint64 precision survives JavaScript and other
number-limited consumers. `reject_class` is absent on success and required on
every other outcome.

| Outcome | Required handling |
| --- | --- |
| `success` | usable admission; return the non-empty token and host for the requested `resId` |
| `deny` | authenticated server denial; preserve `errCode` for classification |
| `retry` | authenticated `NHP_COK` overload challenge; retry later |
| `reject` | malformed, mis-correlated, or unusable reply; fail closed |

Closed `reject_class` vocabulary:

| Class | Meaning |
| --- | --- |
| `server_deny` | ACK has a non-success string `errCode` |
| `server_busy` | reply is `NHP_COK` rather than an admission ACK |
| `wrong_resource` | success maps contain entries, but not for the requested `resId` |
| `missing_token` | requested `acTokens` entry is absent or empty |
| `missing_host` | requested `resHost` entry is absent or empty |
| `body_parse` | ACK JSON cannot populate the typed string/map fields |
| `counter` | ACK does not echo the request counter |
| `reply_type` | a knock received neither `NHP_ACK` nor `NHP_COK` |

## Consumer algorithm

Consumers must derive each declared outcome through their production paths:

1. Construct the request body from `request.fields` and compare exact bytes with
   `request.body_json`.
2. Treat `NHP_COK` as retry-later. For every admission reply, require `NHP_ACK`
   and an echoed request counter before trusting its body.
3. Decode the ACK body into typed fields: string `errCode`, string-to-string
   `resHost`, string `agentAddr`, and string-to-string `acTokens`. A wrong map
   type fails parsing; it must not become an empty success value silently.
4. Evaluate `errCode` before map validation. Empty string and `"0"` mean
   success; any other string is an authenticated deny.
5. On success, require non-empty `acTokens[requested_res_id]` and
   `resHost[requested_res_id]`. A value for a different resource never
   authorizes the requested one.
6. Treat `agentAddr` only as corroborating server output. It is not the access
   token, placement target, or source-address trust input.

A missing vector is a hard failure, never a skipped test. The Go loader also
rejects unknown/trailing artifact fields, unsupported schema versions, duplicate
case names, missing mandatory cases, invalid counters, and unknown outcome or
reject labels.

## Consumer behavioral gate

This repository publishes and validates the language-neutral contract; it does
not pretend that a passing `tools/verify-sdk` run exercises this new artifact.
The production serializer and reply interpreter are connector-owned. Before the
OpenNHP removal may ship, `layervai/qurl-connector#421` Phase 1 D must consume
this released artifact and derive every declared outcome through those real
paths. Until that downstream gate is green, this artifact is contract input,
not evidence that a connector implementation is compatible.
