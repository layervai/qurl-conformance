# Registered-agent knock application vectors

`agent_knock_application_vectors.json` is the versioned, language-agnostic
application contract for a registered agent knock. It begins after Noise
decryption and deliberately contains no packet bytes, keys, nonces, or
ciphertext. `relay_knock_golden.json` remains the only artifact for the KNK/ACK
Noise packet format.

All identifiers, addresses, hosts, cookies, and tokens are synthetic. The
artifact id is `qurl-agent-knock-application-vectors`; `schema_version` is `3`.
A breaking shape or semantic change requires a schema-version bump.

## Request golden

`request.fields` carries semantic inputs. A consumer must pass those inputs
through its real registered-agent request serializer and compare the result
byte-for-byte with `request.body_json`. The canonical form is compact JSON with
no insignificant whitespace and keys in this exact order:
`headerType`, `usrId`, `devId`, `aspId`, `resId`, `runId`.

The canonical bytes also use Go `encoding/json`'s default HTML escaping
(`&`, `<`, and `>` become `\u0026`, `\u003c`, and `\u003e`). That is the
producer serializer's behavior and therefore part of this byte-level golden,
even though the synthetic identifiers do not exercise those escapes.
Consumers whose default serializer differs (for example JavaScript or Python)
must configure or post-process serialization to reproduce those escapes before
performing the byte comparison; a semantic JSON comparison is not equivalent.

| Wire field | Meaning |
| --- | --- |
| `headerType` | authenticated body copy of the outer NHP type; must equal `wire_type` (`NHP_KNK`, value `1`) |
| `usrId` | registered agent identity label |
| `devId` | registered device identity |
| `aspId` | authorization handler id (`agent`) |
| `resId` | placement-neutral NHP `knock_resource_id` used for admission and ACK lookup; not the public-key management `resource_id` |
| `runId` | native-UDP-SDK-generated knock-cycle id: exactly 16 lowercase hexadecimal characters encoding 8 random bytes |

Optional generic-agent fields are intentionally absent. This artifact pins the
qURL Connector-ready registered-agent body, not every body shape the generic
protocol can carry.

The native UDP SDK owns cryptorandom generation and canonical validation before
network I/O. qURL Connector calls that generator once per outer cycle and owns
only retry/reconnect reuse of the SDK-issued value, including carrying it to the
subsequent login path. It must not create or normalize a competing identifier.

## Request-policy cases

`request_cases` carries raw authenticated KNK JSON bodies. Each case declares
the independently derived result at two entry points:

```jsonc
{
  "name": "missing_run_id",
  "body_json": "{...}",
  "generic_parser": {"outcome": "accept", "parsed_run_id": ""},
  "native_connector": {"outcome": "reject", "reject_class": "missing_run_id"}
}
```

An accepting expectation has `parsed_run_id` (including the explicit empty
string) and no `reject_class`. A rejecting expectation has `reject_class` and no
`parsed_run_id`. The two policies are deliberately different:

| Input | Generic protocol parser | Native qURL Connector |
| --- | --- | --- |
| canonical 16-character lowercase hex `runId` | accept exact value | accept exact value |
| omitted `runId` | accept empty value | reject `missing_run_id` |
| explicit empty `runId` | accept empty value | reject `missing_run_id` |
| malformed non-empty `runId` | reject `invalid_run_id` | reject `invalid_run_id` |
| duplicate key or unknown alias (`runID`, `run_id`) | reject `body_parse` | reject `body_parse` |

**Schema-v2 migration obligation:** the exact-key and duplicate-key rules apply
to the generic protocol parser as well as the native Connector profile. Generic
implementers that previously relied on a case-insensitive or last-key-wins JSON
decoder must add a raw-body strictness gate before typed decoding. The
`generic_parser` and `native_connector` names are public policy profiles that any
language implementation can exercise; they do not expose a private SDK parser.

The malformed vectors separately pin surrounding whitespace, 16-character
internal whitespace, uppercase hex, 15-character, 17-character, and non-hex values.
Parsers must validate the raw value; trimming, removing whitespace, case
folding, truncating, or aliasing is non-conformant. Go's
`encoding/json` matches field names case-insensitively, so a conformant Go
consumer must apply an exact-key gate rather than relying on struct decoding
alone to reject `runID`.

**Schema-v3 migration obligation:** reply parsing now covers the complete current
ACK producer envelope. Consumers must accept the standard exact-resource
`preActions: null` shape and typed optional `aspToken` / `redirectUrl`, while
rejecting unknown or duplicate fields, trailing data, null/non-object bodies,
wrong field types, and every non-null pre-access action on a successful ACK.
Strict field decoding and wrong-type rejection must occur before pre-access
evaluation. A consumer must not repin to schema v3 until these reply cases run
through its real production interpreter.

Request reject classes are closed:

| Class | Meaning |
| --- | --- |
| `body_parse` | duplicate key, unknown alias, wrong JSON shape, or wrong field type |
| `missing_run_id` | native Connector entry point received omitted or empty `runId` |
| `invalid_run_id` | non-empty `runId` is not exactly 16 lowercase hexadecimal characters |

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
  "expected_ac_token": "...",
  "expected_resource_host": "..."
}
```

Counters are decimal strings so uint64 precision survives JavaScript and other
number-limited consumers. `reject_class` is absent on success and required on
every other outcome. `expected_ac_token` and `expected_resource_host` are
required only on success and pin the values returned from the requested
resource's `acTokens` / `resHost` entries. Despite its historical name,
`reject_class` classifies the reason for all non-success dispositions, including
authenticated `deny` and `retry` outcomes as well as fail-closed client `reject`
outcomes.

The success bodies reproduce the current ACK producer's serialization order and
`omitempty` behavior:

`errCode`, optional `errMsg`, `resHost`, `opnTime`, optional `aspToken`,
`agentAddr`, `acTokens`, optional `preActions`, optional `redirectUrl`.

The ordinary success golden initializes `preActions` and maps the requested
resource to JSON `null`, which is the producer's no-NHP_ACC shape. The optional-
metadata success adds typed `aspToken` and `redirectUrl`; its deliberately
different `aspToken` proves that only `acTokens[requested_res_id]` can become the
declared admission token.

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
| `body_parse` | ACK is not one closed-schema object: unknown/duplicate fields, trailing data, null/non-object body, or wrong field type |
| `unsupported_pre_access` | a successful ACK contains a non-null `preActions` value under any map key and therefore requires an unsupported NHP_ACC phase |
| `counter` | ACK does not echo the request counter |
| `reply_type` | a knock received neither `NHP_ACK` nor `NHP_COK` |

## Consumer algorithm

Consumers must derive each declared outcome through their production paths:

1. Construct the request body from `request.fields` and compare exact bytes with
   `request.body_json`.
2. Feed every `request_cases[].body_json` value through the real generic parser
   and native Connector gate separately. Reject duplicate keys and every unknown
   alias before RunID validation; then derive the declared outcome, parsed value,
   and reject class. Never trust the stored labels without exercising both entry
   points.
3. Treat `NHP_COK` as retry-later before applying the ordinary transaction
   counter gate. Its request and reply counters must each be valid uint64 values
   but are intentionally unconstrained relative to one another: the reference
   relay treats a cookie challenge as an authenticated overload signal rather
   than a completed transaction. For every admission reply, require `NHP_ACK`
   and an echoed request counter before trusting its body.
4. Strictly decode one ACK object with the complete field vocabulary above.
   Reject duplicate/unknown fields, a second/trailing value, null/non-object
   bodies, and wrong types. `aspToken` / `redirectUrl` are optional strings;
   `preActions` is an optional object whose values preserve null-vs-non-null.
5. Evaluate `errCode` before map validation. Empty string and `"0"` mean
   success; any other string is an authenticated deny.
6. On success, accept absent/empty/all-null `preActions`. Reject
   `unsupported_pre_access` if any map value is non-null, regardless of its key;
   ignoring it would falsely report admission before the required NHP_ACC phase.
7. Require non-empty `acTokens[requested_knock_resource_id]` and
   `resHost[requested_knock_resource_id]`, and return those exact values as the
   declared expected result. A value for another resource never authorizes the
   requested one. `aspToken`, `redirectUrl`, `agentAddr`, and `preActions` are
   never alternate authorization or placement sources.

A missing vector is a hard failure, never a skipped test. The Go loader also
rejects unknown/trailing artifact fields, unsupported schema versions, duplicate
case names, missing mandatory cases, invalid counters, unknown outcome or reject
labels, request-policy label drift, success result labels that differ from the
requested resource's body maps, and mandatory request bodies that no longer match
their exact named vectors.

The npm and Python packages intentionally expose the producer bytes through
thin accessors, consistent with the other artifact families; they do not inherit
the Go loader's strict semantic validation. Consumers in those languages must
enforce the same closed schema and disposition rules in their production-path
gate rather than treating a successful JSON parse as conformance.

## Consumer behavioral gate

This repository publishes and validates the language-neutral contract; it does
not pretend that a passing `tools/verify-sdk` run exercises this new artifact.
Before any consumer relies on it for compatibility, that consumer must run the
released artifact through its real production request serializer and reply
interpreter and derive every declared outcome. Until that downstream gate is
green, this artifact is contract input, not evidence that an implementation is
compatible.
