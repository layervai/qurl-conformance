# Connector resource LST/LRT v1 vectors

`connector_resource_lst_v1_vectors.json` freezes the registered-agent,
post-registration application contract for resolving one qURL Connector
resource through standard NHP `NHP_LST` / `NHP_LRT` messages. The customer
runtime does not call an HTTP resource API, use a relay, or carry a Hub cookie
for this operation.

The application query is `connector_resource`, version `1`. One request names
one Connector. Multi-route clients issue independent exchanges so each sealed
reply remains suitable for an unfragmented 1,232-byte UDP path.

## Trust boundary and request

The request body is an exact object:

```json
{"usrId":"agent-conform","devId":"agent-conform","aspId":"agent","usrData":{"query":"connector_resource","version":1,"request_nonce":"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8","connector_id":"prod-dashboard"}}
```

`expected_resource_id` is the only optional member of `usrData` and follows
`connector_id` when present. Duplicate keys, case aliases, unknown members,
null optionals, invalid UTF-8, alternate numeric spellings, and trailing JSON
reject.

The authenticated NHP peer must already map to a registered agent. Both
`usrId` and `devId` repeat that exact `agent_id`; they do not grant identity and
must reject if either differs from the authenticated mapping. This deliberately
differs from pre-registration completion messages, where the registration
exchange has not yet established the same registered-agent application
identity. `aspId` is exactly `agent`.

The Authority derives owner and enrollment entitlement from server-side state.
No client member may select an owner, account, cell, tunnel server, or resource
placement.

`request_nonce` is canonical unpadded base64url for exactly 32 CSPRNG bytes.
It names one logical request and must remain stable across packet-level retries
of that request. A later top-level resolve uses a fresh nonce.

`connector_id` is the immutable route identity: 3-64 lowercase letters, digits,
and hyphens; it starts with a letter and ends alphanumeric.

## Success result

A success is an exact `NHP_LRT` body:

```json
{"errCode":"0","list":{"query":"connector_resource","version":1,"agent_id":"agent-conform","connector_id":"prod-dashboard","resource_id":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ","connector_routing_id":"c-pvlulb4otmwg4scb7dajq37eiov6xdwptfxp2uwdsy2j23uo7zda","knock_resource_id":"connector-conformance-01","crid":"ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha","found_existing":false}}
```

The result echoes the authenticated `agent_id` and requested `connector_id`.
The remaining identities have distinct roles:

- `resource_id` is the canonical unpadded base64url P-256 DER SPKI resource
  identity: exactly 91 decoded bytes and 122 encoded characters.
- `connector_routing_id` is an opaque placement-neutral routing identity with
  the exact `c-` plus 52 lowercase base32 pattern. Consumers must not derive or
  reinterpret it.
- `knock_resource_id` is the opaque resource selector used for subsequent
  admission knocks. It is not a routing hostname or internal FRPS URL.
  Authority producers limit it to 64 UTF-8 bytes; together with the whole-body
  cap, this keeps even maximally JSON-escaped valid values inside the UDP
  envelope.
- `crid` is optional. When present it must be valid under
  `qurl-crid-v1-vectors` and match `resource_id` exactly.
- `found_existing` reports the Authority outcome for the first logical
  execution. It is required even when `false`.

No binding revision or epoch is present: the current resource model has no
trustworthy monotonic value. Continuity is instead fail-closed through
`expected_resource_id`.

## Continuity and replay

`expected_resource_id` is a read-only assertion. When supplied, the Authority
may return success only for the same currently active resource. An absent,
revoked, tombstoned, or different resource returns terminal `52503`. The
Authority must never create, reclaim, or substitute a resource while processing
a request that carries this assertion.

The replay key is the authenticated peer, query, and decoded request nonce.
The operation also stores a fingerprint of the exact semantic request:

- the same replay key and same semantics return the byte-identical first
  result, including `found_existing=false` after a first creation;
- the same replay key with changed semantics returns `52506` before any
  Authority mutation;
- a fresh nonce reauthorizes against current entitlement and lifecycle state,
  and reports the current `found_existing` value.

A cached resource binding never bypasses authorization on a later knock.

## Closed public errors

Errors omit `list` and use exact messages:

| Code | Message | Retry rule |
| --- | --- | --- |
| `52500` | `connector resource temporarily unavailable` | `retryAfterSeconds` optional; when present 1-3600 |
| `52501` | `connector resource identity rejected` | terminal; delay forbidden |
| `52502` | `connector resource entitlement denied` | terminal; delay forbidden |
| `52503` | `connector resource identity conflict` | terminal; delay forbidden |
| `52504` | `connector resource quota exceeded` | terminal; delay forbidden |
| `52505` | `connector resource rate limited` | retryable; delay required, 1-3600 |
| `52506` | `invalid connector resource request` | terminal; delay forbidden |

Unknown codes, message drift, a `list` on error, or any retry member that
violates the table reject.

## Private Authority boundary

The authenticated cell converts a valid public request into the private
`ResolveConnectorResource` operation frozen in
`connector_authority_lambda_v1_vectors.json`. Its exact request is:

```json
{"version":1,"cell_request_id":"57b3dac2005f8c49f56e9b23bda0f5f17f0be91bf5f8e853155f53d0ed9f1e4a","agent_id":"agent-conform","authenticated_peer_public_key_b64":"AjPwBu9L7RROoKW7RscGfHwqzsX4zIEfPfWf3NWsdhQ=","connector_id":"prod-dashboard"}
```

The private request optionally carries the same `expected_resource_id`. The
cell derives `cell_request_id`; it is not client-supplied. Let `frame(tag,
value)` be one tag byte, a two-byte big-endian length, then the value. The exact
preimage is:

```text
"layerv:qurl:connector-resource-request-id:v1" || 0x00 ||
frame(0x01, UTF-8 environment) ||
frame(0x02, authenticated peer raw 32 bytes) ||
frame(0x03, decoded public nonce raw 32 bytes)
```

`cell_request_id` is the lowercase hexadecimal SHA-256 digest. For environment
`sandbox`, the fixture peer, and nonce bytes `a0` through `bf`, the preimage is:

```text
6c61796572763a7175726c3a636f6e6e6563746f722d7265736f757263652d726571756573742d69643a76310001000773616e64626f780200200233f006ef4bed144ea0a5bb46c7067c7c2acec5f8cc811f3df59fdcd5ac7614030020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
```

and the result is
`57b3dac2005f8c49f56e9b23bda0f5f17f0be91bf5f8e853155f53d0ed9f1e4a`.

Private errors are `invalid_request`, `identity_rejected`,
`entitlement_denied`, `resource_identity_conflict`, `quota`, `rate_limited`,
and `unavailable`. `rate_limited` requires `retry_after_seconds`; `unavailable`
allows it; all other errors forbid it. The Authority artifact freezes their
exact public mappings.

## Size accounting

The vector records exact plaintext body byte counts and a conservative
pre-seal budget of body bytes plus 256. The maximum accepted body is therefore
976 bytes and every committed success fixture remains below the 1,232-byte
target under that conservative budget. These values are not claimed sealed
packet measurements. The NHP reference codec owns the integration fixture that
must seal the largest accepted body and prove its real packet is at most 1,232
bytes without fragmentation.

## Consumer algorithm

1. Authenticate and decrypt the NHP message under the assigned registered-agent
   key before parsing the body.
2. Require the exact `NHP_LST` header and strict request shape, then bind
   `usrId=devId` to the authenticated agent.
3. Decode the nonce and derive `cell_request_id` from server-owned environment,
   authenticated peer bytes, and the decoded nonce.
4. Invoke only `ResolveConnectorResource`; validate its closed response before
   mapping it to the public result.
5. Seal exactly one result under `NHP_LRT`. Never fall back to HTTP and never
   infer placement from a hostname.
6. On the consumer side, correlate success with the originating request and
   validate every echoed identity, continuity assertion, and optional CRID
   before persisting or dialing.

`request_cases`, `result_reject_cases`, `error_reject_cases`, and `size_cases`
are mandatory executable suites. A consumer supports this artifact only when
it accepts every success/error case and rejects every negative case with the
declared `reject_class`.
