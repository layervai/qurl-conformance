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

`expected_crid` is the only optional member of `usrData` and follows
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
{"errCode":"0","list":{"query":"connector_resource","version":1,"agent_id":"agent-conform","connector_id":"prod-dashboard","resource_public_key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ","connector_routing_id":"c-pvlulb4otmwg4scb7dajq37eiov6xdwptfxp2uwdsy2j23uo7zda","knock_resource_id":"connector-conformance-01","crid":"ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha","found_existing":false}}
```

The result echoes the authenticated `agent_id` and requested `connector_id`.
The remaining identities have distinct roles:

- `resource_public_key` is the canonical unpadded base64url P-256 DER SPKI resource
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
  `qurl-crid-v1-vectors` and match `resource_public_key` exactly.
- `found_existing` reports the Authority outcome for the first logical
  execution. It is required even when `false`.

No binding revision or epoch is present: the current resource model has no
trustworthy monotonic value. Continuity is instead fail-closed through
`expected_crid`.

## Continuity and replay

`expected_crid` is a read-only assertion. When supplied, the Authority
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

The authenticated cell converts a valid public request into one private
Authority operation. That operation's name, request body, replay identity, and
error vocabulary are frozen with the private conformance artifact, not here;
nothing an SDK sends or receives carries them. Only the public `52500`-series
codes above and the `request_nonce` grammar cross the boundary.

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
3. Decode the nonce with the shared `request_nonce` gate; the cell binds it
   into its private request identity as frozen by the private artifact.
4. Invoke only the private resource-resolution Authority operation; validate
   its closed response before mapping it to the public result.
5. Seal exactly one result under `NHP_LRT`. Never fall back to HTTP and never
   infer placement from a hostname.
6. On the consumer side, correlate success with the originating request and
   validate every echoed identity, continuity assertion, and optional CRID
   before persisting or dialing.

`request_cases`, `result_reject_cases`, `error_reject_cases`, and `size_cases`
are mandatory executable suites. A consumer supports this artifact only when
it accepts every success/error case and rejects every negative case with the
declared `reject_class`.
