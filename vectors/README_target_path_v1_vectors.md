# qURL Connector target-path vectors

`target_path_v1_vectors.json` is the shared request grammar for an optional
per-qURL destination on a qURL Connector resource. The service appends the
accepted value to the trusted `qurl_site` origin after a successful knock. One
Connector resource can therefore issue independent qURLs for distinct
fileviewer objects without exposing the Connector origin.

The service is authoritative. Go and TypeScript SDKs must also apply the same
local gate before dispatch so callers get the same deterministic error and no
invalid request leaves the process.

## Input contract

- Omission means the bare trusted origin. It is not the same input as a present
  empty string.
- A present value is 1 through 2,048 raw ASCII bytes. Because accepted input is
  ASCII, this is also 1 through 2,048 characters in the OpenAPI schema.
- It starts with one `/`. A leading `//` is rejected because it can select a new
  authority.
- It contains URI path and query characters only. Backslash, whitespace,
  controls, `#`, and non-ASCII characters are rejected.
- A literal `..` path segment is rejected. `..` text in the query is allowed.
- Each `%` has two hexadecimal digits. In the path portion, case-insensitive
  `%2e` and `%2f` escapes are rejected because a later decode could create a
  dot segment or path separator. Other accepted escapes are preserved exactly;
  validators do not decode, normalize, recase, or re-encode them. Percent
  escapes in the query do not affect path authorization and remain accepted.
- Resource-type gating is outside this artifact. The service is authoritative:
  it accepts `target_path` only for a wire `type: tunnel` resource and returns
  `invalid_target_path` for another resource type.

The closed local `reject_class` values are:

| Class | Meaning |
| --- | --- |
| `empty` | the field is present with an empty value |
| `too_long` | the raw ASCII value is longer than 2,048 bytes |
| `not_absolute` | the value does not start with `/` |
| `authority` | the value starts with `//` |
| `invalid_character` | the value contains a character outside the allowed raw ASCII set, or a case-insensitive `%2f` escape occurs in the path portion |
| `dot_segment` | the path portion contains a literal `..` segment or a case-insensitive `%2e` escape |
| `percent_encoding` | a `%` escape is incomplete or is not hexadecimal |

The order above is not a precedence contract. Consumers assert the declared
class for each exact vector. Adding a new class or changing an accepted input is
a schema change and needs a coordinated release.

## Open behavior

The service ignores the query when it authorizes the protected request. The
path allows the exact path and descendants at a segment boundary. For example,
`/view/abc` also allows `/view/abc/thumbnail`, but it does not allow
`/view/abcd`.

Well-formed percent escapes other than encoded dot and slash in the path are
valid mint inputs and stay byte exact. They are marked `open_supported: false`
because qurl-service issue #1250 tracks a current false-deny: the router supplies
a decoded request path while the stored scope is escaped. Consumers must not
decode, normalize, recase, or re-encode accepted mint values. Applications must
use unescaped allowed ASCII path bytes until #1250 is fixed. Percent escapes
that occur only in the query are open-supported because the query is not part
of path authorization. This is a one-layer wire contract: `%252e` is accepted
and preserved as exact bytes. A Connector must validate the final path after
its framework's decoding and must still treat every delivered path as untrusted
input for its own object lookup.

## Consumer algorithm

For every case, pass `present` and `value` through the real public option gate:

1. For `accept`, assert that the SDK sends the exact value under `target_path`,
   or omits the key for `present: false`.
2. For `reject`, assert the declared local class and assert that no network
   dispatch occurs.
3. For each accepted present value, assert that appending it to a fixed trusted
   origin cannot change the scheme or host.
4. Keep `open_supported` as runtime evidence. It does not change mint validity.

The strict Go loader independently derives every outcome and rejects missing,
duplicate, unknown, or modified cases. The npm and Python packages carry
byte-identical copies.

## Lockstep rule

qurl-go issue #244 and qurl-typescript issue #248 track adoption. Neither SDK
ships this public capability until both SDKs consume the same released vector
artifact and pass every case. qurl-service remains the final validation and
resource-type boundary.
