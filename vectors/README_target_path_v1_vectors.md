# qURL Connector target-path vectors

`target_path_v1_vectors.json` is the shared request grammar for an optional
per-qURL destination on a qURL Connector resource. The service appends the
accepted value to the trusted `qurl_site` origin after a successful knock. One
Connector resource can issue independent qURLs for distinct fileviewer objects
without exposing the Connector origin.

The service is authoritative. Go and TypeScript SDKs must also apply the same
local gate before dispatch. Thus, callers get the same deterministic error and
no invalid request leaves the process.

## Input contract

- Omission means the bare trusted origin. It is not the same input as a present
  empty string.
- A present value is 1 through 2,048 raw ASCII bytes. Length is checked before
  character validity. Thus, a value that is both non-ASCII and more than 2,048
  bytes is `too_long`.
- It starts with one `/`. A leading `//` is rejected because it can select a new
  authority.
- It contains URI path and query characters only. Backslash, whitespace,
  controls, `#`, and non-ASCII characters are rejected in both components.
- The path has no `.` or `..` segment and no interior empty segment. Dot text
  inside a segment, such as `a..b` or `...`, is allowed. Root `/` and one
  trailing slash are allowed and preserved.
- Every percent escape in the path is rejected. A case-insensitive `%2e` path
  escape is `dot_segment`. Every other well-formed path escape, including
  `%2f`, is `invalid_character`.
- Well-formed percent escapes in the query are accepted and preserved exactly.
  Validators do not decode, normalize, recase, or re-encode them. The service
  does not use the query for path authorization.
- Resource-type gating is outside this artifact. The service is authoritative:
  it accepts `target_path` only for a wire `type: tunnel` resource and returns
  `invalid_target_path` for another resource type.

The closed local `reject_class` values are:

| Class | Meaning |
| --- | --- |
| `empty` | the field is present with an empty value |
| `too_long` | the raw value is longer than 2,048 UTF-8 bytes |
| `not_absolute` | the value does not start with `/` |
| `authority` | the value starts with `//` |
| `invalid_character` | the value contains a character outside the allowed raw ASCII set, an interior empty path segment, or a well-formed path escape other than `%2e` |
| `dot_segment` | the path contains a literal `.` or `..` segment or a case-insensitive `%2e` escape |
| `percent_encoding` | a `%` escape in the path or query is incomplete or is not hexadecimal |

Malformed percent encoding is classified before the path escape and dot checks.
After percent syntax is valid, `dot_segment` wins when the path contains any
case-insensitive `%2e` escape or a literal `.` or `..` segment. This stays true
when another well-formed path escape is also present. Otherwise, any path escape
or interior empty segment is `invalid_character`. The `%2e` classification
deliberately names the escape risk; the decoded dot does not have to be a
standalone segment.

Other rule combinations have no general precedence contract. Each exact vector
states its required class. Adding a class or changing an accepted input requires
a coordinated contract release.

## Open behavior

Every accepted value has `open_supported: true`. This field remains an explicit
invariant and a reserved compatibility gate even though every v1 accepted case
is true. Appending the value to a fixed trusted origin must preserve the scheme,
host, path, and complete request target bytes. The service ignores the query
when it authorizes the protected request. A scoped path allows the exact path
and descendants at a segment boundary. For example, `/view/abc` also allows
`/view/abc/thumbnail`, but it does not allow `/view/abcd`.

The service preserves one trailing slash on redirect. Its path authorization
treats a scoped path with or without that trailing slash as the same boundary.
Changing `open_supported` requires a coordinated release across the service,
both SDKs, and the Connector.

## Consumer algorithm

For every case, pass `present` and `value` through the real public option gate:

1. For `accept`, assert that the SDK sends the exact value under `target_path`,
   or omits the key for `present: false`.
2. For `reject`, assert the declared local class and assert that no network
   dispatch occurs.
3. For each accepted present value, assert that appending it to a fixed trusted
   origin cannot change the scheme, host, or path.
4. Assert that every accepted value has `open_supported: true`.

The strict Go loader independently derives every outcome and rejects missing,
duplicate, unknown, or modified cases. The npm and Python packages carry
byte-identical copies.

## Lockstep rule

qurl-go issue #244 and qurl-typescript issue #248 track adoption. Neither SDK
ships this public capability until both SDKs consume the same released vector
artifact and pass every case. qurl-service remains the final validation and
resource-type boundary.
