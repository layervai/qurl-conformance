# qURL Connector target-path vectors

`target_path_v1_vectors.json` is the shared request grammar for an optional
per-qURL destination on a tunnel resource. The authoritative opener appends an
accepted value to the trusted `qurl_site` origin after a successful knock. One
resource can issue independent qURLs for distinct protected objects without
exposing the resource origin.

The authoritative validator is the final boundary. Every SDK also applies the
same local gate before dispatch. Thus, callers get the same deterministic error
and no invalid request leaves the process.

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
  `contract.allowed_ascii` is the complete machine-readable raw alphabet. A
  consumer must compare its character gate with this value as an unordered set
  of ASCII bytes; the string order is not normative. It must not infer the
  alphabet from the examples. The published artifact value is still byte-frozen;
  the unordered-set rule applies to consumer comparison, not artifact rewrites.
  The validator uses a whole-value full match. It must not use a regular
  expression end anchor that can match before a trailing line terminator.
- `contract.forbidden_path_ascii` is the complete path-only reject alphabet.
  It is an unordered set of ASCII bytes. Each byte remains valid in the query.
  The published string is still byte-frozen; consumers compare it as a set but
  must not rewrite the artifact. The `!()*` members protect against a Go
  consumer that rebuilds a request-target from `url.URL.Path` after it discards
  `RawPath`; `net/url.URL.RequestURI` then percent-encodes them. They are not the
  union of bytes that every language-specific URL serializer can escape.
  Consumers must apply the published set and must not derive a replacement set
  from their local URL API.
- A raw apostrophe is rejected in both components because rebuilding a Go URL
  from `url.URL.Path` and the WHATWG special-query percent-encode set can change
  it to `%27`. The path behavior has a Go standard-library gate. Go appends
  `RawQuery` verbatim, so each HTTP consumer must verify the WHATWG query
  behavior in its own client.
- The path has no `.` or `..` segment and no interior empty segment. Dot text
  inside a segment, such as `a..b` or `...`, is allowed. Root `/` and one
  trailing slash are allowed and preserved.
- The path rejects raw `!`, `(`, `)`, and `*` because a Go consumer that
  rebuilds from `url.URL.Path` can percent-encode them and change the authorized
  request-target. It also rejects a literal `;` because proxies and origin
  frameworks can strip matrix parameters after authorization. All five bytes
  remain valid and byte-exact in the query, which does not take part in path
  authorization.
- Every percent escape in the path is rejected. A case-insensitive `%2e` path
  escape is `dot_segment`. Every other well-formed path escape, including
  `%2f`, is `invalid_character`.
- Well-formed percent escapes in the query are accepted and preserved exactly.
  The first literal `?` separates the path from the query. Every later `?` is
  query data. Validators do not decode, normalize, recase, or re-encode query
  escapes. Path authorization does not use the query. Consumers must never
  decode encoded query controls before validation, authorization, or HTTP
  dispatch because decoding can turn accepted data into request separators.
- Resource-type gating is outside this artifact. The authoritative validator
  accepts `target_path` only for a wire `type: tunnel` resource and returns
  `invalid_target_path` for another resource type.

The closed local `reject_class` values are:

| Class | Meaning |
| --- | --- |
| `empty` | the field is present with an empty value |
| `too_long` | the raw value is longer than 2,048 UTF-8 bytes |
| `not_absolute` | the value does not start with `/` |
| `authority` | the value starts with `//` |
| `invalid_character` | the value contains a character outside the allowed raw ASCII set, a byte from `contract.forbidden_path_ascii` in the path, an interior empty path segment, or a well-formed path escape other than `%2e` |
| `dot_segment` | the path contains a literal `.` or `..` segment or a case-insensitive `%2e` escape |
| `percent_encoding` | a `%` escape in the path or query is incomplete or is not hexadecimal |

`contract.query_delimiter` pins the first literal `?` as the path/query split.
`contract.validation_order` is the complete normative order. Each step name
states whether it applies to the whole value or only to the path. After
presence, the validator checks whole-value emptiness, UTF-8 byte length, the
leading slash, a protocol-relative authority, and the raw ASCII character set.
Thus, length wins over `not_absolute` and `authority`. The `authority` class
wins over all later character, percent, and dot checks. The validator then
splits the path at the first literal `?`. The path-only forbidden-byte check
precedes the whole-value percent-syntax check. Thus `/view/a;b%` is
`invalid_character`, not `percent_encoding`. The earlier whole-value
character-set check gives the same precedence to `/view/a[b]%`. Malformed
escapes in either the path or query are `percent_encoding`. After percent
syntax is valid, `dot_segment` wins when the path contains any case-insensitive
`%2e` escape or
a literal `.` or `..` segment. This stays true when another well-formed path
escape is also present. Otherwise, any path escape or interior empty segment is
`invalid_character`. The `%2e` classification deliberately names the escape
risk; the decoded dot does not have to be a standalone segment. Adding a class
or changing this order requires a coordinated contract release.

`schema_version: 2` adds the path-only reject alphabet and removes apostrophe
from the whole-value `allowed_ascii` alphabet. Strict consumers must upgrade
their loader and the artifact together. They must continue to reject unknown
fields and unsupported schema versions. The `v1` text in the artifact ID and
filename is a frozen identifier. Grammar changes are signaled by
`schema_version`.

## Open behavior

Every accepted value has `open_supported: true`. This field remains an explicit
invariant and a reserved compatibility gate even though every v1 accepted case
is true. Because v1 has no false vector, consumers must also inject a false case
in a unit test and prove that the open operation rejects it. Appending the value
to a fixed trusted origin must preserve the scheme, host, and complete resulting
request-target bytes. The authoritative opener ignores the query when it
authorizes the protected request. A scoped path allows the exact path and
descendants at a segment boundary. For example, `/view/abc` also allows
`/view/abc/thumbnail`, but it does not allow `/view/abcd`.
The accepted `/?` case also preserves its bare trailing query delimiter; an HTTP
stack must not normalize it to `/`.

The authoritative opener preserves one trailing slash on redirect. Its path
authorization treats a scoped path with or without that trailing slash as the
same boundary. Scope matching, redirect handling, and resource-type gating are
runtime rules outside the validation cases in this artifact. Each runtime must
test them separately. Changing `open_supported`, including adding the first
false case, requires a coordinated loader and artifact release across the
validator, SDK consumers, and the protected-resource runtime.

## Consumer algorithm

For every case, pass `present` and `value` through the real public option gate:

1. For `accept`, assert that the SDK sends the exact value under `target_path`,
   or omits the key for `present: false`.
2. For `reject`, assert the declared local class and assert that no network
   dispatch occurs.
3. For each accepted present value, assert that appending it to a fixed trusted
   origin cannot change the scheme, host, or path.
4. Branch on `open_supported` rather than assuming it is true. Every v1
   accepted value is true, so add an injected false-branch unit test. A
   coordinated future contract can gate a subset.
5. For each accepted value, assert that the HTTP client dispatches the exact
   request-target bytes. In particular, it must not decode query escapes before
   validation, authorization, or transmission.
6. Rebuild each accepted request-target from the URL API's decoded path, with
   any retained raw or escaped path cleared, and assert byte equality with the
   accepted value. This catches a serializer that changes authorization bytes
   only after parsed raw-path state is discarded.

Because v1 rejects every path escape, it cannot represent a resource path that
requires percent encoding, such as a path that contains a space or non-ASCII
text. A raw apostrophe is unrepresentable in both the path and query. Raw `!`,
`(`, `)`, `*`, and `;` are also unrepresentable in a path. This is a deliberate
closed grammar, not an instruction to decode or normalize such a path.

The Go `ParseTargetPathV1File` loader independently derives every outcome and
rejects missing, duplicate, unknown, or modified cases. The npm and Python
package accessors return the parsed artifact without strict validation;
consumers in those languages must run the cases through their own public gate.
All packaged JSON copies are byte-identical. When a case input changes, update
the pinned `targetPathFixtures` entry in `target_path.go` before you sync the
npm and Python mirrors with `scripts/sync-vectors.sh`.

## Lockstep rule

No SDK ships this public capability until all SDK consumers use the same
released vector artifact and pass every case. The authoritative validator
remains the final validation and resource-type boundary.
