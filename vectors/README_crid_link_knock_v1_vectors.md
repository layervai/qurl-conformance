# CRID link knock v1 vectors

`crid_link_knock_v1_vectors.json` is the public client contract for turning a
CRID into a qURL link. A client that holds nothing but a CRID asks the server
for a short-lived link over an ordinary knock, checks the link that comes
back, and then opens it exactly as it opens any other qURL link. No account,
API key or HTTP API call is involved.

The artifact id is `qurl-crid-link-knock-v1-vectors`; `schema_version` is `1`.
It starts after packet decryption: every body is application JSON, and no
packet bytes appear here. `relay_knock_golden.json` remains the artifact for
the knock and ACK packet format, and `crid_v1_vectors.json` remains the
artifact for the CRID itself.

Every CRID, link, address and identifier here is synthetic. The fixture link
is the published qURL v2 vector link: its issuer key, its resource key and the
proof-of-possession secret inside its fragment are public test material. Never
admit that issuer key or its `kid` to a production trust store, and never use
those keys outside conformance tests.

## The two steps

1. **Request a link.** The client sends a knock (header type `1`) whose body
   names the CRID. The server answers with an ACK (header type `2`). A
   link-issued ACK carries the link in `redirectUrl`. This step opens nothing
   and leaves no session behind.
2. **Open the link.** Once every check in this document passes, the client
   runs the normal qURL v2 knock with that link. Step 2 is unchanged; it is
   pinned by `qv2_conformance_vectors.json` and
   `issuer_signature_vectors.json`.

A v1 client sends step 1 through the deployment's relay, exactly as it sends
every browser knock. The relay base URL and the server static public key come
from the deployment configuration the client ships with; this artifact carries
neither. The initiator static key may be any X25519 key, and a v1 client uses
a fresh random key for every request, with one exception.

### A request under a registered device key

A client that holds the key of a registered device may send one more request
for the same CRID, with the device key as the initiator static key. It does so
only after a request under a fresh random key was answered `52602`. The server
knows who asks from that key, so it may issue a link for a resource that this
device is allowed to open and that a request under a random key cannot open.
How a device is registered, and how it gets its key, is not part of this
artifact.

**This subsection is a rule for clients, and no vector pins it.** The vectors
pin each single request and each single reply. They hold no case with two
requests and no case under a device key. A consumer that passes the consumer
algorithm below has shown nothing about this rule. A case family for it would
need a new `schema_version`.

- Only `52602` leads to the second request. No other outcome does: for
  example not `52601`, not `52603`, not `52604` to `52606`, not
  `server_error`, `protocol_violation` or `busy`, not a transport error, not a
  link that fails a check, and not a request that got no reply. A fault of the
  moment must not make a device name itself.
- The first request is never sent under the device key. A resource that opens
  for anyone is answered there, under a key that says nothing about the
  client. When a second request follows, this no longer holds for that
  attempt: the two requests are close in time and come from one address, so
  whoever recognises the second knows whose the first was.
- The second request has the same body and the same shapes as the first. Its
  answer is read by the same rules, and a link in it passes the same checks.
- The second request ends the attempt, whatever its answer is. There is no
  third request. When its answer is one that the table below calls retryable,
  the user may try again later, as the table says; that later attempt starts
  again with a request under a fresh random key. "Once" is once for each
  attempt: a user who tries N times shows the device key up to N times.
- Whether a client may use the device key at all is the choice of the
  application that calls it. Once the application has chosen so, the client
  sends the second request by itself, with no further question to the user.
- `retryable` is `no` for `52602`, and it stays `no`: the same question gets
  the same answer. The request under the device key is not a retry. The
  device key tells the server who asks, so it is a different question.

The relay is not trusted on either request. On every request, with any key,
it sees the size of the reply, and a reply with a link is usually larger
than a refusal. It can drop or delay a request. It can hand back bytes that are not
the server's reply, and the client reports a transport error. A transport
error is never a statement of the server.

A long-lived key adds two things. The header digest of a packet is not keyed.
`README_agent_session_control_vectors.md` gives its input for a normal
request (in the section "RKN header digest"): an initial hash, the static
public key of the receiver, and the header up to the digest. For a reply the
receiver is the initiator. No artifact in this repository pins the reply
direction. A device's public key is known outside the device, so a relay that
holds it:

- can tell that a reply belongs to that device, and so knows which device got
  a link;
- can make a header that passes the digest check and has no body. Two such
  headers are known. A cookie header: the client reports `busy`. An ACK
  header with an empty body, which no body seal covers: a client that takes
  it for an ACK finds no `errCode` in it, which is `protocol_violation`. A
  relay can also send an old `busy` reply to the same device again.

So on the second request a client must not read `busy`, or
`protocol_violation` for an ACK with no body, as a statement of the server
either. There is no third request, so what is left is what the client tells
its caller: that the attempt did not complete, not that the CRID was not
found or that the server is busy.

Under a random key the relay cannot compute the digest. A client that checks
the header digest of a reply before it reads the reply type refuses such a
header and reports a transport error. A client that reads the reply type
first can be given `busy` by the relay on any request, and a forged `busy` on
the first request suppresses the second request for good, with no sign to
the client. So a client should check the digest first. It is "should" and not
"must" only because no vector pins it yet; treat it as a rule. On neither
request can the relay forge a link or an outcome code, or read the request or
the reply.

The server learns the device key whenever it answers `52602`, also for a CRID
that names nothing. An application that lets its client use the device key
accepts this: the server learns which device asked, for every CRID that does
not open for anyone.

## Request body

| Member | Value |
| --- | --- |
| `headerType` | `1`, the same value as the packet header type (`constants.knock_header_type`) |
| `aspId` | `qurl` (`constants.auth_service_id`) |
| `resId` | `qurl-crid` (`constants.resource_id`): a fixed sentinel, not a resource key |
| `usrData.qurl_crid` | the CRID, exactly as issued |
| `usrData.qurl_user_agent` | optional: the client's user agent, at most 256 bytes of UTF-8; left out when the user agent holds a control character, U+2028 or U+2029 (`user_agent_omitted_for_line_separator`, `user_agent_omitted_before_truncation`) |

`aspId`, `resId` and a string `usrData.qurl_crid` together make the knock a
link request. A v1 client sends no other member. In particular the body never
carries a key from `constants.forbidden_user_data_keys`. The first four,
`qurl_access_token`, `qurl_claims_b64`, `qurl_issuer_sig_b64` and
`qurl_session_secret`, belong to the knocks that open a link, and
`qurl_passkey` is reserved for a later revision. The server answers `52606` to
a request that carries any of the five.

Each `request_cases` entry gives the caller's input, the body object, and the
body's canonical bytes:

```jsonc
{
  "name": "with_user_agent",
  "input": {"crid": "ah6c...", "user_agent": "Mozilla/5.0 ..."},
  "body": {"headerType": 1, "aspId": "qurl", "resId": "qurl-crid", "usrData": {...}},
  "serialized": "{\"headerType\":1,\"aspId\":\"qurl\",\"resId\":\"qurl-crid\",\"usrData\":{...}}"
}
```

### Canonical bytes

`serialized` is what JavaScript's `JSON.stringify` returns for the body object:

- compact JSON with no insignificant whitespace;
- members in the order `headerType`, `aspId`, `resId`, `usrData`, and inside
  `usrData` the order `qurl_crid`, `qurl_user_agent`;
- strings escaped only where JSON requires it: `"` becomes `\"` and `\`
  becomes `\\`. `/`, `<`, `>` and `&` are written as they are, and every
  non-ASCII character is emitted as UTF-8 rather than as a `\u` escape.
  `user_agent_json_escaping` and `user_agent_at_limit` pin these rules. No
  `serialized` value contains a control character, U+2028 or U+2029.

A control character never reaches these bytes, and neither does U+2028 or
U+2029. A v1 client sends `usrData.qurl_user_agent` only when the user agent
holds no control character (U+0000 to U+001F, and U+007F) and neither U+2028
nor U+2029. Otherwise it leaves the member out. Encoders do not agree on how
to write these characters, so two correct clients would send different
bytes. JSON has a short and a long escape for some control characters:
`JSON.stringify` writes U+0008 and U+000C as `\b` and `\f`, and Go's
`encoding/json` wrote `\u0008` and `\u000c` before Go 1.22. Go's
`encoding/json` always writes U+2028 and U+2029 as `\u2028` and `\u2029`,
while `JSON.stringify`, and Python's `json.dumps` with `ensure_ascii=False`,
write them as UTF-8. The member is optional and only for display, so a
request without it loses nothing. `user_agent_omitted_for_line_separator` and
`user_agent_omitted_before_truncation` pin this rule. Each reports a user
agent and sends none, so its bytes are the bytes of `minimal`, and every
encoder writes those the same way. The rule names these characters and no
others. A C1 control character, U+0080 to U+009F, is sent as UTF-8 like any
other non-ASCII character (`user_agent_c1_character_sent`).

A consumer builds the body from `input` with its real request builder and
compares the result with `serialized` byte for byte. A serializer that
escapes more than that by default needs it turned off: Go's `encoding/json`
escapes `<`, `>` and `&` unless `SetEscapeHTML(false)` is set, and it does so
even when it re-encodes an embedded raw message; Python's `json.dumps`
escapes non-ASCII characters unless `ensure_ascii=False` is passed. The
committed `body` object lists its members in the same order, so
`JSON.stringify(body)` reproduces `serialized` directly.

### User agent

`usrData.qurl_user_agent` is omitted when the client has no user agent to
report. It is also omitted when the user agent holds a control character,
U+2028 or U+2029, as "Canonical bytes" says
(`user_agent_omitted_for_line_separator`). The client looks at the whole
user agent for that, before it truncates anything
(`user_agent_omitted_before_truncation`). A value longer than
`constants.user_agent_max_bytes` is truncated, never rejected: the client
keeps the longest prefix that is at most 256 bytes of UTF-8 and ends on a
code point boundary, so what it sends is always valid UTF-8.

| Case | Input | Sent |
| --- | --- | --- |
| `user_agent_at_limit` | 256 bytes, 255 characters | unchanged |
| `user_agent_truncated` | 300 ASCII bytes | the first 256 bytes |
| `user_agent_truncated_at_code_point_boundary` | 258 bytes in 256 UTF-16 code units; a four-byte character occupies bytes 254 to 257 | the first 253 bytes: the whole character is dropped |
| `user_agent_omitted_for_line_separator` | 39 bytes; one character is U+2028 | nothing: the member is left out |
| `user_agent_omitted_before_truncation` | 300 bytes; the first 256 are ASCII with nothing wrong in them, and byte 257 is U+007F | nothing: the member is left out |
| `user_agent_c1_character_sent` | 33 bytes; one character is U+0085 | unchanged |

`user_agent_truncated_at_code_point_boundary` defeats both common mistakes.
Counting UTF-16 code units finds nothing to truncate, and cutting the encoded
bytes at 256 leaves a broken character.

`user_agent_omitted_before_truncation` pins the order. A client that truncates
first finds nothing wrong in the 256 bytes it keeps, and sends them.
`user_agent_truncated` is the other side: a long user agent that holds no
such character is still truncated and sent. The two omission cases hold
U+2028 and U+007F; U+0000 to U+001F and U+2029 fall under the same rule. In
the vector file their inputs write the two characters as the JSON escapes
`\u2028` and `\u007f`.

`user_agent_c1_character_sent` is the upper edge of the rule. U+0085 is a
control character too, but the rule does not name it, and Go, JavaScript and
Python all write it as UTF-8. A client that leaves out every character its
language calls a control character fails this case. In the vector file the
input writes the character as the JSON escape `\u0085`. `body` and
`serialized` hold the character itself, because they are the canonical form.

### CRID gate

Before it builds a request, the client runs the CRID v1 local validation gate
from `crid_v1_vectors.json` and refuses to send a CRID that fails it. Nothing
is trimmed, lower-cased or otherwise repaired.

A link request has one rule beyond that gate: a client must not send a
request for a CRID whose version it cannot verify a link against. That is a
CRID whose version byte is not registered in the CRID v1 version registry, or
is registered only as reserved, or is active but stands in a length the
registry does not give that byte. Such a CRID is well formed, its checksum is
valid, and the CRID v1 local gate forwards it. Here it is refused, because
the client could never complete check 6 below: it would ask the server to
create a link that it must then reject. Today the versions a client can
verify are the active ones, `01` and `81`, in their full 60-character form.

`invalid_request_cases` lists inputs a client must refuse. `crid_reject_class`
always comes from the CRID v1 vocabulary; this artifact defines no class of
its own for a refused request.

| Case | Input | `crid_reject_class` |
| --- | --- | --- |
| `reject_checksum` | one character of the digest changed | `checksum` |
| `reject_wrong_length` | 59 characters | `length` |
| `reject_uppercase` | upper-cased | `charset` |
| `reject_empty` | the empty string | `length` |
| `reject_unregistered_version` | version byte `7f`, 60 characters, valid checksum | `version` |
| `reject_reserved_version_02`, `reject_reserved_version_82` | the reserved short-form version bytes, 47 characters, valid checksum | `version` |
| `reject_active_version_01_short_form` | the active version byte `01` with a 24-byte digest, 47 characters, valid checksum | `version` |

For the first four the class is what the CRID v1 local gate reports. The last
four pass that gate. The request builder refuses them under `version`, the
CRID v1 vocabulary's class for a version byte a consumer must not act on; in
the local gate itself that class marks only the forbidden `00`.

## Reply types

A client reads the packet header type of a reply before it reads any body.
`reply_type_rules` gives the three cases:

| Rule | Header type | `is_ack` | `carries_outcome_code` | `handling` | What the client does |
| --- | --- | --- | --- | --- | --- |
| `ack` | `2` (`constants.ack_header_type`) | `true` | `true` | `interpret_ack_body` | interprets the body as the next section describes |
| `cookie` | `7` (`constants.cookie_header_type`) | `false` | `false` | `client_result` | reports the client result `busy`, whatever the body holds |
| `other` | any other | `false` | `false` | `transport_error` | reports a transport error, which is not a client result |

The cookie reply is what an overloaded server sends instead of an ACK. It is
not an ACK and it has no `errCode` to read. A v1 client reports `busy`, which
tells the user to try again; it does not answer the cookie.

Any other header type is not an answer to this request. A client treats it as
a transport error and reads nothing from it.

`handling` is a closed vocabulary of these three values. `client_result` is
present only on a rule whose handling is `client_result`, and `header_type`
is absent from the catch-all `other` rule.

## ACK body and outcome codes

The answer to a link request is an ACK whose `errCode` is a string and is
never a success code. `opnTime` is `0`, `resHost` and `acTokens` are `null`,
and there is no `sessId`, because the request opens nothing.

| `errCode` | `name` | `client_result` | `retryable` | Meaning | Client action |
| --- | --- | --- | --- | --- | --- |
| `52600` | `link_issued` | `link` | no | a link was issued; `redirectUrl` carries it | run the checks below, then open it |
| `52601` | `unavailable` | `unavailable` | yes | a link cannot be issued right now | let the user try again later |
| `52602` | `not_found` | `not_found` | no | the CRID is unknown, retired or malformed, or this client may not open it; the answer does not say which | do not send the same request again; a registered device may send the one further request of "A request under a registered device key". When no link follows, ask the user to check the CRID and their access |
| `52603` | `rate_limited` | `rate_limited` | yes | too many requests from this client or for this CRID | let the user try again later |
| `52604` | `resource_offline` | `offline` | yes | the resource exists and this client may open it, but its publisher is offline | tell the user the publisher is offline |
| `52605` | `resource_closed` | `closed` | no | the resource exists and this client may open it, but it has been closed | do not retry |
| `52606` | `invalid_request` | `invalid` | no | the request was malformed, did not arrive through the relay, or carried an unsupported member | do not retry |

`52604` and `52605` are only ever sent to a client that may open the resource.
A client that may not open it gets `52602`, whatever state the resource is in.

Three rules cover every other ACK body:

- **A success code, or a code that is not a string, is a protocol violation.**
  `"0"`, the empty string and a missing `errCode` are the success codes of an
  ordinary knock. A link request opens nothing, so none of them is a usable
  answer, even when the body also carries a valid `redirectUrl`
  (`success_code_is_protocol_violation`). An `errCode` that is not a JSON
  string is never coerced into a code a client knows:
  `numeric_code_is_protocol_violation` is the link-issued body with the
  number `52600`, which a loosely typed lookup would hand out as a link, and
  `null_code_is_protocol_violation` carries `null`.
- **Any other code is a generic server error.** That includes an unassigned
  code in this range and the denial codes of other knocks. It is never a link.
- **Only `52600` carries a link.** A client ignores `redirectUrl` and
  `redirectInfo` on every other code
  (`denied_with_redirect_is_not_a_link`).

`errMsg` is diagnostic text. Clients decide on `errCode` alone, and the
`errMsg` strings in these vectors are examples. Member order inside an ACK
body is not part of the contract.

Each `ack_cases` entry carries the `requested_crid`, the ACK `body`, and the
`expected` result:

```jsonc
{
  "name": "link_issued",
  "requested_crid": "ah6c...",
  "body": {"errCode": "52600", "redirectUrl": "https://qurl.link/#qv2t1...", "redirectInfo": {...}, ...},
  "expected": {
    "client_result": "link",
    "link": "https://qurl.link/#qv2t1...",
    "info": {"qurl_id": "...", "expires_at": "...", "resource_created_at": "...",
             "publisher": {"name": "Example Publisher", "verified": false}}
  }
}
```

`link` and `info` are present only for the `link` result. `client_results` is
the closed set of client results: the seven results in the table, then
`protocol_violation` and `server_error`, which also come from an ACK body,
and `busy`, which comes only from the cookie reply.

## Checks on an issued link

A client never opens, stores or displays a `redirectUrl` before these checks
pass. They run on a `52600` ACK, for the CRID the client asked for.

| # | Check | `reject_class` |
| --- | --- | --- |
| 1 | `redirectUrl` is present and is a non-empty string | `missing_redirect` |
| 2 | it begins with the deployment's link origin, compared as text, and what follows the origin is `/`, `?`, `#` or the end of the link | `origin` |
| 3 | between the origin and the fragment there is nothing, or a single `/`: no other path and no query | `path_or_query` |
| 4 | it has a fragment, and the fragment is a `qv2t1` transport, as defined by `qv2_conformance_vectors.json` | `transport` |
| 5 | the link's inner artifact, the canonical `qv2` body that transport reconstructs, parses and verifies under the client's trust store | `issuer_signature` |
| 6 | the resource public key in the signed claims derives the requested CRID | `crid_mismatch` |
| 7 | if `redirectInfo` is an object with a `crid` member, that member is exactly the requested CRID string | `info_crid_mismatch` |

Checks 2 and 3 compare text. An issued link is exactly the link origin, an
optional `/`, `#` and the fragment, so it has one of two forms:

```text
https://qurl.link/#qv2t1...
https://qurl.link#qv2t1...
```

`accept_link` and `accept_link_without_slash` pin the two. A client does not
parse the link as a URL to compare origins. A URL parser lower-cases the
scheme and the host and drops a default port, so it reads
`HTTPS://qurl.link/#...`, `https://QURL.LINK/#...` and `https://qurl.link:443/#...`
as the link origin. None of them is the text a server writes, and each is
rejected as `origin`. The same comparison rejects a link whose authority only
begins with the link origin: after the origin the next character must end the
authority. The link origin a client is configured with is itself one
spelling: lower-case scheme and host, a port only when it is not the default,
and no trailing slash.

The URL parser that browsers use also changes a link before it reads it. It
removes every tab, line feed and carriage return. So it reads
`https://qurl.li<TAB>nk/#...`, where `<TAB>` stands for one tab character, as
the bare link (`reject_origin_tab_in_host`). It reads a backslash as `/`. So
in `https://qurl.link\@example.com/#...` it ends the host at `qurl.link` and
reads the rest as a path (`reject_origin_backslash`). A parser that does not
read `\` as `/` finds the host `example.com` in the same link. Both links are
rejected as `origin`: the first does not begin with the link origin, and in
the second the character after the origin does not end the authority.

Check 3 is a comparison of text for the same reason. To a URL parser an empty
query is no query, and a dot segment is not part of the path, so it reads
`https://qurl.link/?#...` and `https://qurl.link/.#...` as the bare link.
Neither is one of the two forms, and each is rejected as `path_or_query`
(`reject_empty_query`, `reject_dot_segment`).

The fragment is everything after the first `#`, exactly as it is written. A
client does not percent-decode it before the transport check.

`issuer_signature` means that the link's inner artifact did not parse or did
not verify under the trust store. A client reports any inner-artifact failure
under this class, whichever of its own parsing or signature steps caught it.

Check 6 is the delivered-key rule of `crid_v1_vectors.json`: re-derive the
CRID from the key under the requested CRID's own version byte and digest
length, and compare exactly. `accept_test_environment_crid` asks for the
test-environment CRID of the same key and must pass;
`reject_redirect_info_crid_mismatch` echoes that sibling CRID in
`redirectInfo` while the client asked for the other one and must fail, because
check 7 compares with what was requested, not with what the key could derive.

Check 7 lets only an absent member pass. A member that is present but is not
the requested string fails, whether it is another CRID, a number, `null` or
an object: `reject_redirect_info_crid_number` (`0`),
`reject_redirect_info_crid_null` and `reject_redirect_info_crid_object` (an
object that even holds the requested CRID).

A failed check is a hard error. The client does not open the link and shows
nothing from that reply: not the link and not the publisher.

Each `client_verification_cases` entry carries a `requested_crid`, a `52600`
ACK `body`, an `outcome`, and on a reject its `reject_class`. Every reject
case contains exactly one fault, so its class does not depend on the order in
which an implementation runs the checks. The table order is the reference
order.

`accept_link_without_slash` catches a client that requires the `/` in front
of the fragment. The reject cases are chosen to catch specific mistakes:

| Case | What it catches |
| --- | --- |
| `reject_non_string_redirect` | a one-element array holding the valid link, which a loosely typed client would coerce into that link |
| `reject_origin_lookalike_host` | comparing a string prefix: the host only begins with the link host |
| `reject_origin_http_scheme` | checking the host but not the scheme |
| `reject_origin_other_port` | checking the host name but not the port |
| `reject_origin_userinfo` | comparing a parsed origin, which hides the userinfo in front of the right host |
| `reject_origin_as_userinfo` | comparing a string prefix: the link begins with the link origin, which is only the userinfo of another host |
| `reject_origin_uppercase_scheme`, `reject_origin_uppercase_host` | parsing the link before comparing: a URL parser lower-cases the scheme and the host |
| `reject_origin_default_port` | parsing the link before comparing: a URL parser drops the default port |
| `reject_origin_trailing_dot` | treating the host with a trailing dot as the same host |
| `reject_origin_backslash` | parsing the link before comparing: a browser's URL parser reads a backslash as `/`, so it ends the host at the link host and reads the other host as a path |
| `reject_origin_tab_in_host` | parsing the link before comparing: a browser's URL parser removes a tab, a line feed and a carriage return before it reads the link |
| `reject_path`, `reject_query` | accepting the right origin with something other than the bare fragment link |
| `reject_empty_query` | checking the query with a URL parser, which reports an empty query as no query |
| `reject_dot_segment` | checking the path with a URL parser, which removes a dot segment |
| `reject_legacy_fragment` | accepting the canonical `qv2` body as an outer fragment; only `qv2t1` is a transport |
| `reject_missing_fragment` | assuming a fragment exists |
| `reject_tampered_signature` | skipping signature verification: the signature is well formed and low-S but does not verify |
| `reject_link_for_another_crid` | trusting a correctly signed link without tying it to the requested CRID |
| `reject_redirect_info_crid_number`, `reject_redirect_info_crid_null` | treating a falsy echo as if the member were absent |
| `reject_redirect_info_crid_object` | comparing the echo only when it happens to be a string |

`constants.link_origin` is the link origin of the deployment these vectors
model. A client checks against the link origin of the deployment it is
configured for; configure `https://qurl.link` to run the vectors.

These checks are only the ones this step adds. The validity window, the relay
allowlist and proof of possession belong to opening the link in step 2 and
are pinned by the qURL v2 artifacts. A client may also run its link-opening
checks, for example its relay allowlist and the claims' validity window, on
the issued link before it returns the link; a link that fails those is not
returned, and that outcome is outside this artifact's `reject_classes`,
because the link-opening artifacts pin it. A consumer whose link verifier
enforces the validity window evaluates the fixture link at an instant inside
its claims' `nbf` to `exp` window.

## `redirectInfo` is display-only and unverified

`redirectInfo` is optional metadata for the person about to open the link. It
is not covered by the link signature and not bound to the CRID, and apart from
check 7 it takes no part in verification. A client must treat all of it as
display-only.

The publisher is unverified. `publisher.name` is a name the publisher chose
for itself, and `publisher.verified` is `false` for every publisher today.
Only the JSON boolean `true` could ever mean verified; any other value,
including the string `"true"`, is `false`. A client that shows a publisher
shows it as unverified, and treats the name as untrusted text to be quoted or
escaped where it is displayed.

Malformed metadata never fails the request. A client keeps a sanitized view,
which is what `expected.info` in `ack_cases` and `expected` in
`redirect_info_sanitization_cases` hold.

Every display string in `redirectInfo` follows one rule. It is kept only when
it is a non-empty string of at most 128 Unicode code points
(`constants.info_text_max_code_points`). A longer string is dropped, never
shortened.

| Member | Kept when | Otherwise |
| --- | --- | --- |
| `qurl_id`, `expires_at`, `resource_created_at`, `publisher.name` | it is a non-empty string of at most 128 Unicode code points | absent |
| `publisher.verified` | it is the JSON boolean `true` | `false` |

These cases pin the cap:

| Case | Member | Code points | Kept |
| --- | --- | --- | --- |
| `publisher_name_at_limit` | `publisher.name` | 128 | yes |
| `publisher_name_over_limit` | `publisher.name` | 129 | no |
| `qurl_id_at_limit` | `qurl_id` | 128 | yes |
| `qurl_id_over_limit` | `qurl_id` | 129 | no |
| `expires_at_over_limit` | `expires_at` | 129 | no |
| `resource_created_at_over_limit` | `resource_created_at` | 129 | no |

The cap counts code points, not bytes and not UTF-16 code units: both
at-limit values are 131 bytes and 129 UTF-16 code units. A string over the cap
removes only its own member; the rest of the view is unchanged. Every
over-limit value except the name begins with the genuine value, so a client
that shortened it, or read only its start, would surface something plausible
where the vectors expect the member to be absent.

- `publisher` is always present in the view, even when all it says is
  `{"verified": false}`.
- When `redirectInfo` is absent or is not a JSON object, every optional member
  is absent and the publisher is `{"verified": false}`. The link is still
  usable.
- When `publisher` is not a JSON object, the publisher is
  `{"verified": false}`; a client never reads a name out of a non-object.
- Unknown members are ignored and never surfaced.
- The two timestamps are RFC 3339 text as the server wrote them. This
  artifact pins only that each is a string within the cap; a client that
  cannot parse one treats it as absent where it is used.
- The view has no `crid`: the echoed CRID is checked, not displayed.

A JSON `null` is not a string, so by the table a `null` display member is
absent. `crid` is the exception described under check 7: a `null` there is
present and unequal, and it rejects. Apart from that case the vectors contain
no `null` for an individual member; the server omits a member it has no value
for.

## Fixtures and composition

`composes` names the sibling artifacts this one reuses instead of restating:

| Member | Artifact | What it supplies |
| --- | --- | --- |
| `issuer_trust_anchor` | `issuer_signature_vectors.json` | the `issuer` public key: the whole trust store for these vectors |
| `link_transport` | `qv2_conformance_vectors.json` | the `qv2t1` transport contract and the link itself |
| `crid` | `crid_v1_vectors.json` | the CRID derivation, the local gate, the version registry and the delivered-key rule |

`fixtures` holds the values the cases share:

- `link` is `constants.link_origin`, then `/#`, then the
  `accept_valid_qv2_round_trip` transport fragment of the qURL v2 artifact,
  byte for byte. Its issuer signature verifies under the composed trust
  anchor.
- `resource_public_key_b64` is the resource public key in that link's signed
  claims. `crid` is its CRID under version `01` and `test_environment_crid`
  is its CRID under version `81`.
- `unrelated_crid` is `resource_key_qv2_v01` from the CRID v1 artifact: a
  valid CRID of a different key.

## Consumer algorithm

These steps cover single requests and single replies. They say nothing about
the rule in "A request under a registered device key", which no vector pins.

Consumers derive every declared outcome through their production paths:

1. For each `request_cases` entry, build the request from `input` and compare
   the serialized body with `serialized` byte for byte.
2. For each `invalid_request_cases` entry, confirm that the request builder
   refuses the input before any network I/O. That includes the well-formed
   CRIDs whose version the client cannot verify a link against.
3. Apply `reply_type_rules` in the real reply path: a reply with the cookie
   header type yields `busy` without its body being read, and a reply with
   any header type other than the ACK's or the cookie's is a transport error.
4. For each `ack_cases` entry, feed `requested_crid` and `body` through the
   real reply interpreter as an ACK and compare the result with `expected`:
   the `client_result`, and for a link the exact `link` and the sanitized
   `info`.
5. For each `client_verification_cases` entry, do the same and assert the
   `outcome`; on a reject assert the `reject_class` and that nothing from the
   reply was surfaced.
6. For each `redirect_info_sanitization_cases` entry, sanitize `redirect_info`
   and compare with `expected`. To run it through the full interpreter, put
   the value in place of `redirectInfo` in the `link_issued` ACK; the result
   is still a link.

A missing vector is a hard failure, never a skipped test.

## Versioning

`error_codes`, `client_results`, `reject_classes`, `reply_type_rules` with its
`handling` values, `constants.forbidden_user_data_keys` and the case names
are closed. Adding, removing or renaming an entry, or changing what an
existing rule or case expects, requires a new `schema_version` and a
coordinated release. Consumers pin one released version, so a client cannot
quietly drift from the contract.

## Reference validation in this repository

The dependency-free Go loader is the artifact's strict reference validator.
It rejects duplicate keys, unknown members, missing required members and
optional members written as empty; it pins every case input against a fixture
derived from the composed artifacts; it pins `reply_type_rules`; and it
re-derives every expectation: the canonical request bytes with the truncation
and the omission of the user agent, the request-gate class of every refused
input, the client result of every ACK, the reject class of every issued link
(with a real issuer-signature check against the composed trust anchor and a
real CRID derivation from the signed resource key), and the sanitized view of
every `redirectInfo` value. Every ACK case declared a link also has to pass
those link checks.

The npm and Python packages carry byte-identical copies and expose thin
accessors; they do not inherit the Go loader's validation. This repository's
CI runs the same vectors through `JSON.stringify`, the text comparison with
the link origin and an independent signature verification in Node, and
through Python's serializer and CRID derivation, and both runtimes run the
request gate and dispatch on `reply_type_rules`, so the vectors are known to
be implementable outside Go. The Node run also records what the WHATWG URL
parser makes of each link: it agrees on every link the text comparison lets
through, and it reads exactly six of the rejected links as the bare link on
the link origin: the three spellings, the link with a tab in its host and the
two check 3 links above. It puts the backslash link on the link origin too,
with the path `/@example.com/`. Consumers in those languages still run every
case through their own production code.

## Lockstep with the qURL v2 link

The fixture link is the published qURL v2 accept link, so regenerating that
link changes this artifact too. Until it is updated the loader fails and
names the stale value. In the same change:

1. replace every copy of the old `qv2t1` fragment with the new one;
2. in `reject_legacy_fragment`, replace the old canonical `qv2` body with the
   new one;
3. in `reject_tampered_signature`, use the new fragment with the first
   character of its final (signature) component replaced by `A`, or by `B`
   when it already is `A`;
4. if the claims' `exp` moved, replace every copy of the old `expires_at`
   instant with the new one, which also updates the start of the
   `expires_at_over_limit` value, and update the number in
   `timestamps_not_strings` to match;
5. run `scripts/sync-vectors.sh`.

The CRIDs do not change while the vector resource key stays fixed.

## Lockstep with the CRID version registry

The request gate reads the version registry in `crid_v1_vectors.json`, so
four `invalid_request_cases` depend on what that registry says today.
`reject_unregistered_version` uses the version byte `7f` because the registry
has no row for it. `reject_reserved_version_02` and
`reject_reserved_version_82` use `02` and `82` because their rows are
reserved. `reject_active_version_01_short_form` uses `01` with a 24-byte
digest because the row of `01` is active with a digest length of 32. The day
one of the first three bytes becomes active, or the row of `01` gets a digest
length of 24, the request gate lets that case's CRID through. The loader then
fails and says it wants `accept` for the case, and both package smokes fail
on the case name. That happens in a change about the CRID registry, whose
author has no reason to look here. In the same change:

1. if `7f` gets a row, re-point `reject_unregistered_version` to a version
   byte that still has none: change the byte in the loader's fixture and its
   test, derive the case's CRID again under the new byte, and change the
   byte in the table under "CRID gate" and in both CI smokes. The case keeps
   its name, its class and its 60-character form;
2. if `02` or `82` becomes active, its case no longer names a CRID a client
   must refuse, so the case has to go. Removing a case needs a new
   `schema_version` (see "Versioning"), so plan the two changes together,
   and update the sentence under "CRID gate" that names `01` and `81`;
3. if the row of `01` changes its digest length or is no longer active,
   `reject_active_version_01_short_form` is no longer what its name says, and
   every 60-character `01` CRID this artifact asks a link for is refused. That
   needs a new `schema_version` as well;
4. run `scripts/sync-vectors.sh`.
