# Registered-agent session-control vectors

`agent_session_control_vectors.json` freezes the authenticated NHP session
transitions a native UDP connector needs after its first registered-agent
knock. It is a full-packet artifact, not a replacement for
`agent_knock_application_vectors.json`: the latter defines application-body
policy, while this artifact proves the Noise packet bytes and transition
correlation.

## Positive flows

The artifact contains one deterministic instance of each transition:

1. `overload_reknock.knock_request`: NHP_KNK (type 1), counter 41.
2. `overload_reknock.cookie_reply`: NHP_COK (type 7). Its authenticated
   `body.trxId` is 41 and its cookie is exactly 32 bytes encoded as canonical,
   padded RFC 4648 standard base64.
3. `overload_reknock.reknock_request`: NHP_RKN (type 8), counter 42. It retains
   the KNK identity, resource, and RunID and authenticates the decoded cookie in
   its header digest.
4. `overload_reknock.ack`: NHP_ACK (type 2), counter 42.
5. `clean_exit.request`: NHP_EXT (type 16), counter 43. It retains the same
   identity, resource, and RunID.
6. `clean_exit.ack`: NHP_ACK (type 2), counter 43.

Every packet records the exact sender and receiver key roles, deterministic
ephemeral private key, timestamp, counter, preamble, compact JSON body, body
bytes, header digest, and complete packet bytes. The two static X25519 keypairs
are synthetic. The committed packets were emitted by producer revision
`e0fedfec0cf3215d8af291b21ef9eb5889ae9906`.

## Correlation contract

- A COK wire counter is not a transaction-correlation field and may differ
  from the originating KNK counter. Correlate the challenge only after server
  authentication, strict body decoding, and verifying `body.trxId` equals the
  KNK counter.
- An ACK counter must equal the request counter for its RKN or EXT.
- The authenticated body's case-sensitive `headerType` must equal the outer
  packet type. A type 1 packet with a type 8 body, or the inverse, is invalid.
- `usrId`, `devId`, `aspId`, `resId`, and the canonical 16-character lowercase
  hexadecimal `runId` remain unchanged across KNK, RKN, and EXT.
- A cookie challenge is valid after KNK only. EXT accepts ACK and never COK.
- Decryption is insufficient without peer authentication. Replies are accepted
  only under the assigned cell's pinned static public key; requests are accepted
  only under the registered agent's static public key.

## RKN header digest

For a normal request, the 32-byte digest at header bytes 208:240 is:

```text
BLAKE2s-256(initial_hash || server_static_public_key || header[0:208])
```

For RKN, append the raw decoded 32-byte cookie:

```text
BLAKE2s-256(initial_hash || server_static_public_key || header[0:208] || cookie)
```

The base64 text is never hashed. A different cookie or a one-bit digest change
must fail before body authorization.

## Cookie body contract

The COK body is an exact JSON object with two case-sensitive fields:

```json
{"trxId":41,"cookie":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}
```

A consumer must reject duplicate keys, unknown keys, trailing JSON values,
non-object or null bodies, wrong JSON types, non-standard or whitespace-bearing
base64, decoded lengths other than 32 bytes, and non-canonical encodings such as
missing padding. `cookie_body_cases` is a closed suite and declares the exact
`outcome` and `reject_class` for every case.

## Flow reject vocabulary

`flow_cases` is also closed, but it is a consumer-driven expectation table
rather than a stored mutated-packet suite. Each consumer synthesizes every named
mutation against its real session parser and must produce the declared result:

| Reject class | Meaning |
| --- | --- |
| `body_parse` | COK JSON is not exactly the required typed object |
| `cookie_encoding` | cookie text is not strict standard base64 |
| `cookie_length` | decoded cookie is not exactly 32 bytes |
| `cookie_canonical` | cookie decodes but is not the canonical padded spelling |
| `counter` | authenticated transaction correlation failed |
| `header_type` | outer and authenticated application types disagree |
| `reply_type` | the transition received a disallowed authenticated reply type |
| `header_digest` | RKN digest did not authenticate the exact cookie and header |
| `application_body` | immutable identity, resource, RunID, or exact body parsing failed |
| `peer_authentication` | the expected static peer key did not authenticate the packet |

## Consumer algorithm

1. Require the exact artifact id, schema version, protocol metadata, producer
   revision, key roles, closed case sets, and all canonical hex/base64 forms.
2. Rebuild KNK, RKN, and EXT from their deterministic inputs and compare every
   complete packet byte. For RKN, include the decoded cookie in the digest.
3. Authenticate and decrypt COK and ACK under the assigned cell public key;
   authenticate initiator packets under the agent public key in a responder
   verifier.
4. Apply the counter, type/body, immutable-RunID, cookie, and reply-disposition
   gates above. Missing fixtures or unknown cases are failures, never skips.
5. Execute every cookie and flow case through the implementation's real entry
   points and assert the declared reject class.

The canonical JSON under `vectors/` is the source of truth. npm and Python
copies must remain byte-identical.
