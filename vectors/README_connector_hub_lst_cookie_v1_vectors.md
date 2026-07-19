# Connector Hub LST cookie v1 vectors

`connector_hub_lst_cookie_v1_vectors.json` freezes the mandatory native-UDP
return-routability challenge before a Connector Hub may invoke Connector
Authority or emit an assignment LRT. It is separate from NHP's overload
`KNK -> COK -> RKN` contract: the two cookies use different HMAC domains,
different request types, and different proof flags.

There is no HTTP or padded-request fallback.

## Flow

Both `initial_assignment` and `refresh_assignment` use the same four steps:

1. The SDK sends a valid authenticated NHP_LST with header flags exactly
   `0x0000`.
2. After the Noise static-key decrypt and body AEAD open succeed, global
   admission permits a challenge, and the exact sealed COK packet is strictly
   smaller than the received LST, the Hub may return one authenticated NHP_COK
   with header flags exactly `0x0000`. Core does not call an application codec
   at this stage;
   even crypto-valid framing around malformed application JSON may receive the
   smaller challenge. No Handler or Authority operation has run and COK is not
   an Authority outcome.
3. The SDK verifies COK under the pinned Hub public key, requires its header
   flags to equal `0x0000` and its `trxId` to equal the first LST counter, then
   sends exactly one fresh NHP_LST. An authenticated compressed COK or one with
   any unknown flag is terminal: no proof LST, third LST, or fallback is sent.
   The second LST has fresh Noise ephemeral material, timestamp, and counter;
   flags exactly `0x0004`; and a byte-identical authenticated application body,
   including the same `request_nonce`.
4. NHP core verifies return routability before dispatch. The worker then
   strict-decodes the assignment body; malformed application JSON is silent.
   Only a valid body may reach the Handler and phase's one private Authority
   operation and return NHP_LRT. A COK after the proof LST is terminal; the SDK
   sends no third LST.

Invalid NHP framing, static-key decrypt failure, and body-AEAD failure on the
first flight are silent. Application authorization does not run before source
proof: a syntactically valid new enrollment peer is not required to be in a
registry before COK. Invalid, wrong-address, wrong-peer, expired, future-window,
wrong-flag, wrong-phase, transplanted-RKN, replayed, and application-malformed
proof packets are silent and make zero Authority calls. Credential, owner,
cell, and refresh authorization belongs to the post-proof Handler/Authority.

### Additive application profiles

`contract.additive_application_profiles` is the exact closed allowlist of
`artifact/profile` identifiers that may compose the cookie primitive without
adding a case to this artifact's closed base-flow set. The current sole entry
allows the recovery artifact's `hub_cookie_composition` profile. Membership
grants only composition eligibility: the additive artifact must freeze its own
body, proof, size, Authority-call, success, and reject cases. Unknown profiles
are forbidden, and changing the allowlist requires an explicit reviewed,
versioned conformance release.

## Cookie derivation

The cookie is an opaque 32-byte HMAC-SHA-256 output. The secret signing key is
exactly 32 bytes. Source port is deliberately excluded: NAT and UDP address
fallback may change the port, while the anti-reflection target being proven is
the source IP.

```text
domain = ASCII("nhp-connector-hub-lst-cookie-v1") || 0x00

ip = netip.Unmap(observed_source_ip)
family = 0x04 for IPv4, 0x06 for IPv6

preimage =
  domain ||
  family || u32be(len(ip.raw_bytes)) || ip.raw_bytes ||
  u32be(32) || authenticated_initiator_public_key_raw32 ||
  u64be(window_index)

cookie = HMAC-SHA-256(signing_key_raw32, preimage)
window_index = floor(unix_seconds / 30)
```

Verification accepts the current and immediately previous window only. A
future window and `current-2` or older fail closed. IPv4-mapped IPv6 is unmapped
before the family tag and bytes are framed, so it derives the same cookie as its
IPv4 form. Zone-bearing or missing addresses fail closed.

The synthetic KAT pins every preimage and output byte. Its key is public test
material and must never be deployed.

Workers have exactly two verification slots for safe rolling rotation behind a
UDP load balancer: active is required and previous is optional. Mint uses active
only. Verification order is deterministic: active/current-window,
active/previous-window, previous/current-window, then
previous/previous-window. A previous key without an active key is invalid
configuration and fails closed. No key id appears in COK or the proof LST; the
32-byte cookie stays opaque. `key_cases` pins every accepted overlap and the
missing-active failure.

## Proof placement

No header extension or application-body cookie field is added. Bit `0x0004` is
reserved as `NHP_FLAG_HUB_LST_COOKIE_PROOF`; bit 0 remains extended-length and
bit 1 remains compression. A proof LST requires `0x0004` exclusively.

The raw decoded cookie is additional input to the existing 32-byte Curve header
digest:

```text
BLAKE2s-256(
  initial_hash ||
  hub_server_static_public_key_raw32 ||
  serialized_header[0:208] ||
  cookie_raw32
)
```

`proof_digest_kat` is deliberately a digest-primitive KAT, not a complete
encrypted proof packet. Its 208-byte prefix takes deterministic fresh header
material from the refresh golden, sets the proof flag, and advances the counter
to 23. The loader asserts that both its counter and ephemeral public key differ
from the initial-flight vector. The flow fixtures independently require the
proof flight's authenticated body and embedded `request_nonce` to remain
byte-identical to its own unproven flight.

The digest is unkeyed and is not peer authentication. Return-routability comes
from possession of the opaque HMAC cookie delivered to the observed source;
peer authentication still comes from the normal Noise static-key decrypt and
trust decision. Header type, flag, fresh counter, timestamp, and ephemeral
material are inside the serialized prefix, so copying a proof digest to another
header fails. Copying an overload RKN cookie fails the separate HMAC domain and
the LST-only flag/type gates.

The cookie intentionally does not authorize an application body. Noise AEAD
authenticates the exact body. Reusing a valid current cookie from the same IP
and peer on a fresh transaction proves the same source again, but grants no
additional authority. This artifact's closed base flows select only
IssueAssignment or RefreshAssignment. Its primitive may also be composed by
the explicitly allowlisted recovery application profile in
`agent_credential_recovery_v1_vectors.json`; that additive artifact owns the
recovery body, size, proof, and Authority-call cases without extending this
artifact's two-flow set. In every profile, the private `hub_request_id` remains
derived from the authenticated peer plus `request_nonce`. Same-nonce and
same-semantics retries reuse the Authority result; same-nonce with changed
semantics fails the Authority fingerprint fence. An exact captured proof packet
is rejected by NHP's authenticated timestamp/counter replay gate before
dispatch.

## COK and amplification bound

COK has header flags exactly `0x0000` (uncompressed, with no unknown bits) and
its plaintext is exactly:

```json
{"trxId":21,"cookie":"YG/CuZiC2NxiVNiah1ZJPFGD0GjAdHUAUSfxrfjrrLY="}
```

The 240-byte Curve header plus 16-byte body AEAD tag is a 256-byte overhead for
every nonempty encrypted body. Current NHP emits a truly empty message as a
240-byte header-only packet, with no body tag. With the maximum uint64
transaction id, COK is 86 plaintext bytes and 342 sealed packet bytes. The
size-boundary cases pin that maximum transaction id explicitly. The producer
must still compare the actual sealed COK
length to the actual received LST length; it emits only when
`len(COK) < len(LST)`. Equality is silent. The size cases include
the real 240-byte core-empty packet plus cryptographically valid smaller and
equal-size nonempty LST framing so an
implementation cannot rely only on today's 493-byte initial and 437-byte
refresh assignment fixtures. The `malformed_json_87` case is deliberately
challenge-size eligible: the Hub must not decode or authorize an application
body until the cookie proof returns.

The NHP packet maximum is 4,096 bytes, so the maximum plaintext body is 3,840
bytes (`4096 - 240 - 16`).

The `assignment_success_sizes` cases keep the anti-reflection analysis tied to
the real success envelopes. Initial enrollment's current assignment packet
fixture is only 797 bytes because it carries a placeholder ticket; it is retained
under the explicitly legacy-named field and is not the sizing proof. The real
qat1 golden is 1,521 body bytes / 1,777 packet bytes, an exact amplification
fraction of `1777/493` from the initial LST. Substituting the maximum 2,304-byte
ticket into its 518-byte JSON envelope yields 2,822 / 3,078 bytes and the
worst pinned fraction `3078/493`. Refresh has no ticket and remains 363 / 619,
or `619/437`. These larger success packets are emitted only after source proof.

## Consumer execution

Consumers must:

1. Strict-decode the artifact and reject duplicate or unknown fields.
2. Recompute the KAT preimage, HMAC, and compact COK bodies.
3. Drive both flows through their real state machine, including exact body and
   `request_nonce` equality, fresh proof packet material, the exclusive flag,
   one-proof limit, duplicate/unknown COK rejection, exact zero COK header
   flags, terminal compressed/unknown-flag COK rejection, and zero pre-proof
   Authority calls.
4. Execute every size, server-reject, and client-challenge case at the named
   boundary. Missing cases are failures, never skips.
