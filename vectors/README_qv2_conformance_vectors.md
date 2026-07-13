# qURL v2 conformance vectors

`qv2_conformance_vectors.json` is the **protocol-versioned, language-agnostic**
wire-truth for the qURL v2 *verify* path. Every qURL v2 verifier implementation
re-runs the **same bytes** against its **own** implementation, in whatever
language it is written.

A consumer feeds each class's input through its **real** parser/validator and
asserts the declared `expect` (and, where the class pins it, `reject_class`). The
vectors are **behavioral**: a consumer recomputes/re-verifies rather than trusting
a stored boolean, so a verifier that drifts from the contract fails its own run.

This file (the JSON) is the single source of truth. This README is the schema +
vocabulary + class-to-entry-point map. The artifacts in this directory are:

| Artifact | Role |
| --- | --- |
| `qv2_conformance_vectors.json` | the conformance classes (claims/secret parse, strict base64url, fragment shape, relay allowlist, server-id) |
| `issuer_signature_vectors.json` | the issuer-signature golden vectors the signature class composes by reference |
| `relay_knock_golden.json` | the relay-knock Noise-handshake golden packets (artifact `qurl-relay-knock-golden-vectors`), a separate layer (see below) |
| `agent_registration_golden.json` | the NHP agent-registration OTP/REG/RAK Noise-handshake golden packets (artifact `qurl-agent-registration-golden-vectors`), a separate layer (see below) |
| `agent_knock_application_vectors.json` | registered-agent KNK/ACK application-body and disposition vectors (artifact `qurl-agent-knock-application-vectors`), separate from packet bytes |

---

## Why this artifact exists

There are several would-be sources of truth for "what a qURL v2 verifier must
accept/reject": each implementation's own tests, and the signature golden file.
The signature golden file (`issuer_signature_vectors.json`) pins the signature
bytes once. This artifact extends that single-source pattern to the **rest** of
the verify path (claims/secret parse, strict base64url, fragment shape, relay
allowlist, server-id derivation) so the same divergence-proof exists for every
layer, not just signatures — and composes the signature class **by reference**
instead of copying its bytes a second time.

---

## Schema (`schema_version: 1`)

Top-level document:

```jsonc
{
  "artifact": "qurl-v2-conformance-vectors",   // fixed id; consumers assert it
  "schema_version": 1,                          // bump on any breaking shape change
  "description": "...",                          // human prose
  "source_of_truth": "layervai/qurl-conformance",
  "notes": [ "..." ],
  "signature_class": { ... },                   // COMPOSED, see below
  "classes": { "<class_name>": { ... }, ... }
}
```

Each entry in `classes` is:

```jsonc
{
  "entry_point": "strict claims parser (raw JSON -> Claims)",  // documents the verifier operation the class targets
  "input": "claims_json",                 // which vector field carries the input
  "comment": "...",                       // optional human prose
  "vectors": [ <vector>, ... ]            // ordered, non-empty
}
```

Each `vector`:

```jsonc
{
  "name": "reject_duplicate_key",   // unique within its class
  "expect": "accept" | "reject",
  "reject_class": "parse",          // REQUIRED on reject, ABSENT on accept (see vocabulary)
  "reason": "human explanation",
  // ...plus exactly the input field(s) this class consumes (claims_json, secret_json,
  //    value_b64, fragment, entries+url, or cell_public_key_b64+server_id).
}
```

### Input shape is per-class, on purpose

Each class carries the **exact** input form its target operation consumes, so a
stored fault survives all the way to the code under test:

- **`claims_json` / `secret_json`** — RAW JSON TEXT (ASCII), fed straight to the
  claims / secret parser. **Not base64.** Duplicate keys and other JSON-layer
  faults survive storage because they live *inside a JSON string value* in this
  file, not as object members a re-serializer would normalize away. (If these
  were base64-encoded first, a parser that consumes JSON bytes would reject them
  for the wrong reason.)
- **`value_b64`** — the base64url string VERBATIM; the fault is in the encoding
  layer, fed to the strict base64url decoder.
- **`fragment`** — a full fragment body fed to the fragment parser, which pins
  wire SHAPE and strict-parses the parts but does **not** verify the signature.
- **`entries` + `url`** — fed to the relay-URL validator against an allowlist
  built from `entries`.
- **`cell_public_key_b64` (+ `server_id`)** — the consumer DECODES the key and
  RE-FINGERPRINTS it, asserting the result equals the pinned `server_id`.

---

## Class -> entry-point map

| Class | Verifier operation | Accept means | Reject class(es) |
| --- | --- | --- | --- |
| `signature` (composed) | issuer-signature verify | sig verifies over the claims | `high_s` / `wrong_length` (+ derived `tamper`) |
| `claims_parse` | strict claims parse | strict-parses to a `Claims` | `parse` |
| `secret_parse` | strict secret parse | strict-parses to a `Secret` | `parse` / `key_length` |
| `strict_base64` | strict base64url decode | decodes | `encoding` |
| `fragment` | fragment shape parse | parses (shape only) | `fragment` |
| `relay_allowlist` | relay-URL validation against allowlist | URL allowed | `relay_url` |
| `server_id` | public-key fingerprint of decoded `cell_public_key_b64` | recompute == `server_id` | *(none — recompute-equality, accept-only)* |

Each consumer maps every class to its own equivalent function; the *outcomes*
(accept/reject + `reject_class`) are the contract, the operation names above are
descriptive labels.

---

## `reject_class` vocabulary

`reject_class` is the fixed cross-language vocabulary, so a consumer in any
language can `switch` on a **closed, known** set. It is pinned **precisely** only
where the class is *about* the distinction; JSON-schema faults use the coarse
`parse` class because a conformant verifier may surface any of several internal
sentinels for them.

| `reject_class` | Meaning | Allowed in classes |
| --- | --- | --- |
| `parse` | a JSON-schema violation (duplicate key, unknown field, null, wrong type, missing required, out-of-range/incoherent ordering) | `claims_parse`, `secret_parse` |
| `encoding` | base64url encoding-layer rejection | `strict_base64` |
| `key_length` | decoded key has the wrong byte length | `secret_parse` only (see note) |
| `fragment` | fragment wire-shape rejection | `fragment` |
| `relay_url` | `relay_url` HTTPS/allowlist rejection | `relay_allowlist` |
| `high_s` | signature is not low-S normalized | `signature` (in the composed file's `reject_class`) |
| `wrong_length` | signature is not exactly 64 bytes (raw r\|\|s) | `signature` (in the composed file's `reject_class`) |
| `tamper` | valid signature verified against a (flipped) different message | `signature` (in `signature_class.tamper_derivation`, derived not stored) |

Rules a consumer can rely on:

1. Every **reject** vector carries a `reject_class` from **its class's** allowed
   set above.
2. Every **accept** vector carries **no** `reject_class`.
3. The signature class is **composed** (its stored reject vectors live in the
   composed file and carry their own `reject_class`), so it is not in the
   per-class `classes` table.

**Note on `key_length` (claims vs secret).** A wrong-length **key** field is the
same physical fault in both parse classes, but the artifact pins `key_length`
**only** in `secret_parse` (e.g. `reject_short_private_key`). In `claims_parse`, a
wrong-length key field (e.g. `reject_short_cell_key`) deliberately coarsens to
`parse` — consistent with the rule that JSON-schema faults inside the claims object
use the coarse class (a claims verifier may surface several internal sentinels for
them). So a consumer switching on `reject_class` must **not** expect `key_length`
for a *claims* key field; only `secret_parse` (the standalone PoP secret) pins it.

---

## The signature class is composed, not copied

```jsonc
"signature_class": {
  "entry_point": "qv2.VerifyRawIssuerSignature(pub, claimsB64, rawSig)",
  "composes": "issuer_signature_vectors.json",
  "comment": "..."
}
```

The signature vectors live in `issuer_signature_vectors.json` (P-256 raw r||s
low-S wire encoding, the 0x00 domain separator). This conformance artifact
**references** that file by name; it does **not** duplicate the signature bytes.
There is therefore exactly one copy of the signature bytes in the tree, and the
conformance run exercises the signature class by loading the composed file and
running it through the real verifier.

### Issuer-signature reject(tamper) — derived, language-agnostic

The composed file's reject vectors cover signature **malleability/encoding**
(`high_s`, `wrong_length_der`). The most basic signature negative — a
**payload-tamper**, i.e. a structurally well-formed signature that is simply not
valid over the presented claims — is **derived**, so every consumer can synthesize
it **without** a second copy of signature bytes. The artifact specifies the
derivation under `signature_class.tamper_derivation`:

```jsonc
"tamper_derivation": {
  "reject_class": "tamper",
  "derive_from": "accept_vector",
  "claims_transform": "flip_first_base64url_char_A_B"
}
```

A consumer takes the composed file's **accept** vector, reuses its valid 64-byte
low-S signature **unchanged**, and verifies it against the accept vector's
`claims_b64` with its **first base64url character flipped between `A` and `B`**
(`A`->`B`, any other char->`A`). The signature stays well-formed, so it passes the
length/range/low-S gates and fails **only** at the curve check: the verifier must
reject it with its signature-invalid sentinel (the generic "signature invalid"
result, **not** the high-S or wrong-length result).

**Why the *first* character (portability):** consumers differ in what they hash —
some hash the `claims_b64` **string**, others decode-then-hash or strict-decode
before verifying. The first base64url symbol is the top 6 bits of decoded byte 0 —
always fully significant — so flipping it keeps the string **canonical** base64url
**and** changes the **decoded** bytes. That single transform therefore produces the
*same* tamper rejection for all consumer strategies. A *last*-character flip would
not: when `len(claims_b64) mod 4 != 0` the last symbol's low bits are don't-care
padding bits, so an `A`<->`B` flip there could change only those bits — decoding to
identical bytes (a decode-then-hash verifier would still *accept*) and yielding a
non-canonical string (a strict-decode-first verifier would reject for *encoding*,
not tamper).

A conformant runner reads this spec and applies the named transform (it does
**not** hardcode the recipe), errors loudly on an unknown `claims_transform` so a
drift fails rather than silently skips, **and asserts the portability invariant
directly** — the transformed `claims_b64` must still strict-decode (canonical) and
must decode to different bytes than the original.

---

## Out of this artifact, by layer

Noise-handshake packet byte vectors (the KNK/ACK/OTP/REG/RAK wire bytes of the
handshake) are intentionally **out** of this artifact, by *layer*. The qURL
claims/signature/fragment layer is distinct from the Noise handshake layer, and a
verifier of the qURL layer cannot construct or verify a Noise packet. Folding
handshake bytes in here would couple two layers that are correctly separate. Those
language-agnostic Noise-handshake vector sets now exist as their **own** sibling
artifacts at the handshake layer — `relay_knock_golden.json`
(`qurl-relay-knock-golden-vectors`), which pins the deterministic relay-knock
packet and a frozen server-sealed ack reply, and `agent_registration_golden.json`
(`qurl-agent-registration-golden-vectors`), which pins the deterministic OTP/REG
requests and frozen server-sealed RAK replies — not folded into this one.

**Net: one source of truth per layer.** Signature bytes: one file, composed by
reference. Verify-path classes: this file. Relay-knock handshake bytes:
`relay_knock_golden.json`. Agent-registration handshake bytes:
`agent_registration_golden.json`.
Registered-agent knock application semantics, including the authenticated
RunID policy split between the generic parser and native qURL Connector:
`agent_knock_application_vectors.json`.
Its `missing_run_id` / `invalid_run_id` request classes are scoped to that
separate artifact and intentionally remain outside this qURL-v2 reject vocabulary;
see `README_agent_knock_application_vectors.md` for their closed definitions.

---

## Using these vectors in another repo or language

1. Copy `qv2_conformance_vectors.json` **and** `issuer_signature_vectors.json`
   (the signature class composes the latter) **verbatim** — same bytes, no
   reformatting.
2. Load with a **strict** JSON reader (reject duplicate keys / unknown fields)
   that fails (never returns empty) on a missing/malformed file, so the contract
   can never silently drop out of a suite.
3. For each class, route the vector's input field to your real entry point and
   assert `expect` (+ `reject_class` where the table above pins it). Do **not**
   trust a stored boolean — re-derive the outcome.
4. Treat a missing fixture as a **hard failure**, not a skip.

The `source_of_truth` field records the canonical home; any downstream copy is
downstream of it.

---

## Demonstrating the negatives are real (flip-goes-red)

Because every accept/reject class switches on `expect` and asserts the **real**
outcome, editing any reject vector to `"accept"` (or vice versa) turns the run
RED. The **only** class without an accept/reject flip is `server_id`: it is a
recompute-equality derivation with no reject branch, so its runner fails loudly on
any non-accept `expect` rather than silently honoring a flip.
