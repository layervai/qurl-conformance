# Agent API-key ID vectors

`agent_api_key_id_vectors.json` is the public control-plane contract for the
API-key identifiers returned during agent registration. It is deliberately
separate from `agent_registration_golden.json`: that packet artifact's
synthetic `usrId: "key_conform"` is frozen NHP compatibility data, not an
example of an issued control-plane key ID.

## Contract

An issued ID is exactly 16 ASCII bytes:

```text
key_ + 12 ASCII alphanumeric characters
```

The equivalent pattern is `^key_[A-Za-z0-9]{12}$`. Consumers must not trim,
case-fold, normalize Unicode, accept `_` in the suffix, or infer a broader
grammar from another credential field.

Treat `pattern` as a language-neutral serialization of the grammar, not as a
license to use a partial-match API. Consumers must require a whole-string
match: for example, Python uses `re.fullmatch` rather than `re.match` because
Python's `$` can match immediately before a final newline. The
`reject_trailing_newline` fixture enforces this boundary across languages.

`total_length` and `pattern` intentionally repeat facts derivable from the
prefix, alphabet, and suffix length. That gives length-oriented and
regex-oriented consumers native forms; strict loaders cross-check all fields so
the convenience cannot drift into a second contract.

The same value contract applies to two response surfaces:

| `surface` | Wire field |
| --- | --- |
| `registration_info` | `key_id` |
| `completion` | `device_api_key_id` |

## Fixture roles

- `producer_cases` feed deterministic suffixes through an issuer's real ID
  constructor and compare the exact `expected_id`. A producer test must also
  validate IDs minted from its real randomness source against `contract`.
- `consumer_value_cases` feed the listed string directly through the same ID
  validator used by both response surfaces and assert `outcome`.
- `consumer_response_cases` preserve raw one-field JSON objects. They exercise
  null and non-string values, duplicate keys, trailing JSON, missing/unknown
  fields, and the ID validator. Consumers must keep `body_json` raw until it
  reaches their strict response boundary; parsing and re-serializing first
  would erase the duplicate-key and trailing-value negatives.

For an accepted response case, `expected_id` is the exact parsed result. A
rejected case has one of two stable classes:

- `invalid_id`: the field is a JSON string but violates the public ID grammar.
- `body_parse`: the response object or field type is structurally invalid.

Internal error names are not part of this artifact. Each implementation maps
these outcomes into its own typed errors while preserving fail-closed behavior.

The dependency-free Go loader in this repository is the artifact's strict
reference validator: it independently derives every expectation and preserves
raw JSON long enough to reject duplicate keys and trailing values. The npm and
Python packages carry byte-identical artifact copies and expose data accessors,
so their in-repository gates check package shape and copy parity rather than
reimplementing that parser.
Downstream producers and consumers still run every applicable case through
their real implementation, as required by the lockstep rule below.

## Lockstep rule

This artifact is not satisfied merely by copying its pattern into two local
tests. The issuing service consumes `producer_cases`; every SDK registration
parser consumes `consumer_value_cases` and the response cases for both
surfaces. CI in each repository pins one released artifact version, so a
grammar or field-shape change cannot land independently.

Schema changes require a new `schema_version` and a coordinated producer-first
release. Existing vectors change only deliberately; additions that broaden the
accepted grammar are breaking changes for fail-closed consumers.
