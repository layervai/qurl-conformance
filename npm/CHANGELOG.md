# Changelog

## [0.6.0](https://github.com/layervai/qurl-conformance/compare/npm-v0.5.0...npm-v0.6.0) (2026-07-17)


### ⚠ BREAKING CHANGES

* add registered-agent session-control vectors ([#44](https://github.com/layervai/qurl-conformance/issues/44))

### Features

* add registered-agent session-control vectors ([#44](https://github.com/layervai/qurl-conformance/issues/44)) ([3843f2b](https://github.com/layervai/qurl-conformance/commit/3843f2bc04aaac9827c922b2f19fe41bd27e3008))

## [0.5.0](https://github.com/layervai/qurl-conformance/compare/npm-v0.4.0...npm-v0.5.0) (2026-07-17)


### ⚠ BREAKING CHANGES

* **vectors:** the assignment completion golden request and deterministic packet now use an exact production-grammar lv_live_ device key.

### Bug Fixes

* **vectors:** canonicalize device key fixture ([#42](https://github.com/layervai/qurl-conformance/issues/42)) ([43eccca](https://github.com/layervai/qurl-conformance/commit/43eccca560ad890abe93900df374833485944e92))

## [0.4.0](https://github.com/layervai/qurl-conformance/compare/npm-v0.3.0...npm-v0.4.0) (2026-07-16)


### ⚠ BREAKING CHANGES

* **vectors:** add account OTP assignment vectors ([#40](https://github.com/layervai/qurl-conformance/issues/40))

### Features

* **vectors:** add account OTP assignment vectors ([#40](https://github.com/layervai/qurl-conformance/issues/40)) ([25298f6](https://github.com/layervai/qurl-conformance/commit/25298f6223b451b012f236a2004c4b5c5a872dd5))

## [0.3.0](https://github.com/layervai/qurl-conformance/compare/npm-v0.2.0...npm-v0.3.0) (2026-07-16)


### ⚠ BREAKING CHANGES

* **vectors:** align ACK vectors with live producer ([#30](https://github.com/layervai/qurl-conformance/issues/30))

### Features

* add agent assignment wire vectors ([#34](https://github.com/layervai/qurl-conformance/issues/34)) ([1c008b9](https://github.com/layervai/qurl-conformance/commit/1c008b94b41c1ff0a5facd9c6caa5cccbaa050f1))
* **vectors:** add agent API-key ID contract ([#31](https://github.com/layervai/qurl-conformance/issues/31)) ([faa4fb1](https://github.com/layervai/qurl-conformance/commit/faa4fb17939c144cd64afd04217cb91847820016))
* **vectors:** add qat1 assignment ticket conformance ([#35](https://github.com/layervai/qurl-conformance/issues/35)) ([7d519ef](https://github.com/layervai/qurl-conformance/commit/7d519efd3e3216f0ea97f10b932bbf5d4fdc943d))
* **vectors:** align ACK vectors with live producer ([#30](https://github.com/layervai/qurl-conformance/issues/30)) ([78bf85a](https://github.com/layervai/qurl-conformance/commit/78bf85a4408bd6c124f4d452b25c94919af52c1c))

## [0.2.0](https://github.com/layervai/qurl-conformance/compare/npm-v0.1.3...npm-v0.2.0) (2026-07-14)


### ⚠ BREAKING CHANGES

* **vectors:** agent knock application vectors now use schema version 2 with authenticated runId request policies.

### Features

* **vectors:** bind agent knocks to cycle run IDs ([#26](https://github.com/layervai/qurl-conformance/issues/26)) ([dce363b](https://github.com/layervai/qurl-conformance/commit/dce363b5c018639cd5cacdb321cde0daf37eb805))

## [0.1.3](https://github.com/layervai/qurl-conformance/compare/npm-v0.1.2...npm-v0.1.3) (2026-07-12)


### Features

* add NHP agent-registration golden vectors (OTP/REG/RAK) ([#20](https://github.com/layervai/qurl-conformance/issues/20)) ([9332f91](https://github.com/layervai/qurl-conformance/commit/9332f910429cac98470266fe2e671f20964d2d2b))
* **vectors:** add agent knock application contract ([#24](https://github.com/layervai/qurl-conformance/issues/24)) ([ba592ec](https://github.com/layervai/qurl-conformance/commit/ba592ecf18aa39369479d583b4c234343c675278))

## [0.1.2](https://github.com/layervai/qurl-conformance/compare/npm-v0.1.1...npm-v0.1.2) (2026-07-01)


### Bug Fixes

* **vectors:** add signature reject_class ([#14](https://github.com/layervai/qurl-conformance/issues/14)) ([cdaee56](https://github.com/layervai/qurl-conformance/commit/cdaee567c8b424a025dc0d9c1c2d1644843407ea))

## [0.1.1](https://github.com/layervai/qurl-conformance/compare/npm-v0.1.0...npm-v0.1.1) (2026-06-28)


### Features

* **packages:** npm + python wrappers embedding synced vectors + sync/check scripts ([98d7b45](https://github.com/layervai/qurl-conformance/commit/98d7b45044b57e9b0864f08ec0711864d0e264d9))
* **vectors:** add relayknock Noise-handshake golden vectors ([246d86b](https://github.com/layervai/qurl-conformance/commit/246d86b3855cc2fa1272866f4e2d67b6c8b8af33))
* **vectors:** add relayknock Noise-handshake golden vectors ([b87531c](https://github.com/layervai/qurl-conformance/commit/b87531c55b6573cb107c457336669e312f0e1966))


### Bug Fixes

* **relay:** npm export parity, consumer-neutral notes, symmetric fail-closed ([5681b61](https://github.com/layervai/qurl-conformance/commit/5681b610a7c3b96d3aacd098ef27f3e4730faa3f))
