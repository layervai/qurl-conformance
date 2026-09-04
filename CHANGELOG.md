# Changelog

## [0.13.1](https://github.com/layervai/qurl-conformance/compare/v0.13.0...v0.13.1) (2026-09-04)


### Bug Fixes

* **ci:** assert the review origin's destination, not an exact URL ([#122](https://github.com/layervai/qurl-conformance/issues/122)) ([a86ebef](https://github.com/layervai/qurl-conformance/commit/a86ebef7d8dd48d668e16f6da68fc062fbf11983))


### Continuous Integration

* **deps:** bump age-check-actions reusable to v0.13.0 ([#120](https://github.com/layervai/qurl-conformance/issues/120)) ([b46efd4](https://github.com/layervai/qurl-conformance/commit/b46efd4c9a51b628b1ca0b87a6074e70177ee922))
* **deps:** bump remaining ops-routines-workflows shims to v0.13.0 ([#121](https://github.com/layervai/qurl-conformance/issues/121)) ([0af598d](https://github.com/layervai/qurl-conformance/commit/0af598d016be2b2bd94642252ae63132f5cf4fdb))
* drop Task from the review, keep code search ([#114](https://github.com/layervai/qurl-conformance/issues/114)) ([38605b8](https://github.com/layervai/qurl-conformance/commit/38605b84a7461656ab5c12eea3cebe04cbf4450d))
* enable code search and delegation in the PR review ([#113](https://github.com/layervai/qurl-conformance/issues/113)) ([b5c8b4b](https://github.com/layervai/qurl-conformance/commit/b5c8b4bd810965b0ecffddb7457472838fd539ad))
* move Claude PR review to Opus 5 ([#111](https://github.com/layervai/qurl-conformance/issues/111)) ([6e84366](https://github.com/layervai/qurl-conformance/commit/6e8436671adca1702daa26af6cf1986153570bc0))

## [0.13.0](https://github.com/layervai/qurl-conformance/compare/v0.12.6...v0.13.0) (2026-08-23)


### ⚠ BREAKING CHANGES

* **vectors:** define exact session retirement receipts
* **vectors:** add durable session lifecycle authority ([#101](https://github.com/layervai/qurl-conformance/issues/101))
* **vectors:** publish session-bound ACK and one-way EXT vectors ([#98](https://github.com/layervai/qurl-conformance/issues/98))
* define Connector resource NHP contract

### Features

* define Connector resource NHP contract ([daba318](https://github.com/layervai/qurl-conformance/commit/daba31877fb69562885f2aa8799f6b7e1d909c61))
* **vectors:** add durable session lifecycle authority ([#101](https://github.com/layervai/qurl-conformance/issues/101)) ([149814a](https://github.com/layervai/qurl-conformance/commit/149814a3d6316f4913b626323c760492d5cde0b9))
* **vectors:** define exact session retirement receipts ([c6c0b67](https://github.com/layervai/qurl-conformance/commit/c6c0b67637f0f81e281647ab18b5efce45d6ee64))
* **vectors:** publish session-bound ACK and one-way EXT vectors ([#98](https://github.com/layervai/qurl-conformance/issues/98)) ([7248e53](https://github.com/layervai/qurl-conformance/commit/7248e535c5e85376c4c73cf5bb7d459032dd8e35))


### Bug Fixes

* **ci:** restore credential-free Claude review origin ([#99](https://github.com/layervai/qurl-conformance/issues/99)) ([64c3e44](https://github.com/layervai/qurl-conformance/commit/64c3e44bbc2a58acf280cc7edfbc57323bdecf07))
* **vectors:** pin session producer to merged main ([9d130aa](https://github.com/layervai/qurl-conformance/commit/9d130aaf1b6bcb371a4a1efa48e0fb98c2ab4077))
* **vectors:** restore current-envelope session vectors ([#103](https://github.com/layervai/qurl-conformance/issues/103)) ([9f5d2f2](https://github.com/layervai/qurl-conformance/commit/9f5d2f2938a5c783610c31852f63f33a0117dbe5))


### Reverts

* **vectors:** restore current NHP envelope ([#102](https://github.com/layervai/qurl-conformance/issues/102)) ([c1b361c](https://github.com/layervai/qurl-conformance/commit/c1b361c040c273abc2301b33a2562e39cfb71533))

## [0.12.6](https://github.com/layervai/qurl-conformance/compare/v0.12.5...v0.12.6) (2026-08-20)


### Features

* **vectors:** add qv2 share-safe transport contract ([#94](https://github.com/layervai/qurl-conformance/issues/94)) ([d420f25](https://github.com/layervai/qurl-conformance/commit/d420f25f5417b717fe1029860e3621c03dc656b0))

## [0.12.5](https://github.com/layervai/qurl-conformance/compare/v0.12.4...v0.12.5) (2026-08-12)


### Features

* add CRID v1 derivation and validation conformance vectors ([#92](https://github.com/layervai/qurl-conformance/issues/92)) ([501bb3a](https://github.com/layervai/qurl-conformance/commit/501bb3a62923f0281c7642b516746cb2cb4d66f8))

## [0.12.4](https://github.com/layervai/qurl-conformance/compare/v0.12.3...v0.12.4) (2026-08-10)


### Bug Fixes

* **ci:** let a root-only release actually cut its tag ([#89](https://github.com/layervai/qurl-conformance/issues/89)) ([3def404](https://github.com/layervai/qurl-conformance/commit/3def404d2fc2af348031ec8efb169ec847a7f38b))

## [0.12.3](https://github.com/layervai/qurl-conformance/compare/v0.12.2...v0.12.3) (2026-08-10)


### Build System

* **go:** lower the module Go floor to 1.25.12 ([#86](https://github.com/layervai/qurl-conformance/issues/86)) ([6945bd1](https://github.com/layervai/qurl-conformance/commit/6945bd1d8cf90a93f919e1f24054e202cbcd8340))


### Continuous Integration

* make build and ci commits cut a release ([#87](https://github.com/layervai/qurl-conformance/issues/87)) ([f5ead68](https://github.com/layervai/qurl-conformance/commit/f5ead68bfdacb70f81a0758d1ae7843d37e25b86))

## [0.12.2](https://github.com/layervai/qurl-conformance/compare/v0.12.1...v0.12.2) (2026-08-04)


### Features

* **vectors:** widen the knock deny errCode vocabulary ([#84](https://github.com/layervai/qurl-conformance/issues/84)) ([0919a9d](https://github.com/layervai/qurl-conformance/commit/0919a9dda77eec3d4de994b63ffa65c1b9a2976d))

## [0.12.1](https://github.com/layervai/qurl-conformance/compare/v0.12.0...v0.12.1) (2026-08-03)


### Bug Fixes

* repin the producer revision to the merged qurl-go commit ([#82](https://github.com/layervai/qurl-conformance/issues/82)) ([eb20a94](https://github.com/layervai/qurl-conformance/commit/eb20a94a8de714f18e3082390f873e520fa1c23c))

## [0.12.0](https://github.com/layervai/qurl-conformance/compare/v0.11.0...v0.12.0) (2026-08-03)


### ⚠ BREAKING CHANGES

* these vectors describe NHP protocol 1.1 and do not match a 1.0 implementation. Consumers must adopt the header binding before pinning this release. Release this first: no runtime consumer speaks 1.1 yet, so shipping the vectors ahead of the codecs breaks nothing.

### Features

* regenerate NHP golden vectors for protocol 1.1 header binding ([#71](https://github.com/layervai/qurl-conformance/issues/71)) ([a139c35](https://github.com/layervai/qurl-conformance/commit/a139c359244587b8f639c8de8df3eb29a5522dbe))

## [0.11.0](https://github.com/layervai/qurl-conformance/compare/v0.10.0...v0.11.0) (2026-08-02)


### ⚠ BREAKING CHANGES

* **vectors:** every NHP UDP endpoint in the vectors is now port 443. Consumers pinning 62206 must move in lockstep with their servers.

### Features

* **vectors:** move NHP UDP endpoints to port 443 ([#69](https://github.com/layervai/qurl-conformance/issues/69)) ([160c66c](https://github.com/layervai/qurl-conformance/commit/160c66c03f2c44cfbf906288238e10e72e67fb1a))

## [0.10.0](https://github.com/layervai/qurl-conformance/compare/v0.9.0...v0.10.0) (2026-07-29)


### ⚠ BREAKING CHANGES

* **vectors:** freeze proof mutation control ([#67](https://github.com/layervai/qurl-conformance/issues/67))

### Features

* **vectors:** freeze proof mutation control ([#67](https://github.com/layervai/qurl-conformance/issues/67)) ([d0893ac](https://github.com/layervai/qurl-conformance/commit/d0893aca7ebccd54c339b4b5c257fe764d5ac506))

## [0.9.0](https://github.com/layervai/qurl-conformance/compare/v0.8.1...v0.9.0) (2026-07-19)


### ⚠ BREAKING CHANGES

* **vectors:** freeze UDP credential recovery contract ([#54](https://github.com/layervai/qurl-conformance/issues/54))

### Features

* **vectors:** freeze UDP credential recovery contract ([#54](https://github.com/layervai/qurl-conformance/issues/54)) ([9a9d4d0](https://github.com/layervai/qurl-conformance/commit/9a9d4d040cd8e66c9837766beb3d16cdb623fda1))

## [0.8.1](https://github.com/layervai/qurl-conformance/compare/v0.8.0...v0.8.1) (2026-07-19)


### Features

* **vectors:** freeze Hub LST cookie challenge ([#52](https://github.com/layervai/qurl-conformance/issues/52)) ([cb96ccc](https://github.com/layervai/qurl-conformance/commit/cb96ccca742d0b0512797bb89dda51e4aab0e252))

## [0.8.0](https://github.com/layervai/qurl-conformance/compare/v0.7.0...v0.8.0) (2026-07-19)


### ⚠ BREAKING CHANGES

* **vectors:** pin mode-unknown assignment response phases ([#50](https://github.com/layervai/qurl-conformance/issues/50))

### Features

* **vectors:** pin mode-unknown assignment response phases ([#50](https://github.com/layervai/qurl-conformance/issues/50)) ([4feae03](https://github.com/layervai/qurl-conformance/commit/4feae037b15a1e529a8969d8d1d9d7f48370adce))

## [0.7.0](https://github.com/layervai/qurl-conformance/compare/v0.6.1...v0.7.0) (2026-07-19)


### ⚠ BREAKING CHANGES

* **vectors:** bind Hub requests to logical nonces ([#48](https://github.com/layervai/qurl-conformance/issues/48))

### Features

* **vectors:** bind Hub requests to logical nonces ([#48](https://github.com/layervai/qurl-conformance/issues/48)) ([852b5ab](https://github.com/layervai/qurl-conformance/commit/852b5ab4b1528719ff37b1f14f89211c3433773b))

## [0.6.1](https://github.com/layervai/qurl-conformance/compare/v0.6.0...v0.6.1) (2026-07-18)


### Features

* add Connector Authority Lambda v1 vectors ([#46](https://github.com/layervai/qurl-conformance/issues/46)) ([20dd78d](https://github.com/layervai/qurl-conformance/commit/20dd78dcd9ee1ef9ebaffc3c99c8eaa4496da62b))

## [0.6.0](https://github.com/layervai/qurl-conformance/compare/v0.5.0...v0.6.0) (2026-07-17)


### ⚠ BREAKING CHANGES

* add registered-agent session-control vectors ([#44](https://github.com/layervai/qurl-conformance/issues/44))

### Features

* add registered-agent session-control vectors ([#44](https://github.com/layervai/qurl-conformance/issues/44)) ([3843f2b](https://github.com/layervai/qurl-conformance/commit/3843f2bc04aaac9827c922b2f19fe41bd27e3008))

## [0.5.0](https://github.com/layervai/qurl-conformance/compare/v0.4.0...v0.5.0) (2026-07-17)


### ⚠ BREAKING CHANGES

* **vectors:** the assignment completion golden request and deterministic packet now use an exact production-grammar lv_live_ device key.

### Bug Fixes

* **vectors:** canonicalize device key fixture ([#42](https://github.com/layervai/qurl-conformance/issues/42)) ([43eccca](https://github.com/layervai/qurl-conformance/commit/43eccca560ad890abe93900df374833485944e92))

## [0.4.0](https://github.com/layervai/qurl-conformance/compare/v0.3.0...v0.4.0) (2026-07-16)


### ⚠ BREAKING CHANGES

* **vectors:** add account OTP assignment vectors ([#40](https://github.com/layervai/qurl-conformance/issues/40))

### Features

* **vectors:** add account OTP assignment vectors ([#40](https://github.com/layervai/qurl-conformance/issues/40)) ([25298f6](https://github.com/layervai/qurl-conformance/commit/25298f6223b451b012f236a2004c4b5c5a872dd5))

## [0.3.0](https://github.com/layervai/qurl-conformance/compare/v0.2.0...v0.3.0) (2026-07-16)


### ⚠ BREAKING CHANGES

* **vectors:** align ACK vectors with live producer ([#30](https://github.com/layervai/qurl-conformance/issues/30))

### Features

* add agent assignment wire vectors ([#34](https://github.com/layervai/qurl-conformance/issues/34)) ([1c008b9](https://github.com/layervai/qurl-conformance/commit/1c008b94b41c1ff0a5facd9c6caa5cccbaa050f1))
* **vectors:** add agent API-key ID contract ([#31](https://github.com/layervai/qurl-conformance/issues/31)) ([faa4fb1](https://github.com/layervai/qurl-conformance/commit/faa4fb17939c144cd64afd04217cb91847820016))
* **vectors:** add qat1 assignment ticket conformance ([#35](https://github.com/layervai/qurl-conformance/issues/35)) ([7d519ef](https://github.com/layervai/qurl-conformance/commit/7d519efd3e3216f0ea97f10b932bbf5d4fdc943d))
* **vectors:** align ACK vectors with live producer ([#30](https://github.com/layervai/qurl-conformance/issues/30)) ([78bf85a](https://github.com/layervai/qurl-conformance/commit/78bf85a4408bd6c124f4d452b25c94919af52c1c))

## [0.2.0](https://github.com/layervai/qurl-conformance/compare/v0.1.3...v0.2.0) (2026-07-14)


### ⚠ BREAKING CHANGES

* **vectors:** agent knock application vectors now use schema version 2 with authenticated runId request policies.

### Features

* **vectors:** bind agent knocks to cycle run IDs ([#26](https://github.com/layervai/qurl-conformance/issues/26)) ([dce363b](https://github.com/layervai/qurl-conformance/commit/dce363b5c018639cd5cacdb321cde0daf37eb805))

## [0.1.3](https://github.com/layervai/qurl-conformance/compare/v0.1.2...v0.1.3) (2026-07-12)


### Features

* add NHP agent-registration golden vectors (OTP/REG/RAK) ([#20](https://github.com/layervai/qurl-conformance/issues/20)) ([9332f91](https://github.com/layervai/qurl-conformance/commit/9332f910429cac98470266fe2e671f20964d2d2b))
* **vectors:** add agent knock application contract ([#24](https://github.com/layervai/qurl-conformance/issues/24)) ([ba592ec](https://github.com/layervai/qurl-conformance/commit/ba592ecf18aa39369479d583b4c234343c675278))

## [0.1.2](https://github.com/layervai/qurl-conformance/compare/v0.1.1...v0.1.2) (2026-07-01)


### Bug Fixes

* **vectors:** add signature reject_class ([#14](https://github.com/layervai/qurl-conformance/issues/14)) ([cdaee56](https://github.com/layervai/qurl-conformance/commit/cdaee567c8b424a025dc0d9c1c2d1644843407ea))

## [0.1.1](https://github.com/layervai/qurl-conformance/compare/v0.1.0...v0.1.1) (2026-06-28)


### Features

* **vectors:** add relayknock Noise-handshake golden vectors ([246d86b](https://github.com/layervai/qurl-conformance/commit/246d86b3855cc2fa1272866f4e2d67b6c8b8af33))
* **vectors:** add relayknock Noise-handshake golden vectors ([b87531c](https://github.com/layervai/qurl-conformance/commit/b87531c55b6573cb107c457336669e312f0e1966))


### Bug Fixes

* **relay:** npm export parity, consumer-neutral notes, symmetric fail-closed ([5681b61](https://github.com/layervai/qurl-conformance/commit/5681b610a7c3b96d3aacd098ef27f3e4730faa3f))
