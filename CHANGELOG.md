# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-05-25

### Fixed

- **Mediator delete loop on `messages-received` ack.** The 0.4.0
  ack-on-delivery feature acked queued messages with the inner DIDComm
  message `id` (set by the original sender), but the Affinidi mediator's
  queue-id is `sha256(packed-JWE bytes)` (see
  `affinidi-messaging-mediator` `memory_store.rs::store_message`). Every
  ack 404'd at the mediator (`w.m.database.message.delete.not_found`),
  the message was never deleted, and it was replayed on every reconnect.
  Worse, the `messages-received` handler always returns a `status` reply
  — itself from the mediator — and the old code acked that too, which
  provoked another status, creating an infinite ~300 ms ack/status
  ping-pong over the live socket. Fix: ack with `sha256(raw frame
  bytes)`, and skip frames whose sender is the mediator (status,
  problem-report, etc. — not queued messages).

## [0.2.0] - 2026-05-21

Additive release — all existing X25519 behaviour is unchanged and remains
the default.

### Added

- **did:peer resolution** (numalgo 2, in-tree): purpose-coded key elements
  (`V`/`E`/`A`/`I`/`D`) mapped to verification relationships, and service
  elements (`S`) with the `t`/`s`/`r`/`a`/`dm` abbreviations expanded.
  Registered as the `peer` method on the default resolver.
- **P-256 (NIST secp256r1) key agreement** for authcrypt (ECDH-1PU) and
  anoncrypt (ECDH-ES). The curve is taken from the recipient's key; the JWE
  `epk` is emitted as `EC`/`P-256`. Proven byte-compatible with
  `affinidi-messaging-didcomm` via the Rust round-trip helper.
- **secp256k1 resolution** in `did:key` (signing key only).
- **EC P-256 JWK support** (`kty: "EC"`, `x`/`y`/`d`) in `jwk.js`, alongside
  the existing OKP (X25519/Ed25519) keys.
- New modules: `p256.js` (P-256 primitive) and `key-agreement.js` (curve
  dispatcher). New subpath exports: `./p256`, `./key-agreement`, `./did-peer`.

### Changed

- `ecdh-1pu`, `ecdh-es`, `pack`, `anoncrypt` and `unpack` are now
  curve-aware. They default to X25519, so existing callers are unaffected.
- The test-only Rust round-trip helper is parametrized for X25519, P-256 and
  K-256 (was X25519-only).

## [0.1.0] - 2026-05-21

### Added

- Initial release. DIDComm v2 authcrypt/anoncrypt
  (ECDH-1PU / ECDH-ES + A256KW + A256CBC-HS512) over X25519.
- `did:key` (Ed25519/X25519/P-256) and `did:webvh` resolution, with a
  pluggable method dispatcher.
- `routing/2.0/forward` envelope wrapping.
- VTA REST `/auth/` challenge-response with JWT refresh.
- ATM mediator transport: challenge-response auth, browser WebSocket with
  message-pickup 3.0 live delivery, and `sendAndWait` correlation.
- Byte-compatibility with `affinidi-messaging-didcomm` 0.13, verified by
  round-tripping through the Rust crate's `unpack` in CI.

[0.2.0]: https://github.com/OpenVTC/vti-didcomm-js/releases/tag/v0.2.0
[0.1.0]: https://github.com/OpenVTC/vti-didcomm-js/releases/tag/v0.1.0
