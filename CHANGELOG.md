# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-07-19

### Added

- **`beforeAck` hook on `MediatorSession` — persist before ack (R1.6).**
  The delivery ack tells the mediator to delete its queued copy, so it is the
  point of no return: after it, the consumer holds the only copy of the
  message. Until now the ack fired *before* `onMessage` ran, so a consumer
  that died between the two lost the message permanently — the mediator had
  dropped it, and nothing else had stored it.

  `beforeAck(message, { thid, queueId })` is awaited **before** the ack is
  sent, while the mediator's copy still exists, so a consumer can durably
  store the message first. If the hook rejects the ack is **suppressed** and
  the mediator redelivers on the next connection: duplicate delivery is
  something consumers already de-duplicate, whereas silent loss is not
  recoverable at all. The failure is reported via `onError` rather than
  swallowed, and the message is still delivered in-memory so a user can act
  on it now.

  Purely additive — without the hook the ack behaviour is unchanged.

## [0.5.0] - 2026-06-01

### Fixed

- **ECDH-1PU Concat KDF: length-prefix the content-encryption tag**
  (interop; tracked as #322 in affinidi-messaging-didcomm). `cc_tag` was
  fed into the Concat KDF as SuppPrivInfo **raw**, without the 32-bit
  big-endian length prefix every other OtherInfo field carries. This
  matched the then-buggy `affinidi-messaging-didcomm` (the
  `roundtrip-rust` vectors were generated against it), so JS↔Rust
  authcrypt worked *because both were wrong* — but neither interoperated
  with credo-ts / didcomm-python. The tag is now length-prefixed per the
  ECDH-1PU draft (Appendix B), making `ECDH-1PU+A256KW` authcrypt
  spec-correct. Affects X25519 and P-256; anoncrypt (ECDH-ES) was never
  affected.

### Added

- **Dual-KEK decrypt fallback.** `unpack` derives the spec-correct KEK
  first and, if AES-KW unwrap fails, retries with the legacy (pre-0.5,
  unprefixed-tag) KEK — so an upgraded recipient still reads authcrypt
  from a not-yet-upgraded peer during migration. The result now carries
  `legacyKekUsed` (true when the legacy KEK was used) as a migration
  signal.

### Migration

This is a **breaking authcrypt wire change**: a 0.5 sender's authcrypt
cannot be decrypted by an un-upgraded ≤ 0.4.x recipient. **Upgrade
recipients before senders** — the dual-KEK fallback makes upgraded
recipients accept both old and new senders. Pair with
`affinidi-messaging-didcomm` ≥ 0.14 (the matching Rust fix). The
`roundtrip-rust` interop vectors should be regenerated against a Rust
helper built from didcomm ≥ 0.14.

## [0.4.2] - 2026-05-30

### Added

- **Actionable diagnostics for failed mediator WebSocket upgrades.** A
  failed upgrade previously collapsed into one opaque "WebSocket failed
  to open". The browser `error` event carries no detail, so the handler
  now settles on the `close` event and maps the RFC 6455 close code to a
  cause — `1008` → mediator auth/ACL reject (distinct from the target
  VTA's ACL), `1006` → refused upgrade / TLS / a proxy not passing the
  `Upgrade` header (a CORS-blocked cross-origin upgrade also surfaces
  here), `1015` → TLS failure. The bearer token's `exp` is decoded to
  flag a born-expired / clock-skewed token, and the error carries
  structured `code` / `reason` / `endpoint` fields. Adds a
  `connectTimeoutMs` (default 15s) so a silently-dropped upgrade fails
  fast instead of hanging.
- **Per-frame inbound resilience.** A single bad inbound message
  (undecryptable, malformed, unknown sender, or a throw in dispatch) is
  now logged via a new `onError` hook (default `console.warn`) and
  skipped, so the session never gets stuck on one poison message and
  keeps delivering the rest of the queue. Previously such frames were
  silently dropped.

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
