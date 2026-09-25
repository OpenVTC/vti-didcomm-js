# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Tests

- The Rust round-trip helper (`tools/roundtrip-helper`) is on
  `affinidi-messaging-didcomm` 0.15.9 and unpacks through `unpack_bound`,
  binding the sender key to a key id (an optional `sender_kid` in the request,
  defaulting to the JWE's `skid`). Its response no longer carries
  `legacy_kek_used`.

## [0.12.0] - 2026-09-25

### Changed (breaking)

- **An authcrypt message's `from` must be the DID of its `skid`.** `unpack`
  already required `apu == skid`, which pins the sender *key*; nothing tied
  that key to the `from` the plaintext carries, and consumers read `from`.
  `unpack` now throws `SenderMismatchError` (`code: "E_SENDER_MISMATCH"`) for
  an authcrypt message whose `from` is missing, is a DID URL, or names any DID
  other than the `skid`'s. DIDComm v2 requires both properties of a
  well-formed authcrypt message, so a conforming sender is unaffected. Through
  `MediatorSession` such a frame is reported to `onError` and not acked, like
  any other frame that fails to unpack.
- **`unpack` returns `senderDid`** (the DID of `skid`) beside `senderKid`, and
  for **anoncrypt both are `null`** (previously `senderKid` was `undefined`).
  `senderDid` is the identity to authorise on; `message.from` is documented as
  sender-asserted plaintext.
- **`MediatorSession` passes the verified sender to consumers.**
  `onMessage` and `onMediatorMessage` receive a third argument, a frozen
  `VerifiedSender` `{ did, kid }`. **`waitFor` now resolves
  `{ message, sender }`** instead of the bare message, and takes an optional
  third argument `{ from }` — a DID or list of DIDs — restricting which
  authenticated sender may answer the thread; a message on the thread from
  anyone else is left for other waiters and the listener. `unpackInbound`
  returns `senderDid` too.
- `VtaMediatorClient.sendAndWait` only accepts a reply authenticated as the
  VTA it addressed. Its return value (the message) is unchanged.
- **The sender key is selected by the exact `skid`.** `unpackInbound` used to
  pick a key by the `skid`'s DID alone, so the `senderKid` it reported was the
  header's claim beside a key chosen another way. `senderKeys` entries (a
  `{ kid, publicJwk }` or a list of them) now match only on `kid === skid`
  (a relative `#fragment` resolves against the DID; an entry with no `kid`
  matches nothing), and `resolveSender` is called as `(did, skid)` and held
  to the same rule. `connectVtaViaMediator` resolves the named key with the new
  `resolveX25519KeyAgreementKey(did, kid)`, which requires it to be listed
  under `keyAgreement`. `MediatorSession` seeds the mediator's key with its
  `kid`.
- **A frame that decrypts and is then refused for good is acked and dropped.**
  An authcrypt frame failing the `from` binding (`E_SENDER_MISMATCH`), or an
  anoncrypt frame that carries a `skid` (`E_UNAUTHENTICATED_FRAME`, new), is
  reported to `onError` ("refused and dropped") and acked, so the mediator
  stops redelivering it and it does not occupy the queue. Frames that fail
  to unpack for any other reason — which may be transient — are still left
  queued.

### Added

- `SenderMismatchError`, `E_SENDER_MISMATCH`, `E_UNAUTHENTICATED_FRAME`,
  `didOfKid` and `resolveX25519KeyAgreementKey` exports; the `VerifiedSender`
  and `InboundMessage` types.

### Migration

- `const m = await session.waitFor(thid, ms)` →
  `const { message: m, sender } = await session.waitFor(thid, ms, { from: expectedDid })`.
- Authorise on the listener's `sender.did` (or `unpack`'s `senderDid`), not
  on `message.from`.
- Authcrypt fixtures must carry `from` equal to the sender key's DID.
- Give every `senderKeys` entry its full key id:
  `senderKeys.set(did, { kid, publicJwk })`, and have a `resolveSender` take
  `(did, skid)` and return the key whose id is `skid`.

## [0.11.0] - 2026-09-23

### Added

- **The mediator as a Trust-Task counterparty.** An Affinidi mediator serves
  its `messaging/*` operations surface (statistics, queues, accounts, the
  traffic monitor) as Trust Tasks addressed to *itself*, and a wallet can send
  them over the mediator session it already holds. Three kinds of frame come
  back from the mediator on that socket, and 0.10 handled none of them right:

  - **A reply is now acked.** The mediator stores its reply to a Trust Task in
    the caller's queue *and* pushes it live; the Rust SDK deletes it on
    receipt. This transport never acked a frame whose sender is the mediator
    (to avoid the status ping-pong), so every reply stayed in the caller's
    receive queue — the queue carrying its mail — and replayed on every
    reconnect. A mediator frame of the Trust Tasks envelope type that is
    threaded to a request (`isStoredMediatorReply`) is now acked with the same
    `sha256(frame)` queue-id as any other. Status and problem-report frames
    are still never acked.
  - **A refusal reaches its waiter.** A problem report names the request it
    refuses in `pthid`, not `thid`, so `waitFor` never matched it and a
    `permissionDenied` surfaced as a timeout. `threadOf` keys a problem report
    by its `pthid`. (The mediator threads every refusal since
    affinidi-messaging-mediator 0.28.26.)
  - **`onMediatorMessage`**, a new `MediatorSession` option: an unclaimed
    frame the mediator itself sent — a `messaging/monitor/event` batch, a
    reply that outlived its waiter — goes here instead of to `onMessage`, so a
    consumer that persists every `onMessage` delivery before the ack (R1.6)
    does not write traffic telemetry to storage once a second. Unthreaded
    mediator frames are also no longer buffered for a late waiter, since none
    can want one. Without the option, behaviour is unchanged.
- `threadOf`, `isStoredMediatorReply` and `TRUST_TASK_ENVELOPE_TYPE` are
  exported.

## [0.10.1] - 2026-09-22

### Security

- **Single-label hosts are refused by the endpoint / `did:webvh` net-guard.**
  `isBlockedName` blocked `localhost` and the `*.localhost` / `*.local` /
  `*.internal` / `*.home.arpa` suffixes, but not a bare single-label host
  (`intranet`, `metadata`, `router`) — which is never a public FQDN (the
  platform's search list resolves it) or is a decimal/hex IP spelling the
  dotted-quad check misses. A `did:webvh` (or an advertised endpoint) with such
  a host on a DIDComm resolve path was therefore dialed — a blind-SSRF gap the
  browser wallet's own `did:webvh` guard already closed but this library did
  not. Now refused with `reason: "private_name"`. (SEC #15.)

- **CI actions are pinned to commit SHAs** (`# vX.Y.Z` comments record the
  version each SHA was), the workflow token is `permissions: contents: read`,
  and `actions/checkout` runs with `persist-credentials: false` so the token
  is not left in `.git/config` for later steps to read. A tag is mutable, so
  `@v6` meant "whatever that tag points at when the job runs".
- **`.github/dependabot.yml`** watches `github-actions` and `npm` weekly, with
  a 7-day `cooldown` so a freshly published version is not picked up the day
  it lands.

The net-guard fix above is a shipped-package change, so this release bumps to
**0.10.1** (the CI/Dependabot entries ride along). Consumers
(pnm-browser-plugin) pick it up once published and their range resolves it.

## [0.10.0] - 2026-09-15

### Fixed

- **A long-framed TSP message was routed to the DIDComm unpacker and lost.**
  The inbound demux classified TSP by `text.startsWith("-E")`, which is the
  qb64 spelling of the *short* `-E` count code. Spec Rev 3 widened that count
  to cover all signable content — the ciphertext included — so any message past
  4095 quadlets (~12 KB) is framed with the six-byte long count code instead
  and its text starts `--E`. `"--E…".startsWith("-E")` is false.

  The failure was silent in the worst direction. A TSP frame handed to the
  DIDComm unpacker throws, is logged as a poison frame, and — because the throw
  returns before `_dispatchTspFrame` — is **never acked**, so the mediator
  redelivers it on every reconnect forever while the TSP consumer that wanted
  it never hears. Nothing could have caught this before Rev 3 existed: Rev 2's
  `-E` count covered only the envelope header, a couple of dozen quadlets
  whatever the message size, so it could not produce the frame.

  The mediator's own ingress classifier (`affinidi_tsp::is_tsp`) and the
  wallet's TSP codec (`@openvtc/vti-tsp-js`'s `isTsp`) were fixed for the same
  reason on their own branches. All three have to accept both framings, or a
  large message is dropped at whichever one lags.

### Added

- **`src/tsp-frame.js`** — `isTspFrameText` (qb64, what the demux now calls),
  `isTspFrameBytes` (qb2, the binary-domain twin), and the two magic bytes
  `0xF8` / `0xFB`. Exported from the barrel and as the `./tsp-frame` subpath.

  The predicate was one inline `startsWith` before. It is a module now because
  the rule it encodes is not obvious from the expression, is shared with two
  implementations in other repositories, and has one deliberate exclusion worth
  writing down: Rev 2's long form (`-0E…`, from a superseded draft of the CESR
  v2 tables) is **not** matched, because nothing can emit it — reaching a long
  count under Rev 2's header-only semantics would take ~12 KB of VIDs in one
  envelope — and matching it would route to a TSP consumer a frame no TSP
  implementation produces.

  Reading Rev 2 is unaffected: Rev 2 messages are short-framed and start `-E`
  exactly as they always did. The framing question and the revision question
  are independent, and this library answers only the first — it is key-blind
  for TSP and hands the bytes to a consumer that decides the rest.

## [0.9.1] - 2026-09-12

### Security

- **The DID-resolution cache is bounded.** `resolver.js` expired entries on a
  TTL but had no size limit, and a client resolves DIDs it did not choose — an
  inbound frame's `skid` names its own sender — so whoever can route frames to
  a client decided how much it cached. Two changes bound it:
  - `createResolver(overrides, { maxEntries })`, default **500**, evicting the
    least recently used entry first (a cache hit re-inserts, so Map insertion
    order is the LRU order). Expired entries are dropped first.
  - **`did:key` and `did:peer` are no longer cached at all.** They resolve from
    the identifier itself with no network I/O, so caching them saved nothing,
    and they are free and unlimited to mint — the flooding vector.

### Added

- `resolver.size()` and `didCacheSize()` report the number of cached
  resolutions, and `DEFAULT_DID_CACHE_MAX_ENTRIES` is exported.

### Changed

- A repeat `did:key` / `did:peer` resolution now re-runs its (offline) handler
  instead of being served from cache. Nothing observable changes except that a
  rotated document is never stale for these methods.

## [0.9.0] - 2026-09-12

**Behaviour change:** `did:webvh` resolution now refuses a non-public host,
and `resolveLog` no longer fetches a witness file. See *Migration*.

### Security

- **did:webvh resolution checks the host before fetching the log.** A webvh
  identifier names the host its `did.jsonl` is fetched from, and identifiers
  are not all caller-chosen: `unpackInbound` resolves an inbound frame's
  `skid` before the frame is authenticated, so any party that can route a
  frame through the mediator could make a client GET a host of its choosing.
  `didwebvh-ts` fetched through the global `fetch` with no host check and no
  way to inject one, so the SDK now does the network I/O itself:
  - the log URL is computed here, checked with `net-guard` (`https:` on a
    public host by default) and fetched through `guardedFetch`, so a redirect
    is refused as well;
  - `did-witness.json` is fetched the same way when the log declares
    witnesses, and `witnessProofs` is always passed to `didwebvh-ts` so its
    own unchecked witness fetch never runs;
  - every nested `did:webvh` named in a log entry's or witness file's
    `proof[].verificationMethod` has its host checked **before** the log is
    handed over, because `didwebvh-ts` resolves those itself and that fetch
    cannot be intercepted;
  - each request has a timeout (`timeoutMs`, default 10 s).
- **The plaintext downgrade is exact-match now.** `didwebvh-ts` picks
  `http://` whenever an identifier merely *contains* `localhost`, so
  `did:webvh:<scid>:localhost.attacker.example` was fetched in the clear.
  Only an exact `localhost` host downgrades, and only when the policy admits
  private hosts. A did:webvh host containing `localhost` anywhere is refused
  by default, since upstream would still fetch such a host over plaintext.
- **`netPolicy` reaches DID resolution.** `resolve(did, { netPolicy })` passes
  it through `resolver.js` to the method handler, and
  `connectVtaViaMediator`'s inbound `resolveSender` — the remotely reachable
  path — resolves under the policy the caller gave it.

### Added

- `didWebvh.webvhLogUrl(did, policy)`: the `did.jsonl` URL an identifier
  points at, with its host vetted. Exported so the derivation is testable
  without a network.
- `didWebvh.resolve` options: `netPolicy`, `fetch`, `timeoutMs`.
  `didWebvh.resolveLog` options: `netPolicy`, `witnessProofs`, `scid`.
- `resolveX25519KeyAgreement(did, { netPolicy })`.

### Changed

- `didWebvh.resolveLog` no longer resolves a log that declares witnesses
  unless `witnessProofs` is supplied: it does no I/O, and upstream would
  otherwise fetch `did-witness.json` itself, unchecked.
- `didWebvh.resolve` binds the log to the identifier's SCID (as the upstream
  `resolveDID` did). A log whose SCID does not match is rejected.
- A did:webvh identifier with an IPv6-literal-looking host (more than one
  colon) is refused rather than guessed at.

### Migration

- **Production** webvh DIDs on public `https:` hosts: no change.
- **A local webvh server** (`did:webvh:<scid>:localhost%3A8000`): pass
  `{ netPolicy: { allowInsecure: true, allowPrivate: true } }` to
  `resolve(did, options)`, `didWebvh.resolve` or `createResolver`-backed
  resolution. `allowPrivate` alone keeps the `https:` requirement.
- **Handling refusals:** as elsewhere, test `err.code ===
  "E_BLOCKED_ENDPOINT"`. `err.reason` is `private_name` for a `localhost`
  host and `private_address` for an IP literal.
- **`resolveLog` callers** whose logs declare witnesses must now pass
  `witnessProofs` (or call `resolve(did)`).
- **An injected `fetch`** for webvh resolution must honour
  `redirect: "manual"`.
- Upstream issues, both referenced from `did-webvh.js`: an injectable `fetch`
  covering all three of `didwebvh-ts`'s egress points
  (<https://github.com/decentralized-identity/didwebvh-ts/issues/158>) and the
  substring-`localhost` plaintext downgrade
  (<https://github.com/decentralized-identity/didwebvh-ts/issues/185>). Once
  those ship, the nested-verification-method pre-scan and the local URL
  derivation can go.

## [0.8.0] - 2026-09-11

**Behaviour change for local development:** `allowInsecure: true` no longer
admits loopback or private hosts. See *Migration* below.

### Security

- **Endpoints from a mediator DID document are checked before they are
  dialed.** `parseMediatorEndpoints` (and therefore `resolveMediator`,
  `authenticateToMediator` and `connectVtaViaMediator`) checked only the scheme
  of the REST, auth and WebSocket endpoints a mediator's DID document
  advertises; the host was used as given. Each endpoint now passes the new
  egress guard: no userinfo; no `localhost`, `*.localhost`, `*.local`,
  `*.internal` or `*.home.arpa`; no loopback, private, link-local, CGNAT,
  documentation, multicast or reserved IP literal, including the
  IPv4-mapped, IPv4-compatible, NAT64 and 6to4 forms of those; and, when the
  caller supplies one, a host allow-list. The document is rejected if any
  endpoint fails.
- **No auth request follows a redirect.** Mediator auth and VTA REST auth send
  `redirect: "manual"` and reject a 3xx (Node) or `opaqueredirect` (browser)
  response, so an allowed endpoint cannot pass the request on to another host.
  A caller-supplied `fetch` is wrapped the same way.
- **`MediatorSession` checks `mediator.wsEndpoint`** (`wss:` by default) when
  constructed and again before each socket open, so a hand-built `mediator`
  object is held to the same policy.
- **VTA REST `baseUrl` is checked** by `authenticate` / `refresh` before any
  request: `https:` on a public host by default.
- **Response bodies are no longer copied into error messages.** Mediator auth
  and VTA REST auth errors for a non-2xx, non-JSON or incomplete response put
  the body on `err.body` and the HTTP status on `err.status` instead.

### Added

- **`@openvtc/vti-didcomm-js/net-guard`**: a dependency-free egress guard for
  browsers, MV3 extensions and Node. Exports `assertSafeEndpoint(url, policy)`,
  `guardedFetch(fetchImpl, policy)`, `isBlockedIp(ip)` and
  `BlockedEndpointError` (stable `code: "E_BLOCKED_ENDPOINT"`, plus `reason`,
  `url`, `host` and `label`). Also available from the package root as the
  `netGuard` namespace, with `BlockedEndpointError` and `BLOCKED_ENDPOINT` as
  named exports.
- **`@openvtc/vti-didcomm-js/net-guard/node`**: `guardedLookup(policy)`, a
  `dns.lookup` replacement for `http(s).request`, `https.Agent` or undici's
  `Agent({ connect: { lookup } })`. It refuses a hostname if any resolved
  address is non-public and connects only to the addresses it checked. It is a
  separate subpath, not re-exported from the root, so browser bundles never
  import `node:dns`.
- **`netPolicy: { allowInsecure, allowPrivate, allowHosts }`** on
  `authenticateToMediator`, `resolveMediator`, `parseMediatorEndpoints`,
  `MediatorSession`, `connectVtaViaMediator`, and VTA REST `authenticate` /
  `refresh`.

### Changed

- `allowInsecure` now controls the scheme only. The top-level `allowInsecure`
  option of `authenticateToMediator`, `resolveMediator` and
  `parseMediatorEndpoints` is kept as a **deprecated** alias for
  `netPolicy.allowInsecure`; when both are given, `netPolicy` wins.
- `MediatorSession` refuses a `ws:` endpoint unless `netPolicy.allowInsecure`
  is set. It previously accepted any endpoint.
- VTA REST `authenticate` / `refresh` refuse an `http:` `baseUrl` unless
  `netPolicy.allowInsecure` is set. They previously accepted one.
- HTTP error messages from mediator and VTA REST auth now read
  `<module>: <status> from <url>`, without the status text or body.

### Migration

- **Production** (https/wss on public hosts): no change is required. Passing
  `netPolicy.allowHosts` with the mediator and VTA hosts you expect is
  recommended. In a browser or extension it is the only control that also
  covers a public name resolving to a private address.
- **Local development** against `http://localhost`, `127.0.0.1`, a LAN address
  or a `*.local` name: replace `allowInsecure: true` with
  `netPolicy: { allowInsecure: true, allowPrivate: true }`. Pass the same
  `netPolicy` to `MediatorSession` if you construct it yourself;
  `connectVtaViaMediator` forwards it for you.
- **Handling refusals:** test `err.code === "E_BLOCKED_ENDPOINT"` (or
  `err instanceof BlockedEndpointError`). `err.reason` is one of
  `invalid_url`, `scheme`, `userinfo`, `private_address`, `private_name`,
  `not_allowlisted` or `redirect`.
- **Response details:** read `err.status` and `err.body` rather than parsing
  the error message.
- A custom `fetch` must honour `redirect: "manual"`.

### Fixed

- **Round-trip Rust helper realigned to `affinidi-messaging-didcomm` 0.15
  (test tooling; unblocks CI).** The `roundtrip-rust` interop vectors — the
  JS-pack → Rust-unpack wire-compatibility check — had been failing in CI since
  the 0.5.0 ECDH-1PU cc_tag length-prefix fix (#322): JS pack became
  spec-correct while `tools/roundtrip-helper` still pinned the pre-fix
  `affinidi-messaging-didcomm 0.13`, whose legacy (unprefixed) Concat-KDF KEK
  could no longer unwrap JS's authcrypt (`key unwrap integrity check failed`).
  The helper's 0.13-vs-JS-0.5.0 mismatch — not any wallet code — was the red.
  Bumped the helper to 0.15 (matching the VTA + mediator) and moved the
  key-agreement imports to their new home
  (`affinidi_crypto::jose::key_agreement`); the vectors pass again, so JS↔Rust
  authcrypt is a true compatibility check once more. No shipped-package change
  (helper is `publish = false`, test-only), hence no version bump.

## [0.7.0] - 2026-08-29

### Fixed

- **Inbound TSP frames are now acked, and the consumer is awaited first
  (R1.6).** The single-socket TSP demux added in 0.6.0 routed a `-E` frame to
  `onTspFrame` and returned — before `_dispatchFrame`, which is what acks. But
  the mediator does not treat TSP specially: `handle_inbound_tsp` stores a
  Direct message "reusing the protocol-neutral store path that DIDComm direct
  delivery uses", and live delivery fetches with `DoNotDelete` because
  "redelivery is a notification re-cover, not an ack". TSP obeys the same
  delete-to-ack contract as DIDComm, and nothing was ever deleting.

  Every TSP message a client received therefore stayed queued at the mediator
  and was redelivered on every reconnect, indefinitely. Request/reply masked it
  completely: the consumer's waiter took the first delivery and discarded each
  redelivery as a straggler with no outstanding request. The symptoms are a
  monotonically growing mediator inbox and reconnect traffic that scales with
  everything the client has ever received — neither of which surfaces as an
  error anywhere.

  `_dispatchTspFrame` now applies the ordering `_dispatchFrame` applies to
  DIDComm — hand off, **await**, then ack — with the same `sha256(text)`
  queue-id, which is correct unchanged because the mediator stores the qb64
  text form that it delivers. The bounded `_seen` set now covers TSP too, so a
  redelivery is re-acked without being dispatched twice.

  Two deliberate differences from the DIDComm path, both documented at the
  method: there is no `isQueued` sender check (the mediator speaks DIDComm JSON
  to us and never emits a `-E` frame of its own, and this transport is key-blind
  for TSP regardless), and a **throwing consumer withholds the ack**, so the
  message is redelivered rather than deleted after a failed persist.

### Changed

- **`onTspFrame` may return a promise, and is awaited before the ack.** A
  synchronous handler is unaffected. A handler that persists asynchronously —
  what R1.6 requires of an MV3 host — now completes before the mediator is told
  to delete its copy. A client constructed without `onTspFrame` no longer acks
  TSP frames at all: nothing has handled them, so they stay queued.

## [0.6.2] - 2026-07-16

### Fixed

- **`mediator-transport.js` acks inbound messages only AFTER handing them off
  (D8-F3).** `_dispatchFrame` sent the message-pickup 3.0 `messages-received`
  ack — which makes the mediator delete its queued copy — *before* delivering
  the message to a `waitFor` waiter or the `onMessage` listener. In an MV3 host,
  a worker/offscreen-doc teardown between the ack and the consumer persisting the
  message dropped it permanently (the mediator had already deleted it); a
  consent/confirm request lost there is gone forever. Now the transport:
  - **hands off first, then acks.** `onMessage` may return a promise, which the
    transport awaits before acking — so a listener that persists durably can do
    so before the mediator is told to drop its copy;
  - **dedups at-least-once redelivery.** An un-acked message is redelivered on
    reconnect; a bounded in-memory set of handled mediator queue-ids
    (`sha256(packed frame)`) re-acks a duplicate without re-dispatching it, so a
    lost/racing ack can't double-fire the handler within a session. Durable
    cross-restart dedup remains the consumer's responsibility, and `onMessage`
    is now documented as at-least-once.

  Mediator-originated frames (status, problem-report) are still neither acked
  nor deduped, preserving the anti-ack-loop filter.

## [0.6.1] - 2026-07-16

### Fixed

- **REST auth (`vta-rest-auth.js`) realigned to the current VTA wire
  contract (D8-F2).** The library sent the removed legacy DIDComm message
  types `https://affinidi.com/atm/1.0/authenticate[/refresh]` (the VTA now
  rejects them with "unexpected message type") and parsed response envelopes
  the VTA stopped emitting months ago (`{ sessionId, data: { challenge } }`
  and `{ data: { accessToken, … } }`) — so REST authentication via this
  library could not succeed against a current VTA at all. Now:
  - sends the canonical `https://trusttasks.org/spec/auth/authenticate/0.1`
    and `https://trusttasks.org/spec/auth/refresh/0.1` types;
  - parses the flat `ChallengeResponse` (`{ challenge, sessionId, expiresAt }`,
    no `data` envelope);
  - parses the canonical `AuthenticateResponse` (`{ session, tokens }`), where
    `tokens` carries OAuth-style **relative** lifetimes (`expiresIn`,
    `refreshExpiresIn`); the library converts these to absolute Unix-second
    `accessExpiresAt` / `refreshExpiresAt` against `session.issuedAt`, so the
    public `authenticate()` / `refresh()` return contract is unchanged.

  The challenge request still sends `{ did }` (accepted by the current VTA as a
  one-release deserialize alias of the canonical `subject`). No public API
  change; the `package-lock.json` `version` field (long stale at 0.2.0) is also
  corrected.

## [0.6.2] - 2026-07-16

### Fixed

- **Hand inbound messages to the consumer BEFORE acking the mediator (R1.6).**
  `_dispatchFrame` sent the message-pickup 3.0 `messages-received` ack — which
  makes the mediator delete its queued copy — *before* delivering the message
  to a `waitFor` waiter or the `onMessage` listener. In an MV3 host, a
  worker/offscreen teardown between the ack and the consumer persisting the
  message drops it forever: the mediator has already deleted it and will not
  replay. A consent/confirm request lost there is unrecoverable.

  Delivery is now at-least-once: hand off first (awaiting `onMessage` if it
  returns a promise, so a listener that persists asynchronously finishes
  before the mediator is told to drop its copy), then ack. A bounded
  in-memory set of handled mediator queue-ids re-acks a redelivered duplicate
  without re-dispatching it, so a lost or racing ack cannot double-fire the
  handler within a session.

  **Consumer note:** `onMessage` may now return a promise the transport
  awaits, and must tolerate seeing the same message twice across a reconnect —
  durable cross-restart de-duplication remains the consumer's responsibility.

## [0.6.1] - 2026-07-16

### Fixed

- **REST auth realigned to the current VTA wire contract (R3.6).**
  `vta-rest-auth.js` sent the removed legacy DIDComm message types
  (`https://affinidi.com/atm/1.0/authenticate[/refresh]`) and parsed response
  envelopes the VTA stopped emitting months ago (`{sessionId, data:{challenge}}`
  and `{data:{accessToken,...}}`), so REST auth through this library could not
  succeed against a current VTA at all. Now uses
  `https://trusttasks.org/spec/auth/authenticate/0.1` and the current flat
  response shapes. (Mediator auth is a separate service and legitimately keeps
  its own message type.)

## [0.6.0] - 2026-07-15

### Added

- **TSP frame multiplexing over the mediator socket.** The mediator can
  interleave TSP frames (raw CESR qb2, first byte `0xF8`, delivered as
  base64url text) onto the same WebSocket as DIDComm traffic. A new
  `onTspFrame` handler receives those bytes; without one they are dropped
  rather than being fed to the DIDComm unpacker, which cannot read them.

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
