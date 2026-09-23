# CLAUDE.md — vti-didcomm-js

The JavaScript/TypeScript DIDComm + mediator-transport library used by the
browser wallet (pnm-browser-plugin) and relay (pnm-relay) to talk to the VTA
and mediator. It is one of **three hand-maintained JS clients of the same
wire contracts** — drift between them and the Rust services is this repo's
dominant failure mode.

## Cross-service networking & integration discipline

Read the ecosystem doc set in `../design-docs/` before changing transport or
message-shape code:

- **`vti-stack-development-guide.md`** — binding rules (R-numbers below);
  paste its pre-merge checklist into PRs.
- **`vti-networking-remediation-plan.md`** — deliverable **D8** covers this
  repo (with pnm-browser-plugin and pnm-relay).
- **`vti-architectural-direction.md`** — Decisions 2 (schema-first) and 6
  (one canonical client core) are the long-term answer to this repo's drift.

Rules that bite hardest here:

- **R3.6 — verify every message type and shape against the *current* Rust
  server, not memory.** When the Rust side changes a contract, this repo is
  the consumer most likely to be forgotten; when you change one, grep the
  plugin and relay too. VTA REST auth was realigned in 0.6.1 — it had been
  sending removed legacy `affinidi.com/atm/1.0/*` types and parsing envelopes
  the VTA no longer emitted, so auth could not succeed at all. Note the
  *mediator* auth path legitimately keeps its own `atm/1.0` type; they are
  different services and it is not drift.
- **R1.6 — ack only after durable handoff.** Fixed in 0.6.2 and easy to
  regress: `_dispatchFrame` delivers first — awaiting `onMessage` if it
  returns a promise — and only then acks, because the ack makes the mediator
  delete its queued copy. In an MV3 host, worker teardown between ack and
  persistence is normal operation, so acking first loses the message forever.
  **Never move the ack back above the handoff.** Delivery is therefore
  at-least-once; the bounded `_seen` set of queue-ids keeps that safe within a
  session, and consumers de-duplicate durably across restarts.
- **R1.2 — every fetch/WebSocket operation has a timeout/AbortSignal** and
  reconnect paths use bounded exponential backoff (R1.5) — a tight reconnect
  loop re-authing every 2s hammers the mediator; a missing re-arm leaves the
  listener dead. Re-arm on *every* failure including first-connect: an
  `onClose`-driven retry cannot cover a session that never opened.
- **R4.1 — don't fork fixes.** A fix to error parsing, reconnect, or auth
  shapes here almost certainly applies to code copied into the plugin/relay;
  land it everywhere in the same change or extract the shared core.

- **A TSP frame is `-E…` *or* `--E…`, and `src/tsp-frame.js` is the only place
  that may decide.** Spec Rev 3 widened the `-E` count code to cover all
  signable content, so a message past ~12 KB is framed with the six-byte long
  count and begins `0xFB` rather than `0xF8` — in qb64, `--E` rather than `-E`.
  This transport is key-blind for TSP and classifies on that prefix alone, so
  getting it wrong drops whole messages: the frame falls through to the DIDComm
  unpacker, throws, is logged as poison, and never reaches the ack, so the
  mediator redelivers it forever while the consumer never hears. That is the
  defect 0.10.0 fixed, and it was invisible until Rev 3 existed because Rev 2's
  count covered only the envelope header and could not reach the long form.

  **This predicate exists three times** — here, in the mediator's
  `affinidi_tsp::is_tsp`, and in `@openvtc/vti-tsp-js`'s `isTsp` — which is
  R4.1's situation exactly, and deliberately not solved by sharing code: these
  are independent implementations of one wire contract and a shared helper
  would only make them agree on a shared mistake. So a change to what counts as
  a TSP frame lands in all three, in the same coordinating issue.

  **What breaks it:** testing the prefix anywhere but `isTspFrameText`; matching
  Rev 2's `-0E…` long form, which nothing can emit; or reading the framing as a
  revision signal — Rev 2 messages are short-framed and start `-E` exactly as
  they always did, and which revision a frame carries is the consumer's
  question, not this library's.

- **The mediator is also a Trust-Task counterparty, and its frames are three
  different things.** A wallet can send `messaging/*` operations to the
  mediator itself over this session. What comes back from the mediator DID:
  a **reply** (Trust Tasks envelope, threaded by `thid`) is *stored* as well as
  pushed, so it is acked like mail — `isStoredMediatorReply`; a **refusal** is
  a problem report threaded by `pthid` and sent on the socket only — never
  acked, matched by `threadOf`; a **monitor batch** is an envelope with no
  `thid`, live-only — never acked, never buffered, delivered to
  `onMediatorMessage`. Status frames remain unacked (the ping-pong below).
  **What breaks it:** acking every mediator frame (the status loop), acking
  none (every reply sits in the caller's queue and replays forever — the 0.10
  behaviour), or keying a problem report by `thid`.

## Releasing

Consumers install from npm, so **a fix merged here changes nothing for them
until it is published** — pnm-browser-plugin depends on a version range and
will keep resolving to the last published version. Check
`npm view @openvtc/vti-didcomm-js version` against `package.json` before
assuming a consumer has a fix.

- `main` carries the version bump; `npm publish` runs `prepack` →
  `build:types`, which generates the `types/` the tarball ships.
- The package publishes `src/` directly (`files: ["src","types",...]`,
  `main: src/index.js`) — consumers run the source, there is no build output.
- `npm pack --dry-run` lists exactly what would ship; use it to confirm a fix
  is actually in the tarball.
- Add the CHANGELOG entry in the same PR as the bump. Entries for 0.3.0,
  0.4.0 and 0.6.x were all written retroactively because this was skipped.
