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
