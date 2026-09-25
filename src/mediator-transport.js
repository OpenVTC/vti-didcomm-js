// Mediator WebSocket transport — message-pickup 3.0 live delivery.
//
// Flow once authenticated (see `mediator-auth.js`):
//   1. Open a browser WebSocket to the mediator's wss endpoint, with
//      the mediator JWT carried as a subprotocol: `["bearer.<jwt>"]`
//      (browsers can't set an Authorization header on a WebSocket;
//      the mediator accepts the bearer subprotocol as an additive,
//      backwards-compatible auth channel alongside the header path
//      that Rust clients use).
//   2. Send a `messagepickup/3.0/live-delivery-change` ({live_delivery:
//      true}, with a top-level `return_route: "all"`), authcrypt'd to
//      the mediator. This tells the mediator to push messages destined
//      for our DID over this socket as they arrive.
//   3. Send the `routing/2.0/forward` (authcrypt'd to the mediator,
//      `next` = VTA) as a WS text frame. The mediator unwraps it,
//      relays the inner JWE to the VTA, and the VTA's response comes
//      back addressed to us.
//   4. The mediator stores the (already-unwrapped) inner response JWE
//      and pushes it over the socket as a raw text frame. We unpack it
//      directly — the mediator does NOT re-wrap it in a forward on
//      live delivery.
//
// Inbound dispatch: frames can come from the VTA (the response,
// authcrypt'd VTA→client) OR the mediator (status / problem-report,
// authcrypt'd mediator→client). We read `skid` from each frame's
// protected header and pick the matching sender public key from a
// seeded map (mediator + VTA), falling back to DID resolution.

import { unpack, didOfKid, E_SENDER_MISMATCH } from "./unpack.js";
import { pack } from "./pack.js";
import { assertSafeEndpoint } from "./net-guard.js";
import * as b64u from "./base64url.js";
import { isTspFrameText } from "./tsp-frame.js";
import * as jwk from "./jwk.js";

const LIVE_DELIVERY_CHANGE_TYPE = "https://didcomm.org/messagepickup/3.0/live-delivery-change";
const MESSAGES_RECEIVED_TYPE = "https://didcomm.org/messagepickup/3.0/messages-received";
// The Trust Tasks DIDComm binding: a message of this type carries a whole
// Trust Task document as its body. The mediator answers Trust Tasks addressed
// to it (its `messaging/*` operations surface) in this envelope.
const TRUST_TASK_ENVELOPE_TYPE = "https://trusttasks.org/binding/didcomm/0.1/envelope";
const PROBLEM_REPORT_TYPE = "https://didcomm.org/report-problem/2.0/problem-report";

// A second, application subprotocol offered alongside the bearer one.
//
// Why it's required: the mediator authenticates via the `bearer.<jwt>`
// subprotocol, but when ONLY that entry is offered it selects no
// subprotocol and the 101 response carries no `Sec-WebSocket-Protocol`
// header. A spec-strict WHATWG client (every browser, and Node's
// undici) treats "I offered a subprotocol, the server agreed to none"
// as a handshake failure and closes with code 1006. Offering a second,
// non-bearer entry gives the mediator something to echo back (it
// passes non-bearer entries through verbatim), so the client sees a
// selected protocol and the upgrade completes.
//
// It must be a valid RFC 6455 subprotocol token — NO separators. The
// canonical `didcomm/v2` is rejected at WebSocket construction because
// `/` isn't a token char, so we use a separator-free value. The
// mediator never acts on it and the VTA never sees it; it exists only
// to satisfy the subprotocol-echo handshake.
const WS_APP_SUBPROTOCOL = "didcomm";

// Human-readable hint for an RFC 6455 close code, oriented at the
// failure modes a mediator client actually hits. The browser hides the
// HTTP status of a rejected upgrade, so the close code is the only
// machine signal distinguishing "auth/ACL reject" from "network/TLS"
// from "proxy misconfig".
function describeCloseCode(code) {
  switch (code) {
    case undefined:
    case null:
      return "no close code (the implementation passed no close event)";
    case 1000:
      return "normal closure";
    case 1001:
      return "endpoint going away";
    case 1002:
      return "protocol error — likely a subprotocol mismatch (the mediator must echo a Sec-WebSocket-Protocol)";
    case 1005:
      return "no status received";
    case 1006:
      return "abnormal closure — no close frame was sent. The HTTP upgrade was most likely refused outright (401/403/426), or a TLS/DNS/network failure occurred, or a reverse proxy is not configured to pass WebSocket upgrades on this path. If REST auth succeeds but the WS gives 1006, suspect a 401/403 on the upgrade (stale/expired bearer, or the client DID is not in the MEDIATOR's ACL — distinct from the VTA's ACL) or a proxy that strips the Upgrade header";
    case 1008:
      return "policy violation — the mediator rejected the connection. Re-authenticate to the mediator, and confirm the client DID is permitted by the MEDIATOR's ACL (updating the target VTA's ACL does NOT change the mediator's gate)";
    case 1011:
      return "mediator internal error — check mediator logs";
    case 1015:
      return "TLS handshake failure — certificate/SNI/protocol problem reaching the wss endpoint";
    default:
      if (code >= 4000) return `application-specific close code ${code} — see mediator logs`;
      return `close code ${code}`;
  }
}

// Default per-frame error sink: warn to the console if one is available,
// otherwise stay silent. Overridable via the `onError` constructor option
// (pass `() => {}` to silence, or a logger to capture).
function defaultOnError(err) {
  if (typeof console !== "undefined" && typeof console.warn === "function") {
    console.warn(err?.message ?? err);
  }
}

// Decode a JWT's `exp` (seconds) without verifying the signature —
// purely to surface a born-expired bearer in diagnostics. Returns null
// on any malformed input (never throws).
function decodeJwtExp(jwt) {
  if (typeof jwt !== "string") return null;
  const parts = jwt.split(".");
  if (parts.length < 2) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64u.decode(parts[1])));
    return typeof payload.exp === "number" ? payload.exp : null;
  } catch {
    return null;
  }
}

// Cap on un-awaited inbound messages held for a future `waitFor`. A
// request/response client buffers at most a handful; this only bounds a
// misbehaving mediator pushing unsolicited frames.
const MAX_INBOX = 256;

// Cap on the in-memory set of already-handled mediator queue-ids used for
// at-least-once dedup. The mediator only redelivers un-acked messages, so this
// only needs to cover the window between a handled message and its (possibly
// lost) ack within a single session; bounded so a long-lived tab can't grow it
// without limit. Durable cross-restart dedup is the consumer's responsibility.
const MAX_SEEN = 1024;

/**
 * Build the `live-delivery-change` plaintext that enables live
 * delivery over the current WebSocket. The caller authcrypt-packs it
 * to the mediator.
 *
 * @param {Object} args
 * @param {string} args.from - client DID
 * @param {string} args.mediatorDid - mediator DID (the `to`)
 * @param {boolean} [args.live=true]
 * @returns {Object} plaintext message, ready to pack
 */
export function buildLiveDeliveryChange({ from, mediatorDid, live = true }) {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: `urn:uuid:${randomUuid()}`,
    typ: "application/didcomm-plain+json",
    type: LIVE_DELIVERY_CHANGE_TYPE,
    from,
    to: [mediatorDid],
    created_time: now,
    expires_time: now + 300,
    // The mediator reads `return_route: all` to mean "deliver replies
    // back over this same channel". It's a top-level message field.
    return_route: "all",
    body: { live_delivery: live },
  };
}

/**
 * Build the `messages-received` plaintext that tells the mediator we've
 * taken delivery of the listed message ids so it deletes them from the
 * queue and stops re-delivering them on the next (re)connection. Without
 * this, message-pickup 3.0 keeps every un-acked message queued and a
 * client that reconnects (e.g. an ephemeral MV3 service worker) sees the
 * same inbound messages replayed every time.
 */
export function buildMessagesReceived({ from, mediatorDid, messageIds }) {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: `urn:uuid:${randomUuid()}`,
    typ: "application/didcomm-plain+json",
    type: MESSAGES_RECEIVED_TYPE,
    from,
    to: [mediatorDid],
    created_time: now,
    expires_time: now + 300,
    return_route: "all",
    body: { message_id_list: messageIds },
  };
}

/**
 * Read the `skid` (sender key id) from a JWE's protected header
 * without decrypting. Returns null if absent (anoncrypt) or malformed.
 *
 * @param {string} jweString
 * @returns {string|null}
 */
export function peekSkid(jweString) {
  let jwe;
  try {
    jwe = JSON.parse(jweString);
  } catch {
    return null;
  }
  if (!jwe || typeof jwe.protected !== "string") return null;
  try {
    const header = JSON.parse(new TextDecoder().decode(b64u.decode(jwe.protected)));
    return typeof header.skid === "string" ? header.skid : null;
  } catch {
    return null;
  }
}

/**
 * Stable code for a frame that decrypted but carries no authenticated sender
 * (anoncrypt, whatever its header claims). Permanent: redelivery cannot fix it.
 */
export const E_UNAUTHENTICATED_FRAME = "E_UNAUTHENTICATED_FRAME";

/**
 * Codes of frames that decrypted for us and were then refused for good. They
 * are acked (and logged) rather than left queued, since the mediator would
 * otherwise redeliver them on every reconnect and they would occupy the queue.
 */
const PERMANENTLY_REFUSED = new Set([E_SENDER_MISMATCH, E_UNAUTHENTICATED_FRAME]);

/** Resolve a possibly-relative key id (`#key-1`) against `did`. */
function absoluteKid(did, kid) {
  return typeof kid === "string" && kid.startsWith("#") ? `${did}${kid}` : kid;
}

/**
 * The key among `entry` whose id is exactly `skid`, or undefined.
 *
 * @param {Object|Object[]|undefined} entry - `{ kid, publicJwk }` or a list.
 * @param {string} did
 * @param {string} skid
 */
function keyForSkid(entry, did, skid) {
  const list = Array.isArray(entry) ? entry : entry ? [entry] : [];
  return list.find((k) => k?.publicJwk && absoluteKid(did, k.kid) === skid);
}

/**
 * Unpack an inbound mediator frame, using the sender key named by its `skid`.
 *
 * The key is selected by the **exact** `skid` key id, not merely by its DID,
 * so the `senderKid` this returns is the key the envelope was actually
 * authenticated with — not a claim beside a key chosen some other way.
 *
 * @param {string} frameString - the raw JWE text frame.
 * @param {Object} args
 * @param {Object} args.recipient - `{ kid, privateJwk }` (our X25519 key).
 * @param {Map<string, {kid: string, publicJwk: Object} | Array<{kid: string, publicJwk: Object}>>} args.senderKeys
 *   - map of sender DID → its key-agreement key(s), each with its full key
 *   id. Seeded with the mediator and VTA keys. An entry without a `kid`
 *   matches nothing.
 * @param {Function} [args.resolveSender] - async fallback
 *   `(did, skid) => { kid, publicJwk } | Array<{ kid, publicJwk }>` when no
 *   seeded key has id `skid`. It must return key-agreement keys **of that
 *   DID** (from its DID document): the sender is authenticated as `senderDid`
 *   only because the envelope decrypts under a key that DID publishes.
 * @returns {Promise<{ message: Object, senderKid: string, senderDid: string, authenticated: true, legacyKekUsed: boolean }>}
 *   `senderDid` is the authenticated sender; `message.from` has been
 *   checked equal to it (see `unpack`).
 * @throws with `code` {@link E_SENDER_MISMATCH} or
 *   {@link E_UNAUTHENTICATED_FRAME} for a frame that decrypted and is refused.
 */
export async function unpackInbound(frameString, { recipient, senderKeys, resolveSender }) {
  const skid = peekSkid(frameString);
  if (!skid) {
    throw new Error("mediator-transport: inbound frame has no skid (anoncrypt not supported)");
  }
  const senderDid = didOfKid(skid);
  let sender = keyForSkid(senderKeys.get(senderDid), senderDid, skid);
  if (!sender && typeof resolveSender === "function") {
    sender = keyForSkid(await resolveSender(senderDid, skid), senderDid, skid);
  }
  if (!sender) {
    throw new Error(`mediator-transport: no key ${skid} for sender ${senderDid}`);
  }
  const result = await unpack(frameString, recipient, sender);
  if (!result.authenticated) {
    // An anoncrypt frame carrying a `skid` header: nothing authenticated it.
    const err = new Error("mediator-transport: inbound frame is not sender-authenticated");
    err.code = E_UNAUTHENTICATED_FRAME;
    throw err;
  }
  return result;
}

/**
 * The sender an inbound message was authenticated as.
 *
 * @typedef {Object} VerifiedSender
 * @property {string} did - the DID of the authcrypt sender key (`skid`).
 * @property {string} kid - the sender key id (`skid`) itself.
 */

/**
 * An inbound message together with the sender it was authenticated as.
 *
 * @typedef {Object} InboundMessage
 * @property {Object} message - the unpacked DIDComm plaintext message.
 * @property {VerifiedSender} sender - who sent it, as proven by the envelope.
 */

/**
 * A live mediator WebSocket session. Browser-first: uses the global
 * `WebSocket` by default, injectable for tests.
 *
 * Lifecycle: `await session.connect()` opens the socket + enables live
 * delivery; `session.send(jwe)` ships a frame; `session.waitFor(thid,
 * timeoutMs, { from })` resolves with the first inbound message whose `thid`
 * matches (and, given `from`, whose authenticated sender is that DID);
 * `session.close()` tears down.
 *
 * Every message this session delivers — to a waiter or a listener — comes
 * with its {@link VerifiedSender}: the DID and key id the authcrypt envelope
 * was authenticated with. Authorise on that. The message's own `from` is
 * sender-written plaintext; it is guaranteed equal to `sender.did` here only
 * because `unpack` refuses anything else, and code that reads `from` instead
 * of `sender` is one refactor away from trusting a claim.
 */
export class MediatorSession {
  /**
   * @param {Object} args
   * @param {{wsEndpoint:string, did:string, kid:string, x25519Pub:Uint8Array}} args.mediator
   * @param {string} args.mediatorJwt - mediator access token.
   * @param {{did:string, kid:string, privateKey:Uint8Array, publicKey:Uint8Array}} args.client
   * @param {Map<string,Object>} [args.senderKeys] - seed sender keys.
   * @param {Function} [args.resolveSender] - async sender-key fallback.
   * @param {Function} [args.WebSocketImpl] - WebSocket ctor (default global).
   * @param {(message: Object, thid: string, sender: VerifiedSender) => void|Promise<void>} [args.onMessage]
   *   - called for each inbound message NOT claimed by a `waitFor` waiter,
   *   with the sender the envelope authenticated (`sender.did`) — the identity
   *   to authorise on, rather than the message's `from`
   *   (unsolicited inbound, e.g. a server-initiated request). Fired in addition
   *   to the internal buffering, so request/reply via `waitFor` is unaffected;
   *   handlers should filter by the message `type`. **If it returns a promise,
   *   the transport awaits it before acking the frame to the mediator** — a
   *   handler that persists the message durably should do so before resolving,
   *   so an MV3 teardown between handoff and ack cannot lose it (R1.6). Delivery
   *   is at-least-once: a handler must tolerate seeing the same message twice
   *   across a reconnect and dedupe durably on its own side.
   * @param {(message: Object, thid: string, sender: VerifiedSender) => void|Promise<void>} [args.onMediatorMessage]
   *   - called instead of `onMessage` for an unclaimed message whose sender is
   *   the mediator itself: a `messaging/monitor/event` batch, or a Trust-Task
   *   reply that arrived after its waiter gave up. These are the mediator's
   *   own frames, not mail from a peer, so a consumer that persists every
   *   `onMessage` delivery before the ack (R1.6) can keep them off that path.
   *   Without it they reach `onMessage`, as they always have.
   * @param {(bytes: Uint8Array) => void|Promise<void>} [args.onTspFrame] - called
   *   for each inbound TSP frame (raw qb2 bytes), which the mediator multiplexes
   *   onto this same socket. **Awaited before the frame is acked**, exactly as
   *   `onMessage` is (R1.6): the ack deletes the mediator's queued copy, so a
   *   consumer that persists asynchronously must finish first. A throw withholds
   *   the ack and the message is redelivered. Without a handler, TSP frames are
   *   neither dispatched nor acked — they stay queued, since nothing has
   *   handled them — and are never run through the DIDComm unpacker (which
   *   cannot read them).
   * @param {import("./net-guard.js").NetPolicy} [args.netPolicy] - egress
   *   policy for `mediator.wsEndpoint`, checked here and again before each
   *   socket open. Defaults to `wss:` on a public host; a local mediator on
   *   `ws://localhost` needs `{ allowInsecure: true, allowPrivate: true }`.
   *   Pass the policy given to `authenticateToMediator`.
   * @throws {import("./net-guard.js").BlockedEndpointError} if
   *   `mediator.wsEndpoint` fails the policy.
*/
  constructor({ mediator, mediatorJwt, client, senderKeys, resolveSender, WebSocketImpl, onMessage, onMediatorMessage, onTspFrame, onClose, onError, connectTimeoutMs, netPolicy }) {
    if (!mediator?.wsEndpoint) {
      throw new Error("MediatorSession: mediator.wsEndpoint required (mediator advertises no wss endpoint)");
    }
    if (netPolicy != null && typeof netPolicy !== "object") {
      throw new TypeError("MediatorSession: netPolicy must be an object");
    }
    // `mediator` normally comes from a DID document, and callers can also
    // build it by hand. The upgrade request carries the mediator JWT, so the
    // endpoint is checked rather than trusted.
    this._wsPolicy = {
      allowInsecure: Boolean(netPolicy?.allowInsecure),
      allowPrivate: Boolean(netPolicy?.allowPrivate),
      allowHosts: netPolicy?.allowHosts ?? null,
      label: "mediator WebSocket",
      schemes: ["wss:"],
    };
    assertSafeEndpoint(mediator.wsEndpoint, this._wsPolicy);
    this.mediator = mediator;
    this.mediatorJwt = mediatorJwt;
    // Upper bound on the WS upgrade. Without it, a silently-dropped
    // upgrade (proxy blackhole, no open/error/close ever fires) would
    // hang connect() forever. 0 disables the timeout.
    this.connectTimeoutMs = connectTimeoutMs ?? 15000;
    this.client = client;
    this.senderKeys = senderKeys ?? new Map();
    this.resolveSender = resolveSender;
    this.onMessage = onMessage;
    // Unsolicited frames the *mediator itself* sent (a traffic-monitor batch,
    // a stale reply whose waiter gave up). Given, they go here instead of to
    // `onMessage`, so a consumer that persists everything `onMessage` sees
    // before the ack does not write telemetry to storage once a second.
    this.onMediatorMessage = onMediatorMessage;
    // Fired for each inbound TSP frame (a non-DIDComm message the mediator
    // multiplexes onto this same socket — CESR qb2, first byte 0xF8 or 0xFB,
    // delivered
    // as base64url(qb2) text). Receives the raw qb2 bytes; a TSP consumer
    // unpacks them. Awaited before the frame is acked (R1.6) — see
    // `_dispatchTspFrame`. Without a handler, TSP frames are neither dispatched
    // nor acked, and are never run through the DIDComm unpacker (which can't
    // read them).
    this.onTspFrame = onTspFrame;
    // Fired once when the socket drops *unexpectedly* (after a successful
    // open, not via close()). Lets a caller holding a warm session evict +
    // reconnect. Not fired on an intentional close().
    this.onClose = onClose;
    // Per-frame error sink. A single un-unpackable / malformed inbound
    // message must never get stuck or silently vanish: it's logged here
    // and processing moves on to the next frame. Defaults to console.warn;
    // pass a no-op to silence, or your own logger to capture.
    this.onError = onError ?? defaultOnError;
    this._userClosed = false;
    this.WebSocketImpl = WebSocketImpl ?? globalThis.WebSocket;
    if (typeof this.WebSocketImpl !== "function") {
      throw new Error("MediatorSession: no WebSocket implementation available");
    }
    // Seed the mediator's own key so status/problem-report frames unpack.
    this.senderKeys.set(mediator.did, {
      kid: mediator.kid,
      publicJwk: jwk.publicJwk("X25519", mediator.x25519Pub),
    });

    this.ws = null;
    // Buffer of unpacked inbound messages not yet claimed by a waiter,
    // plus the set of pending waiters keyed by the thid they want.
    this._inbox = [];
    this._waiters = [];
    // Mediator queue-ids (sha256 of the packed frame) we've already handed
    // off. Bounds re-dispatch of an at-least-once redelivery when an ack was
    // lost mid-session. Insertion-ordered so the oldest evicts first.
    this._seen = new Set();
  }

  /** Our recipient descriptor for unpack. */
  get _recipient() {
    return {
      kid: this.client.kid,
      privateJwk: jwk.privateJwk("X25519", this.client.privateKey, this.client.publicKey),
    };
  }

  /**
   * Open the socket + enable live delivery. Resolves once the socket
   * is open and the live-delivery-change has been sent.
   */
  async connect() {
    await this._openSocket();
    const change = buildLiveDeliveryChange({
      from: this.client.did,
      mediatorDid: this.mediator.did,
    });
    const packed = await pack({
      message: change,
      sender: {
        kid: this.client.kid,
        privateJwk: jwk.privateJwk("X25519", this.client.privateKey, this.client.publicKey),
      },
      recipient: {
        kid: this.mediator.kid,
        publicJwk: jwk.publicJwk("X25519", this.mediator.x25519Pub),
      },
    });
    this.ws.send(packed);
  }

  _openSocket() {
    return new Promise((resolve, reject) => {
      // `connect()` settles exactly once: on the first of open / close /
      // timeout. A strict client that rejects the 101 (e.g. no
      // subprotocol echoed) fires `error` then `close` *before* `onopen`.
      // We prefer to settle on `close` rather than `error`, because the
      // browser `error` event is deliberately information-free (no code,
      // no reason — a privacy measure) while the `close` event carries
      // the `code`/`reason` that actually says WHY the upgrade failed.
      // After open, error/close instead fail any pending waiters.
      let settled = false;
      let sawError = false;
      let timer = null;
      const settleConnect = (fn, arg) => {
        if (settled) return false;
        settled = true;
        if (timer) clearTimeout(timer);
        fn(arg);
        return true;
      };

      // Re-check before every dial: `mediator` is a plain object the caller
      // still holds, so its endpoint may have changed since construction.
      // Throwing here rejects connect() before any socket exists.
      assertSafeEndpoint(this.mediator.wsEndpoint, this._wsPolicy);

      // Subprotocol bearer: ["bearer.<jwt>", "<app>"]. The mediator
      // reads the JWT from Sec-WebSocket-Protocol when no Authorization
      // header is present (browsers can't set the header), and echoes
      // the non-bearer app subprotocol back so a spec-strict client
      // accepts the 101 (see WS_APP_SUBPROTOCOL).
      const ws = new this.WebSocketImpl(this.mediator.wsEndpoint, [
        `bearer.${this.mediatorJwt}`,
        WS_APP_SUBPROTOCOL,
      ]);
      this.ws = ws;

      if (this.connectTimeoutMs > 0) {
        timer = setTimeout(() => {
          settleConnect(
            reject,
            this._connectError({
              reason: `no open/close within ${this.connectTimeoutMs}ms`,
              hint: "the upgrade was silently dropped — a reverse proxy or firewall not configured to pass WebSocket upgrades on this path will hang rather than reject",
            }),
          );
          try {
            ws.close();
          } catch {
            // best effort
          }
        }, this.connectTimeoutMs);
      }

      ws.onopen = () => settleConnect(resolve);
      ws.onmessage = (ev) => this._onFrame(ev.data);
      ws.onerror = () => {
        // The browser `error` event carries no detail. Record that it
        // happened and wait for the `close` event (which has the code).
        // Only if no close follows do we settle on the bare error.
        sawError = true;
        if (settled) {
          for (const w of this._waiters.splice(0)) {
            clearTimeout(w.timer);
            w.reject(new Error("mediator-transport: WebSocket error"));
          }
        }
      };
      ws.onclose = (ev) => {
        const code = ev?.code;
        const reason = ev?.reason;
        if (
          settleConnect(
            reject,
            this._connectError({
              code,
              reason,
              sawError,
              hint: describeCloseCode(code),
            }),
          )
        ) {
          return;
        }
        for (const w of this._waiters.splice(0)) {
          clearTimeout(w.timer);
          w.reject(new Error("mediator-transport: WebSocket closed"));
        }
        // Surface an unexpected drop (the socket was open and we didn't
        // close it ourselves) so a warm-session holder can reconnect.
        if (!this._userClosed && this.onClose) {
          try {
            this.onClose();
          } catch {
            // A throwing handler must not break teardown.
          }
        }
      };
    });
  }

  /**
   * Build a rich, actionable error for a failed WS upgrade. The browser
   * `error` event is detail-free, so the close `code`/`reason` plus a
   * decoded view of the bearer token's expiry is the most we can give a
   * caller. Structured fields (`code`, `reason`, `endpoint`) are attached
   * so the plugin can branch/log programmatically.
   */
  _connectError({ code, reason, sawError, hint }) {
    const parts = ["mediator-transport: WebSocket failed to open"];
    if (code != null) parts.push(`(close code ${code}${reason ? ` "${reason}"` : ""})`);
    else if (sawError) parts.push("(error before close — no code provided by the browser)");
    if (hint) parts.push(`— ${hint}`);

    // Decode the bearer token's exp so a born-expired / skewed token (a
    // common cause of an upgrade reject that REST auth accepts) is
    // visible without server logs.
    const exp = decodeJwtExp(this.mediatorJwt);
    if (exp != null) {
      const expMs = exp * 1000;
      const skewMs = expMs - this._nowMs();
      if (skewMs <= 0) {
        parts.push(
          `— bearer token is already EXPIRED (exp ${new Date(expMs).toISOString()}, ${Math.round(-skewMs / 1000)}s ago); re-authenticate, and check client/mediator clock skew`,
        );
      }
    }

    const err = new Error(parts.join(" "));
    err.code = code;
    err.reason = reason;
    err.endpoint = this.mediator.wsEndpoint;
    return err;
  }

  // Wall-clock for skew reporting only (never gates logic). Isolated so
  // it's the single Date use and easy to stub in tests.
  _nowMs() {
    return new Date().getTime();
  }

  // Report a per-frame failure without throwing. Includes a short, stable
  // fingerprint of the offending frame (first 12 chars of its content) so
  // a recurring poison message is recognizable across redeliveries in
  // logs, without dumping the full (possibly sensitive) ciphertext.
  _reportFrameError(stage, err, text) {
    const fp = typeof text === "string" ? `${text.slice(0, 12)}…(${text.length}b)` : "n/a";
    try {
      this.onError(new Error(`mediator-transport: failed to ${stage} [frame ${fp}]: ${err?.message ?? err}`), {
        stage,
        cause: err,
        frameFingerprint: fp,
      });
    } catch {
      // The error sink itself must never break the receive loop.
    }
  }

  /** Send a raw packed JWE as a WS text frame. */
  send(jweString) {
    if (!this.ws) throw new Error("mediator-transport: not connected");
    this.ws.send(jweString);
  }

  /**
   * Send a raw TSP message as a WS binary frame. The mediator sniffs the
   * leading byte — `0xF8` short-framed or `0xFB` long-framed — and routes it to
   * its TSP inbound handler (the same socket carries DIDComm text frames and
   * TSP binary frames). Its `affinidi_tsp::is_tsp` and this library's
   * `isTspFrameBytes` must agree on both, or a message past ~12 KB is dropped
   * at whichever side lags.
   * @param {Uint8Array} bytes
   */
  sendBinary(bytes) {
    if (!this.ws) throw new Error("mediator-transport: not connected");
    this.ws.send(bytes);
  }

  async _onFrame(data) {
    // Every inbound frame is processed independently and defensively: a
    // single bad message (undecryptable, malformed, unknown sender, or a
    // throw anywhere in dispatch) is logged via `onError` and skipped, so
    // the session never gets stuck on one poison message and keeps
    // delivering the rest of the queue.
    let text;
    try {
      text = typeof data === "string" ? data : new TextDecoder().decode(data);
    } catch (err) {
      this._reportFrameError("decode inbound frame bytes", err, null);
      return;
    }

    // TSP demux: the mediator multiplexes TSP messages onto this same socket.
    // A stored TSP message is delivered as base64url(qb2) text whose leading
    // CESR `-E` count code is what marks it — `-E…` short-framed, `--E…` long-
    // framed. `isTspFrameText` owns that test and explains both; DIDComm frames
    // are JSON (`{`) or compact JWS (`ey…`), so neither prefix is ambiguous.
    // Route the raw qb2 bytes to the TSP consumer instead of the DIDComm
    // unpacker, which throws on them.
    if (isTspFrameText(text)) {
      let qb2;
      try {
        qb2 = b64u.decode(text);
      } catch (err) {
        this._reportFrameError("decode inbound TSP frame", err, text);
        return;
      }
      await this._dispatchTspFrame(qb2, text);
      return;
    }

    let result;
    try {
      result = await unpackInbound(text, {
        recipient: this._recipient,
        senderKeys: this.senderKeys,
        resolveSender: this.resolveSender,
      });
    } catch (err) {
      if (PERMANENTLY_REFUSED.has(err?.code) && peekSkid(text)?.split("#")[0] !== this.mediator.did) {
        // Decrypted for us and refused for good (a `from` that is not the
        // sender key's DID, or no authenticated sender). Nothing is delivered;
        // the frame is acked so the mediator stops redelivering it, and
        // logged so it is not silent.
        this._reportFrameError("accept inbound frame (refused and dropped)", err, text);
        const queueId = await sha256Hex(text);
        this._markSeen(queueId);
        void this._ackReceived(queueId);
        return;
      }
      // Unparseable / undecryptable / unknown-sender frame. Log (so a
      // recurring poison message is visible rather than silently dropped)
      // and move on — correlation only cares about responses we await.
      // Not acked: a failure here may be transient (a sender DID that would
      // not resolve), and redelivery is how it recovers.
      this._reportFrameError("unpack inbound frame", err, text);
      return;
    }

    try {
      await this._dispatchFrame(result, text);
    } catch (err) {
      // A malformed-but-decryptable message (bad thid/id, throwing
      // listener, ack failure that escaped) must not break the loop.
      this._reportFrameError("dispatch inbound message", err, text);
    }
  }

  /**
   * Hand a TSP frame to its consumer, then ack it — the same R1.6 ordering
   * `_dispatchFrame` applies to DIDComm, and for the same reason.
   *
   * The mediator does not treat TSP specially. `handle_inbound_tsp` stores a
   * Direct message "reusing the protocol-neutral store path that DIDComm
   * direct delivery uses", base64url-encoded, and live delivery fetches with
   * `DoNotDelete` because "redelivery is a notification re-cover, not an ack".
   * So a TSP message obeys the same delete-to-ack contract, and the ack id is
   * `sha256(text)` over the frame exactly as received — the mediator stores the
   * qb64 text form, which is the form it delivers.
   *
   * Until this existed the TSP branch returned before ever reaching the ack,
   * so every TSP message a client received stayed queued and was redelivered
   * on each reconnect, forever. Replies masked it: the consumer's waiter took
   * the first delivery and discarded every redelivery as a straggler.
   *
   * Two deliberate differences from the DIDComm path:
   *
   *  - **No `isQueued` sender check.** That check exists to avoid acking the
   *    mediator's own status/problem-report frames, which would provoke another
   *    status in an endless loop. The mediator speaks DIDComm JSON to us and
   *    never emits a TSP frame of its own, and this transport is key-blind for
   *    TSP so it could not read a sender anyway. Every frame `isTspFrameText`
   *    accepts is a queued message.
   *  - **A throwing consumer is not acked.** `_deliver` swallows an
   *    `onMessage` throw and acks regardless; here a throw means the consumer
   *    did not persist, so the ack is withheld and the mediator redelivers.
   *    (The DIDComm path's swallow-then-ack is the older behaviour and a
   *    separate change — narrowing it here would alter delivery for every
   *    existing listener.)
   */
  async _dispatchTspFrame(qb2, text) {
    // No consumer means nothing has been persisted, so the frame must stay
    // queued: a client built without `onTspFrame` is not one that has handled
    // the message.
    if (!this.onTspFrame) return;

    const queueId = await sha256Hex(text);
    if (this._seen.has(queueId)) {
      // A redelivery after a lost or racing ack. Re-ack so the mediator finally
      // drops it, but do not hand it to the consumer twice.
      void this._ackReceived(queueId);
      return;
    }

    try {
      // Awaited: a consumer that persists asynchronously must finish before the
      // ack tells the mediator to delete its only other copy.
      await this.onTspFrame(qb2);
    } catch (err) {
      this._reportFrameError("dispatch inbound TSP frame", err, text);
      return;
    }

    this._markSeen(queueId);
    // Best-effort: a failed ack must never break frame processing — the message
    // is redelivered and deduped instead.
    void this._ackReceived(queueId);
  }

  async _dispatchFrame(result, text) {
    // R1.6 — hand the message off to its consumer (durably, when the consumer
    // persists) BEFORE acking. The ack tells the mediator to delete its queued
    // copy and stop replaying it (message-pickup 3.0); if we acked first and
    // the host (MV3 offscreen doc / service worker) were torn down before the
    // consumer persisted, the message would be lost forever — the mediator has
    // already dropped it. Ack-after-handoff instead makes delivery
    // at-least-once: an un-acked message is redelivered on reconnect. In-memory
    // dedup below keeps that safe within a session; durable cross-restart dedup
    // is the consumer's job.
    //
    // Two non-obvious points about the ack itself:
    //   1. The mediator's queue-id is sha256(packed JWE bytes), NOT the inner
    //      DIDComm message id (set by the original sender, unknown to the
    //      mediator). See affinidi-messaging-mediator memory_store.rs
    //      `store_message`: `let msg_id = digest(message.as_bytes());`.
    //   2. Frames from the mediator itself (status, problem-report, …) are not
    //      queued messages: don't ack them (acking one provokes another status
    //      reply, which is also from the mediator — an endless ~300ms loop) and
    //      don't dedup them. Filtering by sender breaks that loop.
    //   3. …with one exception: the mediator's *reply to a Trust Task* is
    //      stored in our queue as well as pushed live (the Rust SDK deletes it
    //      on receipt), so it is a queued message and must be acked, or every
    //      reply stays in our receive queue and is replayed on each reconnect.
    //      That queue is the one carrying every other message to this DID, and
    //      a full queue refuses them. See `isStoredMediatorReply`.
    const senderDid = result.senderDid ?? null;
    const fromMediator = senderDid === this.mediator.did;
    const isQueued = Boolean(senderDid) && (!fromMediator || isStoredMediatorReply(result.message));

    // For a queued message, the mediator queue-id doubles as the ack id and the
    // dedup key.
    const queueId = isQueued ? await sha256Hex(text) : null;
    if (queueId && this._seen.has(queueId)) {
      // Already handled this exact delivery (a redelivery after a lost/racing
      // ack). Re-ack so the mediator finally drops it, but do NOT re-dispatch.
      void this._ackReceived(queueId);
      return;
    }

    // Hand off first (awaiting an async consumer so it can persist), THEN ack.
    await this._deliver(result);

    if (queueId) {
      this._markSeen(queueId);
      // Best-effort + fire-and-forget: a failed ack must never break frame
      // processing — the message is redelivered and deduped instead.
      void this._ackReceived(queueId);
    }
  }

  /**
   * Deliver an unpacked inbound message to its consumer: a matching `waitFor`
   * waiter if one is pending, otherwise the `onMessage` listener (buffered for
   * a late waiter either way). Awaits `onMessage` so a listener that persists
   * asynchronously completes before the caller acks (R1.6).
   */
  async _deliver(result) {
    const message = result.message;
    // `unpackInbound` only returns authcrypt it authenticated, so both are set;
    // refuse rather than deliver a message with no proven sender.
    if (typeof result.senderDid !== "string" || typeof result.senderKid !== "string") {
      throw new Error("mediator-transport: inbound message has no authenticated sender");
    }
    /** @type {VerifiedSender} */
    const sender = Object.freeze({ did: result.senderDid, kid: result.senderKid });
    const thid = threadOf(message);
    const idx = this._waiters.findIndex((w) => w.thid === thid && acceptsSender(w.from, sender));
    if (idx >= 0) {
      const [w] = this._waiters.splice(idx, 1);
      clearTimeout(w.timer);
      w.resolve({ message, sender });
      return;
    }
    const fromMediator = sender.did === this.mediator.did;
    const listener = fromMediator && this.onMediatorMessage ? this.onMediatorMessage : this.onMessage;
    // Buffer for a not-yet-registered waiter, but bound the buffer so a
    // chatty/malicious mediator can't grow it without limit in a long-lived
    // tab. Drop the oldest when over the cap. A frame the mediator sends
    // unthreaded (a traffic-monitor batch, once a second) answers nothing, so
    // no waiter can want it — buffering it would only evict the raced replies
    // the buffer exists for.
    if (!(fromMediator && message.thid == null && message.pthid == null)) {
      this._inbox.push({ thid, message, sender });
      if (this._inbox.length > MAX_INBOX) this._inbox.shift();
    }
    // Surface unsolicited inbound (server-initiated requests) to a listener, if
    // one is registered. Buffering above is preserved so a late `waitFor` for a
    // raced reply still finds it; the listener should filter by message `type`.
    if (listener) {
      try {
        // Await so a listener returning a promise (e.g. persist-to-storage)
        // finishes before we ack. A synchronous listener returns undefined and
        // `await` resolves immediately.
        await listener(message, thid, sender);
      } catch {
        // A throwing listener must not break frame processing.
      }
    }
  }

  /** Record a handled queue-id for dedup, evicting the oldest past the cap. */
  _markSeen(queueId) {
    this._seen.add(queueId);
    if (this._seen.size > MAX_SEEN) {
      this._seen.delete(this._seen.values().next().value);
    }
  }

  /**
   * Authcrypt + send a `messages-received` ack for the given message id(s)
   * to the mediator over the live socket. Best-effort: swallows errors so
   * a transient pack/send failure can't break frame processing.
   * @param {string|string[]} ids
   */
  async _ackReceived(ids) {
    const messageIds = Array.isArray(ids) ? ids : [ids];
    if (messageIds.length === 0) return;
    try {
      if (!this.ws || this.ws.readyState !== 1) return;
      const ack = buildMessagesReceived({
        from: this.client.did,
        mediatorDid: this.mediator.did,
        messageIds,
      });
      const packed = await pack({
        message: ack,
        sender: {
          kid: this.client.kid,
          privateJwk: jwk.privateJwk("X25519", this.client.privateKey, this.client.publicKey),
        },
        recipient: {
          kid: this.mediator.kid,
          publicJwk: jwk.publicJwk("X25519", this.mediator.x25519Pub),
        },
      });
      this.ws.send(packed);
    } catch {
      // Best-effort: persistent client-side dedup is the durable guard.
    }
  }

  /**
   * Wait for the first inbound message answering `thid`: a reply threaded to
   * it, or a problem report whose `pthid` names it (see `threadOf`), so a
   * refusal arrives as the refusal instead of as a timeout. Checks
   * already-buffered frames first.
   *
   * A thread id is not a secret — it is the id of a message this client sent
   * through the mediator — so pass `from` whenever the answering party is
   * known: a message on the thread from any other authenticated sender is
   * then not this waiter's reply, and stays available to other waiters and
   * the `onMessage` listener.
   *
   * @param {string} thid - the request message id we're correlating to.
   * @param {number} timeoutMs
   * @param {{ from?: string | readonly string[] }} [options] - the DID (or
   *   DIDs) the reply must be authenticated as.
   * @returns {Promise<InboundMessage>} the reply and its authenticated sender.
   */
  waitFor(thid, timeoutMs, options = {}) {
    const from = normalizeFrom(options?.from);
    const buffered = this._inbox.findIndex((m) => m.thid === thid && acceptsSender(from, m.sender));
    if (buffered >= 0) {
      const [m] = this._inbox.splice(buffered, 1);
      return Promise.resolve({ message: m.message, sender: m.sender });
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this._waiters.findIndex((w) => w.timer === timer);
        if (i >= 0) this._waiters.splice(i, 1);
        reject(new Error(`mediator-transport: timeout waiting for response (thid ${thid})`));
      }, timeoutMs);
      this._waiters.push({ thid, from, resolve, reject, timer });
    });
  }

  /** True while the underlying socket is open (live delivery active). */
  get isOpen() {
    return Boolean(this.ws) && this.ws.readyState === 1;
  }

  close() {
    this._userClosed = true;
    for (const w of this._waiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(new Error("mediator-transport: session closed"));
    }
    try {
      this.ws?.close();
    } catch {
      /* ignore */
    }
    this.ws = null;
  }
}

export { LIVE_DELIVERY_CHANGE_TYPE, TRUST_TASK_ENVELOPE_TYPE };

/**
 * Normalise a `waitFor` `from` option to a list of DIDs, or null for "any".
 *
 * @param {string | readonly string[] | undefined} from
 * @returns {readonly string[] | null}
 */
function normalizeFrom(from) {
  if (from == null) return null;
  const list = typeof from === "string" ? [from] : Array.from(from);
  if (list.length === 0 || list.some((d) => typeof d !== "string" || d.length === 0)) {
    throw new TypeError("mediator-transport: waitFor `from` must be a DID or a non-empty list of DIDs");
  }
  return list;
}

/**
 * Whether a waiter restricted to `from` may take a message from `sender`.
 *
 * @param {readonly string[] | null} from
 * @param {VerifiedSender} sender
 * @returns {boolean}
 */
function acceptsSender(from, sender) {
  return from === null || from.includes(sender.did);
}

/**
 * The thread a message answers — what a `waitFor` waiter is keyed by.
 *
 * A reply names its request in `thid`. A **problem report** names it in
 * `pthid` instead (DIDComm: the report opens its own thread, whose parent is
 * the one that failed), so a refusal matches the request it refuses rather
 * than timing out as "no response". Anything else falls back to its own id.
 *
 * @param {{id?: string, type?: string, thid?: string, pthid?: string}} message
 * @returns {string}
 */
export function threadOf(message) {
  if (message.thid != null) return message.thid;
  if (message.type === PROBLEM_REPORT_TYPE && message.pthid != null) return message.pthid;
  return message.id;
}

/**
 * Whether a frame the mediator sent us is its stored reply to a Trust Task.
 *
 * The mediator answers a Trust Task addressed to it in the Trust Tasks
 * envelope, threaded to the request, and **stores** that reply in our queue as
 * well as pushing it live — so, unlike its status and problem-report frames
 * (sent on the socket only), it has to be acked. The other envelope frame it
 * sends, a traffic-monitor batch, is never stored and carries no `thid`, which
 * is what tells the two apart: a batch answers no request.
 *
 * @param {{type?: string, thid?: string}} message
 * @returns {boolean}
 */
export function isStoredMediatorReply(message) {
  return message.type === TRUST_TASK_ENVELOPE_TYPE && message.thid != null;
}

function randomUuid() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b).map((v) => v.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// Lowercase hex sha256 of a UTF-8 string. Matches the mediator's
// Rust `sha256::digest(message.as_bytes())` byte-for-byte (same
// output format and same input encoding), so the digests align as
// the pickup queue-id on both sides.
async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
