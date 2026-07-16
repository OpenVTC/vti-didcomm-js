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

import { unpack } from "./unpack.js";
import { pack } from "./pack.js";
import * as b64u from "./base64url.js";
import * as jwk from "./jwk.js";

const LIVE_DELIVERY_CHANGE_TYPE = "https://didcomm.org/messagepickup/3.0/live-delivery-change";
const MESSAGES_RECEIVED_TYPE = "https://didcomm.org/messagepickup/3.0/messages-received";

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
 * Unpack an inbound mediator frame, picking the sender's public key by
 * its `skid`.
 *
 * @param {string} frameString - the raw JWE text frame.
 * @param {Object} args
 * @param {Object} args.recipient - `{ kid, privateJwk }` (our X25519 key).
 * @param {Map<string,Object>} args.senderKeys - map of sender DID
 *   (the part before `#`) → `{ publicJwk }`. Seeded with the mediator
 *   and VTA keys.
 * @param {Function} [args.resolveSender] - async fallback
 *   `(did) => { publicJwk }` when `skid`'s DID isn't in `senderKeys`.
 * @returns {Promise<{ message: Object, senderKid: string }>}
 */
export async function unpackInbound(frameString, { recipient, senderKeys, resolveSender }) {
  const skid = peekSkid(frameString);
  if (!skid) {
    throw new Error("mediator-transport: inbound frame has no skid (anoncrypt not supported)");
  }
  const senderDid = skid.split("#")[0];
  let sender = senderKeys.get(senderDid);
  if (!sender && typeof resolveSender === "function") {
    sender = await resolveSender(senderDid);
  }
  if (!sender) {
    throw new Error(`mediator-transport: no sender key for ${senderDid} (skid ${skid})`);
  }
  return unpack(frameString, recipient, sender);
}

/**
 * A live mediator WebSocket session. Browser-first: uses the global
 * `WebSocket` by default, injectable for tests.
 *
 * Lifecycle: `await session.connect()` opens the socket + enables live
 * delivery; `session.send(jwe)` ships a frame; `session.waitFor(thid,
 * timeoutMs)` resolves with the first inbound message whose `thid`
 * matches; `session.close()` tears down.
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
   * @param {(message: Object, thid: string) => void|Promise<void>} [args.onMessage]
   *   - called for each inbound message NOT claimed by a `waitFor` waiter
   *   (unsolicited inbound, e.g. a server-initiated request). Fired in addition
   *   to the internal buffering, so request/reply via `waitFor` is unaffected;
   *   handlers should filter by the message `type`. **If it returns a promise,
   *   the transport awaits it before acking the frame to the mediator** — a
   *   handler that persists the message durably should do so before resolving,
   *   so an MV3 teardown between handoff and ack cannot lose it (R1.6). Delivery
   *   is at-least-once: a handler must tolerate seeing the same message twice
   *   across a reconnect and dedupe durably on its own side.
   * @param {(bytes: Uint8Array) => void} [args.onTspFrame] - called for each
   *   inbound TSP frame the mediator multiplexes onto this socket (raw qb2
   *   bytes, first byte 0xF8). Without it, TSP frames are dropped rather than
   *   run through the DIDComm unpacker (which can't read them).
   * @param {() => void} [args.onClose] - called once if the socket drops
   *   unexpectedly (after a successful open, not via `close()`). Lets a
   *   warm-session holder evict + reconnect.
   */
  constructor({ mediator, mediatorJwt, client, senderKeys, resolveSender, WebSocketImpl, onMessage, onTspFrame, onClose, onError, connectTimeoutMs }) {
    if (!mediator?.wsEndpoint) {
      throw new Error("MediatorSession: mediator.wsEndpoint required (mediator advertises no wss endpoint)");
    }
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
    // Fired for each inbound TSP frame (a non-DIDComm message the mediator
    // multiplexes onto this same socket — CESR qb2, first byte 0xF8, delivered
    // as base64url(qb2) text). Receives the raw qb2 bytes; a TSP consumer
    // unpacks them. Without a handler, TSP frames are dropped (not run through
    // the DIDComm unpacker, which can't read them).
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
   * leading 0xF8 magic byte and routes it to its TSP inbound handler (the same
   * socket carries DIDComm text frames and TSP binary frames).
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
    // A stored TSP message is delivered as base64url(qb2) text, which starts
    // with "-E" (the CESR `-E` count code, whose first decoded byte is the
    // 0xF8 TSP magic). DIDComm frames are JSON (`{`) or compact JWS (`ey…`), so
    // a leading "-E" is an unambiguous TSP marker. Route the raw qb2 bytes to
    // the TSP consumer instead of the DIDComm unpacker (which throws on them).
    if (text.startsWith("-E")) {
      let qb2;
      try {
        qb2 = b64u.decode(text);
      } catch (err) {
        this._reportFrameError("decode inbound TSP frame", err, text);
        return;
      }
      if (this.onTspFrame) {
        try {
          this.onTspFrame(qb2);
        } catch (err) {
          this._reportFrameError("dispatch inbound TSP frame", err, text);
        }
      }
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
      // Unparseable / undecryptable / unknown-sender frame. Log (so a
      // recurring poison message is visible rather than silently dropped)
      // and move on — correlation only cares about responses we await.
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
    const senderDid = result.senderKid ? result.senderKid.split("#")[0] : null;
    const isQueued = senderDid && senderDid !== this.mediator.did;

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
    const thid = result.message.thid ?? result.message.id;
    const idx = this._waiters.findIndex((w) => w.thid === thid);
    if (idx >= 0) {
      const [w] = this._waiters.splice(idx, 1);
      clearTimeout(w.timer);
      w.resolve(result.message);
      return;
    }
    // Buffer for a not-yet-registered waiter, but bound the buffer so a
    // chatty/malicious mediator can't grow it without limit in a long-lived
    // tab. Drop the oldest when over the cap.
    this._inbox.push({ thid, message: result.message });
    if (this._inbox.length > MAX_INBOX) this._inbox.shift();
    // Surface unsolicited inbound (server-initiated requests) to a listener, if
    // one is registered. Buffering above is preserved so a late `waitFor` for a
    // raced reply still finds it; the listener should filter by message `type`.
    if (this.onMessage) {
      try {
        // Await so a listener returning a promise (e.g. persist-to-storage)
        // finishes before we ack. A synchronous listener returns undefined and
        // `await` resolves immediately.
        await this.onMessage(result.message, thid);
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
   * Wait for the first inbound message whose `thid` matches `thid`.
   * Checks already-buffered frames first.
   *
   * @param {string} thid - the request message id we're correlating to.
   * @param {number} timeoutMs
   * @returns {Promise<Object>} the unpacked response message.
   */
  waitFor(thid, timeoutMs) {
    const buffered = this._inbox.findIndex((m) => m.thid === thid);
    if (buffered >= 0) {
      const [m] = this._inbox.splice(buffered, 1);
      return Promise.resolve(m.message);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this._waiters.findIndex((w) => w.timer === timer);
        if (i >= 0) this._waiters.splice(i, 1);
        reject(new Error(`mediator-transport: timeout waiting for response (thid ${thid})`));
      }, timeoutMs);
      this._waiters.push({ thid, resolve, reject, timer });
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

export { LIVE_DELIVERY_CHANGE_TYPE };

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
