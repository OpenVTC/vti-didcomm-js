import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildLiveDeliveryChange,
  buildMessagesReceived,
  peekSkid,
  unpackInbound,
  MediatorSession,
  LIVE_DELIVERY_CHANGE_TYPE,
} from "../src/mediator-transport.js";
import { pack } from "../src/pack.js";
import { generateEphemeralClient } from "../src/vta-rest-auth.js";
import * as x25519 from "../src/x25519.js";
import * as multibase from "../src/multibase.js";
import * as jwk from "../src/jwk.js";

function keypairDid() {
  const kp = x25519.generateKeyPair();
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
  return {
    did: `did:key:${mb}`,
    kid: `did:key:${mb}#${mb}`,
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
  };
}

// Minimal browser-WebSocket stand-in: records sent frames, fires
// onopen on the next tick, and lets the test push inbound frames.
class FakeWebSocket {
  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.sent = [];
    this.closed = false;
    this.readyState = 0; // CONNECTING
    this.onopen = null;
    this.onmessage = null;
    this.onerror = null;
    this.onclose = null;
    FakeWebSocket.last = this;
    setTimeout(() => {
      this.readyState = 1; // OPEN
      this.onopen && this.onopen();
    }, 0);
  }
  addEventListener() {}
  send(data) {
    this.sent.push(data);
  }
  close() {
    this.closed = true;
    this.readyState = 3; // CLOSED
    this.onclose && this.onclose();
  }
  // Test helper: simulate the mediator pushing a frame.
  inject(data) {
    this.onmessage && this.onmessage({ data });
  }
}

test("buildLiveDeliveryChange: correct type, body, return_route", () => {
  const m = buildLiveDeliveryChange({ from: "did:key:zC", mediatorDid: "did:key:zM" });
  assert.equal(m.type, LIVE_DELIVERY_CHANGE_TYPE);
  assert.equal(m.body.live_delivery, true);
  assert.equal(m.return_route, "all");
  assert.equal(m.from, "did:key:zC");
  assert.deepEqual(m.to, ["did:key:zM"]);
});

test("peekSkid: reads skid from a packed authcrypt JWE", async () => {
  const client = generateEphemeralClient();
  const recip = keypairDid();
  const jwe = await pack({
    message: { id: "1", type: "t", from: client.did, to: [recip.did], body: {} },
    sender: {
      kid: client.kid,
      privateJwk: jwk.privateJwk("X25519", client.privateKey, client.publicKey),
    },
    recipient: { kid: recip.kid, publicJwk: jwk.publicJwk("X25519", recip.publicKey) },
  });
  assert.equal(peekSkid(jwe), client.kid);
  assert.equal(peekSkid("not json"), null);
});

test("unpackInbound: dispatches by skid to the right sender key", async () => {
  // Two senders: a 'VTA' and a 'mediator'. A frame from each must
  // unpack via its own seeded key.
  const me = keypairDid();
  const vta = generateEphemeralClient();
  const med = generateEphemeralClient();

  const senderKeys = new Map([
    [vta.did, { publicJwk: jwk.publicJwk("X25519", vta.publicKey) }],
    [med.did, { publicJwk: jwk.publicJwk("X25519", med.publicKey) }],
  ]);
  const recipient = {
    kid: me.kid,
    privateJwk: jwk.privateJwk("X25519", me.privateKey, me.publicKey),
  };

  const fromVta = await pack({
    message: { id: "r1", type: "resp", thid: "req1", from: vta.did, to: [me.did], body: { ok: 1 } },
    sender: { kid: vta.kid, privateJwk: jwk.privateJwk("X25519", vta.privateKey, vta.publicKey) },
    recipient: { kid: me.kid, publicJwk: jwk.publicJwk("X25519", me.publicKey) },
  });
  const out = await unpackInbound(fromVta, { recipient, senderKeys });
  assert.equal(out.message.thid, "req1");
  assert.equal(out.message.body.ok, 1);
  assert.equal(out.senderKid, vta.kid);
});

test("unpackInbound: errors on unknown sender (no key, no resolver)", async () => {
  const me = keypairDid();
  const stranger = generateEphemeralClient();
  const jwe = await pack({
    message: { id: "x", type: "t", from: stranger.did, to: [me.did], body: {} },
    sender: {
      kid: stranger.kid,
      privateJwk: jwk.privateJwk("X25519", stranger.privateKey, stranger.publicKey),
    },
    recipient: { kid: me.kid, publicJwk: jwk.publicJwk("X25519", me.publicKey) },
  });
  await assert.rejects(
    () =>
      unpackInbound(jwe, {
        recipient: { kid: me.kid, privateJwk: jwk.privateJwk("X25519", me.privateKey, me.publicKey) },
        senderKeys: new Map(),
      }),
    /no sender key/,
  );
});

test("MediatorSession: connect sends live-delivery-change; waitFor resolves on matching thid", async () => {
  const client = generateEphemeralClient();
  const vta = generateEphemeralClient();
  const mediatorKp = keypairDid();
  const mediator = {
    did: mediatorKp.did,
    kid: mediatorKp.kid,
    x25519Pub: mediatorKp.publicKey,
    wsEndpoint: "wss://mediator.test/ws",
  };

  const session = new MediatorSession({
    mediator,
    mediatorJwt: "med.jwt.token",
    client,
    senderKeys: new Map([[vta.did, { publicJwk: jwk.publicJwk("X25519", vta.publicKey) }]]),
    WebSocketImpl: FakeWebSocket,
  });

  await session.connect();
  const ws = FakeWebSocket.last;

  // Subprotocol bearer + a non-bearer app entry (so the mediator can
  // echo one back and a spec-strict client accepts the 101).
  assert.equal(ws.protocols[0], "bearer.med.jwt.token");
  assert.equal(ws.protocols.length, 2);
  assert.ok(!ws.protocols[1].startsWith("bearer."));
  // connect() sent exactly one frame: the live-delivery-change,
  // authcrypt'd to the mediator. Unpack it as the mediator to verify.
  assert.equal(ws.sent.length, 1);
  const { unpack } = await import("../src/unpack.js");
  const ldc = await unpack(ws.sent[0], {
    kid: mediatorKp.kid,
    privateJwk: jwk.privateJwk("X25519", mediatorKp.privateKey, mediatorKp.publicKey),
  }, { publicJwk: jwk.publicJwk("X25519", client.publicKey) });
  assert.equal(ldc.message.type, LIVE_DELIVERY_CHANGE_TYPE);
  assert.equal(ldc.message.return_route, "all");

  // Now simulate the VTA's response arriving over the socket: a
  // message authcrypt'd VTA→client with thid == our request id.
  const reqId = "urn:uuid:req-42";
  const responseJwe = await pack({
    message: {
      id: "urn:uuid:resp-1",
      type: "https://trusttasks.org/spec/vta/discovery/capabilities/1.0/response",
      thid: reqId,
      from: vta.did,
      to: [client.did],
      body: { capabilities: ["a", "b"] },
    },
    sender: { kid: vta.kid, privateJwk: jwk.privateJwk("X25519", vta.privateKey, vta.publicKey) },
    recipient: { kid: client.kid, publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  });

  const waiter = session.waitFor(reqId, 2000);
  ws.inject(responseJwe);
  const response = await waiter;
  assert.equal(response.thid, reqId);
  assert.deepEqual(response.body.capabilities, ["a", "b"]);

  session.close();
  assert.ok(ws.closed);
});

test("buildMessagesReceived: correct type + message_id_list", () => {
  const m = buildMessagesReceived({
    from: "did:key:zC",
    mediatorDid: "did:key:zM",
    messageIds: ["urn:uuid:a", "urn:uuid:b"],
  });
  assert.equal(m.type, "https://didcomm.org/messagepickup/3.0/messages-received");
  assert.deepEqual(m.body.message_id_list, ["urn:uuid:a", "urn:uuid:b"]);
  assert.equal(m.from, "did:key:zC");
  assert.deepEqual(m.to, ["did:key:zM"]);
});

test("MediatorSession: acks delivered messages with sha256(packed-JWE) so the mediator stops replaying them", async () => {
  const client = generateEphemeralClient();
  const vta = generateEphemeralClient();
  const mediatorKp = keypairDid();
  const mediator = {
    did: mediatorKp.did,
    kid: mediatorKp.kid,
    x25519Pub: mediatorKp.publicKey,
    wsEndpoint: "wss://mediator.test/ws",
  };

  const received = [];
  const session = new MediatorSession({
    mediator,
    mediatorJwt: "med.jwt.token",
    client,
    senderKeys: new Map([[vta.did, { publicJwk: jwk.publicJwk("X25519", vta.publicKey) }]]),
    WebSocketImpl: FakeWebSocket,
    onMessage: (msg) => received.push(msg),
  });

  await session.connect();
  const ws = FakeWebSocket.last;
  assert.equal(ws.sent.length, 1); // live-delivery-change only

  // An unsolicited inbound message (no waiter claims it) — e.g. an
  // RP-initiated confirm request.
  const inboundId = "urn:uuid:inbound-7";
  const inboundJwe = await pack({
    message: {
      id: inboundId,
      type: "https://trusttasks.org/wallet/confirm/1.0",
      from: vta.did,
      to: [client.did],
      body: { challenge: "c1" },
    },
    sender: { kid: vta.kid, privateJwk: jwk.privateJwk("X25519", vta.privateKey, vta.publicKey) },
    recipient: { kid: client.kid, publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  });

  ws.inject(inboundJwe);
  // The ack is packed asynchronously; let microtasks/timers settle.
  await new Promise((r) => setTimeout(r, 100));

  assert.equal(received.length, 1);
  // A second frame was sent: the messages-received ack, authcrypt'd to
  // the mediator. Unpack it as the mediator and check the id list.
  assert.equal(ws.sent.length, 2);
  const { unpack } = await import("../src/unpack.js");
  const ack = await unpack(
    ws.sent[1],
    { kid: mediatorKp.kid, privateJwk: jwk.privateJwk("X25519", mediatorKp.privateKey, mediatorKp.publicKey) },
    { publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  );
  assert.equal(ack.message.type, "https://didcomm.org/messagepickup/3.0/messages-received");
  // The mediator's queue-id is sha256(packed JWE bytes) — the inner
  // message id is set by the original sender and is unknown to the
  // mediator. See memory_store.rs `store_message`.
  const expectedQueueId = await sha256HexUtf8(inboundJwe);
  assert.deepEqual(ack.message.body.message_id_list, [expectedQueueId]);
  // Negative assertion guards the regression — the previous
  // implementation acked with the inner DIDComm id, which 404'd at the
  // mediator and let the message be replayed forever.
  assert.notDeepEqual(ack.message.body.message_id_list, [inboundId]);

  session.close();
});

test("MediatorSession: does NOT ack frames from the mediator itself (status / problem-report)", async () => {
  // Acking a mediator status reply provokes another status reply
  // (the `messages-received` handler always emits one), which is also
  // from the mediator — so an unfiltered ack creates an infinite
  // ack/status ping-pong over the socket. Filter by sender DID.
  const client = generateEphemeralClient();
  const mediatorKp = keypairDid();
  const mediator = {
    did: mediatorKp.did,
    kid: mediatorKp.kid,
    x25519Pub: mediatorKp.publicKey,
    wsEndpoint: "wss://mediator.test/ws",
  };

  const session = new MediatorSession({
    mediator,
    mediatorJwt: "med.jwt.token",
    client,
    WebSocketImpl: FakeWebSocket,
  });

  await session.connect();
  const ws = FakeWebSocket.last;
  assert.equal(ws.sent.length, 1); // live-delivery-change only

  // A status reply from the mediator, addressed to the client.
  const statusJwe = await pack({
    message: {
      id: "urn:uuid:status-1",
      type: "https://didcomm.org/messagepickup/3.0/status",
      thid: "urn:uuid:req-x",
      from: mediatorKp.did,
      to: [client.did],
      body: { message_count: 0, live_delivery: true },
    },
    sender: {
      kid: mediatorKp.kid,
      privateJwk: jwk.privateJwk("X25519", mediatorKp.privateKey, mediatorKp.publicKey),
    },
    recipient: { kid: client.kid, publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  });

  ws.inject(statusJwe);
  await new Promise((r) => setTimeout(r, 100));

  // No second frame — the status was processed silently, no ack sent.
  assert.equal(ws.sent.length, 1);

  session.close();
});

// Match the mediator's `sha256::digest(message.as_bytes())` byte-for-byte:
// lowercase hex over the UTF-8 bytes of the packed JWE text.
async function sha256HexUtf8(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

test("MediatorSession: waitFor times out when no matching frame arrives", async () => {
  const client = generateEphemeralClient();
  const mediatorKp = keypairDid();
  const session = new MediatorSession({
    mediator: { did: mediatorKp.did, kid: mediatorKp.kid, x25519Pub: mediatorKp.publicKey, wsEndpoint: "wss://m.test/ws" },
    mediatorJwt: "jwt",
    client,
    WebSocketImpl: FakeWebSocket,
  });
  await session.connect();
  await assert.rejects(() => session.waitFor("nope", 50), /timeout waiting for response/);
  session.close();
});

test("MediatorSession: requires a wsEndpoint", () => {
  const client = generateEphemeralClient();
  assert.throws(
    () =>
      new MediatorSession({
        mediator: { did: "did:key:zM", kid: "did:key:zM#k", x25519Pub: new Uint8Array(32) },
        mediatorJwt: "jwt",
        client,
        WebSocketImpl: FakeWebSocket,
      }),
    /wsEndpoint required/,
  );
});

// ── Connect-failure diagnostics ────────────────────────────────────
//
// A WebSocket stand-in whose upgrade FAILS: it fires `error` (detail-
// free, like a browser) then `close` with a caller-chosen code/reason,
// without ever firing `onopen`.
class FailingWebSocket {
  static code = 1006;
  static reason = "";
  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.onopen = null;
    this.onmessage = null;
    this.onerror = null;
    this.onclose = null;
    setTimeout(() => {
      this.onerror && this.onerror({});
      this.onclose && this.onclose({ code: FailingWebSocket.code, reason: FailingWebSocket.reason });
    }, 0);
  }
  addEventListener() {}
  send() {}
  close() {}
}

function failingSession(jwt = "med.jwt.token", { connectTimeoutMs } = {}) {
  const m = keypairDid();
  return new MediatorSession({
    mediator: { did: m.did, kid: m.kid, x25519Pub: m.publicKey, wsEndpoint: "wss://mediator.test/ws" },
    mediatorJwt: jwt,
    client: generateEphemeralClient(),
    WebSocketImpl: FailingWebSocket,
    connectTimeoutMs,
  });
}

test("connect failure: 1008 surfaces the close code + mediator-ACL hint", async () => {
  FailingWebSocket.code = 1008;
  FailingWebSocket.reason = "unauthorized";
  const session = failingSession();
  await assert.rejects(
    () => session.connect(),
    (err) => {
      assert.match(err.message, /close code 1008/);
      assert.match(err.message, /unauthorized/);
      assert.match(err.message, /MEDIATOR's ACL/);
      assert.equal(err.code, 1008);
      assert.equal(err.endpoint, "wss://mediator.test/ws");
      return true;
    },
  );
});

test("connect failure: 1006 explains a refused/blackholed upgrade", async () => {
  FailingWebSocket.code = 1006;
  FailingWebSocket.reason = "";
  const session = failingSession();
  await assert.rejects(
    () => session.connect(),
    (err) => {
      assert.match(err.message, /close code 1006/);
      assert.match(err.message, /upgrade was most likely refused|proxy/);
      return true;
    },
  );
});

test("connect failure: a born-expired bearer token is flagged", async () => {
  FailingWebSocket.code = 1008;
  FailingWebSocket.reason = "";
  // JWT with exp 1h in the past (signature irrelevant — we never verify).
  const past = Math.floor(new Date().getTime() / 1000) - 3600;
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const jwt = `${b64({ alg: "none" })}.${b64({ exp: past })}.sig`;
  const session = failingSession(jwt);
  await assert.rejects(
    () => session.connect(),
    (err) => {
      assert.match(err.message, /already EXPIRED/);
      return true;
    },
  );
});

test("connect failure: times out when no event ever fires", async () => {
  // A socket that never opens, errors, or closes.
  class SilentWebSocket {
    constructor() {}
    addEventListener() {}
    send() {}
    close() {}
  }
  const m = keypairDid();
  const session = new MediatorSession({
    mediator: { did: m.did, kid: m.kid, x25519Pub: m.publicKey, wsEndpoint: "wss://mediator.test/ws" },
    mediatorJwt: "med.jwt.token",
    client: generateEphemeralClient(),
    WebSocketImpl: SilentWebSocket,
    connectTimeoutMs: 20,
  });
  await assert.rejects(() => session.connect(), /silently dropped|within 20ms/);
});

// ── Inbound resilience: a bad frame must not stick the loop ─────────
test("inbound: a poison frame is logged via onError and the next good frame still resolves", async () => {
  const client = generateEphemeralClient();
  const vta = generateEphemeralClient();
  const mediatorKp = keypairDid();
  const mediator = {
    did: mediatorKp.did,
    kid: mediatorKp.kid,
    x25519Pub: mediatorKp.publicKey,
    wsEndpoint: "wss://mediator.test/ws",
  };

  const errors = [];
  const session = new MediatorSession({
    mediator,
    mediatorJwt: "med.jwt.token",
    client,
    senderKeys: new Map([[vta.did, { publicJwk: jwk.publicJwk("X25519", vta.publicKey) }]]),
    WebSocketImpl: FakeWebSocket,
    onError: (err) => errors.push(err),
  });
  await session.connect();
  const ws = FakeWebSocket.last;

  const reqId = "urn:uuid:after-poison";
  const waiting = session.waitFor(reqId, 1000);

  // 1) A poison frame: not even valid JSON. Must be logged, not thrown.
  ws.inject("}{ this is not a JWE");
  // 2) A second poison frame: valid JSON but undecryptable by us.
  ws.inject(JSON.stringify({ protected: "x", ciphertext: "y", tag: "z" }));
  // 3) A good frame from the VTA with the awaited thid — must still resolve.
  const good = await pack({
    message: { id: "urn:uuid:resp", type: "t", from: vta.did, to: [client.did], thid: reqId, body: { ok: true } },
    sender: { kid: vta.kid, privateJwk: jwk.privateJwk("X25519", vta.privateKey, vta.publicKey) },
    recipient: { kid: client.kid, publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  });
  ws.inject(good);

  const msg = await waiting;
  assert.equal(msg.body.ok, true, "the good frame after two poison frames still resolves");
  assert.ok(errors.length >= 2, `both poison frames were logged (got ${errors.length})`);
  assert.match(errors[0].message, /failed to (unpack|dispatch) inbound/);
});
