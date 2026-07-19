// R1.6 — persist before ack.
//
// The delivery ack tells the mediator to delete its queued copy, so it is the
// point of no return: after it, the consumer holds the only copy. A consumer
// that dies between the ack and its own persist loses the message for good.
// `beforeAck` is awaited while the mediator's copy still exists.

import { test } from "node:test";
import assert from "node:assert/strict";

import { MediatorSession } from "../src/mediator-transport.js";
import { pack } from "../src/pack.js";
import { unpack } from "../src/unpack.js";
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

class FakeWebSocket {
  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.sent = [];
    this.closed = false;
    this.readyState = 0;
    this.onopen = null;
    this.onmessage = null;
    this.onerror = null;
    this.onclose = null;
    FakeWebSocket.last = this;
    setTimeout(() => {
      this.readyState = 1;
      this.onopen && this.onopen();
    }, 0);
  }
  addEventListener() {}
  send(data) {
    this.sent.push(data);
  }
  close() {
    this.closed = true;
    this.readyState = 3;
    this.onclose && this.onclose();
  }
  inject(data) {
    this.onmessage && this.onmessage({ data });
  }
}

/** Stand up a connected session plus a packed VTA→client message. */
async function harness(opts = {}) {
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
    ...opts,
  });
  await session.connect();
  const ws = FakeWebSocket.last;
  ws.sent.length = 0; // drop the live-delivery-change

  const jwe = await pack({
    message: {
      id: "urn:uuid:consent-1",
      type: "https://trusttasks.org/spec/task-consent/request/0.1",
      from: vta.did,
      to: [client.did],
      body: { payloadDigest: "z6Mkdigest", challenge: "c-1" },
    },
    sent: undefined,
    sender: { kid: vta.kid, privateJwk: jwk.privateJwk("X25519", vta.privateKey, vta.publicKey) },
    recipient: { kid: client.kid, publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  });

  /** Decrypt whatever the client sent to the mediator, as the mediator. */
  const readSent = async (i) =>
    (
      await unpack(
        ws.sent[i],
        {
          kid: mediatorKp.kid,
          privateJwk: jwk.privateJwk("X25519", mediatorKp.privateKey, mediatorKp.publicKey),
        },
        { publicJwk: jwk.publicJwk("X25519", client.publicKey) },
      )
    ).message;

  return { session, ws, jwe, readSent };
}

/** Let the fire-and-forget ack and the async dispatch settle. */
const settle = () => new Promise((r) => setTimeout(r, 20));

test("beforeAck runs BEFORE the ack reaches the mediator", async () => {
  const order = [];
  const { ws, jwe, readSent } = await harness({
    beforeAck: async (message, ctx) => {
      order.push("persist");
      assert.equal(message.type, "https://trusttasks.org/spec/task-consent/request/0.1");
      assert.equal(typeof ctx.queueId, "string");
      assert.ok(ctx.queueId.length > 0, "the mediator's queue id must be supplied");
      assert.equal(ctx.thid, "urn:uuid:consent-1");
    },
  });

  const originalSend = ws.send.bind(ws);
  ws.send = (data) => {
    order.push("ack");
    originalSend(data);
  };

  ws.inject(jwe);
  await settle();

  assert.deepEqual(order, ["persist", "ack"], "the persist must complete first");
  const ack = await readSent(0);
  assert.equal(ack.type, "https://didcomm.org/messagepickup/3.0/messages-received");
});

test("a slow persist delays the ack rather than racing it", async () => {
  // The window this closes: a hook that takes real time (an IndexedDB write)
  // must still finish before the mediator is told to forget the message.
  let done = false;
  const { ws, jwe } = await harness({
    beforeAck: async () => {
      await new Promise((r) => setTimeout(r, 40));
      done = true;
    },
  });

  ws.inject(jwe);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(ws.sent.length, 0, "no ack while the persist is still running");

  await new Promise((r) => setTimeout(r, 60));
  assert.equal(done, true);
  assert.equal(ws.sent.length, 1, "ack sent only after the persist resolved");
});

test("a rejecting beforeAck suppresses the ack so the mediator redelivers", async () => {
  // Losing a message is worse than handling it twice — consumers de-duplicate.
  const errors = [];
  const { ws, jwe } = await harness({
    beforeAck: async () => {
      throw new Error("IndexedDB is unavailable");
    },
    onError: (err) => errors.push(err),
  });

  ws.inject(jwe);
  await settle();

  assert.equal(ws.sent.length, 0, "a failed persist must NOT ack");
  assert.ok(
    errors.some((e) => String(e?.message ?? e).includes("IndexedDB is unavailable")),
    "the failure must be reported, not swallowed",
  );
});

test("a failed persist still delivers the message to the consumer", async () => {
  // The ack is suppressed, but the in-memory path continues: the user may
  // still act on the prompt now, and redelivery is de-duplicated later.
  const seen = [];
  const { ws, jwe } = await harness({
    beforeAck: async () => {
      throw new Error("nope");
    },
    onMessage: (m) => seen.push(m.id),
    onError: () => {},
  });

  ws.inject(jwe);
  await settle();
  assert.deepEqual(seen, ["urn:uuid:consent-1"]);
});

test("without beforeAck the ack still fires — existing consumers are unaffected", async () => {
  const { ws, jwe, readSent } = await harness();
  ws.inject(jwe);
  await settle();
  assert.equal(ws.sent.length, 1);
  const ack = await readSent(0);
  assert.equal(ack.type, "https://didcomm.org/messagepickup/3.0/messages-received");
});

test("the queueId handed to beforeAck is the one that gets acked", async () => {
  // A consumer keys its durable record by queueId; if that disagreed with the
  // acked id the record could never be reconciled against a redelivery.
  let handed;
  const { ws, jwe, readSent } = await harness({
    beforeAck: async (_m, ctx) => {
      handed = ctx.queueId;
    },
  });

  ws.inject(jwe);
  await settle();
  const ack = await readSent(0);
  assert.deepEqual(ack.body.message_id_list, [handed]);
});
