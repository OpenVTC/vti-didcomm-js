// The authenticated sender of an authcrypt message is the DID of its `skid`,
// and that is what consumers are handed. `from` is sender-written plaintext:
// `unpack` refuses an authcrypt message whose `from` is anything but the
// `skid` DID, and the mediator transport passes the proven sender to its
// listeners and waiters so nothing downstream has to read `from` at all.

import { test } from "node:test";
import assert from "node:assert/strict";

import { pack } from "../src/pack.js";
import { packAnoncrypt } from "../src/anoncrypt.js";
import { unpack, SenderMismatchError, E_SENDER_MISMATCH } from "../src/unpack.js";
import { MediatorSession } from "../src/mediator-transport.js";
import { generateEphemeralClient } from "../src/vta-rest-auth.js";
import * as jwk from "../src/jwk.js";
import * as x25519 from "../src/x25519.js";
import * as multibase from "../src/multibase.js";

function party() {
  const kp = x25519.generateKeyPair();
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
  const did = `did:key:${mb}`;
  return {
    did,
    kid: `${did}#${mb}`,
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
    privateJwk: jwk.privateJwk("X25519", kp.privateKey, kp.publicKey),
    publicJwk: jwk.publicJwk("X25519", kp.publicKey),
  };
}

async function authcrypt(from, sender, recipient, extra = {}) {
  const message = { id: `urn:uuid:${Math.random()}`, type: "t", to: [recipient.did], body: {}, ...extra };
  if (from !== undefined) message.from = from;
  return pack({
    message,
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  });
}

function open(jwe, recipient, sender) {
  return unpack(jwe, { kid: recipient.kid, privateJwk: recipient.privateJwk }, sender && { publicJwk: sender.publicJwk });
}

// ── unpack ──────────────────────────────────────────────────────────────

test("authcrypt: the proven sender is returned as senderDid/senderKid", async () => {
  const alice = party();
  const bob = party();
  const out = await open(await authcrypt(alice.did, alice, bob), bob, alice);
  assert.equal(out.authenticated, true);
  assert.equal(out.senderKid, alice.kid);
  assert.equal(out.senderDid, alice.did);
  assert.equal(out.message.from, alice.did);
});

test("authcrypt: a `from` naming another DID than the skid is refused", async () => {
  // The attacker authcrypts with its own key (so the envelope authenticates
  // as the attacker) and writes the victim's DID into `from`.
  const victim = party();
  const attacker = party();
  const bob = party();
  const jwe = await authcrypt(victim.did, attacker, bob);
  await assert.rejects(
    () => open(jwe, bob, attacker),
    (err) =>
      err instanceof SenderMismatchError &&
      err.code === E_SENDER_MISMATCH &&
      err.senderDid === attacker.did &&
      err.claimedFrom === victim.did,
  );
});

test("authcrypt: a missing `from` is refused", async () => {
  const alice = party();
  const bob = party();
  const jwe = await authcrypt(undefined, alice, bob);
  await assert.rejects(() => open(jwe, bob, alice), { code: E_SENDER_MISMATCH });
});

test("authcrypt: `from` must be the DID itself, not a DID URL", async () => {
  const alice = party();
  const bob = party();
  const jwe = await authcrypt(alice.kid, alice, bob);
  await assert.rejects(() => open(jwe, bob, alice), { code: E_SENDER_MISMATCH });
});

test("anoncrypt: no sender, whatever `from` claims", async () => {
  const victim = party();
  const bob = party();
  const jwe = await packAnoncrypt({
    message: { id: "a1", type: "t", from: victim.did, to: [bob.did], body: {} },
    recipient: { kid: bob.kid, publicJwk: bob.publicJwk },
  });
  const out = await open(jwe, bob);
  assert.equal(out.authenticated, false);
  assert.equal(out.senderDid, null);
  assert.equal(out.senderKid, null);
});

// ── MediatorSession ─────────────────────────────────────────────────────

class FakeWebSocket {
  constructor() {
    this.sent = [];
    this.readyState = 0;
    FakeWebSocket.last = this;
    setTimeout(() => {
      this.readyState = 1;
      this.onopen && this.onopen();
    }, 0);
  }
  addEventListener() {}
  send(d) {
    this.sent.push(d);
  }
  close() {
    this.readyState = 3;
  }
  inject(data) {
    this.onmessage && this.onmessage({ data });
  }
}

const settle = () => new Promise((r) => setTimeout(r, 50));

async function sessionFixture(extra = {}) {
  const client = generateEphemeralClient();
  const vta = party();
  const attacker = party();
  const med = party();
  const received = [];
  const errors = [];
  const session = new MediatorSession({
    mediator: { did: med.did, kid: med.kid, x25519Pub: med.publicKey, wsEndpoint: "wss://m.example/ws" },
    mediatorJwt: "jwt",
    client,
    senderKeys: new Map([
      [vta.did, { publicJwk: vta.publicJwk }],
      [attacker.did, { publicJwk: attacker.publicJwk }],
    ]),
    WebSocketImpl: FakeWebSocket,
    onMessage: (message, thid, sender) => received.push({ message, thid, sender }),
    onError: (err, info) => errors.push({ err, info }),
    ...extra,
  });
  await session.connect();
  const me = {
    did: client.did,
    kid: client.kid,
    publicJwk: jwk.publicJwk("X25519", client.publicKey),
  };
  return { session, ws: FakeWebSocket.last, vta, attacker, me, received, errors };
}

test("session: a genuine message reaches onMessage with its verified sender", async () => {
  const { session, ws, vta, me, received } = await sessionFixture();
  ws.inject(await authcrypt(vta.did, vta, me));
  await settle();
  assert.equal(received.length, 1);
  assert.deepEqual(received[0].sender, { did: vta.did, kid: vta.kid });
  assert.ok(Object.isFrozen(received[0].sender));
  assert.equal(ws.sent.length, 2, "live-delivery-change, then the ack");
  session.close();
});

test("session: a forged `from` is never delivered, and is not acked", async () => {
  const { session, ws, vta, attacker, me, received, errors } = await sessionFixture();
  ws.inject(await authcrypt(vta.did, attacker, me));
  await settle();
  assert.equal(received.length, 0, "a message claiming the VTA from the attacker's key must not surface");
  assert.equal(errors.length, 1);
  assert.equal(errors[0].info.cause.code, E_SENDER_MISMATCH, String(errors[0].err.message));
  assert.equal(ws.sent.length, 1, "refused before the ack");
  session.close();
});

test("session: waitFor resolves with the reply and its verified sender", async () => {
  const { session, ws, vta, me } = await sessionFixture();
  const waiting = session.waitFor("urn:uuid:req", 1000, { from: vta.did });
  ws.inject(await authcrypt(vta.did, vta, me, { thid: "urn:uuid:req" }));
  const { message, sender } = await waiting;
  assert.equal(message.thid, "urn:uuid:req");
  assert.equal(sender.did, vta.did);
  session.close();
});

test("session: a waiter bound to one sender ignores another sender on its thread", async () => {
  const { session, ws, vta, attacker, me, received } = await sessionFixture();
  const waiting = session.waitFor("urn:uuid:req", 1000, { from: vta.did });
  // The attacker knows the thread id and answers it under its own identity.
  ws.inject(await authcrypt(attacker.did, attacker, me, { thid: "urn:uuid:req", body: { forged: true } }));
  await settle();
  assert.equal(received.length, 1, "the attacker's frame falls through to the listener");
  assert.equal(received[0].sender.did, attacker.did);
  ws.inject(await authcrypt(vta.did, vta, me, { thid: "urn:uuid:req", body: { real: true } }));
  const { message, sender } = await waiting;
  assert.equal(sender.did, vta.did);
  assert.deepEqual(message.body, { real: true });
  // Nor does a later bound waiter pick the attacker's buffered frame up.
  await assert.rejects(() => session.waitFor("urn:uuid:req", 30, { from: vta.did }), /timeout/);
  session.close();
});

test("session: waitFor rejects a malformed `from`", async () => {
  const { session } = await sessionFixture();
  assert.throws(() => session.waitFor("t", 10, { from: [] }), TypeError);
  assert.throws(() => session.waitFor("t", 10, { from: [""] }), TypeError);
  session.close();
});
