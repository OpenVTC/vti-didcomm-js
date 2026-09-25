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
import { MediatorSession, unpackInbound, E_UNAUTHENTICATED_FRAME } from "../src/mediator-transport.js";
import { generateEphemeralClient } from "../src/vta-rest-auth.js";
import * as jwk from "../src/jwk.js";
import * as x25519 from "../src/x25519.js";
import * as multibase from "../src/multibase.js";
import * as b64u from "../src/base64url.js";
import * as aes from "../src/aes.js";
import * as a256cbcHs512 from "../src/a256cbc-hs512.js";
import * as ecdhEs from "../src/ecdh-es.js";
import * as keyAgreement from "../src/key-agreement.js";

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
//
// No timers: every wait is on the event it is waiting for — a frame sent, a
// message delivered, an error reported.

/** Resolves when `pred()` holds, re-checked each time `signal` fires. */
function waitable() {
  const waiters = [];
  return {
    fire() {
      for (const w of waiters.splice(0)) if (!w.pred()) waiters.push(w); else w.resolve();
    },
    until(pred) {
      if (pred()) return Promise.resolve();
      return new Promise((resolve) => waiters.push({ pred, resolve }));
    },
  };
}

class FakeWebSocket {
  constructor() {
    this.sent = [];
    this.readyState = 0;
    this.sends = waitable();
    FakeWebSocket.last = this;
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen && this.onopen();
    });
  }
  addEventListener() {}
  send(d) {
    this.sent.push(d);
    this.sends.fire();
  }
  close() {
    this.readyState = 3;
  }
  inject(data) {
    this.onmessage && this.onmessage({ data });
  }
  /** Resolves once `n` frames have been sent. */
  sentCount(n) {
    return this.sends.until(() => this.sent.length >= n);
  }
}

async function sessionFixture(extra = {}) {
  const client = generateEphemeralClient();
  const vta = party();
  const attacker = party();
  const med = party();
  const received = [];
  const errors = [];
  const events = waitable();
  const session = new MediatorSession({
    mediator: { did: med.did, kid: med.kid, x25519Pub: med.publicKey, wsEndpoint: "wss://m.example/ws" },
    mediatorJwt: "jwt",
    client,
    senderKeys: new Map([
      [vta.did, { kid: vta.kid, publicJwk: vta.publicJwk }],
      [attacker.did, { kid: attacker.kid, publicJwk: attacker.publicJwk }],
    ]),
    WebSocketImpl: FakeWebSocket,
    onMessage: (message, thid, sender) => {
      received.push({ message, thid, sender });
      events.fire();
    },
    onError: (err, info) => {
      errors.push({ err, info });
      events.fire();
    },
    ...extra,
  });
  await session.connect();
  const me = {
    did: client.did,
    kid: client.kid,
    publicJwk: jwk.publicJwk("X25519", client.publicKey),
  };
  const until = (pred) => events.until(pred);
  return { session, ws: FakeWebSocket.last, vta, attacker, med, me, received, errors, until };
}

test("session: a genuine message reaches onMessage with its verified sender", async () => {
  const { session, ws, vta, me, received, until } = await sessionFixture();
  ws.inject(await authcrypt(vta.did, vta, me));
  await until(() => received.length === 1);
  await ws.sentCount(2); // live-delivery-change, then the ack
  assert.deepEqual(received[0].sender, { did: vta.did, kid: vta.kid });
  assert.ok(Object.isFrozen(received[0].sender));
  session.close();
});

test("session: a forged `from` is never delivered, and is acked and dropped", async () => {
  const { session, ws, vta, attacker, me, received, errors, until } = await sessionFixture();
  const frame = await authcrypt(vta.did, attacker, me);
  ws.inject(frame);
  await until(() => errors.length === 1);
  await ws.sentCount(2);
  assert.equal(received.length, 0, "a message claiming the VTA from the attacker's key must not surface");
  assert.equal(errors[0].info.cause.code, E_SENDER_MISMATCH, String(errors[0].err.message));
  assert.match(errors[0].err.message, /refused and dropped/);
  assert.equal(ws.sent.length, 2, "acked so the mediator stops redelivering it");
  session.close();
});

/** Anoncrypt, but with a `skid` in its protected header (which anoncrypt
 *  never carries) — so it reaches the unpacker with a sender "named". */
async function anoncryptWithSkid(message, recipient, skid) {
  const crv = jwk.curveOf(recipient.publicJwk);
  const ephem = keyAgreement.generateKeyPair(crv);
  const { cek, iv } = a256cbcHs512.generateCekAndIv();
  const apv = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(recipient.kid)));
  const header = {
    typ: "application/didcomm-encrypted+json",
    alg: "ECDH-ES+A256KW",
    enc: "A256CBC-HS512",
    apv: b64u.encode(apv),
    skid,
    epk: jwk.publicJwk(crv, ephem.publicKey),
  };
  const protectedB64 = b64u.encode(new TextEncoder().encode(JSON.stringify(header)));
  const { ciphertext, tag } = await a256cbcHs512.encrypt({
    cek,
    iv,
    aad: new TextEncoder().encode(protectedB64),
    plaintext: new TextEncoder().encode(JSON.stringify(message)),
  });
  const kek = await ecdhEs.deriveKekAnoncrypt({
    ephemeralPrivate: ephem.privateKey,
    recipientPublic: jwk.rawPublic(recipient.publicJwk),
    alg: "ECDH-ES+A256KW",
    apu: new Uint8Array(),
    apv,
    crv,
  });
  return JSON.stringify({
    protected: protectedB64,
    recipients: [{ header: { kid: recipient.kid }, encrypted_key: b64u.encode(await aes.wrapKey(kek, cek)) }],
    iv: b64u.encode(iv),
    ciphertext: b64u.encode(ciphertext),
    tag: b64u.encode(tag),
  });
}

test("session: an anoncrypt frame carrying a skid header is acked and dropped", async () => {
  const { session, ws, vta, me, received, errors, until } = await sessionFixture();
  ws.inject(await anoncryptWithSkid({ id: "a", type: "t", from: vta.did, to: [me.did], body: {} }, me, vta.kid));
  await until(() => errors.length === 1);
  await ws.sentCount(2);
  assert.equal(received.length, 0, "nothing authenticated it, so nothing is delivered");
  assert.equal(errors[0].info.cause.code, E_UNAUTHENTICATED_FRAME, String(errors[0].err.message));
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
  const { session, ws, vta, attacker, me, received, until } = await sessionFixture();
  const waiting = session.waitFor("urn:uuid:req", 1000, { from: vta.did });
  // The attacker knows the thread id and answers it under its own identity.
  ws.inject(await authcrypt(attacker.did, attacker, me, { thid: "urn:uuid:req", body: { forged: true } }));
  await until(() => received.length === 1);
  assert.equal(received[0].sender.did, attacker.did, "the attacker's frame falls through to the listener");
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

// ── Sender key selection ────────────────────────────────────────────────

test("unpackInbound: the key is selected by the exact skid, not by the DID", async () => {
  const alice = party();
  const bob = party();
  const jwe = await authcrypt(alice.did, alice, bob);
  const recipient = { kid: bob.kid, privateJwk: bob.privateJwk };
  // A seeded key for alice's DID under another key id does not match.
  await assert.rejects(
    () =>
      unpackInbound(jwe, {
        recipient,
        senderKeys: new Map([[alice.did, { kid: `${alice.did}#other`, publicJwk: alice.publicJwk }]]),
      }),
    /no key .* for sender/,
  );
  // Nor does one with no key id at all.
  await assert.rejects(
    () => unpackInbound(jwe, { recipient, senderKeys: new Map([[alice.did, { publicJwk: alice.publicJwk }]]) }),
    /no key .* for sender/,
  );
  // The exact key id — absolute or relative — does, and is what is reported.
  for (const kid of [alice.kid, `#${alice.kid.split("#")[1]}`]) {
    const out = await unpackInbound(jwe, {
      recipient,
      senderKeys: new Map([[alice.did, [{ kid: `${alice.did}#other`, publicJwk: bob.publicJwk }, { kid, publicJwk: alice.publicJwk }]]]),
    });
    assert.equal(out.senderKid, alice.kid);
  }
  // The resolver is asked for the skid, and its answer is held to it too.
  const asked = [];
  const out = await unpackInbound(jwe, {
    recipient,
    senderKeys: new Map(),
    resolveSender: async (did, skid) => {
      asked.push([did, skid]);
      return { kid: skid, publicJwk: alice.publicJwk };
    },
  });
  assert.deepEqual(asked, [[alice.did, alice.kid]]);
  assert.equal(out.senderKid, alice.kid);
});
