// P-256 authcrypt + anoncrypt round-trips (JS pack → JS unpack), and
// the curve-consistency guards in pack/unpack. The wire-compatibility
// proof against the Rust crate lives in roundtrip-rust.test.js.

import { test } from "node:test";
import assert from "node:assert/strict";

import { pack } from "../src/pack.js";
import { packAnoncrypt } from "../src/anoncrypt.js";
import { unpack } from "../src/unpack.js";
import * as jwk from "../src/jwk.js";
import * as p256 from "../src/p256.js";
import * as x25519 from "../src/x25519.js";
import * as didPeer from "../src/did-peer.js";
import * as multibase from "../src/multibase.js";
import { p256 as noble } from "@noble/curves/nist.js";

// Build a did:peer:2 with a single P-256 keyAgreement (E) key from a
// keypair, returning the DID, kid, and the keypair for the holder.
function p256PeerDid(kp) {
  const { x } = p256.pointCoordinates(kp.publicKey);
  const comp = new Uint8Array(33);
  comp[0] = kp.publicKey[64] & 1 ? 0x03 : 0x02;
  comp.set(x, 1);
  const eKey = multibase.encodeMultikey(multibase.MULTICODEC.P256_PUB, comp);
  return `did:peer:2.E${eKey}`;
}

// Turn a resolved P-256 keyAgreement verification method into a public JWK
// (decompress the multikey to an uncompressed SEC1 point).
function p256PubJwkFromVm(vm) {
  const { key } = multibase.decodeMultikey(vm.publicKeyMultibase);
  const uncompressed = noble.Point.fromBytes(key).toBytes(false);
  return jwk.publicJwk("P-256", uncompressed, vm.id);
}

function p256Party(kid) {
  const kp = p256.generateKeyPair();
  return {
    kid,
    priv: jwk.privateJwk("P-256", kp.privateKey, kp.publicKey, kid),
    pub: jwk.publicJwk("P-256", kp.publicKey, kid),
  };
}

test("P-256 authcrypt: JS pack → JS unpack round-trips", async () => {
  const sender = p256Party("did:key:zSenderP#p256-1");
  const recipient = p256Party("did:key:zRecipientP#p256-1");

  const message = {
    id: "msg-p256-1",
    type: "https://example.com/test/1.0",
    from: "did:key:zSenderP",
    to: ["did:key:zRecipientP"],
    body: { hello: "p256" },
  };

  const jwe = await pack({
    message,
    sender: { kid: sender.kid, privateJwk: sender.priv },
    recipient: { kid: recipient.kid, publicJwk: recipient.pub },
  });

  // The protected header's epk must be EC/P-256.
  const parsed = JSON.parse(jwe);
  const header = JSON.parse(Buffer.from(parsed.protected, "base64url").toString("utf8"));
  assert.equal(header.epk.kty, "EC");
  assert.equal(header.epk.crv, "P-256");
  assert.ok(header.epk.x && header.epk.y, "EC epk carries x and y");

  const out = await unpack(
    jwe,
    { kid: recipient.kid, privateJwk: recipient.priv },
    { publicJwk: sender.pub },
  );
  assert.deepEqual(out.message, message);
  assert.equal(out.authenticated, true);
  assert.equal(out.senderKid, sender.kid);
});

test("P-256 anoncrypt: JS pack → JS unpack round-trips", async () => {
  const recipient = p256Party("did:key:zRecipientP#p256-1");
  const message = { id: "m", type: "t", body: { secret: "anon-p256" } };

  const jwe = await packAnoncrypt({
    message,
    recipient: { kid: recipient.kid, publicJwk: recipient.pub },
  });

  const out = await unpack(jwe, { kid: recipient.kid, privateJwk: recipient.priv });
  assert.deepEqual(out.message, message);
  assert.equal(out.authenticated, false);
  assert.equal(out.senderKid, undefined);
});

test("P-256 authcrypt: wrong recipient private key fails to decrypt", async () => {
  const sender = p256Party("did:key:zS#p");
  const recipient = p256Party("did:key:zR#p");
  const eve = p256Party("did:key:zR#p"); // same kid, different key

  const jwe = await pack({
    message: { id: "m", type: "t", body: {} },
    sender: { kid: sender.kid, privateJwk: sender.priv },
    recipient: { kid: recipient.kid, publicJwk: recipient.pub },
  });

  await assert.rejects(
    unpack(jwe, { kid: recipient.kid, privateJwk: eve.priv }, { publicJwk: sender.pub }),
  );
});

test("pack rejects sender/recipient curve mismatch", async () => {
  const recipient = p256Party("did:key:zR#p");
  const xkp = x25519.generateKeyPair();
  const senderX = {
    kid: "did:key:zS#x",
    privateJwk: jwk.privateJwk("X25519", xkp.privateKey, xkp.publicKey, "did:key:zS#x"),
  };

  await assert.rejects(
    pack({
      message: { id: "m", type: "t", body: {} },
      sender: senderX,
      recipient: { kid: recipient.kid, publicJwk: recipient.pub },
    }),
    /sender key curve .* must match recipient curve/,
  );
});

test("end-to-end: resolve did:peer P-256 keyAgreement → authcrypt round-trip", async () => {
  // Two holders, each a did:peer:2 with a P-256 keyAgreement key.
  const senderKp = p256.generateKeyPair();
  const recipientKp = p256.generateKeyPair();
  const senderDid = p256PeerDid(senderKp);
  const recipientDid = p256PeerDid(recipientKp);

  // Resolve both — exactly what a DIDComm agent does before packing.
  const keyAgreementVm = (doc) =>
    doc.verificationMethod.find((v) => v.id === doc.keyAgreement[0]);
  const senderVm = keyAgreementVm(didPeer.resolve(senderDid).didDocument);
  const recipientVm = keyAgreementVm(didPeer.resolve(recipientDid).didDocument);

  const senderKid = `${senderDid}#key-1`;
  const recipientKid = recipientVm.id;

  const message = {
    id: "peer-p256",
    type: "https://example.com/test/1.0",
    from: senderDid,
    to: [recipientDid],
    body: { hello: "p256-over-did-peer" },
  };

  const jwe = await pack({
    message,
    sender: {
      kid: senderKid,
      privateJwk: jwk.privateJwk("P-256", senderKp.privateKey, senderKp.publicKey, senderKid),
    },
    recipient: { kid: recipientKid, publicJwk: p256PubJwkFromVm(recipientVm) },
  });

  const out = await unpack(
    jwe,
    {
      kid: recipientKid,
      privateJwk: jwk.privateJwk("P-256", recipientKp.privateKey, recipientKp.publicKey, recipientKid),
    },
    // The recipient resolves the sender's keyAgreement from skid.
    { publicJwk: p256PubJwkFromVm(senderVm) },
  );

  assert.deepEqual(out.message, message);
  assert.equal(out.authenticated, true);
  assert.equal(out.senderKid, senderKid);
});

test("unpack rejects recipient key whose curve differs from epk", async () => {
  const sender = p256Party("did:key:zS#p");
  const recipient = p256Party("did:key:zR#p");
  const jwe = await pack({
    message: { id: "m", type: "t", body: {} },
    sender: { kid: sender.kid, privateJwk: sender.priv },
    recipient: { kid: recipient.kid, publicJwk: recipient.pub },
  });

  // Recipient presents an X25519 key for a P-256 envelope.
  const xkp = x25519.generateKeyPair();
  const wrongCurveRecipient = {
    kid: recipient.kid,
    privateJwk: jwk.privateJwk("X25519", xkp.privateKey, xkp.publicKey, recipient.kid),
  };
  await assert.rejects(
    unpack(jwe, wrongCurveRecipient, { publicJwk: sender.pub }),
    /does not match epk curve/,
  );
});
