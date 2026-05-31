// Migration coverage for the ECDH-1PU Concat KDF length-prefix fix
// (issue #322). Versions ≤ 0.4.x fed `cc_tag` to the KDF without a
// length prefix; 0.5 length-prefixes it (spec-correct, interoperable
// with credo-ts / didcomm-python / affinidi-messaging-didcomm ≥ 0.14).
//
// To stay interoperable during rollout, `unpack` tries the spec-correct
// KEK first and falls back to the legacy (unprefixed) KEK, reporting
// `legacyKekUsed`. These tests cover both directions.

import { test } from "node:test";
import assert from "node:assert/strict";

import { pack } from "../src/pack.js";
import { unpack } from "../src/unpack.js";
import * as jwk from "../src/jwk.js";
import * as x25519 from "../src/x25519.js";
import * as a256cbcHs512 from "../src/a256cbc-hs512.js";
import * as aes from "../src/aes.js";
import * as b64u from "../src/base64url.js";
import * as ecdh1pu from "../src/ecdh-1pu.js";
import * as keyAgreement from "../src/key-agreement.js";

const ALG = "ECDH-1PU+A256KW";
const ENC = "A256CBC-HS512";

function makeParty(kid) {
  const { privateKey, publicKey } = x25519.generateKeyPair();
  return {
    kid,
    privateJwk: jwk.privateJwk("X25519", privateKey, publicKey, kid),
    publicJwk: jwk.publicJwk("X25519", publicKey, kid),
  };
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/**
 * Pack an authcrypt JWE the way a pre-0.5 peer would — identical to
 * `pack` except the KEK is derived with the legacy (unprefixed cc_tag)
 * Concat KDF. Test-only; production `pack` is always spec-correct.
 */
async function packLegacy({ message, sender, recipient }) {
  const crv = jwk.curveOf(recipient.publicJwk);
  const senderPriv = jwk.rawPrivate(sender.privateJwk);
  const recipientPub = jwk.rawPublic(recipient.publicJwk);
  const ephem = keyAgreement.generateKeyPair(crv);
  const { cek, iv } = a256cbcHs512.generateCekAndIv();
  const apuBytes = new TextEncoder().encode(sender.kid);
  const apvBytes = await sha256(new TextEncoder().encode(recipient.kid));

  const protectedHeader = {
    typ: "application/didcomm-encrypted+json",
    alg: ALG,
    enc: ENC,
    apu: b64u.encode(apuBytes),
    apv: b64u.encode(apvBytes),
    skid: sender.kid,
    epk: jwk.publicJwk(crv, ephem.publicKey),
  };
  const protectedB64 = b64u.encode(
    new TextEncoder().encode(JSON.stringify(protectedHeader)),
  );

  const { ciphertext, tag } = await a256cbcHs512.encrypt({
    cek,
    iv,
    aad: new TextEncoder().encode(protectedB64),
    plaintext: new TextEncoder().encode(JSON.stringify(message)),
  });

  const kek = await ecdh1pu.deriveKekAuthcrypt({
    ephemeralPrivate: ephem.privateKey,
    senderPrivate: senderPriv,
    recipientPublic: recipientPub,
    alg: ALG,
    apu: apuBytes,
    apv: apvBytes,
    ccTag: tag,
    crv,
    legacy: true, // ← the pre-0.5 behaviour
  });
  const encryptedKey = await aes.wrapKey(kek, cek);

  return JSON.stringify({
    protected: protectedB64,
    recipients: [
      { header: { kid: recipient.kid }, encrypted_key: b64u.encode(encryptedKey) },
    ],
    iv: b64u.encode(iv),
    ciphertext: b64u.encode(ciphertext),
    tag: b64u.encode(tag),
  });
}

test("spec-correct authcrypt unpacks without the legacy fallback", async () => {
  const sender = makeParty("did:key:zSender#x25519-1");
  const recipient = makeParty("did:key:zRecipient#x25519-1");
  const message = { id: "m1", type: "x", body: { hello: "spec" } };

  const jwe = await pack({
    message,
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  });

  const res = await unpack(
    jwe,
    { kid: recipient.kid, privateJwk: recipient.privateJwk },
    { publicJwk: sender.publicJwk },
  );
  assert.deepEqual(res.message, message);
  assert.equal(res.authenticated, true);
  assert.equal(res.legacyKekUsed, false, "spec-correct must not engage the fallback");
});

test("legacy (pre-0.5) authcrypt decrypts via the fallback", async () => {
  const sender = makeParty("did:key:zSenderLegacy#x25519-1");
  const recipient = makeParty("did:key:zRecipientLegacy#x25519-1");
  const message = { id: "m2", type: "x", body: { hello: "legacy" } };

  const jwe = await packLegacy({
    message,
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  });

  const res = await unpack(
    jwe,
    { kid: recipient.kid, privateJwk: recipient.privateJwk },
    { publicJwk: sender.publicJwk },
  );
  assert.deepEqual(res.message, message);
  assert.equal(res.senderKid, sender.kid);
  assert.equal(res.legacyKekUsed, true, "legacy-packed JWE must use the fallback KEK");
});

test("spec-correct and legacy KEKs differ for the same inputs (the #322 fix)", async () => {
  const sender = makeParty("did:key:zS#k");
  const recipient = makeParty("did:key:zR#k");
  const ephem = keyAgreement.generateKeyPair("X25519");
  const apu = new TextEncoder().encode(sender.kid);
  const apv = await sha256(new TextEncoder().encode(recipient.kid));
  const ccTag = new Uint8Array(32).fill(0x5a);

  const common = {
    ephemeralPrivate: ephem.privateKey,
    senderPrivate: jwk.rawPrivate(sender.privateJwk),
    recipientPublic: jwk.rawPublic(recipient.publicJwk),
    alg: ALG,
    apu,
    apv,
    ccTag,
    crv: "X25519",
  };

  const correct = await ecdh1pu.deriveKekAuthcrypt({ ...common, legacy: false });
  const legacy = await ecdh1pu.deriveKekAuthcrypt({ ...common, legacy: true });
  assert.notDeepEqual(correct, legacy, "length-prefixing cc_tag must change the KEK");
});
