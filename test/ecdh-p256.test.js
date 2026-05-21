// P-256 key-agreement coverage for ECDH-1PU (authcrypt) and ECDH-ES
// (anoncrypt). Mirrors the X25519 invariants in ecdh-1pu/ecdh-es
// tests: both sides derive the same 32-byte KEK, and a wrong key
// breaks agreement.

import { test } from "node:test";
import assert from "node:assert/strict";

import * as ecdh1pu from "../src/ecdh-1pu.js";
import * as ecdhEs from "../src/ecdh-es.js";
import * as p256 from "../src/p256.js";

const CRV = "P-256";
const EMPTY = new Uint8Array();

test("ECDH-1PU (P-256): sender and recipient derive the same KEK", async () => {
  const ephem = p256.generateKeyPair();
  const sender = p256.generateKeyPair();
  const recipient = p256.generateKeyPair();
  const apu = new TextEncoder().encode("did:key:zSender#p256");
  const apv = new TextEncoder().encode("did:key:zRecipient#p256");
  const ccTag = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  const senderKek = await ecdh1pu.deriveKekAuthcrypt({
    ephemeralPrivate: ephem.privateKey,
    senderPrivate: sender.privateKey,
    recipientPublic: recipient.publicKey,
    alg: "ECDH-1PU+A256KW",
    apu,
    apv,
    ccTag,
    crv: CRV,
  });
  const recipientKek = await ecdh1pu.recipientKekAuthcrypt({
    recipientPrivate: recipient.privateKey,
    ephemeralPublic: ephem.publicKey,
    senderPublic: sender.publicKey,
    alg: "ECDH-1PU+A256KW",
    apu,
    apv,
    ccTag,
    crv: CRV,
  });

  assert.equal(senderKek.length, 32);
  assert.deepEqual(senderKek, recipientKek);
});

test("ECDH-1PU (P-256): wrong recipient key breaks agreement", async () => {
  const ephem = p256.generateKeyPair();
  const sender = p256.generateKeyPair();
  const recipient = p256.generateKeyPair();
  const eve = p256.generateKeyPair();
  const apu = EMPTY;
  const apv = new TextEncoder().encode("apv");

  const senderKek = await ecdh1pu.deriveKekAuthcrypt({
    ephemeralPrivate: ephem.privateKey,
    senderPrivate: sender.privateKey,
    recipientPublic: recipient.publicKey,
    alg: "ECDH-1PU+A256KW",
    apu,
    apv,
    crv: CRV,
  });
  const eveKek = await ecdh1pu.recipientKekAuthcrypt({
    recipientPrivate: eve.privateKey,
    ephemeralPublic: ephem.publicKey,
    senderPublic: sender.publicKey,
    alg: "ECDH-1PU+A256KW",
    apu,
    apv,
    crv: CRV,
  });
  assert.notDeepEqual(senderKek, eveKek);
});

test("ECDH-ES (P-256): sender and recipient derive the same KEK", async () => {
  const ephem = p256.generateKeyPair();
  const recipient = p256.generateKeyPair();
  const apv = new TextEncoder().encode("did:key:zRecipient#p256");

  const senderKek = await ecdhEs.deriveKekAnoncrypt({
    ephemeralPrivate: ephem.privateKey,
    recipientPublic: recipient.publicKey,
    alg: "ECDH-ES+A256KW",
    apu: EMPTY,
    apv,
    crv: CRV,
  });
  const recipientKek = await ecdhEs.recipientKekAnoncrypt({
    recipientPrivate: recipient.privateKey,
    ephemeralPublic: ephem.publicKey,
    alg: "ECDH-ES+A256KW",
    apu: EMPTY,
    apv,
    crv: CRV,
  });

  assert.equal(senderKek.length, 32);
  assert.deepEqual(senderKek, recipientKek);
});
