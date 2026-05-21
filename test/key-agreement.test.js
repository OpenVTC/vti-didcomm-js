import { test } from "node:test";
import assert from "node:assert/strict";

import * as ka from "../src/key-agreement.js";

for (const crv of [ka.X25519, ka.P256]) {
  test(`key-agreement (${crv}): ECDH agrees on both sides, Z is 32 bytes`, () => {
    const a = ka.generateKeyPair(crv);
    const b = ka.generateKeyPair(crv);
    const za = ka.sharedSecret(crv, a.privateKey, b.publicKey);
    const zb = ka.sharedSecret(crv, b.privateKey, a.publicKey);
    assert.equal(za.length, 32);
    assert.deepEqual(za, zb);
  });

  test(`key-agreement (${crv}): publicKeyFrom matches generateKeyPair`, () => {
    const { privateKey, publicKey } = ka.generateKeyPair(crv);
    assert.deepEqual(ka.publicKeyFrom(crv, privateKey), publicKey);
  });
}

test("key-agreement: isSupported reflects the curve set", () => {
  assert.equal(ka.isSupported("X25519"), true);
  assert.equal(ka.isSupported("P-256"), true);
  assert.equal(ka.isSupported("secp256k1"), false);
  assert.equal(ka.isSupported("Ed25519"), false);
});

test("key-agreement: unsupported curve throws", () => {
  assert.throws(() => ka.generateKeyPair("secp256k1"), /unsupported curve/);
});
