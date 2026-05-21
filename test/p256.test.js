import { test } from "node:test";
import assert from "node:assert/strict";

import * as p256 from "../src/p256.js";

test("P-256: generateKeyPair shapes (32-byte scalar, 65-byte uncompressed point)", () => {
  const { privateKey, publicKey } = p256.generateKeyPair();
  assert.equal(privateKey.length, 32);
  assert.equal(publicKey.length, 65);
  assert.equal(publicKey[0], 0x04, "uncompressed SEC1 point starts with 0x04");
});

test("P-256: publicKeyFrom is deterministic and matches generateKeyPair", () => {
  const { privateKey, publicKey } = p256.generateKeyPair();
  assert.deepEqual(p256.publicKeyFrom(privateKey), publicKey);
});

test("P-256: ECDH shared secret agrees on both sides and is 32 bytes", () => {
  const a = p256.generateKeyPair();
  const b = p256.generateKeyPair();
  const sa = p256.sharedSecret(a.privateKey, b.publicKey);
  const sb = p256.sharedSecret(b.privateKey, a.publicKey);
  assert.equal(sa.length, 32, "Z is the 32-byte X-coordinate");
  assert.deepEqual(sa, sb, "ECDH must agree on both sides");
});

test("P-256: shared secret accepts a compressed peer point too", () => {
  const a = p256.generateKeyPair();
  const b = p256.generateKeyPair();
  // Reconstruct b's compressed point: 0x02/0x03 || X.
  const { x } = p256.pointCoordinates(b.publicKey);
  const yIsOdd = b.publicKey[64] & 1;
  const compressed = new Uint8Array(33);
  compressed[0] = yIsOdd ? 0x03 : 0x02;
  compressed.set(x, 1);
  const sa = p256.sharedSecret(a.privateKey, b.publicKey);
  const sCompressed = p256.sharedSecret(a.privateKey, compressed);
  assert.deepEqual(sCompressed, sa, "compressed and uncompressed peer keys yield the same Z");
});

test("P-256: pointCoordinates / pointFromCoordinates round-trip", () => {
  const { publicKey } = p256.generateKeyPair();
  const { x, y } = p256.pointCoordinates(publicKey);
  assert.equal(x.length, 32);
  assert.equal(y.length, 32);
  assert.deepEqual(p256.pointFromCoordinates(x, y), publicKey);
});

test("P-256: pointFromCoordinates rejects an off-curve point", () => {
  const { publicKey } = p256.generateKeyPair();
  const { x } = p256.pointCoordinates(publicKey);
  assert.throws(() => p256.pointFromCoordinates(x, new Uint8Array(32)));
});

test("P-256: rejects wrong-sized inputs", () => {
  assert.throws(() => p256.publicKeyFrom(new Uint8Array(31)), /32 bytes/);
  assert.throws(() => p256.sharedSecret(new Uint8Array(31), new Uint8Array(65)), /32 bytes/);
  assert.throws(() => p256.pointCoordinates(new Uint8Array(64)), /uncompressed SEC1/);
});
