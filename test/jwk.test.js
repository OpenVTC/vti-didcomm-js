import { test } from "node:test";
import assert from "node:assert/strict";

import * as b64u from "../src/base64url.js";
import * as jwk from "../src/jwk.js";
import * as p256 from "../src/p256.js";

const x = new Uint8Array(32);
for (let i = 0; i < 32; i++) x[i] = i;
const d = new Uint8Array(32);
for (let i = 0; i < 32; i++) d[i] = 31 - i;

test("publicJwk shape is OKP/{crv} with base64url x", () => {
  const out = jwk.publicJwk("X25519", x, "did:key:zA#x");
  assert.equal(out.kty, "OKP");
  assert.equal(out.crv, "X25519");
  assert.equal(out.kid, "did:key:zA#x");
  assert.equal(out.x, b64u.encode(x));
  assert.ok(!("d" in out));
});

test("privateJwk includes 'd'", () => {
  const out = jwk.privateJwk("Ed25519", d, x);
  assert.equal(out.kty, "OKP");
  assert.equal(out.crv, "Ed25519");
  assert.equal(out.d, b64u.encode(d));
});

test("rawPublic round-trip", () => {
  const j = jwk.publicJwk("X25519", x);
  assert.deepEqual(jwk.rawPublic(j), x);
});

test("rawPrivate round-trip", () => {
  const j = jwk.privateJwk("X25519", d, x);
  assert.deepEqual(jwk.rawPrivate(j), d);
});

test("rawPrivate rejects public-only JWK", () => {
  const j = jwk.publicJwk("X25519", x);
  assert.throws(() => jwk.rawPrivate(j), /no 'd'/);
});

test("toPublic strips 'd'", () => {
  const priv = jwk.privateJwk("X25519", d, x, "did:webvh:foo#k");
  const pub = jwk.toPublic(priv);
  assert.equal(pub.kty, "OKP");
  assert.equal(pub.kid, "did:webvh:foo#k");
  assert.ok(!("d" in pub));
});

test("publicJwk rejects unsupported curve", () => {
  assert.throws(() => jwk.publicJwk("Ed448", x), /unsupported OKP curve/);
});

test("publicJwk rejects wrong-length input", () => {
  assert.throws(() => jwk.publicJwk("X25519", new Uint8Array(31), undefined), /must be 32 bytes/);
});

test("rawPublic rejects unknown kty", () => {
  assert.throws(
    () => jwk.rawPublic({ kty: "RSA", x: "AAAA" }),
    /kty must be 'OKP' or 'EC'/,
  );
});

// ─── EC P-256 ──────────────────────────────────────────────────────────

test("publicJwk (P-256) emits kty=EC with base64url x and y", () => {
  const kp = p256.generateKeyPair();
  const out = jwk.publicJwk("P-256", kp.publicKey, "did:key:zP#k");
  assert.equal(out.kty, "EC");
  assert.equal(out.crv, "P-256");
  assert.equal(out.kid, "did:key:zP#k");
  const { x, y } = p256.pointCoordinates(kp.publicKey);
  assert.equal(out.x, b64u.encode(x));
  assert.equal(out.y, b64u.encode(y));
  assert.ok(!("d" in out));
});

test("rawPublic (P-256) reconstructs the uncompressed SEC1 point", () => {
  const kp = p256.generateKeyPair();
  const j = jwk.publicJwk("P-256", kp.publicKey);
  assert.deepEqual(jwk.rawPublic(j), kp.publicKey);
});

test("privateJwk / rawPrivate (P-256) round-trip the scalar", () => {
  const kp = p256.generateKeyPair();
  const j = jwk.privateJwk("P-256", kp.privateKey, kp.publicKey);
  assert.equal(j.kty, "EC");
  assert.equal(j.d, b64u.encode(kp.privateKey));
  assert.deepEqual(jwk.rawPrivate(j), kp.privateKey);
});

test("toPublic (P-256) keeps x and y, drops d", () => {
  const kp = p256.generateKeyPair();
  const priv = jwk.privateJwk("P-256", kp.privateKey, kp.publicKey, "did:key:zP#k");
  const pub = jwk.toPublic(priv);
  assert.equal(pub.kty, "EC");
  assert.equal(pub.kid, "did:key:zP#k");
  assert.ok(pub.x && pub.y);
  assert.ok(!("d" in pub));
});

test("curveOf reports the curve for OKP and EC", () => {
  assert.equal(jwk.curveOf(jwk.publicJwk("X25519", x)), "X25519");
  const kp = p256.generateKeyPair();
  assert.equal(jwk.curveOf(jwk.publicJwk("P-256", kp.publicKey)), "P-256");
});

test("rawPublic (P-256) rejects an off-curve point", () => {
  const kp = p256.generateKeyPair();
  const good = jwk.publicJwk("P-256", kp.publicKey);
  const bad = { ...good, y: b64u.encode(new Uint8Array(32)) };
  assert.throws(() => jwk.rawPublic(bad));
});
