import { test } from "node:test";
import assert from "node:assert/strict";

import * as didKey from "../src/did-key.js";
import * as multibase from "../src/multibase.js";

// ─── Official W3C did:key spec test vectors ─────────────────────────────
//
// Source: https://w3c-ccg.github.io/did-method-key/ (Test Vectors §6)
// These are the canonical strings every did:key implementation
// must agree on. If any of these break, our implementation has
// diverged from the spec.

const ED25519_VECTOR = {
  did: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
  // Ed25519 public key (hex) — the raw 32 bytes after the multicodec prefix.
  edPubHex: "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
};

const X25519_VECTOR = {
  // X25519-only did:key — note the different multibase prefix.
  did: "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F",
};

// ─── did:key Ed25519 ────────────────────────────────────────────────────

test("did:key Ed25519: resolves to DID document with both signing + keyAgreement", () => {
  const { didDocument } = didKey.resolve(ED25519_VECTOR.did);

  assert.equal(didDocument.id, ED25519_VECTOR.did);
  // Two verification methods (signing + agreement).
  assert.equal(didDocument.verificationMethod.length, 2);

  // Signing key gets the four authority relationships.
  const signingId = didDocument.verificationMethod[0].id;
  assert.deepEqual(didDocument.authentication, [signingId]);
  assert.deepEqual(didDocument.assertionMethod, [signingId]);
  assert.deepEqual(didDocument.capabilityDelegation, [signingId]);
  assert.deepEqual(didDocument.capabilityInvocation, [signingId]);

  // keyAgreement is the SECOND vm (the derived X25519).
  const agreementId = didDocument.verificationMethod[1].id;
  assert.deepEqual(didDocument.keyAgreement, [agreementId]);

  // Both VMs are typed `Multikey`.
  for (const vm of didDocument.verificationMethod) {
    assert.equal(vm.type, "Multikey");
    assert.equal(vm.controller, ED25519_VECTOR.did);
    assert.ok(vm.publicKeyMultibase.startsWith("z"));
  }
});

test("did:key Ed25519: keyAgreement multibase has X25519 multicodec", () => {
  const { didDocument } = didKey.resolve(ED25519_VECTOR.did);
  const agreementVm = didDocument.verificationMethod[1];
  const { codec } = multibase.decodeMultikey(agreementVm.publicKeyMultibase);
  assert.deepEqual(
    codec,
    multibase.MULTICODEC.X25519_PUB,
    "keyAgreement public key must use the X25519 multicodec",
  );
});

test("did:key Ed25519: signing key bytes round-trip through multibase", () => {
  const { didDocument } = didKey.resolve(ED25519_VECTOR.did);
  const signingVm = didDocument.verificationMethod[0];
  const { codec, key } = multibase.decodeMultikey(signingVm.publicKeyMultibase);

  assert.deepEqual(codec, multibase.MULTICODEC.ED25519_PUB);
  assert.equal(toHex(key), ED25519_VECTOR.edPubHex);
});

// ─── Ed25519-to-X25519 derivation ───────────────────────────────────────

test("ed25519PublicKeyToX25519: produces an X25519 public key of the right length", () => {
  const ed = new Uint8Array(
    ED25519_VECTOR.edPubHex.match(/.{2}/g).map((h) => parseInt(h, 16)),
  );
  const x = didKey.ed25519PublicKeyToX25519(ed);
  assert.equal(x.length, 32);
  // It's vanishingly unlikely that the derived key equals the input
  // by coincidence — guard against the off-by-one bug where we
  // forget to apply the transformation.
  assert.notDeepEqual(x, ed);
});

test("ed25519PublicKeyToX25519: is deterministic", () => {
  const ed = new Uint8Array(32).fill(0x42);
  // (Random bytes aren't a valid Ed25519 point in general, but the
  // birational map is defined for any y in [0, p-1] regardless of
  // whether the point is on the curve — we're just testing
  // determinism here.)
  const a = didKey.ed25519PublicKeyToX25519(ed);
  const b = didKey.ed25519PublicKeyToX25519(ed);
  assert.deepEqual(a, b);
});

test("ed25519PublicKeyToX25519: matches against a known reference value", async () => {
  // Cross-check against @noble/curves' Ed25519 verify path. We
  // verify that the math is internally consistent: for a random
  // Ed25519 secret, the derived X25519 public key should equal
  // what you get from `ed25519_priv_to_x25519` (clamping the
  // SHA-512(sk)[0..32]) then x25519.getPublicKey.
  const { ed25519, x25519 } = await import("@noble/curves/ed25519.js");
  const sk = new Uint8Array(32);
  for (let i = 0; i < 32; i++) sk[i] = i; // deterministic for reproducibility
  const edPub = ed25519.getPublicKey(sk);

  // Standard transformation: x25519 secret = clamp(SHA-512(ed_sk)[0..32]).
  const sha512 = await import("node:crypto").then((m) => m.createHash("sha512"));
  sha512.update(sk);
  const hash = new Uint8Array(sha512.digest());
  const xSk = hash.slice(0, 32);
  // Clamp per RFC 7748 §5.
  xSk[0] &= 248;
  xSk[31] &= 127;
  xSk[31] |= 64;
  const xPubViaSecret = x25519.getPublicKey(xSk);

  // The "via public key" derivation should match.
  const xPubViaPub = didKey.ed25519PublicKeyToX25519(edPub);
  assert.deepEqual(
    xPubViaPub,
    xPubViaSecret,
    "Edwards-to-Montgomery on the PUBLIC key must agree with X25519 of the clamped secret",
  );
});

// ─── did:key X25519 ─────────────────────────────────────────────────────

test("did:key X25519: resolves to keyAgreement-only DID document", () => {
  const { didDocument } = didKey.resolve(X25519_VECTOR.did);
  assert.equal(didDocument.id, X25519_VECTOR.did);
  assert.equal(didDocument.verificationMethod.length, 1);
  assert.equal(didDocument.verificationMethod[0].type, "Multikey");
  assert.deepEqual(didDocument.keyAgreement, [
    didDocument.verificationMethod[0].id,
  ]);
  // An X25519 key isn't a signing key — no authentication, etc.
  assert.equal(didDocument.authentication, undefined);
  assert.equal(didDocument.assertionMethod, undefined);
});

// ─── Error paths ─────────────────────────────────────────────────────────

test("did:key resolve: rejects non-string input", () => {
  assert.throws(() => didKey.resolve(42), /input must be a string/);
  assert.throws(() => didKey.resolve(null), /input must be a string/);
});

test("did:key resolve: rejects identifiers without the did:key prefix", () => {
  assert.throws(
    () => didKey.resolve("did:web:example.com"),
    /must start with "did:key:"/,
  );
});

test("did:key resolve: rejects non-base58btc encodings", () => {
  // Future-spec base64url would be 'u', not 'z'. Refuse explicitly
  // rather than silently misinterpreting.
  assert.throws(
    () => didKey.resolve("did:key:u3b6a27bcceb6a42d62a3a8d02a6f0d73"),
    /only base58btc/,
  );
});

test("did:key resolve: rejects unknown multicodec", () => {
  // Build a multibase string with a multicodec we don't support
  // (P-384 = 0x81 0x24).
  const fakeMultibase = multibase.encodeMultikey(
    new Uint8Array([0x81, 0x24]),
    new Uint8Array(49).fill(0x42),
  );
  assert.throws(
    () => didKey.resolve("did:key:" + fakeMultibase),
    /unsupported multicodec 0x8124/,
  );
});

// ─── did:key P-256 / secp256k1 (signing-only) ───────────────────────────

test("did:key P-256: resolves to signing-only DID document", async () => {
  const { p256 } = await import("@noble/curves/nist.js");
  const compressed = p256.getPublicKey(p256.utils.randomSecretKey(), true);
  assert.equal(compressed.length, 33);
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.P256_PUB, compressed);
  const did = "did:key:" + mb;

  const { didDocument } = didKey.resolve(did);
  const kid = `${did}#${mb}`;
  assert.equal(didDocument.verificationMethod.length, 1);
  assert.equal(didDocument.verificationMethod[0].type, "Multikey");
  assert.deepEqual(didDocument.authentication, [kid]);
  assert.deepEqual(didDocument.assertionMethod, [kid]);
  assert.deepEqual(didDocument.capabilityDelegation, [kid]);
  assert.deepEqual(didDocument.capabilityInvocation, [kid]);
  // Signing key, not a key-agreement key.
  assert.equal(didDocument.keyAgreement, undefined);
});

test("did:key secp256k1: resolves to signing-only DID document", async () => {
  const { secp256k1 } = await import("@noble/curves/secp256k1.js");
  const compressed = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true);
  assert.equal(compressed.length, 33);
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.SECP256K1_PUB, compressed);
  const did = "did:key:" + mb;

  const { didDocument } = didKey.resolve(did);
  const kid = `${did}#${mb}`;
  assert.equal(didDocument.verificationMethod.length, 1);
  assert.deepEqual(didDocument.authentication, [kid]);
  assert.deepEqual(didDocument.assertionMethod, [kid]);
  assert.equal(didDocument.keyAgreement, undefined);
});

// ─── Helpers ────────────────────────────────────────────────────────────

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
