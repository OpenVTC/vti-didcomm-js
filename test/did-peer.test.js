import { test } from "node:test";
import assert from "node:assert/strict";

import * as didPeer from "../src/did-peer.js";
import * as multibase from "../src/multibase.js";
import * as b64u from "../src/base64url.js";
import * as p256 from "../src/p256.js";
import * as x25519 from "../src/x25519.js";

// ─── Canonical DIF did:peer:2 example ───────────────────────────────────
//
// Source: https://identity.foundation/peer-did-method-spec/ and the
// decentralized-identity/did-peer-2 reference. An E (keyAgreement,
// X25519) key, a V (authentication, Ed25519) key, and an S service.
const DIF_EXAMPLE =
  "did:peer:2" +
  ".Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud" +
  ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" +
  ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0";

test("did:peer:2 (DIF example): keys map to relationships in string order", () => {
  const { didDocument } = didPeer.resolve(DIF_EXAMPLE);
  assert.equal(didDocument.id, DIF_EXAMPLE);
  assert.equal(didDocument.verificationMethod.length, 2);

  // E (keyAgreement) is element 1 → #key-1; V (auth) is element 2 → #key-2.
  assert.equal(didDocument.verificationMethod[0].id, `${DIF_EXAMPLE}#key-1`);
  assert.equal(didDocument.verificationMethod[1].id, `${DIF_EXAMPLE}#key-2`);
  assert.deepEqual(didDocument.keyAgreement, [`${DIF_EXAMPLE}#key-1`]);
  assert.deepEqual(didDocument.authentication, [`${DIF_EXAMPLE}#key-2`]);
  assert.equal(didDocument.assertionMethod, undefined);

  for (const vm of didDocument.verificationMethod) {
    assert.equal(vm.type, "Multikey");
    assert.equal(vm.controller, DIF_EXAMPLE);
    assert.ok(vm.publicKeyMultibase.startsWith("z"));
  }
});

test("did:peer:2 (DIF example): keyAgreement key is X25519", () => {
  const { didDocument } = didPeer.resolve(DIF_EXAMPLE);
  const { codec } = multibase.decodeMultikey(didDocument.verificationMethod[0].publicKeyMultibase);
  assert.deepEqual(codec, multibase.MULTICODEC.X25519_PUB);
});

test("did:peer:2 (DIF example): service abbreviations are expanded", () => {
  const { didDocument } = didPeer.resolve(DIF_EXAMPLE);
  assert.equal(didDocument.service.length, 1);
  const svc = didDocument.service[0];
  assert.equal(svc.id, `${DIF_EXAMPLE}#service`);
  assert.equal(svc.type, "DIDCommMessaging");
  assert.equal(svc.serviceEndpoint, "https://example.com/endpoint");
  assert.deepEqual(svc.routingKeys, ["did:example:somemediator#somekey"]);
  assert.deepEqual(svc.accept, ["didcomm/v2", "didcomm/aip2;env=rfc587"]);
});

// ─── P-256 keyAgreement carried through did:peer ────────────────────────

test("did:peer:2 carries a P-256 keyAgreement key", () => {
  const kp = p256.generateKeyPair();
  // E key encoded as a P-256 multikey (compressed form, as did:key/peer use).
  const { x } = p256.pointCoordinates(kp.publicKey);
  const yOdd = kp.publicKey[64] & 1;
  const comp = new Uint8Array(33);
  comp[0] = yOdd ? 0x03 : 0x02;
  comp.set(x, 1);
  const eKey = multibase.encodeMultikey(multibase.MULTICODEC.P256_PUB, comp);
  const did = `did:peer:2.E${eKey}`;

  const { didDocument } = didPeer.resolve(did);
  assert.deepEqual(didDocument.keyAgreement, [`${did}#key-1`]);
  const { codec } = multibase.decodeMultikey(didDocument.verificationMethod[0].publicKeyMultibase);
  assert.deepEqual(codec, multibase.MULTICODEC.P256_PUB);
});

// ─── Service id numbering & array form ──────────────────────────────────

test("did:peer:2 numbers a second service #service-1", () => {
  const svc = [
    { t: "dm", s: "https://a.example/endpoint" },
    { t: "dm", s: "https://b.example/endpoint" },
  ];
  const sValue = b64u.encode(new TextEncoder().encode(JSON.stringify(svc)));
  const kp = x25519.generateKeyPair();
  const eKey = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
  const did = `did:peer:2.E${eKey}.S${sValue}`;

  const { didDocument } = didPeer.resolve(did);
  assert.equal(didDocument.service.length, 2);
  assert.equal(didDocument.service[0].id, `${did}#service`);
  assert.equal(didDocument.service[1].id, `${did}#service-1`);
});

// ─── Error paths ─────────────────────────────────────────────────────────

test("did:peer rejects non-string and non-peer input", () => {
  assert.throws(() => didPeer.resolve(42), /must be a string/);
  assert.throws(() => didPeer.resolve("did:key:z6Mk"), /must start with "did:peer:"/);
});

test("did:peer rejects unsupported numalgo", () => {
  assert.throws(() => didPeer.resolve("did:peer:0z6MkExample"), /only numalgo 2/);
  assert.throws(() => didPeer.resolve("did:peer:4zExample"), /only numalgo 2/);
});

test("did:peer rejects an unknown purpose code", () => {
  const kp = x25519.generateKeyPair();
  const eKey = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
  const did = `did:peer:2.E${eKey}.Xsomething`;
  assert.throws(() => didPeer.resolve(did), /unknown purpose code/);
});
