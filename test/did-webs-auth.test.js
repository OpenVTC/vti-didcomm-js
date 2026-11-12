// Authenticating and encrypting to a did:webs party (VTI-KEY-003).
//
// A did:webs document publishes its keys as `JsonWebKey` verification
// methods (`publicKeyJwk`, ids `<did>#<CESR key>`), and a VTA with key roles
// (VTI-KEY-150 / VTI-KEY-173) binds a different key to each relationship.
// These tests take a VTA and a mediator minted by `affinidi-did-webs` 0.13.3
// (`test/fixtures/did-webs/parties/README.md`), resolve them through the real
// did:webs resolver over a mocked network, and drive every path that turns
// their documents into keys: mediator auth, VTA REST auth, the VTA DIDComm
// client's recipient key, and its inbound-sender lookup.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve as pathResolve } from "node:path";

import * as didWebs from "../src/did-webs.js";
import * as jwk from "../src/jwk.js";
import * as multibase from "../src/multibase.js";
import * as p256 from "../src/p256.js";
import * as x25519 from "../src/x25519.js";
import * as b64u from "../src/base64url.js";
import { pack } from "../src/pack.js";
import { unpack } from "../src/unpack.js";
import { clearDidCache } from "../src/resolver.js";
import { publicKeyOf, selectKey, x25519KeyAgreement } from "../src/verification-method.js";
import { authenticateToMediator, parseMediatorEndpoints } from "../src/mediator-auth.js";
import { authenticate, generateEphemeralClient } from "../src/vta-rest-auth.js";
import { resolveX25519KeyAgreement, resolveX25519KeyAgreementKey } from "../src/vta-didcomm.js";
import { unpackInbound } from "../src/mediator-transport.js";
import { asRustDocument } from "./support-did-webs-vectors.js";

// ─── Fixtures ───────────────────────────────────────────────────────────

const PARTIES = pathResolve(import.meta.dirname, "fixtures", "did-webs", "parties");

function party(name) {
  const dir = pathResolve(PARTIES, name);
  return {
    did: readFileSync(pathResolve(dir, "did.txt"), "utf8").trim(),
    keriCesr: new Uint8Array(readFileSync(pathResolve(dir, "keri.cesr"))),
    didJson: new Uint8Array(readFileSync(pathResolve(dir, "did.json"))),
  };
}

const VTA = party("vta");
const MEDIATOR = party("mediator");

// The secrets behind the fixtures' key agreement keys (README).
const VTA_X25519_PRIVATE = new Uint8Array(32).fill(0x31);
const VTA_P256_PRIVATE = new Uint8Array(32).fill(0x34);
const MEDIATOR_X25519_PRIVATE = new Uint8Array(32).fill(0x41);

// The fixtures' ids, exactly as the documents write them.
const VTA_X25519_KID = `${VTA.did}#CAT18pFiwxqN76GObnQiJO6Ab8FxiieL6Fm6ViBAK486`;
const VTA_P256_KID = `${VTA.did}#1AAJAxAExOYTxnMlFtF30ibtc4LWFn92rfoHJDanK2UgZM61`;
const VTA_AUTHENTICATION_KID = `${VTA.did}#DBfLefsrQSDysexl5BmNbgiyjoE_6wHkpACDm4XhgIDO`;
const VTA_ASSERTION_KID = `${VTA.did}#DF4hLAmA5LOfwJchE0qgIQk3Tt_SYMDT0Dy1AcjWVFep`;
const MEDIATOR_X25519_KID = `${MEDIATOR.did}#CHoaTnCb8IWsSUq6BGm5se2gqx94sWqrt5_-2pBiPoUi`;

/** A fetch serving the parties' published artifacts, and nothing else. */
function artifactFetch(parties = [VTA, MEDIATOR]) {
  return async (url) => {
    const { host, pathname } = new URL(String(url));
    for (const p of parties) {
      const { host: h, aid } = didWebs.parseDidWebs(p.did);
      if (host !== h || !pathname.startsWith(`/${aid}/`)) continue;
      if (pathname.endsWith("/keri.cesr")) return new Response(p.keriCesr);
      if (pathname.endsWith("/did.json")) return new Response(p.didJson);
    }
    return new Response("not found", { status: 404 });
  };
}

/**
 * Route the global fetch — which the default resolver's did:webs handler
 * uses — to the artifacts, and HTTP calls for `routes` to their handlers.
 */
function withNetwork(t, routes = {}) {
  const original = globalThis.fetch;
  const artifacts = artifactFetch();
  globalThis.fetch = async (url, init) => {
    const handler = routes[String(url)];
    return handler ? handler(init) : artifacts(url, init);
  };
  clearDidCache();
  t.after(() => {
    globalThis.fetch = original;
    clearDidCache();
  });
}

async function resolved(p) {
  return (await didWebs.resolve(p.did, { fetch: artifactFetch() })).didDocument;
}

function json(body) {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

test("fixtures: this resolver derives the document affinidi-did-webs derived", async () => {
  for (const name of ["vta", "mediator"]) {
    const p = party(name);
    const rust = JSON.parse(readFileSync(pathResolve(PARTIES, name, "resolved.json"), "utf8"));
    assert.deepEqual(asRustDocument(await resolved(p)), asRustDocument(rust), name);
  }
});

// ─── The shared helper: encodings ───────────────────────────────────────

test("publicKeyOf: reads JsonWebKey OKP Ed25519 / X25519 and EC P-256 (did:webs)", async () => {
  const doc = await resolved(VTA);
  const byId = (id) => doc.verificationMethod.find((v) => v.id === id);

  const ka = publicKeyOf(byId(VTA_X25519_KID));
  assert.equal(ka.crv, "X25519");
  assert.deepEqual(ka.publicKey, x25519.publicKeyFrom(VTA_X25519_PRIVATE));

  const ec = publicKeyOf(byId(VTA_P256_KID));
  assert.equal(ec.crv, "P-256");
  assert.deepEqual(ec.publicKey, p256.publicKeyFrom(VTA_P256_PRIVATE));

  assert.equal(publicKeyOf(byId(VTA_AUTHENTICATION_KID)).crv, "Ed25519");
});

test("publicKeyOf: reads the multikey types did:key / did:peer / did:webvh publish", () => {
  const x = x25519.generateKeyPair().publicKey;
  const ec = p256.generateKeyPair().publicKey;
  const compressed = new Uint8Array([2 + (ec[64] & 1), ...ec.slice(1, 33)]);
  const mk = (codec, key) => multibase.encodeMultikey(codec, key);

  assert.deepEqual(publicKeyOf({ id: "#a", type: "Multikey", publicKeyMultibase: mk(multibase.MULTICODEC.X25519_PUB, x) }), {
    crv: "X25519",
    publicKey: x,
  });
  for (const type of ["X25519KeyAgreementKey2020", "X25519KeyAgreementKey2019"]) {
    assert.equal(publicKeyOf({ id: "#a", type, publicKeyMultibase: mk(multibase.MULTICODEC.X25519_PUB, x) }).crv, "X25519");
  }
  const p = publicKeyOf({ id: "#a", type: "Multikey", publicKeyMultibase: mk(multibase.MULTICODEC.P256_PUB, compressed) });
  assert.equal(p.crv, "P-256");
  assert.deepEqual(p.publicKey, ec, "a compressed P-256 multikey is decompressed");
  assert.equal(
    publicKeyOf({ id: "#a", type: "JsonWebKey2020", publicKeyJwk: jwk.publicJwk("X25519", x) }).crv,
    "X25519",
  );
});

test("publicKeyOf: fails closed on anything it cannot read unambiguously", () => {
  const x = x25519.generateKeyPair().publicKey;
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, x);
  const ed = multibase.encodeMultikey(multibase.MULTICODEC.ED25519_PUB, x);
  const k1 = multibase.encodeMultikey(multibase.MULTICODEC.SECP256K1_PUB, new Uint8Array(33).fill(2));
  const okp = jwk.publicJwk("X25519", x);
  const cases = [
    [{ id: "#a", publicKeyMultibase: mb }, /unsupported type undefined/],
    [{ id: "#a", type: "EcdsaSecp256k1VerificationKey2019", publicKeyMultibase: mb }, /unsupported type/],
    [{ id: "#a", type: "JsonWebKey", publicKeyMultibase: mb }, /without publicKeyJwk/],
    [{ id: "#a", type: "Multikey", publicKeyJwk: okp }, /without publicKeyMultibase/],
    [{ id: "#a", type: "JsonWebKey", publicKeyJwk: okp, publicKeyMultibase: mb }, /both/],
    [{ id: "#a", type: "X25519KeyAgreementKey2020", publicKeyMultibase: ed }, /holding a Ed25519 key/],
    [{ id: "#a", type: "Multikey", publicKeyMultibase: k1 }, /unsupported multicodec 0xe701/],
    [{ id: "#a", type: "JsonWebKey", publicKeyJwk: { kty: "EC", crv: "secp256k1", x: "AA", y: "AA" } }, /unsupported EC curve/],
    [{ id: "#a", type: "JsonWebKey", publicKeyJwk: { kty: "RSA", n: "AA", e: "AQAB" } }, /kty/],
    [{ id: "#a", type: "JsonWebKey", publicKeyJwk: { ...okp, d: b64u.encode(new Uint8Array(32)) } }, /private key material/],
    [{ id: "#a", type: "JsonWebKey", publicKeyJwk: { kty: "OKP", crv: "X25519", x: "AAAA" } }, /32 bytes/],
    [{ id: "#a", type: "JsonWebKey", publicKeyJwk: okp, revoked: "2026-11-01T00:00:00Z" }, /revoked/],
  ];
  for (const [vm, pattern] of cases) {
    assert.throws(() => publicKeyOf(vm), pattern, JSON.stringify(vm));
  }
});

// ─── The shared helper: choosing by relationship ────────────────────────

test("selectKey: a key-roles did:webs VTA — each relationship names its own key", async () => {
  const doc = await resolved(VTA);
  // keyAgreement lists a P-256 key first; the X25519 one is chosen by
  // curve, not by being first.
  assert.equal(x25519KeyAgreement(doc, VTA.did).kid, VTA_X25519_KID);
  assert.equal(selectKey(doc, VTA.did, "keyAgreement").kid, VTA_P256_KID);
  assert.equal(selectKey(doc, VTA.did, "keyAgreement", { curves: ["P-256"] }).kid, VTA_P256_KID);
  // authentication and assertionMethod are different Ed25519 keys.
  assert.equal(selectKey(doc, VTA.did, "authentication").kid, VTA_AUTHENTICATION_KID);
  assert.equal(selectKey(doc, VTA.did, "assertionMethod").kid, VTA_ASSERTION_KID);
  assert.notEqual(VTA_AUTHENTICATION_KID, VTA_ASSERTION_KID);
});

test("selectKey: a named key is used or refused, never substituted", async () => {
  const doc = await resolved(VTA);
  assert.equal(x25519KeyAgreement(doc, VTA.did, { kid: VTA_X25519_KID }).kid, VTA_X25519_KID);
  // Listed, but under authentication only.
  assert.throws(() => x25519KeyAgreement(doc, VTA.did, { kid: VTA_AUTHENTICATION_KID }), /lists no keyAgreement key/);
  assert.throws(() => selectKey(doc, VTA.did, "authentication", { kid: VTA_ASSERTION_KID }), /lists no authentication key/);
  // A keyAgreement key, but not X25519.
  assert.throws(() => x25519KeyAgreement(doc, VTA.did, { kid: VTA_P256_KID }), /is P-256, not X25519/);
});

test("selectKey: relative references, embedded methods, and no usable key", () => {
  const did = "did:example:abc";
  const x = x25519.generateKeyPair().publicKey;
  const vm = { id: "#ka", type: "JsonWebKey", controller: did, publicKeyJwk: jwk.publicJwk("X25519", x) };
  const ref = { id: did, verificationMethod: [vm], keyAgreement: ["#ka"] };
  assert.deepEqual(x25519KeyAgreement(ref, did), { kid: `${did}#ka`, x25519Pub: x });
  const embedded = { id: did, keyAgreement: [vm] };
  assert.deepEqual(x25519KeyAgreement(embedded, did), { kid: `${did}#ka`, x25519Pub: x });
  // An unreadable entry is passed over, never used; with nothing left the
  // selection fails and says why.
  const unreadable = { ...vm, id: "#bad", type: "Bls12381G2Key2020" };
  assert.deepEqual(x25519KeyAgreement({ id: did, keyAgreement: [unreadable, vm] }, did).kid, `${did}#ka`);
  assert.throws(() => x25519KeyAgreement({ id: did, keyAgreement: [unreadable] }, did), /no usable X25519 keyAgreement key.*unsupported type/);
  assert.throws(() => x25519KeyAgreement({ id: did, keyAgreement: ["#missing"] }, did), /not in verificationMethod/);
  assert.throws(() => x25519KeyAgreement({ id: did }, did), /has no keyAgreement entries/);
});

// ─── Mediator auth to a did:webs mediator ───────────────────────────────

test("parseMediatorEndpoints: a did:webs mediator's designated service and JsonWebKey key agreement", async () => {
  const doc = await resolved(MEDIATOR);
  const m = parseMediatorEndpoints(doc, MEDIATOR.did);
  assert.equal(m.restEndpoint, "https://mediator.example.com");
  assert.equal(m.wsEndpoint, "wss://mediator.example.com/ws");
  assert.equal(m.authEndpoint, "https://mediator.example.com/authenticate");
  assert.equal(m.kid, MEDIATOR_X25519_KID);
  assert.deepEqual(m.x25519Pub, x25519.publicKeyFrom(MEDIATOR_X25519_PRIVATE));
});

test("authenticateToMediator: to a did:webs mediator, resolved over the network", async () => {
  const client = generateEphemeralClient();
  let authJwe = null;
  const fetch = async (url, init) => {
    if (url === "https://mediator.example.com/authenticate/challenge") {
      return json({ sessionId: "S", data: { challenge: "CHAL", session_id: "S" } });
    }
    if (url === "https://mediator.example.com/authenticate") {
      authJwe = init.body;
      return json({ data: { access_token: "med.jwt", access_expires_at: 1, refresh_token: "r", refresh_expires_at: 2 } });
    }
    return new Response(`unexpected ${url}`, { status: 404 });
  };
  const result = await authenticateToMediator({
    mediatorDid: MEDIATOR.did,
    clientDid: client.did,
    clientX25519Private: client.privateKey,
    clientX25519Public: client.publicKey,
    clientKid: client.kid,
    fetch,
    resolve: (did, options) => didWebs.resolve(did, { ...options, fetch: artifactFetch() }),
  });
  assert.equal(result.accessToken, "med.jwt");
  assert.equal(result.mediator.kid, MEDIATOR_X25519_KID);

  // The mediator decrypts it with the key its document names, under that
  // key's exact id.
  const jwe = JSON.parse(authJwe);
  assert.equal(jwe.recipients[0].header.kid, MEDIATOR_X25519_KID);
  const opened = await unpack(
    authJwe,
    { kid: MEDIATOR_X25519_KID, privateJwk: jwk.privateJwk("X25519", MEDIATOR_X25519_PRIVATE, x25519.publicKeyFrom(MEDIATOR_X25519_PRIVATE)) },
    { publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  );
  assert.equal(opened.message.body.challenge, "CHAL");
  assert.equal(opened.senderKid, client.kid);
});

// ─── VTA REST auth to a did:webs VTA ────────────────────────────────────

test("vta-rest-auth authenticate: to a did:webs VTA with key roles", async (t) => {
  withNetwork(t);
  const client = generateEphemeralClient();
  let authJwe = null;
  const fetch = async (url, init) => {
    if (url === "https://vta.example.com/api/auth/challenge") {
      return json({ challenge: "C1", sessionId: "S1", expiresAt: "2027-01-01T00:01:00Z" });
    }
    if (url === "https://vta.example.com/api/auth/") {
      authJwe = init.body;
      return json({
        session: { id: "S1", issuedAt: "2027-01-01T00:00:00Z" },
        tokens: { accessToken: "vta.jwt", refreshToken: "vta.r", expiresIn: 900, refreshExpiresIn: 3600 },
      });
    }
    return new Response(`unexpected ${url}`, { status: 404 });
  };
  const result = await authenticate({
    baseUrl: "https://vta.example.com/api",
    vtaDid: VTA.did,
    clientDid: client.did,
    clientX25519Private: client.privateKey,
    clientX25519Public: client.publicKey,
    fetch,
  });
  assert.equal(result.accessToken, "vta.jwt");

  // Packed to the designated X25519 key — not the P-256 key listed first,
  // and not a signing key — under its did:webs id.
  assert.equal(JSON.parse(authJwe).recipients[0].header.kid, VTA_X25519_KID);
  const opened = await unpack(
    authJwe,
    { kid: VTA_X25519_KID, privateJwk: jwk.privateJwk("X25519", VTA_X25519_PRIVATE, x25519.publicKeyFrom(VTA_X25519_PRIVATE)) },
    { publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  );
  assert.equal(opened.message.body.challenge, "C1");
  assert.equal(opened.message.body.session_id, "S1");
  assert.deepEqual(opened.message.to, [VTA.did]);
});

// ─── DIDComm to and from a did:webs VTA ─────────────────────────────────

test("vta-didcomm: pack to a did:webs VTA; unpack its reply by the skid its document names", async (t) => {
  withNetwork(t);
  const client = generateEphemeralClient();
  const clientPrivateJwk = jwk.privateJwk("X25519", client.privateKey, client.publicKey);
  const vtaPrivateJwk = jwk.privateJwk("X25519", VTA_X25519_PRIVATE, x25519.publicKeyFrom(VTA_X25519_PRIVATE));

  // Client → VTA.
  const vta = await resolveX25519KeyAgreement(VTA.did);
  assert.equal(vta.kid, VTA_X25519_KID);
  const request = await pack({
    message: { id: "urn:uuid:1", typ: "application/didcomm-plain+json", type: "t", from: client.did, to: [VTA.did], body: { q: 1 } },
    sender: { kid: client.kid, privateJwk: clientPrivateJwk },
    recipient: { kid: vta.kid, publicJwk: jwk.publicJwk("X25519", vta.x25519Pub) },
  });
  const atVta = await unpack(request, { kid: VTA_X25519_KID, privateJwk: vtaPrivateJwk }, { publicJwk: jwk.publicJwk("X25519", client.publicKey) });
  assert.deepEqual(atVta.message.body, { q: 1 });

  // VTA → client, authenticated with the VTA's key agreement key; the
  // client finds it through the inbound-sender fallback
  // `connectVtaViaMediator` installs.
  const reply = await pack({
    message: { id: "urn:uuid:2", thid: "urn:uuid:1", typ: "application/didcomm-plain+json", type: "t", from: VTA.did, to: [client.did], body: { a: 2 } },
    sender: { kid: VTA_X25519_KID, privateJwk: vtaPrivateJwk },
    recipient: { kid: client.kid, publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  });
  const resolveSender = async (did, skid) => {
    const { kid, x25519Pub } = await resolveX25519KeyAgreementKey(did, skid);
    return { kid, publicJwk: jwk.publicJwk("X25519", x25519Pub) };
  };
  const recipient = { kid: client.kid, privateJwk: clientPrivateJwk };
  const atClient = await unpackInbound(reply, { recipient, senderKeys: new Map(), resolveSender });
  assert.equal(atClient.senderKid, VTA_X25519_KID);
  assert.equal(atClient.senderDid, VTA.did);
  assert.deepEqual(atClient.message.body, { a: 2 });

  // A skid naming the VTA's authentication key is not a key agreement key
  // of it, whatever the frame claims.
  const forged = await pack({
    message: { id: "urn:uuid:3", typ: "application/didcomm-plain+json", type: "t", from: VTA.did, to: [client.did], body: {} },
    sender: { kid: VTA_AUTHENTICATION_KID, privateJwk: vtaPrivateJwk },
    recipient: { kid: client.kid, publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  });
  await assert.rejects(unpackInbound(forged, { recipient, senderKeys: new Map(), resolveSender }), /lists no keyAgreement key/);
});

test("pack: P-256 to a did:webs party's P-256 key agreement key", async () => {
  const doc = await resolved(VTA);
  const key = selectKey(doc, VTA.did, "keyAgreement", { curves: ["P-256"] });
  assert.equal(key.kid, VTA_P256_KID);
  const sender = p256.generateKeyPair();
  const senderKid = "did:example:sender#p256";
  const jweJson = await pack({
    message: { id: "urn:uuid:4", typ: "application/didcomm-plain+json", type: "t", from: "did:example:sender", to: [VTA.did], body: { p: 256 } },
    sender: { kid: senderKid, privateJwk: jwk.privateJwk("P-256", sender.privateKey, sender.publicKey) },
    recipient: { kid: key.kid, publicJwk: key.publicJwk },
  });
  const opened = await unpack(
    jweJson,
    { kid: VTA_P256_KID, privateJwk: jwk.privateJwk("P-256", VTA_P256_PRIVATE, p256.publicKeyFrom(VTA_P256_PRIVATE)) },
    { publicJwk: jwk.publicJwk("P-256", sender.publicKey) },
  );
  assert.deepEqual(opened.message.body, { p: 256 });
});
