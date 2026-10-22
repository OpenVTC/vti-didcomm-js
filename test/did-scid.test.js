// did:scid:vh:1 — a DID in its own right, verified by a did:webvh log.
//
// The identity is `did:scid:vh:1:<scid>`; `?src=` is a locator (VTI-KEY-160).
// Resolution returns the did:scid's own document, under the bare DID
// (VTI-KEY-161); a bare DID resolves through the source a resolver last
// verified for its SCID, and an older copy of the log is refused (VTI-KEY-162).
// A did:scid sender carries its `src` in `skid` so a first-contact recipient
// can resolve it, and is bound to `from` by identity (VTI-KEY-163).
//
// The helper and conversion vectors are ported from the Rust stack:
// affinidi_did_common::scid and didwebvh-rs did_web.rs.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  stripScidSrc,
  scidSrc,
  withScidSrc,
  sameReference,
  scidToWebvhDid,
  webvhToScidDidUrl,
  toScidDidDocument,
  createScidSourceBook,
} from "../src/did-scid.js";
import { createResolver } from "../src/resolver.js";
import { pack } from "../src/pack.js";
import { unpack, SenderMismatchError } from "../src/unpack.js";
import { unpackInbound } from "../src/mediator-transport.js";
import { resolveX25519KeyAgreementKey } from "../src/vta-didcomm.js";
import { BlockedEndpointError } from "../src/net-guard.js";
import * as jwk from "../src/jwk.js";
import * as x25519 from "../src/x25519.js";
import * as multibase from "../src/multibase.js";
import { webvhLog, logFetch } from "./support-webvh-log.js";

// ─── The src locator (affinidi_did_common::scid) ────────────────────────

test("stripScidSrc: removes src, keeping the fragment", () => {
  assert.equal(stripScidSrc("did:scid:vh:1:Qm?src=example.com/alice"), "did:scid:vh:1:Qm");
  assert.equal(stripScidSrc("did:scid:vh:1:Qm?src=localhost%3A8000/a#key-1"), "did:scid:vh:1:Qm#key-1");
});

test("stripScidSrc: leaves everything else", () => {
  for (const did of [
    "did:scid:vh:1:Qm",
    "did:scid:vh:1:Qm#key-1",
    "did:scid:vh:1:Qm?src=example.com&versionId=2",
    "did:scid:vh:1:Qm?versionId=2#key-1",
    "did:scid:vh:1:Qm?src=",
    "did:webvh:Qm:example.com?versionId=1#key-1",
    "did:example:123?src=example.com",
  ]) {
    assert.equal(stripScidSrc(did), did, did);
  }
});

test("scidSrc", () => {
  assert.equal(scidSrc("did:scid:vh:1:Qm?src=example.com/alice#k"), "example.com/alice");
  assert.equal(scidSrc("did:scid:vh:1:Qm"), null);
});

test("withScidSrc: adds src to a bare reference only", () => {
  assert.equal(withScidSrc("did:scid:vh:1:Qm#key-1", "example.com/alice"), "did:scid:vh:1:Qm?src=example.com/alice#key-1");
  assert.equal(withScidSrc("did:scid:vh:1:Qm", "example.com"), "did:scid:vh:1:Qm?src=example.com");
  for (const unchanged of ["did:scid:vh:1:Qm?src=a.example#key-1", "did:webvh:Qm:example.com#key-1"]) {
    assert.equal(withScidSrc(unchanged, "b.example"), unchanged);
  }
});

test("sameReference: by DID and fragment, ignoring src", () => {
  assert.ok(sameReference("did:scid:vh:1:Qm?src=example.com#key-1", "did:scid:vh:1:Qm#key-1"));
  assert.ok(sameReference("did:scid:vh:1:Qm?src=a.example#key-1", "did:scid:vh:1:Qm?src=b.example#key-1"));
  assert.ok(!sameReference("did:scid:vh:1:Qm?src=example.com#key-1", "did:scid:vh:1:Qm#key-2"));
  assert.ok(!sameReference("did:scid:vh:1:Qm#key-1", "did:webvh:Qm:example.com#key-1"));
});

// ─── Conversions (didwebvh-rs did_web.rs) ───────────────────────────────

test("scidToWebvhDid: basic", () => {
  assert.equal(scidToWebvhDid("did:scid:vh:1:acme1234?src=affinidi.com/path"), "did:webvh:acme1234:affinidi.com:path");
  assert.equal(scidToWebvhDid("did:scid:vh:1:acme1234?src=affinidi.com"), "did:webvh:acme1234:affinidi.com");
});

test("scid ↔ webvh round trip", () => {
  for (const webvh of [
    "did:webvh:acme1234:affinidi.com",
    "did:webvh:acme1234:affinidi.com:a:b",
    "did:webvh:acme1234:localhost%3A8000:path",
  ]) {
    assert.equal(scidToWebvhDid(webvhToScidDidUrl(webvh)), webvh);
  }
});

test("scidToWebvhDid: lenient src", () => {
  for (const src of [
    "https://localhost:8000/path/",
    "localhost:8000/path",
    "localhost%3A8000/path",
    "http://localhost%3A8000/path",
  ]) {
    assert.equal(scidToWebvhDid(`did:scid:vh:1:abc?src=${src}`), "did:webvh:abc:localhost%3A8000:path", src);
  }
});

test("scidToWebvhDid: keeps the fragment", () => {
  assert.equal(scidToWebvhDid("did:scid:vh:1:abc?src=example.com#key-1"), "did:webvh:abc:example.com#key-1");
});

test("scidToWebvhDid: rejects", () => {
  for (const id of [
    "did:webvh:abc:example.com",
    "did:scid:vh:1:abc",
    "did:scid:vh:2:abc?src=example.com",
    "did:scid:ke:1:abc?src=example.com",
    "did:scid:vh:1:?src=example.com",
    "did:scid:vh:1:abc?src=",
    "did:scid:vh:1:abc?src=https:///",
    "did:scid:vh:1:abc?src=example.com&x=1",
    "did:scid:vh:1:abc?src=example.com:notaport",
    "did:scid:vh:1:abc?src=:8000",
    "did:scid:vh:1:abc?src=example.com//path",
    "did:scid:vh:1:a:b?src=example.com",
  ]) {
    assert.equal(scidToWebvhDid(id), null, id);
  }
});

test("toScidDidDocument: the did:scid's own document", () => {
  const webvh = "did:webvh:Qm123:example.com:alice";
  const scid = "did:scid:vh:1:Qm123";
  const scidUrl = "did:scid:vh:1:Qm123?src=example.com/alice";
  const doc = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: webvh,
    controller: webvh,
    alsoKnownAs: [scidUrl, "did:web:example.com:alice"],
    verificationMethod: [
      { id: `${webvh}#key-1`, controller: webvh, type: "Multikey", publicKeyMultibase: "z6Mk" },
      { id: "#key-2", controller: webvh, type: "Multikey", publicKeyMultibase: "z6LS" },
    ],
    authentication: [`${webvh}#key-1`],
    keyAgreement: ["#key-2"],
    service: [
      { id: `${webvh}#didcomm`, type: "DIDCommMessaging", serviceEndpoint: "did:webvh:QmOther:mediator.example.com" },
      { id: `${webvh}/whois`, type: "LinkedVerifiablePresentation", serviceEndpoint: "https://example.com/alice/whois.vp" },
    ],
  };

  const out = toScidDidDocument(doc);
  assert.equal(out.id, scid);
  assert.equal(out.controller, scid);
  assert.equal(out.verificationMethod[0].id, `${scid}#key-1`);
  assert.equal(out.verificationMethod[0].controller, scid);
  assert.equal(out.verificationMethod[1].id, "#key-2");
  assert.equal(out.authentication[0], `${scid}#key-1`);
  assert.equal(out.keyAgreement[0], "#key-2");
  assert.equal(out.service[0].id, `${scid}#didcomm`);
  assert.equal(out.service[0].serviceEndpoint, "did:webvh:QmOther:mediator.example.com");
  assert.equal(out.service[1].id, `${webvh}/whois`);
  assert.deepEqual(out.alsoKnownAs, [scidUrl, "did:web:example.com:alice", webvh]);
  // The input is not modified.
  assert.equal(doc.id, webvh);
});

test("toScidDidDocument: a log that never listed its did:scid", () => {
  const out = toScidDidDocument({
    id: "did:webvh:Qm123:example.com",
    controller: "did:webvh:Qm123:example.com:alice",
  });
  assert.equal(out.id, "did:scid:vh:1:Qm123");
  assert.equal(out.controller, "did:webvh:Qm123:example.com:alice");
  assert.deepEqual(out.alsoKnownAs, ["did:scid:vh:1:Qm123?src=example.com", "did:webvh:Qm123:example.com"]);
});

test("toScidDidDocument: refuses a non-webvh document", () => {
  assert.throws(() => toScidDidDocument({ id: "did:web:example.com" }));
  assert.throws(() => toScidDidDocument({ id: "did:webvh:Qm123" }));
  assert.throws(() => toScidDidDocument({}));
});

// ─── Source book ────────────────────────────────────────────────────────

test("source book: bounded, oldest forgotten first", () => {
  const book = createScidSourceBook({ capacity: 2 });
  book.addSource("did:scid:vh:1:A?src=a.example");
  book.addSource("did:scid:vh:1:B?src=b.example");
  book.addSource("did:scid:vh:1:C?src=c.example");
  assert.equal(book.size(), 2);
  assert.equal(book.source("did:scid:vh:1:A"), null);
  assert.equal(book.source("did:scid:vh:1:C#key-1"), "c.example");
  assert.equal(book.addSource("did:scid:vh:1:D"), false);
});

// ─── Resolution ─────────────────────────────────────────────────────────

async function servedLog(address = "https://example.com/alice") {
  const log = await webvhLog(address);
  let body = log.jsonl();
  const served = logFetch(() => body);
  const scid = log.did.split(":")[2];
  return {
    log,
    served,
    serve(entries) {
      body = log.jsonl(entries);
    },
    did: `did:scid:vh:1:${scid}`,
    url: webvhToScidDidUrl(log.did),
  };
}

test("resolve: a did:scid DID URL resolves to its own document under the bare DID", async () => {
  const { log, served, did, url } = await servedLog();
  const resolver = createResolver();

  const { didDocument } = await resolver.resolve(url, { fetch: served.fetch });

  assert.equal(didDocument.id, did);
  assert.ok(didDocument.verificationMethod.every((vm) => vm.id.startsWith(`${did}#`)));
  assert.ok(didDocument.keyAgreement.every((ka) => ka.startsWith(`${did}#`)));
  assert.ok(didDocument.alsoKnownAs.includes(log.did));
  assert.ok(didDocument.alsoKnownAs.includes(url));
  assert.deepEqual(served.calls, ["https://example.com/alice/did.jsonl"]);
});

test("resolve: every DID URL of one identity shares a cache entry", async () => {
  const { served, did, url } = await servedLog();
  const resolver = createResolver();
  await resolver.resolve(url, { fetch: served.fetch });
  const { didDocument } = await resolver.resolve(did, { fetch: served.fetch });
  assert.equal(didDocument.id, did);
  assert.equal(served.calls.length, 1);
  assert.equal(resolver.size(), 1);
});

test("resolve: a bare DID resolves through the source last verified", async () => {
  const { served, did, url } = await servedLog();
  const resolver = createResolver();
  await resolver.resolve(url, { fetch: served.fetch });
  resolver.invalidate(did);

  const { didDocument } = await resolver.resolve(did, { fetch: served.fetch });
  assert.equal(didDocument.id, did);
  assert.equal(served.calls.length, 2);
  assert.equal(resolver.scidSource(did), "example.com/alice");
});

test("resolve: a bare DID with no known source fails, uncached", async () => {
  const { served, did } = await servedLog();
  const resolver = createResolver();
  await assert.rejects(resolver.resolve(did, { fetch: served.fetch }), /no source is known/);
  assert.equal(served.calls.length, 0);
  assert.equal(resolver.size(), 0);
});

test("resolve: a seeded source resolves the bare DID", async () => {
  const { served, did, url } = await servedLog();
  const resolver = createResolver();
  assert.equal(resolver.addScidSource(url), true);
  const { didDocument } = await resolver.resolve(did, { fetch: served.fetch });
  assert.equal(didDocument.id, did);
});

test("resolve: an older copy of the log is refused", async () => {
  const { log, served, serve, did, url } = await servedLog();
  const genesis = log.log.slice();
  await log.update(["https://example.com/v1"]);
  serve();
  const resolver = createResolver();
  await resolver.resolve(url, { fetch: served.fetch });

  // The source now serves only the first version, as a stale mirror would.
  serve(genesis);
  resolver.invalidate(did);
  await assert.rejects(resolver.resolve(url, { fetch: served.fetch }), /behind/);
});

test("resolve: a deactivated did:scid does not resolve", async () => {
  const { log, served, serve, url } = await servedLog();
  await log.deactivate();
  serve();
  // The did:webvh layer already refuses a deactivated log (it yields no
  // document); the did:scid layer refuses one flagged deactivated too.
  await assert.rejects(createResolver().resolve(url, { fetch: served.fetch }));
});

test("resolve: the host guard applies to the src host", async () => {
  const { served } = await servedLog();
  const resolver = createResolver();
  await assert.rejects(
    resolver.resolve("did:scid:vh:1:QmAbc?src=localhost:8000", { fetch: served.fetch }),
    BlockedEndpointError,
  );
  assert.equal(served.calls.length, 0);
});

test("resolve: under a private-host policy, src=localhost:<port> is fetched over http", async () => {
  const { served, did, url } = await servedLog("localhost:8000");
  assert.equal(url, `${did}?src=localhost%3A8000`);
  const literal = `${did}?src=localhost:8000`;
  const { didDocument } = await createResolver().resolve(literal, {
    fetch: served.fetch,
    netPolicy: { allowPrivate: true, allowInsecure: true },
  });
  assert.equal(didDocument.id, did);
  assert.deepEqual(served.calls, ["http://localhost:8000/.well-known/did.jsonl"]);
});

// ─── DIDComm ────────────────────────────────────────────────────────────

function keyParty() {
  const kp = x25519.generateKeyPair();
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
  const did = `did:key:${mb}`;
  return {
    did,
    kid: `${did}#${mb}`,
    privateJwk: jwk.privateJwk("X25519", kp.privateKey, kp.publicKey),
    publicJwk: jwk.publicJwk("X25519", kp.publicKey),
  };
}

async function scidSender() {
  const served = await servedLog();
  const resolver = createResolver();
  const { didDocument } = await resolver.resolve(served.url, { fetch: served.served.fetch });
  const kid = didDocument.keyAgreement[0];
  const publicKey = x25519.publicKeyFrom(served.log.kaPrivate);
  return {
    ...served,
    kid,
    privateJwk: jwk.privateJwk("X25519", served.log.kaPrivate, publicKey),
  };
}

async function authcryptFrom(sender, from, recipient) {
  return pack({
    message: { id: "m-1", type: "t", from, to: [recipient.did], body: {} },
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  });
}

function skidOf(jwe) {
  const header = JSON.parse(Buffer.from(JSON.parse(jwe).protected, "base64url").toString());
  return header.skid;
}

test("pack: a did:scid sender's skid carries the src of its from", async () => {
  const sender = await scidSender();
  const bob = keyParty();
  const jwe = await authcryptFrom(sender, sender.url, bob);
  assert.equal(skidOf(jwe), withScidSrc(sender.kid, scidSrc(sender.url)));

  // A bare from leaves the bare key id.
  assert.equal(skidOf(await authcryptFrom(sender, sender.did, bob)), sender.kid);
});

test("first contact: a recipient resolves a did:scid sender from its skid and binds it by identity", async () => {
  const sender = await scidSender();
  const bob = keyParty();
  const jwe = await authcryptFrom(sender, sender.url, bob);

  // Bob has never seen the sender: a fresh resolver, no seeded keys.
  const bobResolver = createResolver();
  const result = await unpackInbound(jwe, {
    recipient: { kid: bob.kid, privateJwk: bob.privateJwk },
    senderKeys: new Map(),
    async resolveSender(senderDid, skid) {
      const { didDocument } = await bobResolver.resolve(senderDid, { fetch: sender.served.fetch });
      const vm = didDocument.verificationMethod.find((v) => sameReference(v.id, skid));
      const { key } = multibase.decodeMultikey(vm.publicKeyMultibase);
      return { kid: vm.id, publicJwk: jwk.publicJwk("X25519", key) };
    },
  });

  assert.equal(result.senderDid, sender.did, "the identity is the bare did:scid");
  assert.equal(result.message.from, sender.url);
  // Having resolved it once, Bob can address the bare DID.
  const { didDocument } = await bobResolver.resolve(sender.did, { fetch: sender.served.fetch });
  assert.equal(didDocument.id, sender.did);
});

test("unpack: a did:scid from of another identity is refused", async () => {
  const sender = await scidSender();
  const bob = keyParty();
  const jwe = await authcryptFrom(sender, "did:scid:vh:1:QmSomeoneElse?src=example.com/alice", bob);
  await assert.rejects(
    unpack(jwe, { kid: bob.kid, privateJwk: bob.privateJwk }, { publicJwk: jwk.publicJwk("X25519", x25519.publicKeyFrom(sender.log.kaPrivate)) }),
    SenderMismatchError,
  );
});

test("resolveX25519KeyAgreementKey: finds a bare key by a src-bearing kid", async () => {
  const sender = await scidSender();
  const skid = withScidSrc(sender.kid, scidSrc(sender.url));
  const resolver = createResolver();
  await resolver.resolve(sender.url, { fetch: sender.served.fetch });
  // The module-level helper resolves through the shared default resolver,
  // which has not seen this DID: seed its document via a DID URL fetch.
  const { addScidSource } = await import("../src/resolver.js");
  addScidSource(sender.url);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = sender.served.fetch;
  try {
    const key = await resolveX25519KeyAgreementKey(sender.url, skid);
    assert.equal(key.kid, skid);
    assert.equal(key.x25519Pub.length, 32);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
