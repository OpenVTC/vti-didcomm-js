// did:webs: the identifier, the derivation and its refusals, on the
// fixtures `affinidi-did-webs` 0.13.1 is tested against (copied into
// `test/fixtures/did-webs/`). The full cross-implementation comparison is
// `did-webs-conformance.test.js`; this file holds the cases worth reading on
// their own.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import * as didWebs from "../src/did-webs.js";
import { DID_WEBS_ERROR, DidWebsError, parseDidWebs, resolveFromArtifacts, websArtifactUrls } from "../src/did-webs.js";
import { Kels, MAX_STREAM_BACKERS, MAX_STREAM_MESSAGES, MAX_STREAM_SEALS, MAX_STREAM_SIGNATURES } from "../src/did-webs-kel.js";
import { parseAll } from "../src/did-webs-cesr.js";
import { BLOCKED_ENDPOINT } from "../src/net-guard.js";
import * as index from "../src/index.js";

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), "fixtures", "did-webs");
const read = (name) => new Uint8Array(readFileSync(resolve(FIXTURES, name)));

const AID = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
const DID = `did:webs:did-webs-service%3a7676:${AID}`;
const CESR = read("ENro7uf0.keri.cesr");
const DID_JSON = read("ENro7uf0.did.json");

function refused(kind) {
  return (err) => {
    assert.ok(err instanceof DidWebsError, `expected a DidWebsError, got ${err?.name}: ${err?.message}`);
    assert.equal(err.code, DID_WEBS_ERROR);
    assert.equal(err.kind, kind, err.message);
    return true;
  };
}

const edited = (edit) => {
  const doc = JSON.parse(new TextDecoder().decode(DID_JSON));
  edit(doc);
  return JSON.stringify(doc);
};

// ─── The identifier ─────────────────────────────────────────────────────

test("parseDidWebs: host, port, path and AID, with a versionId", () => {
  assert.deepEqual(parseDidWebs(`did:webs:example.com:${AID}`), { did: `did:webs:example.com:${AID}`, versionId: null, host: "example.com", path: [], aid: AID });
  const parsed = parseDidWebs(`did:webs:example.com%3A8443:users:alice:${AID}?versionId=2#key-1`);
  assert.equal(parsed.did, `did:webs:example.com%3A8443:users:alice:${AID}`);
  assert.equal(parsed.host, "example.com:8443");
  assert.deepEqual(parsed.path, ["users", "alice"]);
  assert.equal(parsed.versionId, 2);
  // The port separator is written lowercase in the wild.
  assert.equal(parseDidWebs(DID).host, "did-webs-service:7676");
  assert.equal(parseDidWebs(`did:webs:%5B%3A%3A1%5D%3A7676:${AID}`).host, "[::1]:7676");
});

test("parseDidWebs: refuses what is not a did:webs, or names something other than a host", () => {
  for (const did of [
    "did:web:example.com:" + AID,
    "did:webs:",
    `did:webs:${AID}`,
    `did:webs:example.com::${AID}`,
    "did:webs:example.com:E!",
    "did:webs:example.com:Eab",
    `did:webs:example.com:${AID}?versionId=two`,
    // A host label that decodes to user information, a path, a fragment, a
    // further escape, whitespace or a bad port (0.13.2's hardening).
    `did:webs:a.example%40b.example:${AID}`,
    `did:webs:a.example%2Fb:${AID}`,
    `did:webs:a.example%23x:${AID}`,
    `did:webs:a.example%2541:${AID}`,
    `did:webs:a%20b.example:${AID}`,
    `did:webs:example.com%3A99999:${AID}`,
    `did:webs:example.com%3A:${AID}`,
    `did:webs:%5Bnot-v6%5D:${AID}`,
    `did:webs:example.com%zz:${AID}`,
    // A path label that is not one segment.
    `did:webs:example.com:..:${AID}`,
    `did:webs:example.com:a%2Fb:${AID}`,
    `did:webs:example.com:a%3Fb:${AID}`,
  ]) {
    assert.throws(() => parseDidWebs(did), refused("InvalidDid"), did);
  }
});

test("websArtifactUrls: the artifacts sit under the AID, over https unless the policy says otherwise", () => {
  const urls = (did, policy) => {
    const u = websArtifactUrls(did, policy);
    return [u.keriCesr.href, u.didJson.href];
  };
  assert.deepEqual(urls(`did:webs:example.com:users:${AID}`), [
    `https://example.com/users/${AID}/keri.cesr`,
    `https://example.com/users/${AID}/did.json`,
  ]);
  // Loopback over plain http once private hosts are admitted (as the Rust
  // `HostPolicy::AllowPrivate`), and any host over http with allowInsecure
  // (its `allow_http`).
  assert.deepEqual(urls(`did:webs:localhost%3A7676:${AID}`, { allowPrivate: true }), [
    `http://localhost:7676/${AID}/keri.cesr`,
    `http://localhost:7676/${AID}/did.json`,
  ]);
  assert.equal(urls(`did:webs:10.0.0.5:${AID}`, { allowPrivate: true })[0], `https://10.0.0.5/${AID}/keri.cesr`);
  assert.equal(urls(`did:webs:example.com:${AID}`, { allowInsecure: true })[0], `http://example.com/${AID}/keri.cesr`);
  assert.throws(() => websArtifactUrls(`did:webs:localhost%3A7676:${AID}`), (e) => e.code === BLOCKED_ENDPOINT);
});

// ─── The reference identifier (hyperledger-labs/did-webs-resolver) ──────

test("resolves the did-webs-resolver reference identifier from its artifacts", () => {
  const { didDocument, didDocumentMetadata, didResolutionMetadata } = resolveFromArtifacts(DID, CESR, DID_JSON);
  assert.equal(didResolutionMetadata.contentType, "application/did+ld+json");
  assert.equal(didDocument.id, DID);
  assert.equal(didDocument.controller, DID);
  const key = `${DID}#DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr`;
  assert.deepEqual(didDocument.authentication, [key]);
  assert.deepEqual(didDocument.assertionMethod, [key]);
  assert.deepEqual(didDocument.verificationMethod[0], {
    id: key,
    type: "JsonWebKey",
    controller: DID,
    publicKeyJwk: { crv: "Ed25519", kid: "DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr", kty: "OKP", x: "evT4j6Yw3uHpwsw5NEmSR8-4x3S-BA-s6Thjd51oeOs" },
  });
  // It designates no key agreement, so its Ed25519 key's X25519 conversion
  // is rendered, as KERI practice does.
  assert.deepEqual(didDocument.keyAgreement, [`${DID}#CPz5wadpRpL4rGHeRSLHIc-2jMndx_mYBhuPhcr7WFRg`]);
  assert.ok(didDocument.alsoKnownAs.includes(`did:keri:${AID}`));
  assert.ok(didDocument.alsoKnownAs.includes(`did:webs:foo.com:${AID}`));
  assert.ok(!didDocument.alsoKnownAs.includes(DID), "the subject is not its own alias");
  assert.deepEqual(didDocumentMetadata, { versionId: "2", equivalentId: [`did:webs:foo.com:${AID}`] });
});

test("resolves as of a key event with versionId", () => {
  assert.equal(resolveFromArtifacts(`${DID}?versionId=2`, CESR, DID_JSON).didDocumentMetadata.versionId, "2");
  // At sequence number 1 the registry is anchored but the issuance is not,
  // so nothing designated the DID yet, and it did not resolve then.
  assert.throws(() => resolveFromArtifacts(`${DID}?versionId=1`, CESR, null), refused("NotDesignated"));
  assert.throws(() => resolveFromArtifacts(`${DID}?versionId=7`, CESR, DID_JSON), refused("Kel"));
});

test("the same artifacts do not resolve for a DID the AID never designated", () => {
  // Served from another host, the stream verifies but does not publish this DID.
  assert.throws(() => resolveFromArtifacts(`did:webs:attacker.example:${AID}`, CESR, DID_JSON), refused("NotDesignated"));
});

test("did.json may leave out what the key state implies, but never add to it or change it", () => {
  // The reference implementation publishes no did:keri alias and no
  // relationships beyond those the key state implies: accepted.
  resolveFromArtifacts(DID, CESR, DID_JSON);
  resolveFromArtifacts(DID, CESR, edited((d) => delete d.service));
  for (const [what, edit] of [
    ["a member nothing establishes", (d) => (d.extra = true)],
    ["an undesignated alias", (d) => d.alsoKnownAs.push("did:web:attacker.example:x")],
    ["an unauthorised service", (d) => d.service.push({ id: "#x", type: "LinkedDomains", serviceEndpoint: "https://x.example/" })],
    ["an unauthorised key", (d) => d.verificationMethod.push({ ...d.verificationMethod[0], id: "#DAAAA" })],
    ["a missing key", (d) => (d.verificationMethod = [])],
    ["a changed key", (d) => (d.verificationMethod[0].publicKeyJwk.x = "AAAA")],
    ["an empty authentication", (d) => (d.authentication = [])],
  ]) {
    assert.throws(() => resolveFromArtifacts(DID, CESR, edited(edit)), refused("DocumentMismatch"), what);
  }
  assert.throws(() => resolveFromArtifacts(DID, CESR, edited((d) => (d.id = `did:web:other.example:${AID}`))), refused("DocumentMismatch"));
  // In its did:webs form a document names its controller as it stands (the
  // did:web form's top-level controller is rewritten to the subject on the
  // way back, whatever it was, as the Rust `swap_subject` does).
  const webs = edited((d) => {
    d.id = DID;
    d.controller = "did:web:attacker.example:x";
  });
  assert.throws(() => resolveFromArtifacts(DID, CESR, webs), refused("DocumentMismatch"));
  assert.throws(() => resolveFromArtifacts(DID, CESR, "{not json"), refused("Json"));
});

test("a tampered key event stream is refused", () => {
  const text = new TextDecoder().decode(CESR);
  // A changed key in the inception: its SAID no longer holds.
  const tampered = text.replace("DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr", "DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjs");
  assert.throws(() => resolveFromArtifacts(DID, tampered, DID_JSON), refused("Kel"));
  // A truncated stream cannot be framed.
  assert.throws(() => resolveFromArtifacts(DID, CESR.subarray(0, CESR.length - 7), DID_JSON), refused("Stream"));
  // A body this implementation does not read is refused, not skipped.
  assert.throws(() => resolveFromArtifacts(DID, Uint8Array.of(0xa1, 0x61, 0x76), DID_JSON), refused("Stream"));
});

test("a stream is bounded in bytes and in messages", () => {
  assert.throws(() => resolveFromArtifacts(DID, new Uint8Array(didWebs.MAX_ARTIFACT_BYTES + 1).fill(0x20), DID_JSON), refused("Stream"));
  assert.throws(() => parseAll(CESR, { maxMessages: 2 }), /more than 2 messages/);
  assert.equal(parseAll(CESR, { maxMessages: 6 }).length, 6);
});

// A KERI 1.0 JSON message with its `v` sized; its SAID is not computed,
// which the stream bounds do not reach.
function keriJson(fields) {
  const msg = { v: "KERI10JSON000000_", ...fields };
  const size = new TextEncoder().encode(JSON.stringify(msg)).length;
  msg.v = `KERI10JSON${size.toString(16).padStart(6, "0")}_`;
  return JSON.stringify(msg);
}

const SAID = "E".padEnd(44, "A");
const SIG = "AA".padEnd(88, "A");

test("a stream past the bounds is refused before anything is verified (0.13.3 kel::MAX_STREAM_*)", () => {
  const stream = (text) => new TextEncoder().encode(text);
  const rct = keriJson({ t: "rct", d: SAID, i: SAID, s: "0" });
  const refusedStream = (text) => assert.throws(() => Kels.parse(stream(text)), (e) => e.name === "StreamError" && /more than/.test(e.message));
  refusedStream(rct.repeat(MAX_STREAM_MESSAGES + 1));
  Kels.parse(stream(rct.repeat(10)));
  refusedStream(rct + `-AAB${SIG}`.repeat(MAX_STREAM_SIGNATURES + 1));
  Kels.parse(stream(rct + `-AAB${SIG}`.repeat(4)));
  const ixn = (seals) => keriJson({ t: "ixn", d: SAID, i: SAID, s: "1", p: SAID, a: Array.from({ length: seals }, () => ({ d: SAID })) });
  refusedStream(ixn(MAX_STREAM_SEALS + 1));
  Kels.parse(stream(ixn(4)));
  const icp = (backers) =>
    keriJson({ t: "icp", d: SAID, i: SAID, s: "0", kt: "1", k: [], nt: "0", n: [], bt: "0", b: Array.from({ length: backers }, () => `B${"A".repeat(43)}`), c: [], a: [] });
  refusedStream(icp(MAX_STREAM_BACKERS + 1));
  Kels.parse(stream(icp(4)));
});

// ─── Deactivation (0.13.3, TDK-SEC-027) ─────────────────────────────────

const DEACTIVATED = read("deactivated/keri.cesr");
const DEACTIVATED_DID = readFileSync(resolve(FIXTURES, "deactivated", "did.txt"), "utf8").trim();

test("a deactivated identifier's document keeps no keys, at the deactivating version", () => {
  for (const published of ["deactivated/did.json", "deactivated/legacy.did.json", null]) {
    const { didDocument, didDocumentMetadata } = resolveFromArtifacts(DEACTIVATED_DID, DEACTIVATED, published && read(published));
    assert.deepEqual(Object.keys(didDocument).sort(), ["alsoKnownAs", "id"], String(published));
    assert.equal(didDocumentMetadata.deactivated, true);
  }
  // An earlier version keeps that version's keys, for checking a signature
  // made while they were current; the DID is still reported deactivated.
  const earlier = resolveFromArtifacts(`${DEACTIVATED_DID}?versionId=3`, DEACTIVATED, null);
  assert.ok(earlier.didDocument.verificationMethod.length > 0);
  assert.equal(earlier.didDocumentMetadata.deactivated, true);
});

test("resolve() refuses a deactivated identifier: it is a document provider", async () => {
  for (const published of ["deactivated/did.json", "deactivated/legacy.did.json"]) {
    const fetch = async (url) => new Response(String(url).endsWith("/keri.cesr") ? DEACTIVATED : read(published));
    await assert.rejects(didWebs.resolve(DEACTIVATED_DID, { fetch }), refused("Deactivated"), published);
  }
});

// ─── KERI 2.0 fixtures ──────────────────────────────────────────────────

test("a KEL with native CESR bodies reaches the key state keripy reaches", () => {
  const expected = JSON.parse(readFileSync(resolve(FIXTURES, "keripy-native", "v2-basic-native.json"), "utf8")).keripy;
  const state = Kels.parse(read("keripy-native/v2-basic-native.cesr")).keyState(expected.prefix);
  assert.equal(state.sn, expected.sn);
  assert.equal(state.lastEventDigest, expected.said);
  assert.equal(state.said, expected.establishment.said);
  assert.deepEqual(state.keys, expected.keys);
});

test("the KERI 2.0 lifecycle keripy accepts resolves, with its designations", () => {
  const spec = JSON.parse(readFileSync(resolve(FIXTURES, "ours-v2", "lifecycle.json"), "utf8"));
  const { didDocument } = resolveFromArtifacts(spec.did, read("ours-v2/lifecycle.keri.cesr"), read("ours-v2/lifecycle.did.json"));
  // Only the replacement key agreement key, the designated service, and the
  // endpoint endorsed under the rotation's key state.
  assert.equal(didDocument.keyAgreement.length, 1);
  const services = JSON.stringify(didDocument.service);
  assert.ok(services.includes("DIDCommMessaging"), services);
  assert.ok(services.includes("https://example.com/v2/"), services);
  const state = Kels.parse(read("ours-v2/lifecycle.keri.cesr")).keyState(parseDidWebs(spec.did).aid);
  assert.equal(state.sn, spec.kel.sn);
  assert.equal(state.lastEventDigest, spec.kel.said);
});

// ─── The surface ────────────────────────────────────────────────────────

test("resolve refuses versionTime: did:webs history is by key event", async () => {
  await assert.rejects(didWebs.resolve(DID, { versionTime: "2026-01-01T00:00:00Z" }), /versionTime is not supported/);
});

test("did:webs is exported and registered with the default resolver", () => {
  assert.equal(index.didWebs.resolve, didWebs.resolve);
  assert.equal(index.DidWebsError, DidWebsError);
  assert.equal(index.DID_WEBS_ERROR, "E_DID_WEBS");
});
