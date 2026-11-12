// did:webvh resolution as of a time (`versionTime`): the document is the
// `state` of the last log entry whose `versionTime` is at or before the
// instant, and the log is verified exactly as a current resolution verifies
// it before any entry is chosen.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  createDID,
  updateDID,
  deactivateDID,
  deriveNextKeyHash,
  prepareDataForSigning,
  multibaseEncode,
  MultibaseEncoding,
  signWitnessProofEntry,
} from "didwebvh-ts";
import { ed25519 } from "@noble/curves/ed25519.js";

import * as didWebvh from "../src/did-webvh.js";
import { createResolver, DidVersionNotFoundError, DID_VERSION_NOT_FOUND } from "../src/index.js";
import { encodeMultikey } from "../src/multibase.js";
import { webvhToScidDidUrl } from "../src/did-scid.js";
import { webvhLog, logFetch } from "./support-webvh-log.js";

const ED25519_PUB = new Uint8Array([0xed, 0x01]);

const verifier = {
  async verify(signature, message, publicKey) {
    return ed25519.verify(signature, message, publicKey);
  },
};

function keypair() {
  const secret = ed25519.utils.randomSecretKey();
  const multikey = encodeMultikey(ED25519_PUB, ed25519.getPublicKey(secret));
  return {
    multikey,
    signer: {
      getVerificationMethodId: () => `did:key:${multikey}#${multikey}`,
      async sign({ document, proof }) {
        const data = await prepareDataForSigning(document, proof);
        return { proofValue: multibaseEncode(ed25519.sign(data, secret), MultibaseEncoding.BASE58_BTC) };
      },
    },
  };
}

/**
 * A complete did:webvh document (didwebvh-ts 3 takes one rather than a key
 * list) whose only verification method is `k` as an assertion key. `{DID}`
 * is filled in by `createDID`; an update passes the real `did`.
 */
const docWith = (k, did = "{DID}") => {
  const id = `${did}#${k.multikey.slice(-8)}`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: did,
    controller: did,
    verificationMethod: [{ id, type: "Multikey", controller: did, publicKeyMultibase: k.multikey }],
    assertionMethod: [id],
  };
};

/** Whole seconds, as a log's `versionTime` carries them. */
const at = (ms) => new Date(Math.floor(ms / 1000) * 1000);
const iso = (d) => d.toISOString().replace(".000Z", "Z");

const T0 = at(Date.now() - 3 * 3600_000); // created, with assertion key A
const T1 = at(Date.now() - 2 * 3600_000); // rotated to assertion key B

/** The multibase keys a document lists as verification methods. */
const keysOf = (doc) => (doc.verificationMethod ?? []).map((vm) => vm.publicKeyMultibase);

/** A did:webvh created at T0 with assertion key A, rotated to B at T1. */
async function rotatedLog() {
  const update = keypair();
  const a = keypair();
  const b = keypair();
  const created = await createDID({
    address: "example.com",
    signer: update.signer,
    updateKeys: [update.multikey],
    didDocument: docWith(a),
    created: iso(T0),
    verifier,
  });
  const rotated = await updateDID({
    log: created.log,
    signer: update.signer,
    updateKeys: [update.multikey],
    didDocument: docWith(b, created.did),
    updated: iso(T1),
    verifier,
  });
  return { did: created.did, log: rotated.log, a, b, update };
}

// ─── Which entry ────────────────────────────────────────────────────────

test("versionTime: before a rotation resolves the key then in force, not the current one", async () => {
  const { log, a, b } = await rotatedLog();
  const between = new Date((T0.getTime() + T1.getTime()) / 2);
  const { didDocument, didDocumentMetadata } = await didWebvh.resolveLog(log, { versionTime: between });
  assert.deepEqual(keysOf(didDocument), [a.multikey]);
  assert.equal(didDocumentMetadata.versionId, log[0].versionId);

  const now = await didWebvh.resolveLog(log);
  assert.deepEqual(keysOf(now.didDocument), [b.multikey], "current resolution is unchanged");
});

test("versionTime: a key not yet active at the instant is not in the document", async () => {
  const { log, b } = await rotatedLog();
  const justBefore = new Date(T1.getTime() - 1);
  const { didDocument } = await didWebvh.resolveLog(log, { versionTime: justBefore });
  assert.ok(!keysOf(didDocument).includes(b.multikey), "B was added at T1, after the instant");
});

test("versionTime: an instant equal to an entry's versionTime selects that entry", async () => {
  // The specification's rule is the last entry at *or before* the instant;
  // `didwebvh-ts`'s own selector compares strictly and selects nothing here.
  const { log, a, b } = await rotatedLog();
  assert.deepEqual(keysOf((await didWebvh.resolveLog(log, { versionTime: iso(T1) })).didDocument), [b.multikey]);
  assert.deepEqual(keysOf((await didWebvh.resolveLog(log, { versionTime: iso(T0) })).didDocument), [a.multikey]);
});

test("versionTime: after the last entry resolves the current document", async () => {
  const { log, b } = await rotatedLog();
  const { didDocument, didDocumentMetadata } = await didWebvh.resolveLog(log, { versionTime: new Date() });
  assert.deepEqual(keysOf(didDocument), [b.multikey]);
  assert.equal(didDocumentMetadata.versionId, log[1].versionId);
});

test("versionTime: an instant before the DID's creation is refused with E_DID_VERSION_NOT_FOUND", async () => {
  const { did, log } = await rotatedLog();
  const before = new Date(T0.getTime() - 1000);
  await assert.rejects(
    () => didWebvh.resolveLog(log, { versionTime: before }),
    (err) => {
      assert.ok(err instanceof DidVersionNotFoundError);
      assert.equal(err.code, DID_VERSION_NOT_FOUND);
      assert.equal(err.did, did);
      assert.equal(err.created, log[0].versionTime);
      return true;
    },
  );
});

test("versionTime: accepts an RFC 3339 string with an offset, refuses anything else", async () => {
  const { log, a } = await rotatedLog();
  const between = new Date((T0.getTime() + T1.getTime()) / 2);
  const offset = between.toISOString().replace("Z", "+00:00");
  assert.deepEqual(keysOf((await didWebvh.resolveLog(log, { versionTime: offset })).didDocument), [a.multikey]);
  for (const bad of ["2026-01-01", "2026-01-01T00:00:00", "yesterday", 1_700_000_000_000, new Date(NaN)]) {
    await assert.rejects(() => didWebvh.resolveLog(log, { versionTime: bad }), TypeError, String(bad));
  }
});

test("versionTime: a deactivated DID still resolves as of before its deactivation", async () => {
  const { log, update, b } = await rotatedLog();
  const { log: deactivated } = await deactivateDID({ log, signer: update.signer, verifier });
  const { didDocument } = await didWebvh.resolveLog(deactivated, { versionTime: new Date(T1.getTime() + 1000) });
  assert.deepEqual(keysOf(didDocument), [b.multikey]);
});

// ─── The log is verified as current resolution verifies it ─────────────

test("versionTime: a tampered entry before the instant is refused", async () => {
  const { log } = await rotatedLog();
  const tampered = structuredClone(log);
  tampered[0].state.alsoKnownAs = ["https://attacker.example"];
  await assert.rejects(() => didWebvh.resolveLog(tampered, { versionTime: new Date() }));
});

test("versionTime: a broken entry after the instant is refused too, not skipped", async () => {
  // Upstream's own selector swallows a failure after the entry it selected;
  // a log that would not resolve now does not resolve as of any time.
  const { log } = await rotatedLog();
  const tampered = structuredClone(log);
  tampered[1].state.alsoKnownAs = ["https://attacker.example"];
  const between = new Date((T0.getTime() + T1.getTime()) / 2);
  await assert.rejects(() => didWebvh.resolveLog(tampered, { versionTime: between }), /Hash chain|verification|proof/i);
});

test("versionTime: a pre-rotation log resolves as of before its rotation, with the update keys then in force", async () => {
  const k1 = keypair();
  const k2 = keypair();
  const a = keypair();
  const b = keypair();
  const created = await createDID({
    address: "example.com",
    signer: k1.signer,
    updateKeys: [k1.multikey],
    nextKeyHashes: [await deriveNextKeyHash(k2.multikey)],
    didDocument: docWith(a),
    created: iso(T0),
    verifier,
  });
  const rotated = await updateDID({
    log: created.log,
    signer: k2.signer,
    updateKeys: [k2.multikey],
    nextKeyHashes: [],
    didDocument: docWith(b, created.did),
    updated: iso(T1),
    verifier,
  });
  const between = new Date((T0.getTime() + T1.getTime()) / 2);
  const then = await didWebvh.resolveLog(rotated.log, { versionTime: between });
  assert.deepEqual(keysOf(then.didDocument), [a.multikey]);
  assert.equal(then.didDocumentMetadata.prerotation, true);
  assert.deepEqual(then.didDocumentMetadata.updateKeys, [k1.multikey], "the update keys in force then");
});

/** A witness proof over `versionId` by `k`, which signWitnessProofEntry would not make. */
async function strangerProof(versionId, k) {
  const proof = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: k.signer.getVerificationMethodId(),
    created: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    proofPurpose: "assertionMethod",
  };
  const { proofValue } = await k.signer.sign({ document: { versionId }, proof });
  return { versionId, proof: [{ ...proof, proofValue }] };
}

test("versionTime: witness thresholds apply to a historical resolution", async () => {
  const update = keypair();
  const witness = keypair();
  const witnessDid = `did:key:${witness.multikey}`;
  const created = await createDID({
    address: "example.com",
    signer: update.signer,
    updateKeys: [update.multikey],
    didDocument: docWith(keypair()),
    witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
    created: iso(T0),
    verifier,
  });
  const proofs = [
    await signWitnessProofEntry({
      trustedLog: [],
      candidateLog: created.log,
      witnessSigner: witness.signer,
      witnessProofs: [],
      verifier,
    }),
  ];
  const now = new Date();
  const ok = await didWebvh.resolveLog(created.log, { versionTime: now, witnessProofs: proofs });
  assert.equal(ok.didDocumentMetadata.versionId, created.log[0].versionId);

  const stranger = keypair();
  const unwitnessed = [
    // `signWitnessProofEntry` refuses a signer outside the witness list,
    // so the stranger's otherwise well-formed proof is made by hand.
    await strangerProof(created.log[0].versionId, stranger),
  ];
  await assert.rejects(
    () => didWebvh.resolveLog(created.log, { versionTime: now, witnessProofs: unwitnessed }),
    /[Ww]itness threshold/,
  );
});

// ─── Over the network, and through a caching resolver ──────────────────

function serving(log) {
  const calls = [];
  const jsonl = log.map((entry) => JSON.stringify(entry)).join("\n");
  const fetch = async (url) => {
    calls.push(String(url));
    return new Response(jsonl, { status: 200 });
  };
  return { fetch, calls };
}

test("resolve(did, { versionTime }) fetches and resolves as of the instant", async () => {
  const { did, log, a } = await rotatedLog();
  const { fetch } = serving(log);
  const between = new Date((T0.getTime() + T1.getTime()) / 2);
  const { didDocument } = await didWebvh.resolve(did, { fetch, versionTime: between });
  assert.deepEqual(keysOf(didDocument), [a.multikey]);
  await assert.rejects(
    () => didWebvh.resolve(did, { fetch, versionTime: new Date(T0.getTime() - 1000) }),
    (err) => err.code === DID_VERSION_NOT_FOUND,
  );
});

test("resolver: a resolution as of a time is never cached, nor answered from the cache", async () => {
  const { did, log, a, b } = await rotatedLog();
  const { fetch, calls } = serving(log);
  const resolver = createResolver();
  const between = new Date((T0.getTime() + T1.getTime()) / 2);

  const current = await resolver.resolve(did, { fetch });
  assert.deepEqual(keysOf(current.didDocument), [b.multikey]);
  assert.equal(resolver.size(), 1);

  const then = await resolver.resolve(did, { fetch, versionTime: between });
  assert.deepEqual(keysOf(then.didDocument), [a.multikey], "not the cached current document");
  assert.equal(calls.length, 2, "the historical resolution fetched the log itself");

  resolver.clearCache();
  await resolver.resolve(did, { fetch, versionTime: between });
  assert.equal(resolver.size(), 0, "the historical document was not cached");
  const again = await resolver.resolve(did, { fetch });
  assert.deepEqual(keysOf(again.didDocument), [b.multikey], "a later current resolution is current");
});

test("did:scid: a resolution as of a time is not held against the source book, nor recorded in it", async () => {
  const log = await webvhLog("https://example.com/alice");
  await log.update(["https://example.com/v1"]);
  const served = logFetch(() => log.jsonl());
  const url = webvhToScidDidUrl(log.did);
  const resolver = createResolver();

  await resolver.resolve(url, { fetch: served.fetch });
  // Version 1 is behind the version 2 the book holds; as of its own time it
  // is the right answer, not a stale mirror.
  const then = await resolver.resolve(url, { fetch: served.fetch, versionTime: log.log[0].versionTime });
  assert.equal(then.didDocumentMetadata.versionId, log.log[0].versionId);
  assert.ok(!(then.didDocument.alsoKnownAs ?? []).includes("https://example.com/v1"));

  // And a fresh book is not seeded with the old version either.
  const fresh = createResolver();
  await fresh.resolve(url, { fetch: served.fetch, versionTime: log.log[0].versionTime });
  assert.equal(fresh.scidSource(url), null);
});
