// Signed did:webvh logs for tests, made with `didwebvh-ts` and an Ed25519
// key held here. Not a test file (no `.test.js`), so `npm test` only runs
// it through the tests that import it.

import { createDID, updateDID, deactivateDID, prepareDataForSigning, multibaseEncode, MultibaseEncoding } from "didwebvh-ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { x25519 } from "@noble/curves/ed25519.js";

import { encodeMultikey } from "../src/multibase.js";

const ED25519_PUB = new Uint8Array([0xed, 0x01]);
const X25519_PUB = new Uint8Array([0xec, 0x01]);

const verifier = {
  async verify(signature, message, publicKey) {
    return ed25519.verify(signature, message, publicKey);
  },
};

function signerFor(secretKey) {
  const multikey = encodeMultikey(ED25519_PUB, ed25519.getPublicKey(secretKey));
  return {
    multikey,
    signer: {
      getVerificationMethodId: () => `did:key:${multikey}#${multikey}`,
      async sign({ document, proof }) {
        const data = await prepareDataForSigning(document, proof);
        return { proofValue: multibaseEncode(ed25519.sign(data, secretKey), MultibaseEncoding.BASE58_BTC) };
      },
    },
  };
}

/**
 * A did:webvh log at `address` (`host[:port][/path]`) with an X25519
 * key-agreement key, and helpers to extend it.
 *
 * @param {string} address
 * @param {Object} [options]
 * @param {string[]} [options.alsoKnownAs]
 */
export async function webvhLog(address, { alsoKnownAs } = {}) {
  const updateSecret = ed25519.utils.randomSecretKey();
  const { multikey, signer } = signerFor(updateSecret);
  const kaPrivate = x25519.utils.randomSecretKey();
  const kaMultikey = encodeMultikey(X25519_PUB, x25519.getPublicKey(kaPrivate));

  const created = await createDID({
    address,
    signer,
    updateKeys: [multikey],
    verificationMethods: [{ type: "Multikey", publicKeyMultibase: kaMultikey, purpose: "keyAgreement" }],
    ...(alsoKnownAs ? { alsoKnownAs } : {}),
    verifier,
  });

  let log = created.log;
  return {
    did: created.did,
    doc: created.doc,
    kaPrivate,
    get log() {
      return log;
    },
    jsonl(entries = log) {
      return entries.map((entry) => JSON.stringify(entry)).join("\n");
    },
    async update(alsoKnownAs) {
      const updated = await updateDID({ log, signer, updateKeys: [multikey], alsoKnownAs, verifier });
      log = updated.log;
      return log;
    },
    async deactivate() {
      const deactivated = await deactivateDID({ log, signer, verifier });
      log = deactivated.log;
      return log;
    },
  };
}

/** A fetch serving `body()` as every `did.jsonl`, counting requests. */
export function logFetch(body) {
  const calls = [];
  const fetch = async (url) => {
    calls.push(String(url));
    if (!String(url).endsWith("did.jsonl")) return new Response("", { status: 404 });
    return new Response(body(), { status: 200, headers: { "content-type": "text/jsonl" } });
  };
  return { fetch, calls };
}
