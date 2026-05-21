// `did:webvh` resolver — thin wrapper around the DIF-maintained
// `didwebvh-ts` package.
//
// We don't reimplement the webvh log walk, hash chain, or
// Data-Integrity-proof verification — those live in
// `didwebvh-ts`, which:
//   - ships a `browser` export (≈37 KB, no Node-only deps),
//   - takes a pluggable `Verifier` so we can hand in our existing
//     `@noble/curves` Ed25519 verifier (no extra crypto dep),
//   - is maintained by DIF, the same body publishing the webvh spec.
//
// This module just adapts the API to our resolver shape and supplies
// the verifier. If we ever need to vendor the implementation (e.g.
// for a strict Content Security Policy), the swap-out point is here.

import { resolveDID, resolveDIDFromLog } from "didwebvh-ts";

/**
 * Resolve a `did:webvh:…` identifier to its current DID document.
 *
 * Fetches `did.jsonl` over HTTPS, walks the log, verifies the
 * hash chain and every Data Integrity proof, and returns the
 * latest valid `state`.
 *
 * @param {string} did
 * @param {Object} [options]
 * @param {Function} [options.verifier] - override the Ed25519
 *   verifier. Defaults to `@noble/curves`. Mainly useful for tests
 *   that want to inject a failing verifier and confirm we propagate
 *   the error.
 * @returns {Promise<{
 *   didDocument: Object,
 *   didResolutionMetadata: Object,
 *   didDocumentMetadata: Object,
 * }>}
 */
export async function resolve(did, options = {}) {
  if (typeof did !== "string") {
    throw new TypeError("did:webvh resolve: input must be a string");
  }
  if (!did.startsWith("did:webvh:")) {
    throw new Error(`did:webvh resolve: identifier must start with "did:webvh:"`);
  }

  const verifier = options.verifier ?? (await defaultEd25519Verifier());
  const result = await resolveDID(did, { verifier });
  return adaptResolutionResult(result);
}

/**
 * Resolve from an already-loaded log (skip the HTTP step). Useful
 * for tests and replay.
 *
 * @param {Object[]} log - parsed LogEntry objects in order
 * @param {Object} [options]
 * @param {Function} [options.verifier]
 */
export async function resolveLog(log, options = {}) {
  const verifier = options.verifier ?? (await defaultEd25519Verifier());
  const result = await resolveDIDFromLog(log, { verifier });
  return adaptResolutionResult(result);
}

/**
 * Build a `Verifier` that uses `@noble/curves`' Ed25519
 * implementation. Lazy-loaded so the module doesn't pull
 * `@noble/curves/ed25519` until someone actually resolves a DID.
 */
async function defaultEd25519Verifier() {
  const { ed25519 } = await import("@noble/curves/ed25519.js");
  return {
    async verify(signature, message, publicKey) {
      return ed25519.verify(signature, message, publicKey);
    },
  };
}

/**
 * Map `didwebvh-ts`'s `{did, doc, meta}` shape onto the W3C DID
 * Resolution result shape we use elsewhere in this library.
 *
 * `resolveDID` does NOT throw on failure — it returns a result whose
 * `meta.error` carries the reason (network failure, hash-chain
 * mismatch, etc.) and whose `doc` is empty/null. We turn that into a
 * thrown error so callers don't trip over a null `didDocument`
 * downstream with an opaque "Cannot read properties of null" message.
 */
function adaptResolutionResult(result) {
  const err = result?.meta?.error;
  if (err) {
    const detail = result?.meta?.problemDetails?.detail;
    throw new Error(
      `did:webvh resolve failed: ${err}${detail ? ` — ${detail}` : ""}`,
    );
  }
  if (!result?.doc || typeof result.doc !== "object") {
    throw new Error(
      "did:webvh resolve: resolver returned no DID document (and no error) — the log may be empty or unreachable",
    );
  }
  return {
    didDocument: result.doc,
    didResolutionMetadata: { contentType: "application/did+ld+json" },
    didDocumentMetadata: result.meta ?? {},
  };
}
