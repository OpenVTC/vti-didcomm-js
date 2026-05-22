// DID resolver — dispatches by method prefix to the per-method
// resolver modules. Pluggable: callers can pass their own map of
// `{ method: resolver }` to add support for additional methods
// without forking this file.
//
// Resolution is cached with a TTL. did:webvh resolution is expensive
// (an HTTPS `did.jsonl` fetch + full log-chain cryptographic
// verification); the mediator and VTA DIDs a session resolves are
// stable, so re-resolving them on every operation is pure latency.
// The cache keys on the DID string and stores only successful
// resolutions. In-flight resolutions are de-duplicated so concurrent
// callers share one fetch. did:key / did:peer are cheap+deterministic
// but cached uniformly (harmless). Tradeoff: a rotated key isn't
// observed until the entry expires — set a short TTL or call
// `invalidate(did)` after a known rotation.

import * as didKey from "./did-key.js";
import * as didWebvh from "./did-webvh.js";
import * as didPeer from "./did-peer.js";

const DEFAULT_RESOLVERS = Object.freeze({
  key: didKey,
  webvh: didWebvh,
  peer: didPeer,
});

/** Default cache lifetime for a resolved DID document (ms). */
export const DEFAULT_DID_CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Create a DID resolver bound to a specific set of method handlers.
 *
 * @param {Object} [overrides] - map of `{ method: resolverModule }`
 *   to merge over the built-in defaults. Each handler must expose
 *   `resolve(did, options)` returning the W3C DID Resolution result.
 * @param {Object} [config]
 * @param {number} [config.cacheTtlMs] - cache lifetime in ms. `0`
 *   disables caching entirely.
 * @returns {{
 *   resolve(did: string, options?: Object): Promise<{
 *     didDocument: Object,
 *     didResolutionMetadata: Object,
 *     didDocumentMetadata: Object,
 *   }>,
 *   clearCache(): void,
 *   invalidate(did: string): void,
 *   setCacheTtl(ms: number): void,
 * }}
 */
export function createResolver(overrides = {}, { cacheTtlMs = DEFAULT_DID_CACHE_TTL_MS } = {}) {
  const handlers = { ...DEFAULT_RESOLVERS, ...overrides };
  /** @type {Map<string, { expires: number, result: Object }>} */
  const cache = new Map();
  /** @type {Map<string, Promise<Object>>} */
  const inflight = new Map();
  let ttl = cacheTtlMs;

  async function rawResolve(did, options) {
    const method = parseMethod(did);
    const handler = handlers[method];
    if (!handler) {
      const supported = Object.keys(handlers).sort().join(", ");
      throw new Error(
        `resolver: no handler for method "${method}"; supported: ${supported}`,
      );
    }
    return handler.resolve(did, options);
  }

  function isCacheable(result) {
    // Only cache resolutions that actually produced a document and
    // carry no resolution error (did:webvh returns a result-with-error
    // rather than throwing, so an error must not be memoized).
    return Boolean(result && result.didDocument && !result.didResolutionMetadata?.error);
  }

  async function resolve(did, options) {
    if (ttl <= 0) return rawResolve(did, options);

    const now = Date.now();
    const hit = cache.get(did);
    if (hit && hit.expires > now) return hit.result;

    // De-dup concurrent resolutions of the same DID into one fetch.
    let pending = inflight.get(did);
    if (!pending) {
      pending = rawResolve(did, options)
        .then((result) => {
          if (isCacheable(result)) {
            cache.set(did, { expires: Date.now() + ttl, result });
          }
          inflight.delete(did);
          return result;
        })
        .catch((err) => {
          inflight.delete(did);
          throw err;
        });
      inflight.set(did, pending);
    }
    return pending;
  }

  return {
    resolve,
    /** Drop all cached resolutions. */
    clearCache() {
      cache.clear();
    },
    /** Drop a single DID's cached resolution (e.g. after a key rotation). */
    invalidate(did) {
      cache.delete(did);
    },
    /** Change the cache TTL (ms). `0` disables caching; existing entries
     *  are cleared so the change takes effect immediately. */
    setCacheTtl(ms) {
      ttl = ms;
      if (ttl <= 0) cache.clear();
    },
  };
}

/**
 * Convenience: a default resolver wired up with the built-in
 * handlers (did:key + did:peer + did:webvh). Equivalent to
 * `createResolver()`, but doesn't allocate a fresh handler map +
 * cache on every call — so this is the shared, process-wide cache.
 */
export const defaultResolver = createResolver();

/**
 * Module-level shortcut: `resolve(did)` is equivalent to
 * `defaultResolver.resolve(did)`.
 */
export function resolve(did, options) {
  return defaultResolver.resolve(did, options);
}

/** Clear the shared default-resolver DID cache. */
export function clearDidCache() {
  defaultResolver.clearCache();
}

/** Invalidate one DID in the shared default-resolver cache. */
export function invalidateDid(did) {
  defaultResolver.invalidate(did);
}

/** Set the shared default-resolver cache TTL (ms); `0` disables caching. */
export function setDidCacheTtl(ms) {
  defaultResolver.setCacheTtl(ms);
}

function parseMethod(did) {
  if (typeof did !== "string") {
    throw new TypeError("resolver: DID must be a string");
  }
  if (!did.startsWith("did:")) {
    throw new Error(`resolver: not a DID (no "did:" prefix): ${JSON.stringify(did.slice(0, 32))}`);
  }
  const rest = did.slice(4);
  const colon = rest.indexOf(":");
  if (colon < 0) {
    throw new Error(`resolver: DID missing method-specific identifier: ${JSON.stringify(did)}`);
  }
  return rest.slice(0, colon);
}
