// DID resolver — dispatches by method prefix to the per-method
// resolver modules. Pluggable: callers can pass their own map of
// `{ method: resolver }` to add support for additional methods
// without forking this file.
//
// Resolution is cached with a TTL and a size bound. did:webvh
// resolution is expensive (an HTTPS `did.jsonl` fetch + full log-chain
// cryptographic verification); the mediator and VTA DIDs a session
// resolves are stable, so re-resolving them on every operation is pure
// latency. The cache keys on the DID string and stores only successful
// resolutions. In-flight resolutions are de-duplicated so concurrent
// callers share one fetch.
//
// Two things bound the cache, because a client resolves DIDs it did not
// choose: an inbound frame's `skid` names its own sender, so whoever can
// route frames to us decides what we try to resolve.
//   - `maxEntries` (default 500) evicts least-recently-used first.
//     Map insertion order is the LRU order: a hit re-inserts the entry.
//   - did:key and did:peer are not cached at all. They resolve from the
//     identifier itself with no network I/O, so caching them buys
//     nothing and is the cheap way to flood the cache — a sender can
//     mint unlimited distinct did:keys for free.
//
// Tradeoff: for the methods that are cached, a rotated key isn't
// observed until the entry expires — set a short TTL or call
// `invalidate(did)` after a known rotation.
//
// Per-call `options` reach the method handler unchanged, which is how
// `netPolicy` gets to did:webvh: `resolve(did, { netPolicy })` decides
// which hosts that method's `did.jsonl` fetch may reach, and a DID
// naming a refused host throws before any request. Cached entries key on
// the DID alone and carry no policy, so a document first resolved under
// a relaxed policy is served as-is to later callers; a caller that needs
// the strict policy applied to its own resolution should not share a
// resolver with one that relaxes it.

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

/** Default upper bound on cached resolutions. */
export const DEFAULT_DID_CACHE_MAX_ENTRIES = 500;

// Methods that resolve offline from the identifier itself. Caching them
// costs memory and saves no I/O, and they are unlimited and free to
// mint, so they never enter the cache.
const UNCACHED_METHODS = new Set(["key", "peer"]);

/**
 * Create a DID resolver bound to a specific set of method handlers.
 *
 * @param {Object} [overrides] - map of `{ method: resolverModule }`
 *   to merge over the built-in defaults. Each handler must expose
 *   `resolve(did, options)` returning the W3C DID Resolution result.
 *   `options` is the caller's per-call object, passed through untouched
 *   — `{ netPolicy }` for did:webvh (see `./net-guard.js`).
 * @param {Object} [config]
 * @param {number} [config.cacheTtlMs] - cache lifetime in ms. `0`
 *   disables caching entirely.
 * @param {number} [config.maxEntries=500] - upper bound on cached
 *   resolutions. The least recently used entry is evicted first. `0`
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
 *   size(): number,
 * }}
 */
export function createResolver(
  overrides = {},
  { cacheTtlMs = DEFAULT_DID_CACHE_TTL_MS, maxEntries = DEFAULT_DID_CACHE_MAX_ENTRIES } = {},
) {
  const handlers = { ...DEFAULT_RESOLVERS, ...overrides };
  /** @type {Map<string, { expires: number, result: Object }>} */
  const cache = new Map();
  /** @type {Map<string, Promise<Object>>} */
  const inflight = new Map();
  let ttl = cacheTtlMs;
  if (!Number.isFinite(maxEntries) || maxEntries < 0) {
    throw new TypeError("resolver: maxEntries must be a non-negative number");
  }
  const limit = maxEntries;

  async function rawResolve(did, options) {
    const method = parseMethod(did);
    const handler = handlers[method];
    if (!handler) {
      const supported = Object.keys(handlers).sort().join(", ");
      throw new Error(
        `resolver: no handler for method "${method}"; supported: ${supported}`,
      );
    }
    // `options` is passed through untouched, so a caller's `netPolicy`
    // reaches did:webvh and vets the host before it is fetched from.
    return handler.resolve(did, options);
  }

  function isCacheable(result) {
    // Only cache resolutions that actually produced a document and
    // carry no resolution error (did:webvh returns a result-with-error
    // rather than throwing, so an error must not be memoized).
    return Boolean(result && result.didDocument && !result.didResolutionMetadata?.error);
  }

  // Make room for one more entry, dropping expired entries first.
  // Insertion order is oldest-first, and a cache hit re-inserts, so the
  // front of the Map is the least recently used entry.
  function evictFor(now) {
    for (const [did, entry] of cache) {
      if (cache.size < limit) return;
      if (entry.expires <= now) cache.delete(did);
    }
    while (cache.size >= limit) {
      const oldest = cache.keys().next();
      if (oldest.done) return;
      cache.delete(oldest.value);
    }
  }

  function store(did, result) {
    const now = Date.now();
    evictFor(now);
    cache.set(did, { expires: now + ttl, result });
  }

  async function resolve(did, options) {
    // `parseMethod` also validates the DID shape, which must happen
    // whether or not the result is cacheable.
    const method = parseMethod(did);
    if (ttl <= 0 || limit === 0 || UNCACHED_METHODS.has(method)) {
      return rawResolve(did, options);
    }

    const now = Date.now();
    const hit = cache.get(did);
    if (hit) {
      if (hit.expires > now) {
        // Re-insert so this entry becomes the most recently used.
        cache.delete(did);
        cache.set(did, hit);
        return hit.result;
      }
      cache.delete(did);
    }

    // De-dup concurrent resolutions of the same DID into one fetch.
    let pending = inflight.get(did);
    if (!pending) {
      pending = rawResolve(did, options)
        .then((result) => {
          if (isCacheable(result)) {
            store(did, result);
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
    /** Number of cached resolutions. For tests and diagnostics. */
    size() {
      return cache.size;
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
 *
 * @param {string} did
 * @param {Object} [options] - per-method resolution options, e.g.
 *   `{ netPolicy }` for did:webvh (see `./net-guard.js`).
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

/** Number of entries in the shared default-resolver cache. */
export function didCacheSize() {
  return defaultResolver.size();
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
