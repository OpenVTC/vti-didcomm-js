// DID resolver — dispatches by method prefix to the per-method
// resolver modules. Pluggable: callers can pass their own map of
// `{ method: resolver }` to add support for additional methods
// without forking this file.

import * as didKey from "./did-key.js";
import * as didWebvh from "./did-webvh.js";
import * as didPeer from "./did-peer.js";

const DEFAULT_RESOLVERS = Object.freeze({
  key: didKey,
  webvh: didWebvh,
  peer: didPeer,
});

/**
 * Create a DID resolver bound to a specific set of method handlers.
 *
 * @param {Object} [overrides] - map of `{ method: resolverModule }`
 *   to merge over the built-in defaults. Each handler must expose
 *   `resolve(did, options)` returning the W3C DID Resolution result.
 * @returns {{
 *   resolve(did: string, options?: Object): Promise<{
 *     didDocument: Object,
 *     didResolutionMetadata: Object,
 *     didDocumentMetadata: Object,
 *   }>
 * }}
 */
export function createResolver(overrides = {}) {
  const handlers = { ...DEFAULT_RESOLVERS, ...overrides };

  return {
    async resolve(did, options) {
      const method = parseMethod(did);
      const handler = handlers[method];
      if (!handler) {
        const supported = Object.keys(handlers).sort().join(", ");
        throw new Error(
          `resolver: no handler for method "${method}"; supported: ${supported}`,
        );
      }
      return handler.resolve(did, options);
    },
  };
}

/**
 * Convenience: a default resolver wired up with the built-in
 * handlers (did:key + did:webvh). Equivalent to `createResolver()`,
 * but doesn't allocate a fresh handler map on every call.
 */
export const defaultResolver = createResolver();

/**
 * Module-level shortcut: `resolve(did)` is equivalent to
 * `defaultResolver.resolve(did)`.
 */
export function resolve(did, options) {
  return defaultResolver.resolve(did, options);
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
