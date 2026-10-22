// `did:scid` resolver — the `vh` format, verified by a did:webvh log.
//
// A `did:scid:vh:1` identity is the DID `did:scid:vh:1:<scid>`. Its `src`
// query parameter (`did:scid:vh:1:<scid>?src=example.com/alice`) says where
// the did:webvh log that verifies it is published; it is a locator, not part
// of the identity, so the log can move and the DID stays the same
// (VTI-KEY-160). Resolution derives the did:webvh form from a source, verifies
// that log exactly as `./did-webvh.js` does — under the same `netPolicy`, so
// the host guard applies to the `src` host — and returns the did:scid's own
// document: `id` is the bare DID and every reference the log makes to itself
// is under it (VTI-KEY-161), or a verifier looking up `did:scid:…#key-1` would
// find nothing.
//
// The source is the `src` of the DID URL being resolved, or, for a bare DID,
// the one a source book holds for its SCID. A source is untrusted: the SCID
// makes the log unforgeable wherever it is fetched from, but not current, so
// the book also refuses a log older than one it has already verified for that
// SCID (VTI-KEY-162).
//
// Everything here mirrors the Rust stack: `affinidi_did_common::scid` for the
// `src` helpers, `didwebvh-rs` `convert_scid_id_to_webvh_id` /
// `convert_webvh_id_to_scid_id` / `did_web::to_scid_did_document` for the
// mappings, and the TDK resolver's `ScidSourceBook`. Change them together.

import * as didWebvh from "./did-webvh.js";

const PREFIX = "did:scid:";
const VH_PREFIX = "did:scid:vh:1:";
const WEBVH_PREFIX = "did:webvh:";

/** Default upper bound on SCIDs a source book remembers. */
export const DEFAULT_SCID_SOURCE_CAPACITY = 100000;

// ─── The `src` locator ──────────────────────────────────────────────────

// [did, src, fragment] for a did:scid DID URL whose only query parameter is
// `src`, or null. `fragment` keeps its leading `#`, or is "".
function splitSrc(didUrl) {
  if (typeof didUrl !== "string" || !didUrl.startsWith(PREFIX)) return null;
  const q = didUrl.indexOf("?");
  if (q < 0) return null;
  const did = didUrl.slice(0, q);
  const rest = didUrl.slice(q + 1);
  const hash = rest.indexOf("#");
  const query = hash < 0 ? rest : rest.slice(0, hash);
  const fragment = hash < 0 ? "" : rest.slice(hash);
  if (!query.startsWith("src=")) return null;
  const src = query.slice(4);
  if (!src || src.includes("&")) return null;
  return [did, src, fragment];
}

/**
 * Removes the `src` locator from a did:scid DID URL, keeping any fragment:
 * `did:scid:vh:1:Qm?src=example.com#key-1` → `did:scid:vh:1:Qm#key-1`.
 * Anything else — another method, or a did:scid query with any other
 * parameter — is returned unchanged.
 *
 * @param {string} didUrl
 * @returns {string}
 */
export function stripScidSrc(didUrl) {
  const parts = splitSrc(didUrl);
  return parts ? parts[0] + parts[2] : didUrl;
}

/**
 * The `src` locator of a did:scid DID URL, if it carries one.
 *
 * @param {string} didUrl
 * @returns {string|null}
 */
export function scidSrc(didUrl) {
  return splitSrc(didUrl)?.[1] ?? null;
}

/**
 * Gives a bare did:scid reference the locator `src`, before any fragment:
 * `did:scid:vh:1:Qm#key-1` → `did:scid:vh:1:Qm?src=example.com#key-1`. Use it
 * where a recipient resolves the reference before it knows the source, such
 * as a DIDComm `skid`. A reference that is not a bare did:scid, or already
 * carries a query or a path, is returned unchanged.
 *
 * @param {string} reference
 * @param {string} src
 * @returns {string}
 */
export function withScidSrc(reference, src) {
  if (
    typeof reference !== "string" ||
    !reference.startsWith(PREFIX) ||
    reference.includes("?") ||
    reference.includes("/")
  ) {
    return reference;
  }
  const hash = reference.indexOf("#");
  return hash < 0
    ? `${reference}?src=${src}`
    : `${reference.slice(0, hash)}?src=${src}${reference.slice(hash)}`;
}

/**
 * Whether two references name the same thing, ignoring a did:scid `src`. Use
 * this, not `===`, to match a key or sender reference against a DID document:
 * a reference may carry the `src` its document does not.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function sameReference(a, b) {
  return a === b || (typeof a === "string" && typeof b === "string" && stripScidSrc(a) === stripScidSrc(b));
}

/**
 * The identity a reference names: no fragment, and no did:scid `src`.
 *
 * @param {string} reference
 * @returns {string}
 */
export function scidIdentity(reference) {
  return stripScidSrc(String(reference).split("#")[0]);
}

// ─── did:scid ↔ did:webvh ───────────────────────────────────────────────

/**
 * The did:webvh form of a `did:scid:vh:1:<scid>?src=<source>` ID or DID URL,
 * carrying a `#fragment` across, or null for anything else: another method,
 * format or version, no `src` (peer mode), an empty SCID, another query
 * parameter, or a malformed `src`. `src` may carry an `https://` / `http://`
 * scheme, a trailing `/` or a literal `:` before a port (encoded as `%3A`).
 *
 * @param {string} id
 * @returns {string|null}
 */
export function scidToWebvhDid(id) {
  if (typeof id !== "string" || !id.startsWith(VH_PREFIX)) return null;
  let rest = id.slice(VH_PREFIX.length);
  let fragment = null;
  const hash = rest.indexOf("#");
  if (hash >= 0) {
    fragment = rest.slice(hash + 1);
    rest = rest.slice(0, hash);
  }
  const marker = rest.indexOf("?src=");
  if (marker < 0) return null;
  const scid = rest.slice(0, marker);
  let src = rest.slice(marker + 5);
  if (!scid || /[:/?]/.test(scid) || /[&?]/.test(src)) return null;

  if (src.startsWith("https://")) src = src.slice(8);
  else if (src.startsWith("http://")) src = src.slice(7);
  src = src.replace(/\/+$/, "");
  const slash = src.indexOf("/");
  let host = slash < 0 ? src : src.slice(0, slash);
  const path = slash < 0 ? null : src.slice(slash + 1).replace(/\/+$/, "");
  const colon = host.indexOf(":");
  if (colon >= 0) {
    const port = host.slice(colon + 1);
    if (!/^\+?\d+$/.test(port) || Number(port) > 65535) return null;
    host = `${host.slice(0, colon)}%3A${port}`;
  }
  if (!host || host.startsWith("%")) return null;

  let webvh = `${WEBVH_PREFIX}${scid}:${host}`;
  if (path) {
    if (path.split("/").some((segment) => segment === "")) return null;
    webvh += `:${path.replaceAll("/", ":")}`;
  }
  if (fragment !== null) webvh += `#${fragment}`;
  return webvh;
}

/**
 * The `did:scid:vh:1:<scid>?src=<source>` DID URL of a did:webvh DID, or null
 * when it has no SCID and host.
 *
 * @param {string} webvhDid
 * @returns {string|null}
 */
export function webvhToScidDidUrl(webvhDid) {
  if (typeof webvhDid !== "string" || !webvhDid.startsWith(WEBVH_PREFIX)) return null;
  const rest = webvhDid.slice(WEBVH_PREFIX.length);
  const colon = rest.indexOf(":");
  if (colon < 0) return null;
  return `${VH_PREFIX}${rest.slice(0, colon)}?src=${rest.slice(colon + 1).replaceAll(":", "/")}`;
}

/**
 * Expresses a did:webvh DID document as the document of its did:scid DID.
 *
 * - `id` becomes `did:scid:vh:1:<scid>`, with no `src`.
 * - Every string that is exactly the did:webvh DID, or that DID followed by
 *   `#`, is rewritten under the did:scid DID. Other DIDs and URLs, relative
 *   references and DID URLs with a path are left as they are.
 * - `alsoKnownAs` keeps the controller's entries, drops the bare did:scid
 *   itself, and gains the did:scid DID URL of the log's location and the
 *   did:webvh DID, where absent.
 *
 * @param {Object} state - the did:webvh DID document.
 * @returns {Object} a new document.
 */
export function toScidDidDocument(state) {
  const webvhDid = typeof state?.id === "string" && state.id.startsWith(WEBVH_PREFIX) ? state.id : null;
  if (!webvhDid) throw new Error("did:scid: couldn't find a did:webvh id attribute");
  const scidUrl = webvhToScidDidUrl(webvhDid);
  const marker = scidUrl?.indexOf("?src=") ?? -1;
  if (marker < 0) throw new Error(`did:scid: ${webvhDid} has no SCID and host to convert`);
  const scidDid = scidUrl.slice(0, marker);

  const rewrite = (value) => {
    if (typeof value === "string") {
      if (value === webvhDid) return scidDid;
      if (value.startsWith(`${webvhDid}#`)) return `${scidDid}${value.slice(webvhDid.length)}`;
      return value;
    }
    if (Array.isArray(value)) return value.map(rewrite);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, rewrite(v)]));
    }
    return value;
  };
  const doc = rewrite(state);

  let aliases;
  if (state.alsoKnownAs === undefined || state.alsoKnownAs === null) {
    aliases = [];
  } else if (Array.isArray(state.alsoKnownAs)) {
    aliases = state.alsoKnownAs.filter((alias) => alias !== scidDid);
  } else {
    throw new Error("did:scid: alsoKnownAs is not an array");
  }
  for (const alias of [scidUrl, webvhDid]) {
    if (!aliases.includes(alias)) aliases.push(alias);
  }
  doc.alsoKnownAs = aliases;
  return doc;
}

// ─── Source book ────────────────────────────────────────────────────────

/**
 * What a resolver has verified about each did:scid SCID: where its log was
 * last found, and the latest version seen. In memory and bounded; a caller
 * that must resolve a bare did:scid across restarts records the source it
 * learned and seeds it back with `addSource`.
 *
 * @param {Object} [config]
 * @param {number} [config.capacity=100000] - SCIDs held before the oldest is
 *   forgotten to make room.
 */
export function createScidSourceBook({ capacity = DEFAULT_SCID_SOURCE_CAPACITY } = {}) {
  if (!Number.isFinite(capacity) || capacity < 1) {
    throw new TypeError("did:scid: source book capacity must be a positive number");
  }
  /** @type {Map<string, { source: string, version: { number: number, id: string } | null }>} */
  const seen = new Map();
  const key = (did) => scidIdentity(did);
  const makeRoom = () => {
    while (seen.size >= capacity) {
      const oldest = seen.keys().next();
      if (oldest.done) return;
      seen.delete(oldest.value);
    }
  };

  return {
    /** The source last recorded for the SCID of `did`, in `src` form. */
    source(did) {
      return seen.get(key(did))?.source ?? null;
    },
    /**
     * Records the `src` of a did:scid DID URL as where to look for that SCID,
     * without changing the latest version verified for it. Returns false when
     * `didUrl` carries no `src`.
     */
    addSource(didUrl) {
      const src = scidSrc(didUrl);
      if (!src) return false;
      const k = key(didUrl);
      const entry = seen.get(k);
      if (entry) {
        entry.source = src;
      } else {
        makeRoom();
        seen.set(k, { source: src, version: null });
      }
      return true;
    },
    /**
     * Accepts a verified resolution, or throws if it is older than one already
     * verified for the same SCID.
     */
    accept(did, source, versionNumber, versionId) {
      const k = key(did);
      const latest = seen.get(k)?.version;
      if (latest && (versionNumber < latest.number || (versionNumber === latest.number && versionId !== latest.id))) {
        throw new Error(
          `did:scid resolve: ${k}: the log at ${source} is at version ${versionId}, behind ${latest.id} already verified for this SCID`,
        );
      }
      if (!seen.has(k)) makeRoom();
      seen.delete(k);
      seen.set(k, { source, version: { number: versionNumber, id: versionId } });
    },
    /** Number of SCIDs held. For tests and diagnostics. */
    size() {
      return seen.size;
    },
  };
}

// ─── Resolution ─────────────────────────────────────────────────────────

/**
 * A did:scid handler for `createResolver`, recording into and resolving bare
 * DIDs from `book`.
 *
 * @param {ReturnType<typeof createScidSourceBook>} [book]
 */
export function createHandler(book = createScidSourceBook()) {
  return {
    book,
    resolve: (did, options) => resolveWith(did, options, book),
  };
}

/**
 * Resolve a did:scid:vh:1 DID URL (with `src`) to the did:scid's own
 * document. A bare DID resolves only through a resolver's source book — use
 * `createResolver().resolve`.
 *
 * @param {string} did
 * @param {Object} [options] - as for `./did-webvh.js` `resolve`; `netPolicy`
 *   applies to the `src` host.
 */
export function resolve(did, options = {}) {
  return resolveWith(did, options, null);
}

async function resolveWith(did, options = {}, book) {
  if (typeof did !== "string") {
    throw new TypeError("did:scid resolve: input must be a string");
  }
  if (!did.startsWith(PREFIX)) {
    throw new Error(`did:scid resolve: identifier must start with "${PREFIX}"`);
  }
  if (!did.startsWith(VH_PREFIX)) {
    throw new Error("did:scid resolve: only the vh:1 format is supported");
  }
  const bare = scidIdentity(did);
  const src = scidSrc(did) ?? book?.source(bare) ?? null;
  if (!src) {
    throw new Error(
      `did:scid resolve: no source is known for ${bare}; resolve it once with its ?src= DID URL`,
    );
  }
  const webvhDid = scidToWebvhDid(`${bare}?src=${src}`);
  if (!webvhDid) {
    throw new Error(`did:scid resolve: ${JSON.stringify(did.slice(0, 120))} is not a usable did:scid:vh:1 DID URL`);
  }

  const result = await didWebvh.resolve(webvhDid, options);
  const meta = result.didDocumentMetadata ?? {};
  if (meta.deactivated) {
    throw new Error(`did:scid resolve failed: ${webvhDid} has been deactivated`);
  }
  const document = toScidDidDocument(result.didDocument);
  const logDid = result.didDocument.id;
  const source = webvhToScidDidUrl(logDid).split("?src=")[1];
  const versionId = String(meta.versionId ?? "");
  const versionNumber = Number.parseInt(versionId.split("-")[0], 10);

  if (book) book.accept(bare, source, Number.isFinite(versionNumber) ? versionNumber : 0, versionId);

  return {
    didDocument: document,
    didResolutionMetadata: result.didResolutionMetadata,
    didDocumentMetadata: { ...meta, webvhDid: logDid, scidSource: source },
  };
}
