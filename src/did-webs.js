// `did:webs` resolver: did:web discovery with KERI-verified key state.
//
//   did:webs:<host>[%3A<port>][:<path>…]:<AID>
//
//   https://<host>[:<port>]/<path>/<AID>/keri.cesr   the key event stream
//   https://<host>[:<port>]/<path>/<AID>/did.json    the document, as a cache
//
// The document is derived from the verified key event stream, never copied
// from `did.json`: every event, signature, pre-rotation commitment,
// delegation and witness receipt is verified; the AID must designate this
// DID (a designated-aliases attestation it issued itself and anchored in its
// own KEL); the document is built from that state; and the published
// `did.json`, read back from its did:web form, must agree with it. A
// disagreement is an error rather than a choice between two answers.
//
// This is a port of `affinidi-did-webs` 0.13.1 (KERI 2.0) and the
// `affinidi-keri-core` 0.8.1 it verifies with, conformance-tested against
// vectors that crate produced (`test/fixtures/did-webs/`). The identifier
// parsing follows the stricter checks of its 0.13.2 (a host label must decode
// to a host and port, a path label to one segment). The KERI core lives in
// `./did-webs-cesr.js`, `./did-webs-kel.js` and `./did-webs-designations.js`.
//
// Egress: a did:webs DID names the host its artifacts are fetched from, and
// DIDs reach this library from whoever it talks to (an inbound frame's
// `skid` is resolved before the frame is authenticated). Both artifact URLs
// are checked against `netPolicy` before any request (`./net-guard.js`), the
// fetch refuses redirects, each body is capped at 4 MiB while it is read, and
// each request has a timeout. Plain `http` is used for a loopback host when
// `allowPrivate` is set (as the Rust `HostPolicy::AllowPrivate` does), and for
// any host when `allowInsecure` is set (its `allow_http`).
//
// Not covered: CBOR and MessagePack message bodies, and floating-point
// numbers in messages — refused rather than verified. A stream may hold at
// most 10 000 messages, a bound the Rust crate does not set (it bounds only
// the bytes).

import { BlockedEndpointError, assertSafeEndpoint, guardedFetch } from "./net-guard.js";
import { KeriError, compareUtf8, fromJson, fromUtf8, get, matterFromQb64, parseJson, str, toJson, transIdxSigGroups } from "./did-webs-cesr.js";
import { KelError, Kels, MAX_STREAM_MESSAGES, StreamError, verfer, verifySignature } from "./did-webs-kel.js";
import {
  IMPLEMENTED_SCHEMAS,
  InvalidKeyError,
  KEY_ROLES,
  RegistryError,
  compareInstants,
  convertedKeyAgreement,
  designatedAliases,
  designatedKeyAgreement,
  designatedKeyRoles,
  designatedServices,
  jwkFromCesrKey,
  keyAgreementJwk,
  keyAgreementKey,
  parseRfc3339,
  revokedKeyJwk,
  roleKeyJwk,
  unsupportedCritical,
} from "./did-webs-designations.js";

/** `code` of every {@link DidWebsError}. */
export const DID_WEBS_ERROR = "E_DID_WEBS";

/** Default upper bound on one `keri.cesr` / `did.json` fetch (ms), as the Rust crate. */
export const DEFAULT_WEBS_TIMEOUT_MS = 20000;

/** Largest artifact read (`fetch::MAX_ARTIFACT_BYTES`). */
export const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;

export { MAX_STREAM_MESSAGES };


/**
 * Why a did:webs DID did not resolve. `kind` is the `affinidi-did-webs`
 * `DidWebsError` variant: `InvalidDid`, `Fetch`, `Stream`, `Kel`,
 * `DocumentMismatch`, `NotDesignated`, `Registry`, `UnsupportedDesignation`
 * (a critical designation this resolver does not implement), `InvalidKey`,
 * `Json`, or `Deactivated` ({@link resolve} only: the DID's last rotation
 * committed to no next keys). A host the egress policy refuses throws
 * `BlockedEndpointError` instead.
 */
export class DidWebsError extends Error {
  /**
   * @param {string} kind
   * @param {string} message
   * @param {Object} [details]
   * @param {number} [details.status] - the HTTP status of a failed fetch.
   * @param {string} [details.url]
   */
  constructor(kind, message, { status, url } = {}) {
    super(`did:webs: ${message}`);
    this.name = "DidWebsError";
    /** @type {"E_DID_WEBS"} */
    this.code = DID_WEBS_ERROR;
    /** @type {string} */
    this.kind = kind;
    if (status !== undefined) this.status = status;
    if (url !== undefined) this.url = url;
  }
}

const error = (kind, message, details) => new DidWebsError(kind, message, details);

// ─── The identifier (affinidi-did-webs `identifier.rs`, 0.13.2) ─────────

/**
 * @typedef {Object} DidWebs
 * @property {string} did - the DID, without query or fragment.
 * @property {number|null} versionId - the `versionId` parameter, if any.
 * @property {string} host - the host label, percent-decoded (with any port).
 * @property {string[]} path - the path labels, as written.
 * @property {string} aid - the KERI AID, the last label.
 */

const invalid = (did, why) => error("InvalidDid", `invalid did:webs identifier: ${JSON.stringify(did)} ${why}`);

function percentDecode(label, did) {
  const out = [];
  for (let i = 0; i < label.length; ) {
    if (label[i] === "%") {
      const hex = label.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw invalid(did, `has a malformed percent-encoding in ${JSON.stringify(label)}`);
      out.push(parseInt(hex, 16));
      i += 3;
    } else {
      const cp = label.codePointAt(i);
      const ch = String.fromCodePoint(cp);
      out.push(...new TextEncoder().encode(ch));
      i += ch.length;
    }
  }
  try {
    return fromUtf8(new Uint8Array(out));
  } catch {
    throw invalid(did, `has a label that is not UTF-8: ${JSON.stringify(label)}`);
  }
}

const isControl = (c) => /[\u0000-\u001f\u007f-\u009f]/u.test(c);
const isWhitespace = (c) => /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$/u.test(c);

function splitHostPort(authority) {
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 0) return [authority, null];
    const host = authority.slice(0, end + 1);
    const rest = authority.slice(end + 1);
    if (rest.startsWith(":")) return [host, rest.slice(1)];
    if (rest === "") return [host, null];
    return [authority, null];
  }
  const colon = authority.indexOf(":");
  return colon < 0 ? [authority, null] : [authority.slice(0, colon), authority.slice(colon + 1)];
}

function isIpv6(literal) {
  try {
    return new URL(`http://[${literal}]/`).hostname.length > 2 && !literal.includes("%");
  } catch {
    return false;
  }
}

function validateHost(authority, did) {
  const bad = (why) => invalid(did, `does not name a host (${why}): ${JSON.stringify(authority)}`);
  const [host, port] = splitHostPort(authority);
  if (host === "") throw bad("empty host");
  if (port !== null && (!/^[0-9]+$/.test(port) || Number(port) > 65535)) throw bad("the port is not a port number");
  if (host.startsWith("[") && host.endsWith("]")) {
    if (!isIpv6(host.slice(1, -1))) throw bad("not an IPv6 address");
  } else if ([...host].some((c) => isControl(c) || isWhitespace(c) || "/\\?#@%:[]".includes(c))) {
    throw bad("a character a host cannot contain");
  }
  let url;
  try {
    url = new URL(`https://${authority}/`);
  } catch (e) {
    throw bad(e.message);
  }
  if (!url.hostname || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw bad("not a host and port");
  }
}

function validatePathSegment(segment, did) {
  if (segment === "." || segment === ".." || [...segment].some((c) => isControl(c) || "/\\?#@%".includes(c))) {
    throw invalid(did, `has a path label that is not a single path segment: ${JSON.stringify(segment)}`);
  }
}

/**
 * Parse a did:webs DID or DID URL (`DidWebs::parse`). A `versionId` query
 * parameter is the sequence number of the key event to resolve as of.
 *
 * @param {string} did
 * @returns {DidWebs}
 * @throws {DidWebsError} kind `InvalidDid`.
 */
export function parseDidWebs(did) {
  if (typeof did !== "string" || !did.startsWith("did:webs:")) throw invalid(String(did).slice(0, 80), "does not start with 'did:webs:'");
  let rest = did.slice("did:webs:".length).split("#")[0];
  let query = null;
  const q = rest.indexOf("?");
  if (q >= 0) {
    query = rest.slice(q + 1);
    rest = rest.slice(0, q);
  }
  if (rest === "") throw invalid(did, "has an empty method-specific identifier");
  let versionId = null;
  if (query !== null) {
    for (const pair of query.split("&")) {
      const eq = pair.indexOf("=");
      const [key, value] = eq < 0 ? [pair, ""] : [pair.slice(0, eq), pair.slice(eq + 1)];
      if (key === "versionId") {
        const n = /^\+?[0-9]+$/.test(value) ? BigInt(value.replace(/^\+/, "")) : null;
        if (n === null || n > 0xffffffffffffffffn) throw invalid(did, `has a versionId that is not a sequence number: ${JSON.stringify(value)}`);
        // Beyond 2^53 no key event log can reach it.
        versionId = n > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(n);
        break;
      }
    }
  }
  const labels = rest.split(":");
  if (labels.length < 2) throw invalid(did, "has no AID: did:webs requires a host and a trailing AID");
  if (labels.some((l) => l === "")) throw invalid(did, "contains an empty label");
  const aid = labels[labels.length - 1];
  if (new TextEncoder().encode(aid).length < 4) throw invalid(did, `has an AID too short to be a CESR primitive: ${JSON.stringify(aid)}`);
  if (!/^[A-Za-z0-9_-]+$/.test(aid)) throw invalid(did, `has an AID with characters outside the CESR base64url alphabet: ${JSON.stringify(aid)}`);
  const host = percentDecode(labels[0], did);
  validateHost(host, did);
  const path = labels.slice(1, -1);
  for (const segment of path) validatePathSegment(percentDecode(segment, did), did);
  return { did: `did:webs:${rest}`, versionId, host, path, aid };
}

/** Whether the DID's host is loopback, as a URL parser reads it. */
function isLoopback(parsed) {
  try {
    const host = new URL(`http://${parsed.host}/`).hostname;
    return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  } catch {
    return false;
  }
}

function artifactUrl(parsed, scheme, artifact) {
  return `${scheme}://${parsed.host}${parsed.path.map((s) => `/${s}`).join("")}/${parsed.aid}/${artifact}`;
}

const didWebTwin = (parsed) => `did:web:${parsed.did.slice("did:webs:".length)}`;
const didKeri = (parsed) => `did:keri:${parsed.aid}`;

/**
 * The `keri.cesr` and `did.json` URLs a did:webs DID points at, checked
 * against the egress policy.
 *
 * @param {string} did
 * @param {import("./net-guard.js").NetPolicy} [netPolicy]
 * @returns {{ keriCesr: URL, didJson: URL }}
 * @throws {BlockedEndpointError} if the host fails the policy.
 * @throws {DidWebsError} kind `InvalidDid`.
 */
export function websArtifactUrls(did, netPolicy) {
  const parsed = parseDidWebs(did);
  const policy = netPolicyOf({ netPolicy });
  const plaintext = policy.allowInsecure || (policy.allowPrivate && isLoopback(parsed));
  const scheme = plaintext ? "http" : "https";
  const vet = (artifact, label) =>
    assertSafeEndpoint(artifactUrl(parsed, scheme, artifact), { ...policy, label, schemes: ["https:"], allowInsecure: plaintext });
  return { keriCesr: vet("keri.cesr", CESR_LABEL), didJson: vet("did.json", DID_JSON_LABEL) };
}

// ─── Percent-encoding and DID comparison (`document.rs`) ────────────────

/** Uppercase the hex digits of every percent-encoded triplet (RFC 3986 §6.2.2.1). */
function normalizePercent(s) {
  return s.replace(/%([0-9a-fA-F]{2})/g, (_, h) => `%${h.toUpperCase()}`);
}

const sameDid = (a, b) => normalizePercent(a) === normalizePercent(b);

// ─── KERI endpoint services (affinidi-did-webs `services.rs`) ───────────

const compareSeniority = (a, b) => (a[0] !== b[0] ? a[0] - b[0] : compareInstants(a[1], b[1]));

/** Where a reply stands in BADA order, if `signer` signed it (`reply_seniority`). */
function replySeniority(kels, msg, signer) {
  const dt = parseRfc3339(str(get(msg.serder.sad, "dt")));
  if (!dt) return null;
  const group = transIdxSigGroups(msg).find((g) => g.prefix === signer);
  if (group) {
    try {
      return [kels.verifySignatureGroup(signer, msg.serder.raw, group).sn, dt];
    } catch {
      return null;
    }
  }
  for (const a of msg.attachments) {
    if (a.type !== "ReceiptCouples") continue;
    for (const [prefix, sig] of a.couples) {
      if (prefix !== signer) continue;
      let v;
      try {
        v = verfer(prefix);
      } catch {
        continue;
      }
      let ok = false;
      try {
        ok = verifySignature(v, msg.serder.raw, sig);
      } catch {
        ok = false;
      }
      if (ok) return [0, dt];
    }
  }
  return null;
}

/** The verified location schemes `eid` published for itself, by scheme. */
function locationSchemes(kels, eid) {
  kels.locationCache ??= new Map();
  if (kels.locationCache.has(eid)) return kels.locationCache.get(eid);
  const latest = new Map();
  for (const rpy of kels.messagesWithIlk("rpy")) {
    if (str(get(rpy.serder.sad, "r")) !== "/loc/scheme") continue;
    const a = get(rpy.serder.sad, "a");
    const subject = str(get(a, "eid"));
    const scheme = str(get(a, "scheme"));
    const url = str(get(a, "url"));
    if (subject === undefined || scheme === undefined || url === undefined || subject !== eid) continue;
    const seniority = replySeniority(kels, rpy, eid);
    if (!seniority) continue;
    const existing = latest.get(scheme);
    if (existing && compareSeniority(existing[0], seniority) >= 0) continue;
    latest.set(scheme, [seniority, url]);
  }
  const out = new Map([...latest].sort(([a], [b]) => compareUtf8(a, b)).map(([scheme, [, url]]) => [scheme, url]));
  kels.locationCache.set(eid, out);
  return out;
}

/**
 * The endpoints `aid`'s signed `/end/role` replies designate, under BADA
 * reply state (`role_endpoints`).
 *
 * @returns {Array<{ eid: string, role: string, urls: Map<string, string> }>}
 */
export function roleEndpoints(kels, aid) {
  kels.keyState(aid);
  const roles = new Map();
  for (const rpy of kels.messagesWithIlk("rpy")) {
    const route = str(get(rpy.serder.sad, "r")) ?? "";
    let added;
    if (route === "/end/role/add") added = true;
    else if (route === "/end/role/cut") added = false;
    else continue;
    const a = get(rpy.serder.sad, "a");
    const cid = str(get(a, "cid"));
    const role = str(get(a, "role"));
    const eid = str(get(a, "eid"));
    if (cid === undefined || role === undefined || eid === undefined) continue;
    // Only this AID's own authorisations.
    if (cid !== aid) continue;
    const seniority = replySeniority(kels, rpy, aid);
    if (!seniority) continue;
    const key = JSON.stringify([role, eid]);
    const existing = roles.get(key);
    // Equal seniority is not newer, as in keripy.
    if (existing && compareSeniority(existing.seniority, seniority) >= 0) continue;
    roles.set(key, { role, eid, added, seniority });
  }
  const sorted = [...roles.values()].sort((x, y) => compareUtf8(x.role, y.role) || compareUtf8(x.eid, y.eid));
  const endpoints = [];
  for (const { role, eid, added } of sorted) {
    // A witness is designated by the key state, not by a reply.
    if (!added || role === "witness") continue;
    const urls = locationSchemes(kels, eid);
    if (!urls.size) continue;
    endpoints.push({ eid, role, urls });
  }
  return endpoints;
}

/** The witnesses in `backers` that have published a location. */
export function witnessEndpoints(kels, backers) {
  return backers
    .map((eid) => ({ eid, role: "witness", urls: locationSchemes(kels, eid) }))
    .filter((e) => e.urls.size > 0);
}

/** Every endpoint `aid` authorised: role endpoints, then its witnesses. */
export function serviceEndpoints(kels, aid) {
  const state = kels.keyState(aid);
  return [...roleEndpoints(kels, aid), ...witnessEndpoints(kels, state.backers)];
}

function endpointService(e) {
  return { id: `#${e.eid}/${e.role}`, type: e.role, serviceEndpoint: Object.fromEntries(e.urls) };
}

/** The `DelegatorOOBI` service of a delegated identifier, or null. */
export function delegatorService(kels, aid) {
  const state = kels.keyState(aid);
  if (!state.delegator) return null;
  const seal = kels.inceptionSaid(aid);
  if (!seal) return null;
  const locations = locationSchemes(kels, state.delegator);
  const url = locations.get("https") ?? locations.get("http");
  if (url === undefined) return null;
  return { id: seal, type: "DelegatorOOBI", serviceEndpoint: `${url.replace(/\/+$/, "")}/oobi/${state.delegator}/controller` };
}

// ─── The document (affinidi-did-webs `document.rs`) ─────────────────────

const RELATIONSHIPS = ["authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"];

function gcd(a, b) {
  return b === 0n ? a : gcd(b, a % b);
}

/** The `ConditionalProof2022` method for a threshold above one key, or null. */
function thresholdCondition(parsed, keys, threshold) {
  const base = (extra) => ({ id: `#${parsed.aid}`, type: "ConditionalProof2022", controller: parsed.did, ...extra });
  if (threshold.type === "simple") {
    if (threshold.n <= 1n) return null;
    return base({ threshold: Number(threshold.n), conditionThreshold: keys.map((k) => `#${k}`) });
  }
  if (threshold.clauses.length !== 1) {
    throw error("Kel", `key event log verification failed: a weighted threshold with ${threshold.clauses.length} clauses cannot be expressed as one ConditionalProof2022`);
  }
  const [clause] = threshold.clauses;
  if (clause.length !== keys.length) {
    throw error("Kel", `key event log verification failed: weighted threshold has ${clause.length} weights for ${keys.length} keys`);
  }
  let lcd = 1n;
  for (const w of clause) {
    lcd = (lcd / gcd(lcd, w.den)) * w.den;
    if (lcd >= 1n << 64n) throw error("Kel", "key event log verification failed: weighted threshold overflows");
  }
  return base({
    threshold: Number(lcd),
    conditionWeightedThreshold: keys.map((key, i) => ({ condition: `#${key}`, weight: Number(clause[i].num * (lcd / clause[i].den)) })),
  });
}

function keyMethod(parsed, key, jwk, extra = {}) {
  return { id: `#${key}`, type: "JsonWebKey", controller: parsed.did, publicKeyJwk: jwk, ...extra };
}

/** The document implied by verified key state (`derive_document`). */
function deriveDocument(parsed, keys, threshold, aliases, services) {
  if (!keys.length) throw error("Kel", "key event log verification failed: verified key state has no signing keys");
  const methods = keys.map((key) => {
    try {
      return keyMethod(parsed, key, jwkFromCesrKey(key));
    } catch (e) {
      throw error("Kel", `key event log verification failed: ${e.message}`);
    }
  });
  const condition = thresholdCondition(parsed, keys, threshold);
  let referenced;
  if (condition) {
    methods.push(condition);
    referenced = [condition.id];
  } else {
    referenced = keys.map((k) => `#${k}`);
  }
  return {
    id: parsed.did,
    controller: parsed.did,
    verificationMethod: methods,
    authentication: [...referenced],
    assertionMethod: [...referenced],
    service: [...services],
    alsoKnownAs: [...aliases],
  };
}

/** The document of an identifier that designates key roles. */
function deriveKeyRoleDocument(parsed, roles, revoked, aliases, services) {
  const methods = [];
  const keyRoles = {};
  const relationships = { authentication: [], assertionMethod: [], keyAgreement: [] };
  for (const [role, keys] of roles) {
    if (!keys.length) continue;
    const ids = [];
    for (const key of keys) {
      let jwk;
      try {
        jwk = roleKeyJwk(role.name, key);
      } catch (e) {
        throw error("InvalidKey", `invalid key: ${e.message}`);
      }
      methods.push(keyMethod(parsed, key, jwk));
      ids.push(`#${key}`);
    }
    relationships[role.relationship].push(...ids);
    keyRoles[role.name] = ids;
  }
  for (const entry of revoked) {
    let jwk;
    try {
      jwk = revokedKeyJwk(entry.key);
    } catch (e) {
      throw error("InvalidKey", `invalid key: ${e.message}`);
    }
    methods.push(keyMethod(parsed, entry.key, jwk, { revoked: entry.compromisedAt }));
  }
  const doc = { id: parsed.did, controller: parsed.did, verificationMethod: methods };
  doc.authentication = relationships.authentication;
  doc.assertionMethod = relationships.assertionMethod;
  if (relationships.keyAgreement.length) doc.keyAgreement = relationships.keyAgreement;
  doc.keyRoles = keyRoles;
  doc.service = [...services];
  doc.alsoKnownAs = [...aliases];
  return doc;
}

/** Add key agreement keys to a document (`with_key_agreement`). */
function withKeyAgreement(doc, parsed, keys) {
  if (!keys.length) return doc;
  const out = structuredClone(doc);
  for (const key of keys) {
    let jwk;
    try {
      jwk = keyAgreementJwk(keyAgreementKey(key));
    } catch (e) {
      throw error("InvalidKey", `invalid key: ${e.message}`);
    }
    if (Array.isArray(out.verificationMethod)) out.verificationMethod.push(keyMethod(parsed, key, jwk));
  }
  out.keyAgreement = keys.map((k) => `#${k}`);
  return out;
}

/** Rewrite the subject-identifying DIDs of a document from `from` to `to`. */
function swapSubject(doc, from, to) {
  const out = structuredClone(doc);
  if (!out || typeof out !== "object" || Array.isArray(out)) return out;
  for (const f of ["id", "controller"]) if (typeof out[f] === "string") out[f] = to;
  if (Array.isArray(out.verificationMethod)) {
    for (const m of out.verificationMethod) {
      if (m && typeof m === "object" && typeof m.controller === "string" && sameDid(m.controller, from)) m.controller = to;
    }
  }
  if (Array.isArray(out.alsoKnownAs)) {
    out.alsoKnownAs = out.alsoKnownAs.map((a) => (typeof a === "string" && sameDid(a, to) ? from : a));
  }
  return out;
}

/** A published document back in its did:webs form (`from_did_web`). */
function fromDidWeb(doc, parsed, twinDesignated) {
  const id = doc && typeof doc === "object" && !Array.isArray(doc) ? doc.id : undefined;
  if (typeof id !== "string") throw error("DocumentMismatch", "did.json does not match the verified key state: did.json has no `id`");
  const twin = didWebTwin(parsed);
  if (sameDid(id, parsed.did)) return doc;
  if (sameDid(id, twin)) {
    if (!twinDesignated) {
      throw error("DocumentMismatch", `did.json does not match the verified key state: did.json is the did:web document ${JSON.stringify(id)}, but no designated-aliases attestation authorises that identifier`);
    }
    return swapSubject(doc, id, parsed.did);
  }
  throw error("DocumentMismatch", `did.json does not match the verified key state: did.json is for ${JSON.stringify(id)}, which is neither ${JSON.stringify(parsed.did)} nor its did:web twin ${JSON.stringify(twin)}`);
}

function absolutize(value, subject) {
  if (typeof value !== "string") return value;
  if (value.startsWith("#")) return `${subject}${value}`;
  if (!value.includes(":")) return `${subject}#${value}`;
  return value;
}

/**
 * The did:webs form of a document as the resolved DID document: every
 * relative reference resolved against the subject (`into_document`), and,
 * as `affinidi_did_common::Document` serializes it, its empty lists left out.
 */
function intoDocument(doc, parsed) {
  const subject = parsed.did;
  const out = structuredClone(doc);
  if (Array.isArray(out.verificationMethod)) {
    for (const m of out.verificationMethod) {
      if (!m || typeof m !== "object") continue;
      if ("id" in m) m.id = absolutize(m.id, subject);
      if (Array.isArray(m.conditionThreshold)) m.conditionThreshold = m.conditionThreshold.map((r) => absolutize(r, subject));
      if (Array.isArray(m.conditionWeightedThreshold)) {
        for (const c of m.conditionWeightedThreshold) if (c && typeof c === "object" && "condition" in c) c.condition = absolutize(c.condition, subject);
      }
    }
  }
  for (const rel of RELATIONSHIPS) if (Array.isArray(out[rel])) out[rel] = out[rel].map((r) => absolutize(r, subject));
  if (Array.isArray(out.service)) {
    for (const s of out.service) if (s && typeof s === "object" && "id" in s) s.id = absolutize(s.id, subject);
  }
  if (out.keyRoles && typeof out.keyRoles === "object" && !Array.isArray(out.keyRoles)) {
    for (const role of Object.keys(out.keyRoles)) {
      if (Array.isArray(out.keyRoles[role])) out.keyRoles[role] = out.keyRoles[role].map((r) => absolutize(r, subject));
    }
  }
  for (const list of ["alsoKnownAs", "verificationMethod", ...RELATIONSHIPS, "service"]) {
    if (Array.isArray(out[list]) && out[list].length === 0) delete out[list];
  }
  return out;
}

// ─── Comparing the published document (`resolver.rs`) ──────────────────

/** serde_json `Value` equality: objects as maps, arrays in order. */
function jsonEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => jsonEqual(x, b[i]));
  const ka = Object.keys(a);
  if (ka.length !== Object.keys(b).length) return false;
  return ka.every((k) => Object.hasOwn(b, k) && jsonEqual(a[k], b[k]));
}

const asArray = (v) => (Array.isArray(v) ? v : []);
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const sameSet = (a, b, eq = (x, y) => x === y) => a.every((x) => b.some((y) => eq(x, y))) && b.every((x) => a.some((y) => eq(x, y)));

function relative(reference, subject) {
  const norm = normalizePercent(reference);
  const subj = normalizePercent(subject);
  if (norm.startsWith(subj) && norm.slice(subj.length).startsWith("#")) return norm.slice(subj.length);
  return norm;
}

function normalized(value, subject) {
  if (typeof value === "string") {
    if (sameDid(value, subject)) return subject;
    if (value.includes("#")) return relative(value, subject);
    return value;
  }
  if (Array.isArray(value)) return value.map((v) => normalized(v, subject));
  if (isObject(value)) {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      Object.defineProperty(out, k, { value: normalized(v, subject), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return value;
}

function keyed(methods, subject) {
  return asArray(methods).flatMap((m) => (isObject(m) && typeof m.id === "string" ? [[relative(m.id, subject), m]] : []));
}

function refs(value, subject) {
  return asArray(value).flatMap((r) => {
    if (typeof r === "string") return [relative(r, subject)];
    if (isObject(r) && typeof r.id === "string") return [relative(r.id, subject)];
    return [];
  });
}

/** Check a published document, in its did:webs form, against the derivation. */
function checkPublished(derived, theirs) {
  const ours = derived.document;
  const subject = ours.id;
  const mismatch = (what) => error("DocumentMismatch", `did.json does not match the verified key state: ${what}`);
  if (!isObject(theirs)) throw mismatch("did.json is not a JSON object");

  for (const member of Object.keys(theirs)) {
    const known =
      ["@context", "id", "controller", "verificationMethod", "service", "alsoKnownAs"].includes(member) ||
      RELATIONSHIPS.includes(member) ||
      (member === "keyRoles" && ours.keyRoles !== undefined);
    if (!known) throw mismatch(`did.json carries ${JSON.stringify(member)}, which nothing in the key event stream establishes`);
  }

  if (Object.hasOwn(theirs, "controller") && (typeof theirs.controller !== "string" || !sameDid(theirs.controller, subject))) {
    throw mismatch(`did.json names ${JSON.stringify(theirs.controller)} as controller, not ${JSON.stringify(subject)}`);
  }

  const ourMethods = keyed(ours.verificationMethod, subject);
  const theirMethods = keyed(theirs.verificationMethod, subject);
  for (const [id, method] of theirMethods) {
    const match = ourMethods.find(([ourId]) => ourId === id);
    if (!match) throw mismatch(`did.json publishes ${JSON.stringify(id)}, which the verified key event log never authorised`);
    if (!jsonEqual(normalized(match[1], subject), normalized(method, subject))) {
      throw mismatch(`did.json publishes ${JSON.stringify(id)} differently from the verified key state`);
    }
  }
  for (const [id] of ourMethods) {
    if (!theirMethods.some(([theirId]) => theirId === id)) {
      throw mismatch(`did.json does not publish ${JSON.stringify(id)}, which the verified key state authorises`);
    }
  }

  for (const relationship of RELATIONSHIPS) {
    const ourRefs = refs(ours[relationship], subject);
    if (!Object.hasOwn(theirs, relationship)) {
      if (!ourRefs.length || relationship === "authentication" || relationship === "assertionMethod") continue;
      throw mismatch(`did.json does not publish ${relationship}`);
    }
    const theirRefs = refs(theirs[relationship], subject);
    if (!sameSet(ourRefs, theirRefs)) {
      throw mismatch(`did.json's ${relationship} is ${JSON.stringify(theirRefs)}, but the verified state implies ${JSON.stringify(ourRefs)}`);
    }
  }

  if (isObject(ours.keyRoles)) {
    if (!isObject(theirs.keyRoles)) throw mismatch("did.json does not publish keyRoles");
    const ourRoles = Object.entries(ours.keyRoles);
    const same =
      ourRoles.length === Object.keys(theirs.keyRoles).length &&
      ourRoles.every(([role, r]) => Object.hasOwn(theirs.keyRoles, role) && sameSet(refs(r, subject), refs(theirs.keyRoles[role], subject)));
    if (!same) throw mismatch("did.json's keyRoles differ from those the AID designated");
  }

  const serviceKey = (s) => (isObject(s) && s.type === "DelegatorOOBI" ? { id: s.id ?? null, type: s.type } : normalized(s, subject));
  const ourServices = asArray(ours.service).map(serviceKey);
  const optionalDelegator =
    derived.delegationSeal && ourServices.every((s) => !isObject(s) || s.type !== "DelegatorOOBI")
      ? { id: derived.delegationSeal, type: "DelegatorOOBI" }
      : null;
  const theirServices = asArray(theirs.service).map(serviceKey);
  const contains = (list, s) => list.some((x) => jsonEqual(x, s));
  const unexpected = theirServices.some((s) => !contains(ourServices, s) && !(optionalDelegator && jsonEqual(optionalDelegator, s)));
  const missing = ourServices.some((s) => !contains(theirServices, s));
  if (unexpected || missing) throw mismatch("did.json's services differ from those the stream authorises");

  const aliases = (v) => {
    const out = [];
    for (const alias of asArray(v)) {
      if (typeof alias !== "string") continue;
      const norm = normalizePercent(alias);
      if (!sameDid(alias, subject) && !out.includes(norm)) out.push(norm);
    }
    return out;
  };
  let ourAliases = aliases(ours.alsoKnownAs);
  const theirAliases = aliases(theirs.alsoKnownAs);
  // The did:keri form is implied by the AID; leaving it out adds nothing.
  const keri = `did:keri:${subject.split(":").pop()}`;
  if (!theirAliases.includes(keri)) ourAliases = ourAliases.filter((a) => a !== keri);
  if (!sameSet(ourAliases, theirAliases)) {
    throw mismatch(`did.json's alsoKnownAs is ${JSON.stringify(theirAliases)}, but the AID designated ${JSON.stringify(ourAliases)}`);
  }
}

/**
 * What a deactivated identifier's document keeps: its subject and aliases.
 * Every verification method, relationship, key role and service goes with
 * the keys (`deactivated_document`).
 */
function deactivatedDocument(doc) {
  const out = {};
  for (const member of ["@context", "id", "alsoKnownAs"]) if (Object.hasOwn(doc, member)) out[member] = structuredClone(doc[member]);
  return out;
}

/** Use a published `DelegatorOOBI` service when the stream gave none. */
function carryDelegatorService(derived, published, document) {
  if (!derived.delegationSeal || asArray(document.service).some((s) => isObject(s) && s.type === "DelegatorOOBI")) return;
  const delegator = asArray(published?.service).find((s) => isObject(s) && s.type === "DelegatorOOBI");
  if (delegator && Array.isArray(document.service)) document.service.push(delegator);
}

// ─── Derivation (`resolver.rs::derive`) ─────────────────────────────────

/** Run `fn`, reporting the KERI layer's failures as the Rust does. */
function kel(fn) {
  try {
    return fn();
  } catch (e) {
    if (e instanceof DidWebsError) throw e;
    if (e instanceof StreamError) throw error("Stream", `keri.cesr could not be read: ${e.message}`);
    if (e instanceof RegistryError) throw error("Registry", `designation registry: ${e.message}`);
    if (e instanceof InvalidKeyError) throw error("InvalidKey", `invalid key: ${e.message}`);
    if (e instanceof KelError || e instanceof KeriError) throw error("Kel", `key event log verification failed: ${e.message}`);
    throw e;
  }
}

function derive(parsed, keriCesr, limits) {
  const aid = parsed.aid;
  return kel(() => {
    const full = Kels.parse(keriCesr, limits);
    const current = full.keyState(aid);
    if (current.prefix !== aid) throw new KelError(`verified key state is for ${current.prefix}, not the AID in the DID (${aid})`);
    const sequenceNumbers = full.sequenceNumbers(aid);
    const latest = sequenceNumbers.length ? Math.max(...sequenceNumbers) : 0;
    const version = parsed.versionId ?? latest;
    const kels = parsed.versionId !== null && parsed.versionId !== latest ? full.asOf(aid, parsed.versionId) : full;
    const state = kels.keyState(aid);

    // A critical designation this resolver does not implement fails resolution (P6).
    const critical = unsupportedCritical(kels, aid, IMPLEMENTED_SCHEMAS);
    if (critical !== null) throw error("UnsupportedDesignation", `unsupportedDesignation: schema ${critical} is critical and not implemented`);

    // § Read step 4: the AID must designate this DID.
    const designated = designatedAliases(kels, aid);
    if (!designated.aliases.some((a) => sameDid(a, parsed.did))) {
      const reason = designated.rejected ? ` (${designated.rejected})` : "";
      throw error("NotDesignated", `${parsed.did} is not designated by its AID: no valid, unrevoked designated-aliases attestation names it${reason}`);
    }
    const aliases = [];
    for (const alias of designated.aliases) {
      if (!sameDid(alias, parsed.did) && !aliases.some((a) => sameDid(a, alias))) aliases.push(alias);
    }
    if (!aliases.includes(didKeri(parsed))) aliases.push(didKeri(parsed));
    const twinDesignated = aliases.some((a) => sameDid(a, didWebTwin(parsed)));
    const equivalentId = aliases.filter((a) => a.startsWith("did:webs:"));

    // Discovery replies are the latest at resolution time; the selected
    // version supplies the witnesses.
    const services = [...roleEndpoints(full, aid), ...witnessEndpoints(full, state.backers)].map(endpointService);
    const delegator = delegatorService(full, aid);
    if (delegator) services.push(delegator);
    for (const service of designatedServices(kels, aid).services) {
      if (services.every((s) => !jsonEqual(s.id ?? null, toJson(service.get("id")) ?? null))) services.push(toJson(service));
    }

    // Deactivation is a property of the DID, read from the whole stream;
    // a version is retired when it is the deactivating one.
    const metadata = {
      versionId: version,
      nextVersionId: sequenceNumbers.filter((sn) => sn > version).reduce((m, sn) => (m === null || sn < m ? sn : m), null),
      equivalentId,
      deactivated: full.isDeactivated(aid),
    };
    const retired = kels.isDeactivated(aid);
    const delegationSeal = state.delegator ? full.inceptionSaid(aid) : null;

    const keyRoles = designatedKeyRoles(kels, aid);
    if (keyRoles.issued) {
      return {
        document: deriveKeyRoleDocument(parsed, keyRoles.roles, keyRoles.revoked, aliases, services),
        metadata,
        twinDesignated,
        delegationSeal,
        convertedKeyAgreement: [],
        retired,
      };
    }

    // Designated key agreement keys; a key of the current key state is never one.
    const designatedKa = designatedKeyAgreement(kels, aid);
    const converted = designatedKa.issued || designatedKa.rejected !== null || retired ? [] : convertedKeyAgreement(state.keys);
    const stateRaws = state.keys.map((k) => {
      try {
        return matterFromQb64(k).raw;
      } catch {
        return null;
      }
    });
    const keyAgreement = designatedKa.keys.filter((key) => {
      let designatedKey;
      try {
        designatedKey = keyAgreementKey(key);
      } catch {
        return false;
      }
      return !stateRaws.some((raw) => raw && raw.length === designatedKey.raw.length && raw.every((b, i) => b === designatedKey.raw[i]));
    });
    let document = deriveDocument(parsed, state.keys, state.threshold, aliases, services);
    document = withKeyAgreement(document, parsed, keyAgreement);
    return { document, metadata, twinDesignated, delegationSeal, convertedKeyAgreement: converted, retired };
  });
}

function metadataJson(m) {
  const out = { versionId: String(m.versionId) };
  if (m.nextVersionId !== null) out.nextVersionId = String(m.nextVersionId);
  if (m.equivalentId.length) out.equivalentId = m.equivalentId;
  if (m.deactivated) out.deactivated = true;
  return out;
}

function toBytes(value, what) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof value === "string") return new TextEncoder().encode(value);
  throw new TypeError(`did:webs: ${what} must be a Uint8Array, an ArrayBuffer or a string`);
}

/**
 * Resolve a did:webs DID from artifacts already fetched
 * (`resolve_with_metadata`). Skips the network; everything else is as for
 * {@link resolve}.
 *
 * `keriCesr` is the only input that carries authority. `didJson` is checked
 * against the derived document and a disagreement fails the resolution. A
 * conforming resolution needs both; `null` is accepted for verifying a
 * stream offline, and {@link resolve} never passes it.
 *
 * @param {string} did - a did:webs DID, or a DID URL with `versionId`.
 * @param {Uint8Array|ArrayBuffer|string} keriCesr
 * @param {Uint8Array|ArrayBuffer|string|null} [didJson]
 * @returns {{ didDocument: Object, didResolutionMetadata: Object, didDocumentMetadata: Object }}
 * @throws {DidWebsError}
 */
export function resolveFromArtifacts(did, keriCesr, didJson = null) {
  const parsed = parseDidWebs(did);
  const cesr = toBytes(keriCesr, "keriCesr");
  if (cesr.length > MAX_ARTIFACT_BYTES) throw error("Stream", `keri.cesr could not be read: it is over the ${MAX_ARTIFACT_BYTES}-byte cap`);
  const derived = derive(parsed, cesr, { maxMessages: MAX_STREAM_MESSAGES });
  let document = structuredClone(derived.document);

  if (didJson !== null && didJson !== undefined) {
    let published;
    try {
      published = parseJson(toBytes(didJson, "didJson"), { plain: true });
    } catch (e) {
      throw error("Json", `JSON error: ${e.message}`);
    }
    published = fromDidWeb(published, parsed, derived.twinDesignated);
    if (derived.retired) {
      // For the deactivating version a published did.json may be the
      // document without keys, or the full derivation published before.
      try {
        checkPublished({ ...derived, document: deactivatedDocument(derived.document) }, published);
      } catch {
        checkPublished(derived, published);
      }
    } else {
      try {
        checkPublished(derived, published);
      } catch (e) {
        // The converted keys are not part of the derivation the
        // specification defines, so a document published without them
        // agrees, and so does one published with them.
        if (!derived.convertedKeyAgreement.length) throw e;
        const withConverted = { ...derived, document: withKeyAgreement(derived.document, parsed, derived.convertedKeyAgreement) };
        try {
          checkPublished(withConverted, published);
        } catch {
          throw e;
        }
      }
    }
    carryDelegatorService(derived, published, document);
  }
  document = withKeyAgreement(document, parsed, derived.convertedKeyAgreement);
  if (derived.retired) document = deactivatedDocument(document);

  return {
    didDocument: intoDocument(document, parsed),
    didResolutionMetadata: { contentType: "application/did+ld+json" },
    didDocumentMetadata: metadataJson(derived.metadata),
  };
}

// ─── Fetching (affinidi-did-webs `fetch.rs`) ────────────────────────────

const CESR_LABEL = "did:webs keri.cesr";
const DID_JSON_LABEL = "did:webs did.json";

function netPolicyOf(options) {
  const netPolicy = options?.netPolicy;
  if (netPolicy != null && typeof netPolicy !== "object") throw new TypeError("did:webs: netPolicy must be an object");
  return {
    allowInsecure: Boolean(netPolicy?.allowInsecure),
    allowPrivate: Boolean(netPolicy?.allowPrivate),
    allowHosts: netPolicy?.allowHosts ?? null,
  };
}

async function fetchArtifact(fetchGuarded, url, options, label) {
  const timeoutMs = options?.timeoutMs ?? DEFAULT_WEBS_TIMEOUT_MS;
  const init = { method: "GET", redirect: "manual" };
  if (timeoutMs > 0 && typeof AbortSignal?.timeout === "function") init.signal = AbortSignal.timeout(timeoutMs);
  let response;
  try {
    response = await fetchGuarded(url.href, init);
  } catch (err) {
    if (err instanceof BlockedEndpointError) throw err;
    throw error("Fetch", `could not fetch ${url.href}: ${err?.message ?? err}`, { url: url.href });
  }
  if (!response?.ok) {
    try {
      await response?.body?.cancel?.();
    } catch {
      // Nothing to release.
    }
    throw error("Fetch", `could not fetch ${url.href}: HTTP ${response?.status}`, { status: response?.status, url: url.href });
  }
  const tooLarge = (why) => error("Fetch", `could not fetch ${url.href}: the ${label} ${why} the ${MAX_ARTIFACT_BYTES}-byte cap`, { url: url.href });
  // The advertised length first, then the bytes as they arrive: a
  // Content-Length is the server's claim, not a fact.
  const declared = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declared) && declared > MAX_ARTIFACT_BYTES) {
    try {
      await response.body?.cancel?.();
    } catch {
      // Nothing to release.
    }
    throw tooLarge(`declares ${declared} bytes, over`);
  }
  try {
    if (response.body && typeof response.body.getReader === "function") {
      const reader = response.body.getReader();
      const chunks = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_ARTIFACT_BYTES) {
          await reader.cancel().catch(() => {});
          throw tooLarge("is over");
        }
        chunks.push(value);
      }
      const out = new Uint8Array(total);
      let offset = 0;
      for (const c of chunks) {
        out.set(c, offset);
        offset += c.byteLength;
      }
      return out;
    }
    const buf = new Uint8Array(await response.arrayBuffer());
    if (buf.length > MAX_ARTIFACT_BYTES) throw tooLarge("is over");
    return buf;
  } catch (err) {
    if (err instanceof DidWebsError) throw err;
    throw error("Fetch", `could not fetch ${url.href}: ${err?.message ?? err}`, { url: url.href });
  }
}

/**
 * Resolve a did:webs DID (or a DID URL with a `versionId` parameter) to its
 * DID document.
 *
 * Fetches `keri.cesr` and then `did.json` from the vetted host — both are
 * required — verifies the stream, derives the document and checks
 * `did.json` against it.
 *
 * @param {string} did
 * @param {Object} [options]
 * @param {import("./net-guard.js").NetPolicy} [options.netPolicy] - egress
 *   policy for the host the DID names. Defaults to `https:` on a public
 *   host. A local host needs `allowPrivate` (and is then fetched over
 *   `http` when it is loopback); `allowInsecure` fetches any host over
 *   `http`.
 * @param {Function} [options.fetch] - fetch impl; defaults to global. It is
 *   wrapped rather than trusted: every URL is re-checked and a 3xx is
 *   refused, so it must honour `redirect: "manual"`.
 * @param {number} [options.timeoutMs=20000] - per-request timeout. `0`
 *   disables it.
 * @returns {Promise<{ didDocument: Object, didResolutionMetadata: Object, didDocumentMetadata: Object }>}
 * @throws {BlockedEndpointError} if the host fails the policy.
 * @throws {DidWebsError}
 */
export async function resolve(did, options = {}) {
  if (typeof did !== "string") throw new TypeError("did:webs resolve: input must be a string");
  if (options?.versionTime !== undefined) {
    throw new TypeError("did:webs: versionTime is not supported; resolve a DID URL with a versionId parameter instead");
  }
  const policy = netPolicyOf(options);
  const { keriCesr, didJson } = websArtifactUrls(did, options?.netPolicy);
  const plaintext = keriCesr.protocol === "http:";
  const fetchGuarded = guardedFetch(options.fetch ?? globalThis.fetch, {
    ...policy,
    label: CESR_LABEL,
    schemes: ["https:"],
    allowInsecure: plaintext,
  });
  const cesr = await fetchArtifact(fetchGuarded, keriCesr, options, CESR_LABEL);
  const document = await fetchArtifact(fetchGuarded, didJson, options, DID_JSON_LABEL);
  const resolution = resolveFromArtifacts(did, cesr, document);
  // This is a document provider: a deactivated identifier's keys, at any
  // version, must not be taken for current ones (TDK-SEC-027).
  if (resolution.didDocumentMetadata.deactivated) {
    throw error("Deactivated", `${parseDidWebs(did).did} is deactivated`);
  }
  return resolution;
}

// For the conformance tests, which compare the KERI layer with the Rust
// crate's, function by function.
export const internals = Object.freeze({
  Kels,
  serviceEndpoints,
  delegatorService,
  designatedAliases,
  designatedKeyAgreement,
  designatedServices,
  designatedKeyRoles,
  kel,
  KEY_ROLES,
  fromJson,
});
