// DID document verification methods → key bytes, chosen by relationship.
//
// The one place this library turns a verification method into a public key.
// Every auth and encryption path (mediator auth, VTA REST auth, the VTA
// DIDComm client and its inbound-sender lookup) goes through here, so a DID
// method that publishes its keys differently is supported everywhere at once
// or nowhere.
//
// Two encodings are read:
//
//   - `publicKeyMultibase` (multicodec multikey) — did:key, did:peer,
//     did:webvh, did:scid. Types `Multikey`, `Ed25519VerificationKey2020`,
//     `X25519KeyAgreementKey2020`, `X25519KeyAgreementKey2019`.
//   - `publicKeyJwk` — did:webs (`JsonWebKey`, ids `<did>#<CESR key>`), and
//     `JsonWebKey2020`. Read through `jwk.js`: OKP Ed25519 / X25519 and EC
//     P-256.
//
// Anything else fails closed: an unknown `type`, a type whose encoding the
// method does not carry (a `JsonWebKey` with only `publicKeyMultibase`), both
// encodings at once, a curve this library has no primitive for (secp256k1,
// P-384), a curve that contradicts the type, a JWK carrying private material,
// or a method marked `revoked`.
//
// A key is chosen by its verification relationship (`keyAgreement`,
// `authentication`, `assertionMethod`, …), never as "the first key of the
// right curve" in `verificationMethod[]`. A did:webs identifier with key roles
// (VTI-KEY-150 / VTI-KEY-173) binds different keys to each relationship, and a
// key listed under one relationship is not authorised for another. Entries are
// references (absolute or relative to the DID) into `verificationMethod[]` or
// embedded methods, as DID Core allows.
//
// The `kid` returned is the method's own id, made absolute against the DID
// when the document writes it relative — so the `kid` / `skid` this library
// puts in a JWE header is exactly the id in the party's document.

import * as multibase from "./multibase.js";
import * as jwk from "./jwk.js";
import * as p256 from "./p256.js";
import { sameReference } from "./did-scid.js";

/** Curves this library has a primitive for. */
export const ED25519 = "Ed25519";
export const X25519 = "X25519";
export const P256 = "P-256";

/** Verification method types that carry `publicKeyMultibase`, and the curve each pins (null: any). */
const MULTIKEY_TYPES = new Map([
  ["Multikey", null],
  ["Ed25519VerificationKey2020", ED25519],
  ["X25519KeyAgreementKey2020", X25519],
  ["X25519KeyAgreementKey2019", X25519],
]);

/** Verification method types that carry `publicKeyJwk`. */
const JWK_TYPES = new Set(["JsonWebKey", "JsonWebKey2020"]);

const CODECS = [
  [multibase.MULTICODEC.ED25519_PUB, ED25519],
  [multibase.MULTICODEC.X25519_PUB, X25519],
  [multibase.MULTICODEC.P256_PUB, P256],
];

/**
 * The public key a verification method carries.
 *
 * @param {Object} vm - a verification method object.
 * @returns {{ crv: "Ed25519"|"X25519"|"P-256", publicKey: Uint8Array }}
 *   `publicKey` is 32 raw bytes for Ed25519 / X25519 and the 65-byte
 *   uncompressed SEC1 point for P-256 — the form `key-agreement.js` and
 *   `jwk.publicJwk` take.
 * @throws {Error} on anything it cannot read unambiguously (see the module
 *   documentation).
 */
export function publicKeyOf(vm) {
  if (!vm || typeof vm !== "object" || Array.isArray(vm)) {
    throw new TypeError("verification-method: a verification method must be an object");
  }
  const label = typeof vm.id === "string" ? vm.id : "(no id)";
  if (vm.revoked !== undefined && vm.revoked !== null) {
    throw new Error(`verification-method: ${label} is revoked`);
  }
  const hasMultibase = vm.publicKeyMultibase !== undefined;
  const hasJwk = vm.publicKeyJwk !== undefined;
  if (hasMultibase && hasJwk) {
    throw new Error(`verification-method: ${label} carries both publicKeyMultibase and publicKeyJwk`);
  }
  if (MULTIKEY_TYPES.has(vm.type)) {
    if (!hasMultibase) {
      throw new Error(`verification-method: ${label} is a ${vm.type} without publicKeyMultibase`);
    }
    const key = fromMultikey(vm.publicKeyMultibase, label);
    const pinned = MULTIKEY_TYPES.get(vm.type);
    if (pinned && key.crv !== pinned) {
      throw new Error(`verification-method: ${label} is a ${vm.type} holding a ${key.crv} key`);
    }
    return key;
  }
  if (JWK_TYPES.has(vm.type)) {
    if (!hasJwk) {
      throw new Error(`verification-method: ${label} is a ${vm.type} without publicKeyJwk`);
    }
    return fromJwk(vm.publicKeyJwk, label);
  }
  throw new Error(`verification-method: ${label} has unsupported type ${JSON.stringify(vm.type)}`);
}

/**
 * Choose a key from `relationship` of a DID document.
 *
 * With `kid`, the entry whose id is exactly `kid` (a did:scid `src` aside),
 * which must be readable and of one of `curves`; it is refused if it is
 * listed only under another relationship. Without `kid`, the first entry
 * that is readable and of one of `curves`, in document order — an entry of
 * another curve or of a type this library cannot read is passed over, never
 * used.
 *
 * @param {Object} didDocument
 * @param {string} did - the DID the document was resolved for; the base of
 *   relative ids.
 * @param {"keyAgreement"|"authentication"|"assertionMethod"|"capabilityInvocation"|"capabilityDelegation"} relationship
 * @param {Object} [options]
 * @param {string} [options.kid] - absolute key id to select.
 * @param {string[]} [options.curves] - acceptable curves (default: any this
 *   library supports).
 * @param {string} [options.label] - prefix for error messages, in place of
 *   `verification-method`.
 * @returns {{ kid: string, crv: "Ed25519"|"X25519"|"P-256", publicKey: Uint8Array, publicJwk: Object }}
 * @throws {Error} when no entry qualifies.
 */
export function selectKey(didDocument, did, relationship, { kid, curves, label } = {}) {
  try {
    return select(didDocument, did, relationship, { kid, curves });
  } catch (e) {
    if (label && typeof e?.message === "string" && e.message.startsWith(PREFIX)) {
      e.message = `${label}: ${e.message.slice(PREFIX.length)}`;
    }
    throw e;
  }
}

const PREFIX = "verification-method: ";

function select(didDocument, did, relationship, { kid, curves }) {
  if (!didDocument || typeof didDocument !== "object") {
    throw new TypeError(`verification-method: no DID document for ${did}`);
  }
  const entries = didDocument[relationship];
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error(`verification-method: ${did} has no ${relationship} entries`);
  }
  const allowed = curves ? new Set(curves) : null;
  const methods = Array.isArray(didDocument.verificationMethod) ? didDocument.verificationMethod : [];
  const abs = (id) => (typeof id === "string" && id.startsWith("#") ? `${did}${id}` : id);
  const reasons = [];
  for (const entry of entries) {
    const id = abs(typeof entry === "string" ? entry : entry?.id);
    if (typeof id !== "string") {
      reasons.push("an entry without an id");
      continue;
    }
    if (kid && !sameReference(id, kid)) continue;
    const vm = typeof entry === "string" ? methods.find((v) => sameReference(abs(v?.id), id)) : entry;
    let key;
    try {
      if (!vm) throw new Error(`verification-method: ${relationship} reference ${id} is not in verificationMethod[]`);
      key = publicKeyOf(vm);
      if (allowed && !allowed.has(key.crv)) {
        throw new Error(`verification-method: ${id} is ${key.crv}, not ${[...allowed].join(" or ")}`);
      }
    } catch (e) {
      // An explicitly named key is used or refused, never substituted.
      if (kid) throw e;
      reasons.push(e.message);
      continue;
    }
    return {
      kid: kid ?? id,
      crv: key.crv,
      publicKey: key.publicKey,
      publicJwk: jwk.publicJwk(key.crv, key.publicKey),
    };
  }
  if (kid) throw new Error(`verification-method: ${did} lists no ${relationship} key ${kid}`);
  const wanted = allowed ? ` ${[...allowed].join("/")}` : "";
  throw new Error(
    `verification-method: ${did} has no usable${wanted} ${relationship} key` +
      (reasons.length ? ` (${reasons.join("; ")})` : ""),
  );
}

/**
 * The X25519 `keyAgreement` key of a DID document — or the one whose id is
 * `kid` — as the DIDComm clients here need it.
 *
 * @param {Object} didDocument
 * @param {string} did
 * @param {Object} [options]
 * @param {string} [options.kid]
 * @param {string} [options.label] - prefix for error messages.
 * @returns {{ kid: string, x25519Pub: Uint8Array }}
 */
export function x25519KeyAgreement(didDocument, did, { kid, label } = {}) {
  const key = selectKey(didDocument, did, "keyAgreement", { kid, curves: [X25519], label });
  return { kid: key.kid, x25519Pub: key.publicKey };
}

// ─── Internals ──────────────────────────────────────────────────────────

function fromMultikey(value, label) {
  if (typeof value !== "string") {
    throw new Error(`verification-method: ${label} publicKeyMultibase must be a string`);
  }
  const { codec, key } = multibase.decodeMultikey(value);
  const match = CODECS.find(([c]) => c.length === codec.length && c.every((b, i) => b === codec[i]));
  if (!match) {
    const hex = Array.from(codec, (b) => b.toString(16).padStart(2, "0")).join("");
    throw new Error(`verification-method: ${label} uses unsupported multicodec 0x${hex}`);
  }
  const crv = match[1];
  if (crv === P256) {
    if (key.length !== 33 && key.length !== 65) {
      throw new Error(`verification-method: ${label} P-256 key must be a 33- or 65-byte SEC1 point`);
    }
    return { crv, publicKey: p256.uncompressedPoint(key) };
  }
  if (key.length !== 32) {
    throw new Error(`verification-method: ${label} ${crv} key must be 32 bytes, got ${key.length}`);
  }
  return { crv, publicKey: key };
}

function fromJwk(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`verification-method: ${label} publicKeyJwk must be an object`);
  }
  if (value.d !== undefined) {
    throw new Error(`verification-method: ${label} publicKeyJwk carries private key material`);
  }
  let crv;
  let publicKey;
  try {
    crv = jwk.curveOf(value);
    publicKey = jwk.rawPublic(value);
  } catch (e) {
    throw new Error(`verification-method: ${label} publicKeyJwk: ${e.message}`);
  }
  return { crv, publicKey };
}
