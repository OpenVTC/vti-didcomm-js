// `did:key` resolver — pure, deterministic, no I/O.
//
// Spec: https://w3c-ccg.github.io/did-method-key/
//
// A `did:key` identifier looks like `did:key:<multibase>`, where
// `<multibase>` decodes (via multibase 'z' base58btc) to:
//
//   multicodec_varint || raw_public_key_bytes
//
// Multicodecs we support:
//   - 0xed 0x01 → Ed25519   public key (32 bytes)
//   - 0xec 0x01 → X25519    public key (32 bytes)
//   - 0x80 0x24 → P-256     public key (33 bytes, compressed)
//   - 0xe7 0x01 → secp256k1 public key (33 bytes, compressed)
//
// Per the spec, an Ed25519 `did:key` exposes BOTH the signing key
// (authentication / assertionMethod) AND a `keyAgreement` entry —
// the latter derived from the Ed25519 public key via the
// Edwards-to-Montgomery transformation. This file inlines that
// transformation (BigInt arithmetic, ~30 lines) rather than pulling
// in another dependency.
//
// The NIST/secp256k1 curves (P-256, secp256k1) are signing keys here:
// the did:key spec places them in authentication / assertionMethod /
// capabilityDelegation / capabilityInvocation, but NOT keyAgreement.
// (P-256 *key agreement* is reachable via did:peer `E` keys and
// did:webvh keyAgreement entries, where the relationship is explicit.)
//
// What we DON'T do (yet):
//   - JsonWebKey2020 representation. We emit `Multikey` only.
//   - did:key parameter strings (e.g. "did:key:z6Mk...?versionId=").
//   - Disambiguation by service-endpoint hints.

import * as multibase from "./multibase.js";

const ED25519_CODEC = multibase.MULTICODEC.ED25519_PUB;
const X25519_CODEC = multibase.MULTICODEC.X25519_PUB;
const P256_CODEC = multibase.MULTICODEC.P256_PUB;
const SECP256K1_CODEC = multibase.MULTICODEC.SECP256K1_PUB;

const ED25519_FIELD_PRIME = (1n << 255n) - 19n;

/**
 * Resolve a `did:key:z...` identifier into a DID document.
 *
 * @param {string} did - the full `did:key:z...` string.
 * @returns {{
 *   didDocument: Object,
 *   didResolutionMetadata: Object,
 *   didDocumentMetadata: Object,
 * }}
 */
export function resolve(did) {
  if (typeof did !== "string") {
    throw new TypeError("did:key resolve: input must be a string");
  }
  if (!did.startsWith("did:key:")) {
    throw new Error(`did:key resolve: identifier must start with "did:key:" (got ${JSON.stringify(did.slice(0, 32))}…)`);
  }
  const multibaseStr = did.slice("did:key:".length);
  if (!multibaseStr.startsWith("z")) {
    throw new Error("did:key resolve: only base58btc (z-prefix) is supported");
  }

  const { codec, key } = multibase.decodeMultikey(multibaseStr);

  if (bytesEqual(codec, ED25519_CODEC)) {
    assertLen(key, 32, "Ed25519");
    return {
      didDocument: ed25519DidDocument(did, multibaseStr, key),
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {},
    };
  }
  if (bytesEqual(codec, X25519_CODEC)) {
    assertLen(key, 32, "X25519");
    return {
      didDocument: x25519DidDocument(did, multibaseStr),
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {},
    };
  }
  if (bytesEqual(codec, P256_CODEC)) {
    assertLen(key, 33, "P-256");
    return {
      didDocument: signingKeyDidDocument(did, multibaseStr),
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {},
    };
  }
  if (bytesEqual(codec, SECP256K1_CODEC)) {
    assertLen(key, 33, "secp256k1");
    return {
      didDocument: signingKeyDidDocument(did, multibaseStr),
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {},
    };
  }

  throw new Error(
    `did:key resolve: unsupported multicodec ${formatBytes(codec)}; supported: Ed25519(0xed01), X25519(0xec01), P-256(0x8024), secp256k1(0xe701)`,
  );
}

// ─── DID Document builders ─────────────────────────────────────────────

function ed25519DidDocument(did, multibaseStr, edPubBytes) {
  // For Ed25519 keys, the DID exposes BOTH the signing key and an
  // X25519 keyAgreement key derived from it. Both verification
  // methods are emitted with `Multikey` type.
  const signingKid = `${did}#${multibaseStr}`;

  const xPubBytes = ed25519PublicKeyToX25519(edPubBytes);
  const xMultikeyStr = multibase.encodeMultikey(X25519_CODEC, xPubBytes);
  const agreementKid = `${did}#${xMultikeyStr}`;

  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: signingKid,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: multibaseStr,
      },
      {
        id: agreementKid,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: xMultikeyStr,
      },
    ],
    authentication: [signingKid],
    assertionMethod: [signingKid],
    capabilityDelegation: [signingKid],
    capabilityInvocation: [signingKid],
    keyAgreement: [agreementKid],
  };
}

function x25519DidDocument(did, multibaseStr) {
  // An X25519-only did:key has no signing key — only keyAgreement.
  const kid = `${did}#${multibaseStr}`;
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: kid,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: multibaseStr,
      },
    ],
    keyAgreement: [kid],
  };
}

// Shared builder for the signing-only curves (P-256, secp256k1):
// the verification method lands in every signing relationship but
// not keyAgreement.
function signingKeyDidDocument(did, multibaseStr) {
  const kid = `${did}#${multibaseStr}`;
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: kid,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: multibaseStr,
      },
    ],
    authentication: [kid],
    assertionMethod: [kid],
    capabilityDelegation: [kid],
    capabilityInvocation: [kid],
  };
}

// ─── Ed25519 → X25519 conversion ───────────────────────────────────────

/**
 * Derive the X25519 public key for an Ed25519 public key.
 *
 * Ed25519 publishes a compressed Edwards point — the 32-byte little-
 * endian encoding of the y-coordinate with the sign bit of x in the
 * top bit of byte 31. The corresponding X25519 public key is the
 * Montgomery u-coordinate, related by the birational map:
 *
 *     u = (1 + y) / (1 - y)   mod p,   p = 2^255 - 19
 *
 * (Bernstein "Curve25519: new Diffie-Hellman speed records" §6, the
 * birational equivalence between curve25519/Montgomery and edwards25519.)
 *
 * @param {Uint8Array} edPub - 32 bytes
 * @returns {Uint8Array} 32-byte X25519 public key
 */
export function ed25519PublicKeyToX25519(edPub) {
  if (!(edPub instanceof Uint8Array) || edPub.length !== 32) {
    throw new TypeError("ed25519PublicKeyToX25519: input must be 32 bytes");
  }
  // Decode y from little-endian, clearing the sign bit.
  const yLe = new Uint8Array(edPub);
  yLe[31] &= 0x7f;
  const y = leToBigInt(yLe);

  const p = ED25519_FIELD_PRIME;
  const one = 1n;
  // numerator = (1 + y) mod p ; denominator = (1 - y) mod p (positive)
  const num = (one + y) % p;
  const denomRaw = (one - y) % p;
  const denom = denomRaw < 0n ? denomRaw + p : denomRaw;

  const u = (num * modInverse(denom, p)) % p;
  return bigIntToLe32(u);
}

// ─── BigInt helpers ─────────────────────────────────────────────────────

function leToBigInt(bytes) {
  let out = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    out = (out << 8n) | BigInt(bytes[i]);
  }
  return out;
}

function bigIntToLe32(n) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/**
 * Modular inverse via Fermat's little theorem: for prime p,
 * a^(p-2) ≡ a^-1 (mod p). Slower than extended-Euclidean but tiny
 * and obviously correct.
 */
function modInverse(a, p) {
  return modPow(a, p - 2n, p);
}

function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  if (base < 0n) base += mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * base) % mod;
    e >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

// ─── Misc ───────────────────────────────────────────────────────────────

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function assertLen(buf, expected, label) {
  if (buf.length !== expected) {
    throw new Error(`did:key resolve: ${label} key must be ${expected} bytes, got ${buf.length}`);
  }
}

function formatBytes(b) {
  return "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}
