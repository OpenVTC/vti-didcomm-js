// Curve-agnostic key-agreement dispatcher.
//
// DIDComm v2 / JOSE allow several curves for ECDH key agreement. We
// support the two that matter for our flows:
//
//   - X25519 (OKP) — the DIDComm default; raw 32-byte scalar mult.
//   - P-256  (EC)  — NIST secp256r1; `Z` is the 32-byte X-coordinate
//                    of the ECDH point (RFC 7518 §4.6).
//
// Everything above this layer (ECDH-1PU / ECDH-ES, the Concat KDF,
// AES-KW, content encryption) is curve-independent: it only ever sees
// a 32-byte shared secret `Z` and opaque public-key bytes. This module
// is the single seam where the curve matters, so adding P-384/P-521
// later is a matter of one more case here plus a primitive module.
//
// secp256k1 is intentionally NOT a key-agreement curve here — it's a
// signing curve in our scope (resolution only). DIDComm key agreement
// uses X25519 and the NIST curves.

import * as x25519 from "./x25519.js";
import * as p256 from "./p256.js";

/** Curve identifiers as they appear in JWK `crv` members. */
export const X25519 = "X25519";
export const P256 = "P-256";

const CURVES = {
  [X25519]: x25519,
  [P256]: p256,
};

function impl(crv) {
  const m = CURVES[crv];
  if (!m) {
    throw new Error(
      `key-agreement: unsupported curve ${JSON.stringify(crv)}; supported: ${Object.keys(CURVES).join(", ")}`,
    );
  }
  return m;
}

/** @returns {boolean} whether `crv` is a supported key-agreement curve. */
export function isSupported(crv) {
  return Object.prototype.hasOwnProperty.call(CURVES, crv);
}

/**
 * Generate a fresh key-agreement keypair on the given curve.
 *
 * @param {"X25519"|"P-256"} crv
 * @returns {{ privateKey: Uint8Array, publicKey: Uint8Array }}
 *   For X25519 the public key is the 32-byte u-coordinate; for P-256
 *   it's the 65-byte uncompressed SEC1 point.
 */
export function generateKeyPair(crv) {
  return impl(crv).generateKeyPair();
}

/**
 * Derive the public key for a private scalar on the given curve.
 *
 * @param {"X25519"|"P-256"} crv
 * @param {Uint8Array} privateKey - 32-byte scalar
 * @returns {Uint8Array}
 */
export function publicKeyFrom(crv, privateKey) {
  return impl(crv).publicKeyFrom(privateKey);
}

/**
 * Compute the ECDH shared secret `Z` on the given curve.
 *
 * @param {"X25519"|"P-256"} crv
 * @param {Uint8Array} privateKey - 32-byte scalar
 * @param {Uint8Array} peerPublicKey - curve-appropriate public key
 * @returns {Uint8Array} the 32-byte shared secret consumed by the KDF
 */
export function sharedSecret(crv, privateKey, peerPublicKey) {
  return impl(crv).sharedSecret(privateKey, peerPublicKey);
}
