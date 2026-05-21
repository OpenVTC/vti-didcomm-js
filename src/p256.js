// P-256 (NIST secp256r1) key agreement primitive — wraps
// `@noble/curves` for the browser/Node universal path, mirroring
// `x25519.js`.
//
// DIDComm v2 / JOSE supports the NIST curves for ECDH key agreement
// (RFC 7518 §4.6). For P-256 the ECDH shared secret `Z` fed into the
// Concat KDF is the 32-byte big-endian X-coordinate of the
// scalar-multiplication result — NOT the full SEC1 point. That's the
// one place this differs from X25519 (whose raw output is used
// directly); everything downstream (Concat KDF, AES-KW, content
// encryption) is curve-independent.
//
// Public keys are handled in uncompressed SEC1 form (0x04 || X || Y,
// 65 bytes) because the JWE `epk`/JWK representation needs both the X
// and Y coordinates. `getSharedSecret`/key construction in @noble
// accept either compressed or uncompressed SEC1 input.

import { p256 } from "@noble/curves/nist.js";

const UNCOMPRESSED_LEN = 65; // 0x04 || X(32) || Y(32)
const COORD_LEN = 32;

/**
 * Generate a fresh P-256 keypair from the OS CSPRNG.
 *
 * @returns {{ privateKey: Uint8Array, publicKey: Uint8Array }}
 *   `privateKey` is the 32-byte scalar; `publicKey` is the 65-byte
 *   uncompressed SEC1 point.
 */
export function generateKeyPair() {
  const privateKey = p256.utils.randomSecretKey();
  const publicKey = p256.getPublicKey(privateKey, false);
  return { privateKey, publicKey };
}

/**
 * Derive the uncompressed P-256 public key for a 32-byte scalar.
 *
 * @param {Uint8Array} privateKey - 32 bytes
 * @returns {Uint8Array} 65-byte uncompressed SEC1 public key
 */
export function publicKeyFrom(privateKey) {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== COORD_LEN) {
    throw new TypeError("P-256 privateKey must be 32 bytes");
  }
  return p256.getPublicKey(privateKey, false);
}

/**
 * Compute the P-256 ECDH shared secret between a private key and a
 * peer's public key.
 *
 * @param {Uint8Array} privateKey - 32-byte scalar
 * @param {Uint8Array} peerPublicKey - SEC1 point (33 compressed or
 *   65 uncompressed bytes)
 * @returns {Uint8Array} the 32-byte shared secret (the X-coordinate
 *   of the ECDH point), per RFC 7518 §4.6. This is the `Z` value the
 *   Concat KDF consumes — the KDF runs separately via `concat-kdf.js`.
 */
export function sharedSecret(privateKey, peerPublicKey) {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== COORD_LEN) {
    throw new TypeError("P-256 privateKey must be 32 bytes");
  }
  if (!(peerPublicKey instanceof Uint8Array)) {
    throw new TypeError("P-256 peerPublicKey must be a Uint8Array");
  }
  // `true` → compressed output: 0x02/0x03 sign byte || X(32). We drop
  // the sign byte and keep the 32-byte X-coordinate (the JOSE `Z`).
  const point = p256.getSharedSecret(privateKey, peerPublicKey, true);
  return point.slice(1, 1 + COORD_LEN);
}

/**
 * Split an uncompressed SEC1 point into its raw X and Y coordinates,
 * for building an EC JWK (`x` / `y` members).
 *
 * @param {Uint8Array} publicKey - 65-byte uncompressed SEC1 point
 * @returns {{ x: Uint8Array, y: Uint8Array }} 32-byte coordinates
 */
export function pointCoordinates(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== UNCOMPRESSED_LEN || publicKey[0] !== 0x04) {
    throw new TypeError("P-256 public key must be a 65-byte uncompressed SEC1 point (0x04 prefix)");
  }
  return {
    x: publicKey.slice(1, 1 + COORD_LEN),
    y: publicKey.slice(1 + COORD_LEN),
  };
}

/**
 * Build an uncompressed SEC1 point (0x04 || X || Y) from raw X and Y
 * coordinates — the inverse of {@link pointCoordinates}, used when
 * reconstructing a public key from an EC JWK.
 *
 * @param {Uint8Array} x - 32-byte X-coordinate
 * @param {Uint8Array} y - 32-byte Y-coordinate
 * @returns {Uint8Array} 65-byte uncompressed SEC1 point
 */
export function pointFromCoordinates(x, y) {
  if (!(x instanceof Uint8Array) || x.length !== COORD_LEN) {
    throw new TypeError("P-256 x-coordinate must be 32 bytes");
  }
  if (!(y instanceof Uint8Array) || y.length !== COORD_LEN) {
    throw new TypeError("P-256 y-coordinate must be 32 bytes");
  }
  const point = new Uint8Array(UNCOMPRESSED_LEN);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 1 + COORD_LEN);
  // Validate the point lies on the curve (throws on a bad/forged JWK).
  p256.Point.fromBytes(point);
  return point;
}
