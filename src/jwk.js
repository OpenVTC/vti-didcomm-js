// JWK ↔ raw byte conversions for the curves we use:
//
//   - X25519 (key-agreement, kty=OKP, crv=X25519)
//   - Ed25519 (signing, kty=OKP, crv=Ed25519)
//   - P-256   (key-agreement, kty=EC, crv=P-256)
//
// OKP curves (RFC 8037) have a public JWK with `x`; the private JWK
// adds `d`. All values are base64url-encoded raw curve bytes (32 each).
//
// EC curves (RFC 7518 §6.2) split the public point into `x` and `y`
// (32-byte big-endian coordinates each); the private JWK adds the
// 32-byte scalar `d`. Internally we move P-256 public keys around as
// 65-byte uncompressed SEC1 points (0x04 || X || Y) — the form
// `p256.js` / `key-agreement.js` consume — and (de)serialise the
// `x`/`y` members at the JWK boundary.
//
// We deliberately don't ship general JWK support — no P-384/P-521,
// no RSA, no symmetric keys. Future curve additions land here.

import * as b64u from "./base64url.js";
import * as p256 from "./p256.js";

/** @typedef {{ kty: "OKP", crv: "X25519" | "Ed25519", x: string, d?: string, kid?: string }} OkpJwk */
/** @typedef {{ kty: "EC", crv: "P-256", x: string, y: string, d?: string, kid?: string }} EcJwk */
/** @typedef {OkpJwk | EcJwk} Jwk */

const OKP_CURVES = new Set(["X25519", "Ed25519"]);
const EC_CURVES = new Set(["P-256"]);

/**
 * Build a public JWK from raw key bytes.
 *
 * @param {"X25519"|"Ed25519"|"P-256"} crv
 * @param {Uint8Array} keyBytes - for OKP curves, 32 raw curve bytes;
 *   for P-256, a 65-byte uncompressed SEC1 point (0x04 || X || Y).
 * @param {string} [kid] - optional `kid` to attach
 * @returns {Jwk}
 */
export function publicJwk(crv, keyBytes, kid) {
  if (EC_CURVES.has(crv)) {
    const { x, y } = p256.pointCoordinates(keyBytes);
    const jwk = { kty: "EC", crv, x: b64u.encode(x), y: b64u.encode(y) };
    if (kid) jwk.kid = kid;
    return jwk;
  }
  assertOkpCurve(crv);
  if (keyBytes.length !== 32) {
    throw new Error(`jwk: ${crv} public key must be 32 bytes, got ${keyBytes.length}`);
  }
  const jwk = { kty: "OKP", crv, x: b64u.encode(keyBytes) };
  if (kid) jwk.kid = kid;
  return jwk;
}

/**
 * Build a private JWK from raw private + public key bytes.
 *
 * @param {"X25519"|"Ed25519"|"P-256"} crv
 * @param {Uint8Array} privateBytes - 32 raw scalar bytes (d)
 * @param {Uint8Array} publicBytes - OKP: 32 raw curve bytes; P-256:
 *   65-byte uncompressed SEC1 point.
 * @param {string} [kid]
 * @returns {Jwk}
 */
export function privateJwk(crv, privateBytes, publicBytes, kid) {
  const pub = publicJwk(crv, publicBytes, kid);
  if (privateBytes.length !== 32) {
    throw new Error(`jwk: ${crv} private key must be 32 bytes, got ${privateBytes.length}`);
  }
  return { ...pub, d: b64u.encode(privateBytes) };
}

/**
 * The curve of a JWK, validated against the kty. Useful for the
 * key-agreement layer to pick the right primitive.
 *
 * @param {Jwk} jwk
 * @returns {"X25519"|"Ed25519"|"P-256"}
 */
export function curveOf(jwk) {
  assertShape(jwk);
  return jwk.crv;
}

/**
 * Extract raw public-key bytes from a JWK, in the form the
 * key-agreement / signing primitives consume.
 *
 * @param {Jwk} jwk
 * @returns {Uint8Array} OKP: 32-byte key; P-256: 65-byte uncompressed
 *   SEC1 point.
 */
export function rawPublic(jwk) {
  assertShape(jwk);
  if (jwk.kty === "EC") {
    const x = b64u.decode(jwk.x);
    const y = b64u.decode(jwk.y);
    if (x.length !== 32 || y.length !== 32) {
      throw new Error(`jwk: ${jwk.crv} JWK 'x'/'y' must each decode to 32 bytes`);
    }
    return p256.pointFromCoordinates(x, y);
  }
  const bytes = b64u.decode(jwk.x);
  if (bytes.length !== 32) {
    throw new Error(`jwk: ${jwk.crv} JWK 'x' must decode to 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

/**
 * Extract the raw private scalar from a JWK. Throws if `d` is absent
 * (caller passed a public-only JWK by mistake).
 *
 * @param {Jwk} jwk
 * @returns {Uint8Array} 32-byte scalar
 */
export function rawPrivate(jwk) {
  assertShape(jwk);
  if (!jwk.d) {
    throw new Error("jwk: JWK has no 'd' — this is a public-only key");
  }
  const bytes = b64u.decode(jwk.d);
  if (bytes.length !== 32) {
    throw new Error(`jwk: ${jwk.crv} JWK 'd' must decode to 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

/**
 * Strip private material from a JWK, leaving only the public portion.
 * Used to build the `epk` (ephemeral public key) field of a JWE.
 *
 * @param {Jwk} jwk
 * @returns {Jwk}
 */
export function toPublic(jwk) {
  assertShape(jwk);
  const out =
    jwk.kty === "EC"
      ? { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y }
      : { kty: "OKP", crv: jwk.crv, x: jwk.x };
  if (jwk.kid) out.kid = jwk.kid;
  return out;
}

function assertOkpCurve(crv) {
  if (!OKP_CURVES.has(crv)) {
    throw new Error(`jwk: unsupported OKP curve: ${crv}. Expected one of ${[...OKP_CURVES].join(", ")}`);
  }
}

function assertShape(jwk) {
  if (!jwk || typeof jwk !== "object") {
    throw new TypeError("jwk: JWK must be an object");
  }
  if (jwk.kty === "OKP") {
    assertOkpCurve(jwk.crv);
    if (typeof jwk.x !== "string") {
      throw new Error("jwk: OKP JWK 'x' must be a string");
    }
    return;
  }
  if (jwk.kty === "EC") {
    if (!EC_CURVES.has(jwk.crv)) {
      throw new Error(`jwk: unsupported EC curve: ${jwk.crv}. Expected one of ${[...EC_CURVES].join(", ")}`);
    }
    if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
      throw new Error("jwk: EC JWK 'x' and 'y' must be strings");
    }
    return;
  }
  throw new Error(`jwk: JWK kty must be 'OKP' or 'EC', got ${JSON.stringify(jwk.kty)}`);
}
