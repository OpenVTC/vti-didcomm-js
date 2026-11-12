// CESR and KERI message serialization for `./did-webs.js`.
//
// A port of the parts of `affinidi-cesr` 0.1.4 and `affinidi-keri-core`
// 0.8.1 that resolving a did:webs reads: Base64 primitives (`Matter`,
// `Indexer`), counters and the attachment groups of both counter tables,
// version strings, order-preserving JSON (`SadValue`), SAIDs, and native
// CESR bodies. Every rule — what is accepted, what is refused, and in what
// order — follows the Rust code; where this module is stricter it says so.
//
// Message content is held as a "SAD" value whose objects are `Map`s, so
// member order is exactly the order the bytes had (a SAID and a signature
// cover those bytes, and a plain object would move integer-like keys to the
// front). Numbers are `SadNumber`s holding their decimal text.
//
// Not supported, and refused rather than guessed at: CBOR and MessagePack
// bodies, and JSON numbers that are not integers in the signed or unsigned
// 64-bit range (serde_json would hold them as floats, whose text form this
// module does not reproduce).

import { blake3 } from "@noble/hashes/blake3.js";
import { blake2b, blake2s } from "@noble/hashes/blake2.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { sha3_256, sha3_512 } from "@noble/hashes/sha3.js";

/** An error in a KERI message or stream (affinidi-keri-core `CoreError`). */
export class KeriError extends Error {
  /**
   * @param {string} message
   * @param {"parse"|"validation"|"unsupported"|"said"|"threshold"|"crypto"|"json"} [type]
   */
  constructor(message, type = "parse") {
    super(message);
    this.name = "KeriError";
    this.type = type;
  }
}

const fail = (message, type) => {
  throw new KeriError(message, type);
};

// ─── Bytes and text ─────────────────────────────────────────────────────

const ENCODER = new TextEncoder();
const STRICT_DECODER = new TextDecoder("utf-8", { fatal: true });

/** @param {string} s */
export function utf8(s) {
  return ENCODER.encode(s);
}

/** @param {Uint8Array} bytes */
export function fromUtf8(bytes) {
  return STRICT_DECODER.decode(bytes);
}

/** Bytes as text when every byte is ASCII, else null. */
export function asciiText(bytes) {
  for (const b of bytes) if (b > 0x7f) return null;
  let out = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return out;
}

/** @param {string} s */
export function isAscii(s) {
  return /^[\x00-\x7f]*$/.test(s);
}

/** Rust's byte-wise string order (UTF-8 code units), for sorted maps. */
export function compareUtf8(a, b) {
  if (a === b) return 0;
  const x = utf8(a);
  const y = utf8(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

/**
 * `u64::from_str_radix` and friends: an optional `+`, then at least one digit
 * of `radix`. Returns a BigInt, or null.
 */
export function parseUnsigned(text, radix, max = 0xffffffffffffffffn) {
  if (typeof text !== "string") return null;
  const digits = text.startsWith("+") ? text.slice(1) : text;
  const pattern = radix === 16 ? /^[0-9a-fA-F]+$/ : /^[0-9]+$/;
  if (!pattern.test(digits)) return null;
  const value = BigInt(radix === 16 ? `0x${digits}` : digits);
  return value > max ? null : value;
}

/** A sequence number or count, as a JS number when it is exactly representable. */
export function toSafeNumber(big) {
  if (big === null || big > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(big);
}

// ─── Base64 (URL-safe, unpadded) ────────────────────────────────────────

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64_INDEX = new Map([...B64].map((c, i) => [c, i]));

/** @param {string} c */
export function b64Value(c) {
  return B64_INDEX.get(c);
}

/** @param {string} text */
export function isB64(text) {
  for (const c of text) if (!B64_INDEX.has(c)) return false;
  return true;
}

/** Big-endian value of a run of Base64 digits. */
export function b64ToInt(text) {
  let n = 0n;
  for (const c of text) {
    const v = B64_INDEX.get(c);
    if (v === undefined) fail(`invalid Base64 digit ${JSON.stringify(c)} in ${JSON.stringify(text)}`);
    n = n * 64n + BigInt(v);
  }
  return n;
}

/** `value` as `width` Base64 digits, higher digits dropped. */
export function intToB64(value, width) {
  let n = BigInt(value);
  const out = new Array(width).fill("A");
  for (let i = width - 1; i >= 0; i--) {
    out[i] = B64[Number(n % 64n)];
    n /= 64n;
  }
  return out.join("");
}

/** Encode bytes as unpadded URL-safe Base64. */
export function b64Encode(bytes) {
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64[n >> 18] + B64[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63];
  }
  return out;
}

/**
 * Decode unpadded URL-safe Base64 the way `base64ct` does: no padding, no
 * other alphabet, no dangling character, and the unused bits of a partial
 * final group must be zero.
 */
export function b64Decode(text) {
  if (text.length % 4 === 1) fail(`invalid Base64 length ${text.length}`);
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let o = 0;
  let i = 0;
  const v = (k) => {
    const x = B64_INDEX.get(text[k]);
    if (x === undefined) fail(`invalid Base64 character ${JSON.stringify(text[k])}`);
    return x;
  };
  for (; i + 4 <= text.length; i += 4) {
    const n = (v(i) << 18) | (v(i + 1) << 12) | (v(i + 2) << 6) | v(i + 3);
    out[o++] = n >> 16;
    out[o++] = (n >> 8) & 255;
    out[o++] = n & 255;
  }
  const rest = text.length - i;
  if (rest === 2) {
    const a = v(i);
    const b = v(i + 1);
    if (b & 15) fail("non-canonical Base64 encoding");
    out[o++] = (a << 2) | (b >> 4);
  } else if (rest === 3) {
    const a = v(i);
    const b = v(i + 1);
    const c = v(i + 2);
    if (c & 3) fail("non-canonical Base64 encoding");
    out[o++] = (a << 2) | (b >> 4);
    out[o++] = ((b & 15) << 4) | (c >> 2);
  }
  return out;
}

// ─── SAD values: order-preserving JSON (affinidi-keri-core `sad.rs`) ────

/** A JSON number, held as its decimal text (an integer in i64 or u64 range). */
export class SadNumber {
  /** @param {string} text */
  constructor(text) {
    this.text = text;
  }
  /** @returns {bigint} */
  get big() {
    return BigInt(this.text);
  }
}

/** Member `key` of a SAD object, or undefined. */
export function get(value, key) {
  return value instanceof Map ? value.get(key) : undefined;
}

/** The string, if `value` is one. */
export function str(value) {
  return typeof value === "string" ? value : undefined;
}

/** Deep equality of SAD values (serde_json `Value` / `SadValue` `PartialEq`). */
export function sadEqual(a, b) {
  if (a === b) return true;
  if (a instanceof SadNumber && b instanceof SadNumber) return a.text === b.text;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => sadEqual(x, b[i]));
  }
  if (a instanceof Map && b instanceof Map) {
    if (a.size !== b.size) return false;
    for (const [k, v] of a) if (!b.has(k) || !sadEqual(v, b.get(k))) return false;
    return true;
  }
  return false;
}

/** A deep copy. */
export function sadClone(value) {
  if (Array.isArray(value)) return value.map(sadClone);
  if (value instanceof Map) return new Map([...value].map(([k, v]) => [k, sadClone(v)]));
  return value;
}

/**
 * The SAD as plain JSON, for code that wants it (documents, services). Member
 * order is insertion order, as `serde_json` keeps it at best.
 */
export function toJson(value) {
  if (value instanceof SadNumber) {
    const n = Number(value.text);
    return Number.isSafeInteger(n) ? n : value.text;
  }
  if (Array.isArray(value)) return value.map(toJson);
  if (value instanceof Map) {
    const out = {};
    for (const [k, v] of value) {
      Object.defineProperty(out, k, { value: toJson(v), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return value;
}

/** Plain JSON as a SAD value (a parsed did.json, a built document). */
export function fromJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("a non-integer number is not supported", "unsupported");
    return new SadNumber(String(value));
  }
  if (Array.isArray(value)) return value.map(fromJson);
  if (typeof value === "object") return new Map(Object.entries(value).map(([k, v]) => [k, fromJson(v)]));
  fail(`not a JSON value: ${typeof value}`, "json");
}

const MAX_JSON_DEPTH = 128; // serde_json's recursion limit
const NUMBER = /-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
const U64_MAX = 0xffffffffffffffffn;
const I64_MIN = -0x8000000000000000n;

/**
 * Parse JSON as `serde_json::from_slice` into a `SadValue` does: strict
 * syntax, UTF-8, duplicate members refused, at most 127 levels of nesting,
 * only whitespace after the value.
 *
 * With `plain`, as `serde_json::from_slice` into a `serde_json::Value` does
 * instead: plain objects and numbers, and the last of a repeated member.
 *
 * @param {Uint8Array} bytes
 * @param {{ plain?: boolean }} [options]
 */
export function parseJson(bytes, { plain = false } = {}) {
  let text;
  try {
    text = fromUtf8(bytes);
  } catch {
    fail("invalid UTF-8 in JSON", "json");
  }
  let i = 0;
  const err = (m) => fail(`JSON: ${m} at ${i}`, "json");
  const ws = () => {
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  const literal = (word, value) => {
    if (text.startsWith(word, i)) {
      i += word.length;
      return value;
    }
    return err("invalid literal");
  };
  const string = () => {
    i++; // opening quote
    let out = "";
    let start = i;
    for (;;) {
      if (i >= text.length) err("unterminated string");
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(start, i);
        i++;
        return out;
      }
      if (c < 0x20) err("control character in string");
      if (c !== 0x5c) {
        i++;
        continue;
      }
      out += text.slice(start, i);
      const e = text[i + 1];
      i += 2;
      switch (e) {
        case '"': out += '"'; break;
        case "\\": out += "\\"; break;
        case "/": out += "/"; break;
        case "b": out += "\b"; break;
        case "f": out += "\f"; break;
        case "n": out += "\n"; break;
        case "r": out += "\r"; break;
        case "t": out += "\t"; break;
        case "u": {
          const hex = () => {
            const h = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(h)) err("invalid \\u escape");
            i += 4;
            return parseInt(h, 16);
          };
          const u = hex();
          if (u >= 0xd800 && u <= 0xdbff) {
            if (text[i] !== "\\" || text[i + 1] !== "u") err("lone leading surrogate");
            i += 2;
            const lo = hex();
            if (lo < 0xdc00 || lo > 0xdfff) err("invalid trailing surrogate");
            out += String.fromCharCode(u, lo);
          } else if (u >= 0xdc00 && u <= 0xdfff) {
            err("lone trailing surrogate");
          } else {
            out += String.fromCharCode(u);
          }
          break;
        }
        default:
          err("invalid escape");
      }
      start = i;
    }
  };
  const number = () => {
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) err("invalid number");
    i += m[0].length;
    if (plain) {
      const n = Number(m[0]);
      if (!Number.isFinite(n)) err("number out of range");
      return n;
    }
    if (m[2] === undefined && m[3] === undefined) {
      const big = BigInt(m[0]);
      if (m[0].startsWith("-") ? big < 0n && big >= I64_MIN : big <= U64_MAX) {
        return new SadNumber(big.toString());
      }
    }
    // serde_json holds anything else as an f64, whose text form differs from
    // JavaScript's: refused rather than re-serialized wrongly.
    return fail(`JSON number ${m[0]} is not an integer this implementation supports`, "unsupported");
  };
  const value = (depth) => {
    ws();
    const c = text[i];
    if (c === "{" || c === "[") {
      if (depth + 1 >= MAX_JSON_DEPTH) err("recursion limit exceeded");
      i++;
      if (c === "[") {
        const out = [];
        ws();
        if (text[i] === "]") {
          i++;
          return out;
        }
        for (;;) {
          out.push(value(depth + 1));
          ws();
          if (text[i] === ",") i++;
          else if (text[i] === "]") {
            i++;
            return out;
          } else err("expected , or ]");
        }
      }
      const out = plain ? {} : new Map();
      ws();
      if (text[i] === "}") {
        i++;
        return out;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') err("expected a member name");
        const key = string();
        ws();
        if (text[i] !== ":") err("expected :");
        i++;
        const v = value(depth + 1);
        if (plain) {
          // serde_json::Value keeps the last of a repeated member.
          Object.defineProperty(out, key, { value: v, enumerable: true, writable: true, configurable: true });
        } else {
          if (out.has(key)) fail("duplicate member in a KERI message", "json");
          out.set(key, v);
        }
        ws();
        if (text[i] === ",") i++;
        else if (text[i] === "}") {
          i++;
          return out;
        } else err("expected , or }");
      }
    }
    if (c === '"') return string();
    if (c === "t") return literal("true", true);
    if (c === "f") return literal("false", false);
    if (c === "n") return literal("null", null);
    if (c === "-" || (c >= "0" && c <= "9")) return number();
    return err("expected a value");
  };
  const out = value(0);
  ws();
  if (i !== text.length) err("trailing characters");
  return out;
}

/** Serialize a SAD as compact JSON, as `serde_json::to_vec` writes it. */
export function serializeJson(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (value instanceof SadNumber) return value.text;
  if (Array.isArray(value)) return `[${value.map(serializeJson).join(",")}]`;
  if (value instanceof Map) {
    return `{${[...value].map(([k, v]) => `${JSON.stringify(k)}:${serializeJson(v)}`).join(",")}}`;
  }
  return fail(`not a SAD value: ${typeof value}`, "json");
}

// ─── Version strings (affinidi-keri-core `version.rs`) ──────────────────

export const KERI_VER_FULLSIZE = 17;
export const KERI_VER2_FULLSIZE = 19;
const KINDS = new Set(["JSON", "CBOR", "MGPK", "CESR"]);

/**
 * @typedef {Object} Version
 * @property {string} protocol
 * @property {number} major
 * @property {number} minor
 * @property {"JSON"|"CBOR"|"MGPK"|"CESR"} kind
 * @property {number} size
 * @property {[number, number]|null} genus
 */

function parseProtocol(p) {
  if (!/^[A-Z]{4}$/.test(p)) fail(`invalid protocol: ${JSON.stringify(p)}`, "validation");
  return p;
}

function kindOf(tag) {
  if (!KINDS.has(tag)) fail(`unknown serialization kind: ${tag}`, "validation");
  return tag;
}

function hexDigit(c) {
  return /^[0-9a-fA-F]$/.test(c) ? parseInt(c, 16) : null;
}

function b64Small(text, what) {
  const v = b64ToInt(text);
  if (v > 255n) fail(`${what} ${v} is out of range`, "validation");
  return Number(v);
}

/**
 * Parse a version string, in either form (`Version::parse_str`).
 *
 * @param {string} vs
 * @returns {Version}
 */
export function parseVersionString(vs) {
  const bytes = utf8(vs);
  if (bytes.length >= KERI_VER2_FULLSIZE && bytes[18] === 0x2e && bytes.subarray(0, 19).every((b) => b < 0x80)) {
    return parseV2(vs.slice(0, 19));
  }
  return parseV1(bytes);
}

function parseV1(bytes) {
  if (bytes.length < KERI_VER_FULLSIZE) {
    fail(`version string too short: ${bytes.length} chars (need ${KERI_VER_FULLSIZE})`, "validation");
  }
  if (!bytes.subarray(0, 17).every((b) => b < 0x80)) {
    fail("version string contains non-ASCII bytes", "validation");
  }
  const vs = String.fromCharCode(...bytes.subarray(0, 17));
  const protocol = parseProtocol(vs.slice(0, 4));
  const major = hexDigit(vs[4]);
  const minor = hexDigit(vs[5]);
  if (major === null) fail(`invalid major version digit: ${vs[4]}`, "validation");
  if (minor === null) fail(`invalid minor version digit: ${vs[5]}`, "validation");
  if (major > 1) fail(`a version 1 string cannot name major version ${major}`, "validation");
  const kind = kindOf(vs.slice(6, 10));
  if (kind === "CESR") fail("native CESR serialization does not exist in version 1", "validation");
  const size = parseUnsigned(vs.slice(10, 16), 16);
  if (size === null) fail(`invalid hex size: ${vs.slice(10, 16)}`, "validation");
  if (vs[16] !== "_") fail(`expected '_' terminator at position 16, got '${vs[16]}'`, "validation");
  return { protocol, major, minor, kind, size: Number(size), genus: null };
}

function parseV2(vs) {
  const protocol = parseProtocol(vs.slice(0, 4));
  const major = b64Small(vs.slice(4, 5), "protocol major");
  const minor = b64Small(vs.slice(5, 7), "protocol minor");
  const genusMajor = b64Small(vs.slice(7, 8), "genus major");
  const genusMinor = b64Small(vs.slice(8, 10), "genus minor");
  if (major !== 2) fail(`a version 2 string must name protocol major version 2, not ${major}`, "validation");
  if (genusMajor !== 2) fail(`a version 2 string must name genus major version 2, not ${genusMajor}`, "validation");
  const kind = kindOf(vs.slice(10, 14));
  const size = Number(b64ToInt(vs.slice(14, 18)));
  return { protocol, major, minor, kind, size, genus: [genusMajor, genusMinor] };
}

/**
 * Parse the version string at the start of `data` (`Version::parse`).
 *
 * @param {Uint8Array} data
 * @returns {Version}
 */
export function parseVersionBytes(data) {
  const v1 = data.length >= KERI_VER_FULLSIZE && data[16] === 0x5f;
  const v2 = data.length >= KERI_VER2_FULLSIZE && data[18] === 0x2e;
  if (v1 && v2) fail("version string has both a version 1 and a version 2 terminator", "validation");
  if (!v1 && !v2) fail("no version string", "validation");
  const len = v1 ? KERI_VER_FULLSIZE : KERI_VER2_FULLSIZE;
  const head = data.subarray(0, len);
  if (!head.every((b) => b < 0x80)) fail("version string contains non-ASCII bytes", "validation");
  return parseVersionString(String.fromCharCode(...head));
}

/** The version string for a version (`Version::to_version_string`). */
export function versionString(v) {
  if (v.major >= 2) {
    const [gm, gn] = v.genus ?? [2, 0];
    return `${v.protocol}${intToB64(v.major, 1)}${intToB64(v.minor, 2)}${intToB64(gm, 1)}${intToB64(gn, 2)}${v.kind}${intToB64(v.size, 4)}.`;
  }
  return `${v.protocol}${v.major.toString(16)}${v.minor.toString(16)}${v.kind}${v.size.toString(16).padStart(6, "0").slice(-6)}_`;
}

/** The protocol major version a message's `v` field names. */
export function protocolMajor(sad) {
  const vs = str(get(sad, "v"));
  if (vs === undefined) fail("missing field v", "validation");
  return parseVersionString(vs).major;
}

// ─── Digests ────────────────────────────────────────────────────────────

const DIGESTS = {
  E: (d) => blake3(d),
  F: (d) => blake2b(d, { dkLen: 32 }),
  G: (d) => blake2s(d),
  H: (d) => sha3_256(d),
  I: (d) => sha256(d),
  "0D": (d) => blake3(d, { dkLen: 64 }),
  "0E": (d) => blake2b(d),
  "0F": (d) => sha3_512(d),
  "0G": (d) => sha512(d),
};

/** Whether `code` is a digest code (affinidi-keri-crypto `Diger`). */
export function isDigestCode(code) {
  return Object.hasOwn(DIGESTS, code);
}

/** The qb64 digest of `data` under `code` (`Diger::from_data(...).qb64()`). */
export function digest(code, data) {
  const fn = DIGESTS[code];
  if (!fn) fail(`unsupported digest code: ${code}`, "crypto");
  return matterQb64(code, fn(data));
}

/** Whether qb64 digest `qb64` is the digest of `data` (`Diger::verify`). */
export function digestMatches(qb64, data) {
  const m = matterFromQb64(qb64);
  if (!isDigestCode(m.code)) fail(`unsupported digest code: ${m.code}`, "crypto");
  const raw = DIGESTS[m.code](data);
  if (raw.length !== m.raw.length) return false;
  let diff = 0;
  for (let i = 0; i < raw.length; i++) diff |= raw[i] ^ m.raw[i];
  return diff === 0;
}

// ─── Matter (affinidi-cesr `matter.rs` / `tables.rs`) ───────────────────

/** First character to hard size (`tables::hardage`). */
export function hardage(c) {
  if (/^[A-Za-z]$/.test(c)) return 1;
  if (c === "0" || c === "4" || c === "5" || c === "6") return 2;
  if (c === "1" || c === "2" || c === "3" || c === "7" || c === "8" || c === "9") return 4;
  if (c === "-") return 2;
  return null;
}

// [hs, ss, fs]; fs 0 is variable size.
const MATTER = new Map(
  Object.entries({
    B: [1, 0, 44], D: [1, 0, 44], E: [1, 0, 44], F: [1, 0, 44], G: [1, 0, 44], H: [1, 0, 44],
    I: [1, 0, 44], J: [1, 0, 24], K: [1, 0, 44], L: [1, 0, 24], C: [1, 0, 44], A: [1, 0, 44],
    "1AAA": [4, 0, 48], "1AAB": [4, 0, 48], "1AAC": [4, 0, 80], "1AAD": [4, 0, 80],
    "1AAE": [4, 0, 156], "1AAF": [4, 0, 8], "1AAG": [4, 0, 36], "1AAI": [4, 0, 48],
    "1AAJ": [4, 0, 48], "1AAH": [4, 0, 92], "1AAK": [4, 0, 92], "1AAL": [4, 0, 92],
    "1AAM": [4, 0, 92],
    "0A": [2, 0, 24], "0B": [2, 0, 88], "0C": [2, 0, 88], "0D": [2, 0, 88], "0E": [2, 0, 88],
    "0F": [2, 0, 88], "0G": [2, 0, 88], "0I": [2, 0, 88],
    "4A": [2, 2, 0], "4B": [2, 2, 0], "5A": [2, 2, 0], "5B": [2, 2, 0], "6A": [2, 2, 0],
    "6B": [2, 2, 0], "7AAA": [4, 4, 0], "7AAB": [4, 4, 0], "8AAA": [4, 4, 0], "8AAB": [4, 4, 0],
    "9AAA": [4, 4, 0], "9AAB": [4, 4, 0],
  }),
);

/** The sizes of a Matter code as `affinidi-cesr` knows it, or undefined. */
export function matterSizage(code) {
  const s = MATTER.get(code);
  return s && { hs: s[0], ss: s[1], fs: s[2] };
}

function leadOf(hs) {
  return hs === 1 ? 1 : hs === 2 ? 2 : hs === 4 ? 3 : 0;
}

/**
 * Read a primitive (`Matter::from_qb64`). As in `affinidi-cesr`, only the
 * first `fs` characters are read and anything after them is ignored; callers
 * that need a whole primitive compare lengths themselves.
 *
 * @param {string} qb64
 * @returns {{ code: string, raw: Uint8Array, fs: number }}
 */
export function matterFromQb64(qb64) {
  if (typeof qb64 !== "string" || qb64.length === 0) fail("empty input", "crypto");
  if (!isAscii(qb64)) fail("invalid character", "crypto");
  const hs = hardage(qb64[0]);
  if (hs === null) fail(`unknown code ${qb64[0]}`, "crypto");
  if (qb64.length < hs) fail("unexpected end", "crypto");
  const code = qb64.slice(0, hs);
  const s = matterSizage(code);
  if (!s) fail(`unknown code ${code}`, "crypto");
  if (s.fs > 0) {
    if (qb64.length < s.fs) fail("unexpected end", "crypto");
    const all = b64Decode(qb64.slice(0, s.fs));
    const lead = leadOf(s.hs);
    if (all.length <= lead) fail("invalid raw size", "crypto");
    return { code, raw: all.slice(lead), fs: s.fs };
  }
  if (qb64.length < s.hs + s.ss) fail("unexpected end", "crypto");
  const count = Number(b64ToInt(qb64.slice(s.hs, s.hs + s.ss)));
  const fs = s.hs + s.ss + count * 4;
  if (qb64.length < fs) fail("unexpected end", "crypto");
  const all = b64Decode(qb64.slice(s.hs + s.ss, fs));
  let lead = 0;
  while (lead < 2 && lead < all.length && all[lead] === 0) lead++;
  return { code, raw: all.slice(lead), fs };
}

/** Encode a fixed-size primitive (`Matter::new(code, raw)?.qb64()`). */
export function matterQb64(code, raw) {
  const s = matterSizage(code);
  if (!s) fail(`unknown code ${code}`, "crypto");
  if (s.fs === 0) fail(`variable-size code ${code} is not supported here`, "crypto");
  const total = (s.fs * 3) / 4;
  const expected = total - leadOf(s.hs);
  if (raw.length !== expected) fail(`invalid raw size: expected ${expected}, got ${raw.length}`, "crypto");
  const ls = (3 - (raw.length % 3)) % 3;
  const padded = new Uint8Array(ls + raw.length);
  padded.set(raw, ls);
  const encoded = b64Encode(padded);
  const cs = s.fs - s.hs;
  if (encoded.length < cs) fail("invalid raw size", "crypto");
  return code + encoded.slice(encoded.length - cs);
}

// Full sizes of fixed-size codes `affinidi-cesr` does not know but KERI
// attachments carry (affinidi-keri-core `parser::extra_matter_size`).
const EXTRA_MATTER = new Map(
  Object.entries({
    M: 4, "0H": 8, R: 8, N: 12, S: 16, T: 20, U: 24,
    a: 44, "1AAP": 4, "0J": 4, "0K": 4, X: 4, "0L": 8, "0M": 8, Y: 8, "1AAN": 12,
  }),
);

/**
 * The qb64 of the fixed-size primitive at the head of `text`, and its length
 * (affinidi-keri-core `parser::parse_matter_qb64`).
 */
export function readAttachmentMatter(text, name) {
  if (!text.length) fail(`empty data for ${name}`);
  const hs = hardage(text[0]);
  if (hs === null) fail(`unknown hardage for char '${text[0]}' in ${name}`);
  if (text.length < hs) fail(`truncated ${name} code`);
  const code = text.slice(0, hs);
  const s = matterSizage(code);
  let fs;
  if (s && s.fs > 0) fs = s.fs;
  else if (s) fail(`variable-length ${name} not supported in attachment couples`);
  else {
    fs = EXTRA_MATTER.get(code);
    if (fs === undefined) fail(`unknown matter code: ${code} for ${name}`);
  }
  if (text.length < fs) fail(`truncated ${name}: need ${fs}, have ${text.length}`);
  return [text.slice(0, fs), fs];
}

// ─── Indexer (affinidi-cesr `indexer.rs`) ───────────────────────────────

const INDEXER = new Map([
  ...["A", "B", "C", "D", "E", "F"].map((c) => [c, { hs: 1, ss: 1, fs: 88, os: 0, rs: 64 }]),
  ...["0A", "0B"].map((c) => [c, { hs: 2, ss: 2, fs: 156, os: 1, rs: 114 }]),
  ...["2A", "2B", "2C", "2D", "2E", "2F"].map((c) => [c, { hs: 2, ss: 4, fs: 92, os: 2, rs: 64 }]),
  ...["3A", "3B"].map((c) => [c, { hs: 2, ss: 6, fs: 160, os: 3, rs: 114 }]),
]);
const CURRENT_ONLY = new Set(["B", "D", "F", "0B", "2B", "2D", "2F", "3B"]);

/**
 * @typedef {Object} Siger
 * @property {string} code
 * @property {number} index
 * @property {number|null} ondex
 * @property {Uint8Array} raw
 */

/**
 * Read one indexed signature at the head of `text` (affinidi-keri-core
 * `parser::parse_indexed_sig`, `Indexer::from_qb64`, `Indexer::new`).
 *
 * @returns {[Siger, number]}
 */
export function readIndexedSig(text) {
  if (!text.length) fail("empty data for indexed sig");
  const c = text[0];
  const hs = /^[A-Za-z]$/.test(c) ? 1 : c >= "0" && c <= "4" ? 2 : null;
  if (hs === null) fail(`unknown hardage for char '${c}' in indexed sig`);
  if (hs > text.length) fail("truncated indexer code");
  const code = text.slice(0, hs);
  const s = INDEXER.get(code);
  if (!s) fail(`unknown indexer code: ${code}`);
  if (s.fs > text.length) fail(`truncated indexed sig: need ${s.fs}, have ${text.length}`);
  const qb64 = text.slice(0, s.fs);
  const ms = s.ss - s.os;
  const index = Number(b64ToInt(qb64.slice(hs, hs + ms)));
  const ondexChars = qb64.slice(hs + ms, hs + s.ss);
  let ondex;
  if (CURRENT_ONLY.has(code)) {
    if (s.os > 0 && b64ToInt(ondexChars) !== 0n) {
      fail(`failed to parse indexer: current-only code ${code} carries a non-zero ondex`);
    }
    ondex = null;
  } else if (s.os > 0) {
    ondex = Number(b64ToInt(ondexChars));
  } else {
    ondex = index;
  }
  const cs = s.hs + s.ss;
  const all = b64Decode("A".repeat(cs) + qb64.slice(cs, s.fs));
  if (all.length < s.rs) fail("failed to parse indexer: invalid raw size");
  const raw = all.slice(all.length - s.rs);
  return [{ code, index, ondex, raw }, s.fs];
}

// ─── Counters (affinidi-keri-core `counter_table.rs`) ───────────────────

/**
 * Read the counter at the head of `text`.
 *
 * @param {string} text
 * @returns {{ code: string, count: number, size: number }}
 */
export function readCounter(text) {
  if (text[0] !== "-") fail("a counter starts with '-'");
  if (text.length < 2) fail("truncated counter");
  const second = text[1];
  let hs;
  let ss;
  if (second === "-" || second === "0") [hs, ss] = [3, 5];
  else if (second === "_") [hs, ss] = [5, 3];
  else if (/^[A-Za-z]$/.test(second)) [hs, ss] = [2, 2];
  else fail(`no counter code starts with '-${second}'`);
  const fs = hs + ss;
  if (text.length < fs) fail(`truncated counter: need ${fs} characters, have ${text.length}`);
  const head = text.slice(0, fs);
  if (!isAscii(head)) fail("counter is not ASCII");
  let count;
  try {
    count = Number(b64ToInt(head.slice(hs)));
  } catch (e) {
    fail(`counter ${JSON.stringify(head)}: ${e.message}`);
  }
  return { code: head.slice(0, hs), count, size: fs };
}

/** The (major, minor) a genus-version counter names, or null. */
export function genusVersion(counter) {
  if (counter.code !== "-_AAA") return null;
  const major = Math.floor(counter.count / 4096);
  const minor = counter.count % 4096;
  if (major > 255 || minor > 255) return null;
  return [major, minor];
}

/** The counter table a genus selects (`CounterTable::for_genus`). */
export function tableForGenus(major) {
  if (major === 1) return "V1";
  if (major === 2) return "V2";
  return fail(`CESR genus version ${major}`, "unsupported");
}

const GROUPS = {
  V1: { A: "ControllerIdxSigs", B: "WitnessIdxSigs", C: "NonTransReceiptCouples", D: "TransReceiptQuadruples", E: "FirstSeenReplayCouples", F: "TransIdxSigGroups", G: "SealSourceCouples", V: "AttachedMaterialQuadlets" },
  V2: { C: "AttachedMaterialQuadlets", K: "ControllerIdxSigs", L: "WitnessIdxSigs", M: "NonTransReceiptCouples", O: "FirstSeenReplayCouples", S: "SealSourceCouples", X: "TransIdxSigGroups", a: "BlindedStateQuadruples" },
};

/** What a counter code means in a table (`GroupKind::classify`), or null. */
export function classify(code, table) {
  let base;
  if (code.startsWith("--")) base = code.slice(2);
  else if (code.startsWith("-0") && table === "V1") base = code.slice(2);
  else if (code.startsWith("-")) base = code.slice(1);
  else return null;
  return Object.hasOwn(GROUPS[table], base) ? GROUPS[table][base] : null;
}

function countsQuadlets(table, kind) {
  return table === "V2" || kind === "AttachedMaterialQuadlets";
}

// ─── Native CESR bodies (affinidi-keri-core `native.rs`) ─────────────────

const nerr = (m) => fail(`native CESR body: ${m}`);

function fixed(hs, ss, xs, fs, ls) {
  return { hs, ss, xs, fs, ls };
}

const NATIVE_SIZES = {
  K: fixed(1, 0, 0, 76, 0), L: fixed(1, 0, 0, 76, 0), M: fixed(1, 0, 0, 4, 0), N: fixed(1, 0, 0, 12, 0),
  P: fixed(1, 0, 0, 124, 0), R: fixed(1, 0, 0, 8, 0), S: fixed(1, 0, 0, 16, 0), T: fixed(1, 0, 0, 20, 0),
  U: fixed(1, 0, 0, 24, 0), V: fixed(1, 0, 0, 4, 1), W: fixed(1, 0, 0, 4, 0), X: fixed(1, 3, 0, 4, 0),
  Y: fixed(1, 7, 0, 8, 0), Z: fixed(1, 11, 0, 12, 0), b: fixed(1, 3, 0, 8, 0),
  "0A": fixed(2, 0, 0, 24, 0), "0H": fixed(2, 0, 0, 8, 0), "0J": fixed(2, 2, 1, 4, 0), "0K": fixed(2, 2, 0, 4, 0),
  "0L": fixed(2, 6, 1, 8, 0), "0M": fixed(2, 6, 0, 8, 0), "0N": fixed(2, 10, 1, 12, 0), "0O": fixed(2, 10, 0, 12, 0),
  "1AAC": fixed(4, 0, 0, 80, 0), "1AAD": fixed(4, 0, 0, 80, 0), "1AAE": fixed(4, 0, 0, 156, 0),
  "1AAF": fixed(4, 4, 0, 8, 0), "1AAG": fixed(4, 0, 0, 36, 0), "1AAH": fixed(4, 0, 0, 100, 0),
  "1AAN": fixed(4, 8, 0, 12, 0), "1__-": fixed(4, 2, 0, 12, 0), "1___": fixed(4, 0, 0, 8, 0),
  "2__-": fixed(4, 2, 1, 12, 1), "2___": fixed(4, 0, 0, 8, 1), "3__-": fixed(4, 2, 0, 12, 2),
  "3___": fixed(4, 0, 0, 8, 2),
};

/** keripy's `Matter.Sizes`. */
function sizes(code) {
  if (["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "O", "Q", "a"].includes(code)) return fixed(1, 0, 0, 44, 0);

  if (Object.hasOwn(NATIVE_SIZES, code)) return NATIVE_SIZES[code];
  if (["0B", "0C", "0D", "0E", "0F", "0G", "0I"].includes(code)) return fixed(2, 0, 0, 88, 0);
  if (["1AAA", "1AAB", "1AAI", "1AAJ"].includes(code)) return fixed(4, 0, 0, 48, 0);
  if (["1AAK", "1AAL", "1AAM", "1AAO", "1AAP"].includes(code)) return fixed(4, 0, 0, 4, 0);
  const family = (c) => /^[A-FH]$/.test(c);
  if (code.length === 2 && code[0] >= "4" && code[0] <= "6" && family(code[1])) {
    return { hs: 2, ss: 2, xs: 0, fs: null, ls: code.charCodeAt(0) - 0x34 };
  }
  if (code.length === 4 && code[0] >= "7" && code[0] <= "9" && code[1] === "A" && code[2] === "A" && family(code[3])) {
    return { hs: 4, ss: 4, xs: 0, fs: null, ls: code.charCodeAt(0) - 0x37 };
  }
  return null;
}

function hardSize(c) {
  if (/^[A-Za-z]$/.test(c)) return 1;
  if (c === "0" || c === "4" || c === "5" || c === "6") return 2;
  if (c === "1" || c === "2" || c === "3" || c === "7" || c === "8" || c === "9") return 4;
  return null;
}

/** Read the primitive at the head of `buf`, as keripy's `Matter._exfil`. */
function readMatter(buf) {
  if (!buf.length) nerr("a primitive was expected");
  if (buf[0] === "-") nerr("a counter where a primitive was expected");
  const hs = hardSize(buf[0]);
  if (hs === null) nerr(`no primitive code starts with ${JSON.stringify(buf[0])}`);
  if (buf.length < hs) nerr("truncated primitive");
  const hard = buf.slice(0, hs);
  const s = sizes(hard);
  if (!s) nerr(`unknown primitive code ${JSON.stringify(hard)}`);
  const cs = s.hs + s.ss;
  if (buf.length < cs) nerr("truncated primitive");
  const softAll = buf.slice(s.hs, cs);
  if (!isB64(softAll)) nerr("primitive soft part is not Base64");
  const xtra = softAll.slice(0, s.xs);
  const soft = softAll.slice(s.xs);
  if ([...xtra].some((c) => c !== "_")) nerr(`invalid prepad on ${JSON.stringify(hard)}`);
  const fs = s.fs ?? Number(b64ToInt(soft)) * 4 + cs;
  if (buf.length < fs) nerr("truncated primitive");
  const full = buf.slice(0, fs);
  if (!isB64(full.slice(cs))) nerr(`${JSON.stringify(hard)} material is not Base64`);
  const ps = cs % 4;
  let paw;
  try {
    paw = b64Decode("A".repeat(ps) + full.slice(cs));
  } catch (e) {
    nerr(`${JSON.stringify(hard)}: ${e.message}`);
  }
  const lead = ps + s.ls;
  if (paw.length < lead || paw.subarray(0, lead).some((b) => b !== 0)) nerr(`${JSON.stringify(hard)} has nonzero pad bits`);
  const raw = paw.slice(lead);
  if (raw.length + s.ls !== Math.floor(((fs - cs) * 3) / 4)) nerr(`${JSON.stringify(hard)} is improperly qualified`);
  return [{ code: hard, soft, raw, qb64: full }, fs];
}

/** Encode a primitive, as keripy's `Matter(raw=, code=, soft=).qb64`. */
function encodeMatter(code, soft, raw) {
  const s = sizes(code);
  if (!s) nerr(`unknown primitive code ${JSON.stringify(code)}`);
  if (s.fs === null) {
    const family = code[code.length - 1];
    const ls = (3 - (raw.length % 3)) % 3;
    const size = (raw.length + ls) / 3;
    let head;
    let ss;
    if (size < 64 * 64) [head, ss] = [`${"456"[ls]}${family}`, 2];
    else if (size < 64 ** 4) [head, ss] = [`${"789"[ls]}AA${family}`, 4];
    else nerr("primitive too large");
    const padded = new Uint8Array(ls + raw.length);
    padded.set(raw, ls);
    return `${head}${intToB64(size, ss)}${b64Encode(padded)}`;
  }
  if (soft.length !== s.ss - s.xs || !isB64(soft)) nerr(`invalid soft part ${JSON.stringify(soft)} for ${JSON.stringify(code)}`);
  const cs = s.hs + s.ss;
  const ps = (3 - ((raw.length + s.ls) % 3)) % 3;
  if (ps !== cs % 4) nerr(`raw size ${raw.length} does not fit ${JSON.stringify(code)}`);
  const padded = new Uint8Array(ps + s.ls + raw.length);
  padded.set(raw, ps + s.ls);
  const out = `${code}${"_".repeat(s.xs)}${soft}${b64Encode(padded).slice(ps)}`;
  if (out.length !== s.fs) nerr(`raw size ${raw.length} does not fit ${JSON.stringify(code)}`);
  return out;
}

function isWholePrimitive(text) {
  try {
    const [m, n] = readMatter(text);
    return n === text.length ? m : null;
  } catch {
    return null;
  }
}

const DIG = ["E", "F", "G", "H", "I", "0D", "0E", "0F", "0G"];
const PRE = ["B", "D", "E", "F", "G", "H", "I", "0D", "0E", "0F", "0G", "1AAA", "1AAB", "1AAC", "1AAD", "1AAE", "1AAI", "1AAJ"];
const NONCE = ["1AAP", "0A", "a", "E", "F", "G", "H", "I", "0D", "0E", "0F", "0G"];
const NUM = ["M", "0H", "R", "N", "S", "T", "0A", "U"];
const TAG = ["0J", "0K", "X", "1AAF", "0L", "0M", "Y", "1AAN", "0N", "0O", "Z"];
const TRAITS = ["EO", "DND", "RB", "NB", "NRB", "DID"];
const EMPTY = "1AAP";
const ESCAPE = "1AAO";
const NULL = "1AAK";
const NO = "1AAL";
const YES = "1AAM";

const isVariable = (code) => {
  const s = sizes(code);
  return Boolean(s) && s.fs === null;
};
const isBext = (code) => isVariable(code) && code.endsWith("A");
const isTexter = (code) => isVariable(code) && code.endsWith("B");
const isDecimal = (code) => isVariable(code) && code.endsWith("H");
const isLabel = (code) => code === EMPTY || TAG.includes(code) || isBext(code) || isTexter(code) || code === "V" || code === "W";
const isEscaped = (code) => isLabel(code) || [ESCAPE, NULL, NO, YES].includes(code) || isDecimal(code);

function readClass(buf, cls, what) {
  const [m, n] = readMatter(buf);
  if (!cls.includes(m.code)) nerr(`${JSON.stringify(m.code)} is not a valid ${what} code`);
  return [m, buf.slice(n)];
}

function verbatimClass(qb64, cls, what) {
  const m = isWholePrimitive(qb64);
  if (m && cls.includes(m.code)) return qb64;
  return nerr(`${JSON.stringify(qb64)} is not a valid ${what}`);
}

function numh(raw) {
  const hex = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
  const trimmed = hex.replace(/^0+/, "");
  return trimmed === "" ? "0" : trimmed;
}

function encodeNumber(hex) {
  if (!/^[0-9a-fA-F]*$/.test(hex)) nerr(`${JSON.stringify(hex)} is not a hex number`);
  const digits = hex.replace(/^0+/, "");
  const padded = digits.length % 2 === 1 ? `0${digits}` : digits;
  const bytes = [];
  for (let i = 0; i < padded.length; i += 2) bytes.push(parseInt(padded.slice(i, i + 2), 16));
  const pick = [["M", 2], ["R", 5], ["N", 8], ["S", 11], ["T", 14], ["U", 17]].find(([, size]) => bytes.length <= size);
  if (!pick) nerr(`${JSON.stringify(hex)} is too large for a Number`);
  const raw = new Uint8Array(pick[1]);
  raw.set(bytes, pick[1] - bytes.length);
  return encodeMatter(pick[0], "", raw);
}

function readNumber(buf) {
  const [m, rest] = readClass(buf, NUM, "Number");
  return [numh(m.raw), rest];
}

/**
 * The raw bytes of a whole CESR number primitive (`native::number_raw`): a
 * 1.x `Seqner` (`0A`) or a 2.x `Number`.
 */
export function numberRaw(qb64) {
  const m = isWholePrimitive(qb64);
  if (m && NUM.includes(m.code)) return m.raw;
  return nerr(`${JSON.stringify(qb64)} is not a CESR number`);
}

function bextRawify(bext, escapive) {
  if (!isB64(bext)) nerr(`${JSON.stringify(bext)} is not Base64`);
  let text = bext;
  let ws = (4 - (text.length % 4)) % 4;
  if (escapive && ((text.startsWith("A") && ws <= 1) || text.startsWith("-"))) {
    text = `-${text}`;
    ws = (4 - (text.length % 4)) % 4;
  }
  const base = "A".repeat(ws) + text;
  const ls = (3 - (text.length % 4)) % 3;
  return b64Decode(base).slice(ls);
}

function bextDerawify(raw, code, escapive) {
  const ls = sizes(code)?.ls ?? 0;
  const lead = new Uint8Array(ls + raw.length);
  lead.set(raw, ls);
  const bext = b64Encode(lead);
  const ws = ls === 0 ? (bext.startsWith("A") ? 1 : 0) : (ls + 1) % 4;
  let out = bext.slice(ws);
  if (escapive && out.startsWith("-")) out = out.slice(1);
  return out;
}

function encodeText(text) {
  const bytes = utf8(text);
  if (isB64(text)) {
    if (text.length === 0) return encodeMatter(EMPTY, "", new Uint8Array(0));
    if (text.length <= TAG.length) return encodeMatter(TAG[text.length - 1], text, new Uint8Array(0));
    return encodeMatter("4A", "", bextRawify(text, true));
  }
  if (bytes.length === 1) return encodeMatter("V", "", bytes);
  if (bytes.length === 2) return encodeMatter("W", "", bytes);
  return encodeMatter("4B", "", bytes);
}

function labelText(m) {
  if (!isLabel(m.code)) nerr(`${JSON.stringify(m.code)} is not a label code`);
  if (TAG.includes(m.code)) return m.soft;
  if (isBext(m.code)) return bextDerawify(m.raw, m.code, true);
  try {
    return fromUtf8(m.raw);
  } catch {
    return nerr("label is not UTF-8");
  }
}

function isAttributeLabel(label) {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(label);
}

function readLabel(buf, strict) {
  const [m, n] = readMatter(buf);
  const text = labelText(m);
  if (strict && !isAttributeLabel(text)) nerr(`invalid field label ${JSON.stringify(text)}`);
  return [text, buf.slice(n)];
}

function readDater(buf) {
  const [m, n] = readMatter(buf);
  if (m.code !== "1AAG") nerr(`${JSON.stringify(m.code)} is not a date-time code`);
  const dts = m.qb64.slice(4).replace(/[cdp]/g, (c) => ({ c: ":", d: ".", p: "+" })[c]);
  return [dts, buf.slice(n)];
}

function encodeDater(dts) {
  const qb64 = `1AAG${dts.replace(/[:.+]/g, (c) => ({ ":": "c", ".": "d", "+": "p" })[c])}`;
  const m = isWholePrimitive(qb64);
  if (m && m.code === "1AAG") return qb64;
  return nerr(`${JSON.stringify(dts)} is not a CESR date-time`);
}

function readPather(buf) {
  const [m, n] = readMatter(buf);
  let path;
  if (isBext(m.code)) {
    let p = bextDerawify(m.raw, m.code, false);
    if (p.startsWith("--")) p = p.slice(2);
    path = p.split("-").join("/");
  } else if (isTexter(m.code)) {
    try {
      path = fromUtf8(m.raw);
    } catch {
      nerr("path is not UTF-8");
    }
  } else {
    nerr(`${JSON.stringify(m.code)} is not a path code`);
  }
  return [path, buf.slice(n)];
}

function encodePather(path) {
  const parts = path.includes("/") ? path.split("/") : path.split("-");
  const bextable = parts.every((p) => /^[A-Za-z0-9_]*$/.test(p));
  if (bextable) {
    let joined = parts.join("-");
    if (joined.includes("--")) nerr(`path ${JSON.stringify(path)} has empty parts`);
    const ws = (4 - (joined.length % 4)) % 4;
    if (joined.startsWith("A") && ws <= 1) joined = `--${joined}`;
    return encodeMatter("4A", "", bextRawify(joined, false));
  }
  const joined = parts.join("/");
  if (joined.includes("//")) nerr(`path ${JSON.stringify(path)} has empty parts`);
  return encodeMatter("4B", "", utf8(joined));
}

function readVerser(buf) {
  const [m, n] = readMatter(buf);
  if (m.code !== "Y" && m.code !== "0O") nerr(`${JSON.stringify(m.code)} is not a version code`);
  const tag = m.soft;
  const ver = (b) => {
    const major = Number(b64ToInt(b.slice(0, 1)));
    const minor = Number(b64ToInt(b.slice(1, 3)));
    if (minor > 255) nerr("a minor version above 255");
    return [major, minor];
  };
  const protocol = tag.slice(0, 4);
  const [major, minor] = ver(tag.slice(4, 7));
  const genus = tag.length === 10 ? ver(tag.slice(7, 10)) : null;
  return [{ protocol, major, minor, genus }, buf.slice(n)];
}

function encodeVerser(v) {
  const ver = (major, minor) => `${intToB64(major, 1)}${intToB64(minor, 2)}`;
  let tag = `${v.protocol}${ver(v.major, v.minor)}`;
  if (v.genus) tag += ver(v.genus[0], v.genus[1]);
  if (tag.length === 7) return encodeMatter("Y", tag, new Uint8Array(0));
  if (tag.length === 10) return encodeMatter("0O", tag, new Uint8Array(0));
  return nerr(`protocol ${JSON.stringify(v.protocol)} is not four characters`);
}

function readTag(buf) {
  const [m, n] = readMatter(buf);
  if (!TAG.includes(m.code)) nerr(`${JSON.stringify(m.code)} is not a tag code`);
  return [m.soft, buf.slice(n)];
}

function encodeTag(tag) {
  if (tag.length === 0 || tag.length > TAG.length) nerr(`${JSON.stringify(tag)} cannot be a tag`);
  return encodeMatter(TAG[tag.length - 1], tag, new Uint8Array(0));
}

function readNonce(buf) {
  const [m, rest] = readClass(buf, NONCE, "nonce");
  return [m.qb64, rest];
}

function readAcdcNonce(buf) {
  const [m, rest] = readClass(buf, NONCE, "nonce");
  return [m.code === EMPTY ? "" : m.qb64, rest];
}

function encodeAcdcNonce(nonce) {
  return nonce === "" ? encodeMatter(EMPTY, "", new Uint8Array(0)) : verbatimClass(nonce, NONCE, "nonce");
}

// Thresholds (keripy `Tholder`).

function gcd(a, b) {
  return b === 0n ? a : gcd(b, a % b);
}

function weightParse(w) {
  const bad = () => nerr(`invalid weight ${JSON.stringify(w)}`);
  const slash = w.indexOf("/");
  const [n, d] = slash < 0 ? [w, "1"] : [w.slice(0, slash), w.slice(slash + 1)];
  if (!n || !d || !/^[0-9]+$/.test(n) || !/^[0-9]+$/.test(d)) bad();
  const num = BigInt(n);
  const den = BigInt(d);
  if (num >= 2n ** 128n || den >= 2n ** 128n) bad();
  if (den === 0n || num > den) bad();
  let g = gcd(num, den);
  if (g < 1n) g = 1n;
  return { num: num / g, den: den / g };
}

function weightRender(w, sep) {
  return w.num > 0n && w.num < w.den ? `${w.num}${sep}${w.den}` : `${w.num / w.den}`;
}

function atLeastOne(sum) {
  const den = sum.reduce((l, w) => (l / gcd(l, w.den)) * w.den, 1n);
  const num = sum.reduce((acc, w) => acc + w.num * (den / w.den), 0n);
  return num >= den;
}

function checkClauses(clauses) {
  for (const clause of clauses) {
    const top = [];
    for (const e of clause) {
      if (e.nested) {
        if (!atLeastOne(e.nested)) nerr("a nested threshold clause sums to less than 1");
      }
      top.push(e.weight);
    }
    if (!atLeastOne(top)) nerr("a threshold clause sums to less than 1");
  }
}

function readTholder(buf) {
  const [m, n] = readMatter(buf);
  const rest = buf.slice(n);
  if (NUM.includes(m.code)) return [numh(m.raw), rest];
  if (!isBext(m.code)) nerr(`${JSON.stringify(m.code)} is not a threshold code`);
  const bext = bextDerawify(m.raw, m.code, true).replaceAll("s", "/");
  const clauses = bext.split("a").map((c) =>
    c.split("c").map((e) => {
      const k = e.indexOf("k");
      if (k < 0) return { weight: weightParse(e) };
      return { weight: weightParse(e.slice(0, k)), nested: e.slice(k + 1).split("v").map(weightParse) };
    }),
  );
  checkClauses(clauses);
  const sith = clauses.map((clause) =>
    clause.map((e) => (e.nested ? new Map([[weightRender(e.weight, "/"), e.nested.map((x) => weightRender(x, "/"))]]) : weightRender(e.weight, "/"))),
  );
  return [sith.length === 1 ? sith[0] : sith, rest];
}

function encodeTholder(sith) {
  if (typeof sith === "string") return encodeNumber(sith);
  if (!Array.isArray(sith)) nerr("a threshold is a hex number or a list of weights");
  const nested = sith.map((x) => Array.isArray(x));
  let clauses;
  if (nested.every(Boolean)) clauses = sith;
  else if (nested.some(Boolean)) nerr("a threshold mixes clauses and weights");
  else clauses = [sith];
  const parsed = clauses.map((clause) =>
    clause.map((e) => {
      if (typeof e === "string") return { weight: weightParse(e) };
      if (e instanceof Map && e.size === 1) {
        const [k, v] = [...e][0];
        if (!Array.isArray(v)) nerr("a nested threshold clause is a list");
        return {
          weight: weightParse(k),
          nested: v.map((w) => (typeof w === "string" ? weightParse(w) : nerr("weights are strings"))),
        };
      }
      return nerr("invalid threshold element");
    }),
  );
  checkClauses(parsed);
  const bext = parsed
    .map((clause) =>
      clause.map((e) => (e.nested ? `${weightRender(e.weight, "s")}k${e.nested.map((x) => weightRender(x, "s")).join("v")}` : weightRender(e.weight, "s"))).join("c"),
    )
    .join("a");
  return encodeMatter("4A", "", bextRawify(bext, true));
}

// Groups: lists, field maps (keripy `Mapper`) and seals (keripy `Sealer`).

function enclose(selector, body) {
  if (body.length % 4 !== 0) nerr("a group's content is not quadlet aligned");
  const count = body.length / 4;
  if (count < 64 * 64) return `-${selector}${intToB64(count, 2)}${body}`;
  if (count < 64 ** 5) return `--${selector}${intToB64(count, 5)}${body}`;
  return nerr("a group too large to count");
}

function readGroup(buf, selectors) {
  let counter;
  try {
    counter = readCounter(buf);
  } catch (e) {
    nerr(e.message);
  }
  const selector = counter.code.replace(/^-+/, "");
  if (selector.length !== 1 || !selectors.includes(selector)) {
    nerr(`expected a ${JSON.stringify(selectors)} group, found ${JSON.stringify(counter.code)}`);
  }
  const len = counter.count * 4;
  if (buf.length < counter.size + len) nerr("truncated group");
  return [selector, buf.slice(counter.size, counter.size + len), buf.slice(counter.size + len)];
}

const GENERIC_MAP = "I";
const GENERIC_LIST = "J";
const MAX_NATIVE_DEPTH = 128;

function readValue(buf, strict, depth) {
  if (buf[0] === "-") {
    if (depth >= MAX_NATIVE_DEPTH) nerr(`field maps and lists nest deeper than ${MAX_NATIVE_DEPTH}`);
    const [selector, content, rest] = readGroup(buf, [GENERIC_MAP, GENERIC_LIST]);
    if (selector === GENERIC_LIST) {
      const items = [];
      let c = content;
      while (c.length) {
        const [v, r] = readValue(c, strict, depth + 1);
        items.push(v);
        c = r;
      }
      return [items, rest];
    }
    return [readMapContent(content, strict, depth + 1), rest];
  }
  const [m, n] = readMatter(buf);
  const rest = buf.slice(n);
  if (m.code === ESCAPE) {
    const [inner, n2] = readMatter(rest);
    return [inner.qb64, rest.slice(n2)];
  }
  if (m.code === NULL) return [null, rest];
  if (m.code === YES) return [true, rest];
  if (m.code === NO) return [false, rest];
  if (isDecimal(m.code)) return [decimalValue(bextDerawify(m.raw, m.code, false).replaceAll("p", ".")), rest];
  if (isLabel(m.code)) return [labelText(m), rest];
  return [m.qb64, rest];
}

function readMapContent(content, strict, depth) {
  const map = new Map();
  let c = content;
  while (c.length) {
    const [label, r1] = readLabel(c, strict);
    const [value, r2] = readValue(r1, strict, depth);
    // keripy's dict keeps the last of a repeated label, as IndexMap does.
    map.set(label, value);
    c = r2;
  }
  return map;
}

function readMap(buf, strict) {
  const [, content, rest] = readGroup(buf, [GENERIC_MAP]);
  return [readMapContent(content, strict, 1), rest];
}

function decimalValue(dns) {
  // Rust `str::parse::<i64>` / `<u64>`: an optional sign, then digits.
  if (/^[+-]?[0-9]+$/.test(dns)) {
    const big = BigInt(dns);
    if (big >= I64_MIN && big <= U64_MAX) return new SadNumber(big.toString());
  }
  return nerr(`${JSON.stringify(dns)} is not a decimal this implementation supports`);
}

function encodeDecimal(n) {
  const text = n.text.replaceAll(".", "p");
  const ts = text.length % 4;
  const ws = (4 - ts) % 4;
  const ls = (3 - ts) % 3;
  const decoded = b64Decode("A".repeat(ws) + text);
  return encodeMatter("4H", "", decoded.slice(ls));
}

function writeValue(value) {
  if (value === null) return encodeMatter(NULL, "", new Uint8Array(0));
  if (value === true) return encodeMatter(YES, "", new Uint8Array(0));
  if (value === false) return encodeMatter(NO, "", new Uint8Array(0));
  if (value instanceof SadNumber) return encodeDecimal(value);
  if (typeof value === "string") {
    const m = isWholePrimitive(value);
    if (m) return (isEscaped(m.code) ? encodeMatter(ESCAPE, "", new Uint8Array(0)) : "") + value;
    return encodeText(value);
  }
  if (value instanceof Map) return writeMap(value, []);
  if (Array.isArray(value)) return enclose(GENERIC_LIST, value.map(writeValue).join(""));
  return nerr("not a SAD value");
}

function writeMap(map, verbatim) {
  let body = "";
  for (const [label, value] of map) {
    body += encodeText(label);
    body += typeof value === "string" && verbatim.includes(label) ? value : writeValue(value);
  }
  return enclose(GENERIC_MAP, body);
}

const SEALS = [
  ["Q", ["d"]],
  ["R", ["rd"]],
  ["S", ["s", "d"]],
  ["T", ["i", "s", "d"]],
  ["U", ["i"]],
  ["V", ["bi", "d"]],
  ["W", ["t", "d"]],
];

function readSealField(buf, selector, field) {
  if (field === "s") return readNumber(buf);
  if (selector === "W" && field === "t") {
    readVerser(buf);
    const [m, n] = readMatter(buf);
    return [m.qb64, buf.slice(n)];
  }
  if (selector === "W" && field === "d") {
    const [m, r] = readClass(buf, NONCE, "nonce");
    return [m.qb64, r];
  }
  if (field === "i" || field === "bi") {
    const [m, r] = readClass(buf, PRE, "prefix");
    return [m.qb64, r];
  }
  const [m, r] = readClass(buf, DIG, "digest");
  return [m.qb64, r];
}

function writeSealField(selector, field, value) {
  if (typeof value !== "string") nerr(`seal field ${JSON.stringify(field)} is not a string`);
  if (field === "s") return encodeNumber(value);
  if (selector === "W" && field === "t") {
    const [, rest] = readVerser(value);
    if (rest.length) nerr("invalid seal version");
    return value;
  }
  if (selector === "W" && field === "d") return verbatimClass(value, NONCE, "nonce");
  if (field === "i" || field === "bi") return verbatimClass(value, PRE, "prefix");
  return verbatimClass(value, DIG, "digest");
}

function readSeals(content) {
  const selectors = SEALS.map(([c]) => c);
  const seals = [];
  let frame = content;
  while (frame.length) {
    const [selector, group0, rest] = readGroup(frame, selectors);
    const fields = SEALS.find(([c]) => c === selector)[1];
    let group = group0;
    while (group.length) {
      const seal = new Map();
      for (const field of fields) {
        const [value, r] = readSealField(group, selector, field);
        seal.set(field, value);
        group = r;
      }
      seals.push(seal);
    }
    frame = rest;
  }
  return seals;
}

function writeSeals(seals) {
  let frame = "";
  let current = null;
  let group = "";
  for (const seal of seals) {
    if (!(seal instanceof Map)) nerr("a seal is a field map");
    const keys = [...seal.keys()];
    const found = SEALS.find(([, f]) => f.length === keys.length && f.every((x, i) => x === keys[i]));
    if (!found) nerr(`no native seal has the fields ${JSON.stringify(keys)}`);
    const [selector, fields] = found;
    if (current !== selector) {
      if (current !== null) {
        frame += enclose(current, group);
        group = "";
      }
      current = selector;
    }
    for (const field of fields) group += writeSealField(selector, field, seal.get(field));
  }
  if (current !== null) frame += enclose(current, group);
  return enclose(GENERIC_LIST, frame);
}

const KERI_V1_FIELDS = {
  icp: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
  rot: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
  ixn: ["v", "t", "d", "i", "s", "p", "a"],
  dip: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"],
  drt: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
  rct: ["v", "t", "d", "i", "s"],
  qry: ["v", "t", "d", "dt", "r", "rr", "q"],
  rpy: ["v", "t", "d", "dt", "r", "a"],
  pro: ["v", "t", "d", "dt", "r", "rr", "q"],
  bar: ["v", "t", "d", "dt", "r", "a"],
  exn: ["v", "t", "d", "i", "rp", "p", "dt", "r", "q", "a", "e"],
  vcp: ["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"],
  vrt: ["v", "t", "d", "i", "p", "s", "bt", "br", "ba"],
  iss: ["v", "t", "d", "i", "s", "ri", "dt"],
  rev: ["v", "t", "d", "i", "s", "ri", "p", "dt"],
  bis: ["v", "t", "d", "i", "ii", "s", "ra", "dt"],
  brv: ["v", "t", "d", "i", "s", "p", "ra", "dt"],
};

const KERI_V2_FIELDS = {
  icp: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
  rot: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a"],
  ixn: ["v", "t", "d", "i", "s", "p", "a"],
  dip: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"],
  drt: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a"],
  rct: ["v", "t", "d", "i", "s"],
  qry: ["v", "t", "d", "i", "dt", "r", "rr", "q"],
  rpy: ["v", "t", "d", "i", "dt", "r", "a"],
  pro: ["v", "t", "d", "i", "dt", "r", "rr", "q"],
  bar: ["v", "t", "d", "i", "dt", "r", "a"],
  xip: ["v", "t", "d", "u", "i", "ri", "dt", "r", "q", "a"],
  exn: ["v", "t", "d", "i", "ri", "x", "p", "dt", "r", "q", "a"],
};

/** The top-level fields of a KERI message type (`fields::keri_fields`). */
export function keriFields(major, ilk) {
  const table = major === 1 ? KERI_V1_FIELDS : major === 2 ? KERI_V2_FIELDS : null;
  return table && Object.hasOwn(table, ilk) ? table[ilk] : null;
}

/** Check a KERI message's fields are exactly its type's, in order. */
export function checkKeriFields(sad, major, ilk) {
  const expected = keriFields(major, ilk);
  if (!expected) fail(`KERI ${major}.x defines no '${ilk}' message`, "unsupported");
  if (!(sad instanceof Map)) fail("a KERI message is a field map", "validation");
  const got = [...sad.keys()];
  if (got.length !== expected.length || got.some((k, i) => k !== expected[i])) {
    fail(`a KERI ${major}.x '${ilk}' has the fields ${JSON.stringify(expected)}, in that order; this one has ${JSON.stringify(got)}`, "validation");
  }
}

const ACDC_FIELDS = [
  [1, null, { alls: ["v", "d", "u", "i", "ri", "s", "a", "A", "e", "r"], opts: ["u", "ri", "a", "A", "e", "r"] }],
  [2, null, { alls: ["v", "d", "u", "i", "rd", "s", "a", "A", "e", "r"], opts: ["u", "rd", "a", "A", "e", "r"] }],
  [2, "acm", { alls: ["v", "t", "d", "u", "i", "rd", "s", "a", "A", "e", "r"], opts: ["t", "u", "rd", "a", "A", "e", "r"] }],
  [2, "rip", { alls: ["v", "t", "d", "u", "i", "n", "dt"], opts: [] }],
  [2, "bup", { alls: ["v", "t", "d", "rd", "n", "p", "dt", "b"], opts: [] }],
];

/** Check an ACDC message's fields (`fields::check_acdc_fields`). */
export function checkAcdcFields(sad, major, ilk) {
  const name = ilk ?? "bare ACDC";
  const entry = ACDC_FIELDS.find(([m, i]) => m === major && i === (ilk ?? null));
  if (!entry) fail(`ACDC ${major}.x '${name}' messages are not supported`, "unsupported");
  const { alls, opts } = entry[2];
  if (!(sad instanceof Map)) fail("an ACDC message is a field map", "validation");
  const got = [...sad.keys()];
  let cursor = 0;
  for (const label of got) {
    let found = false;
    while (cursor < alls.length) {
      if (alls[cursor++] === label) {
        found = true;
        break;
      }
    }
    if (!found) {
      fail(`an ACDC ${major}.x '${name}' has the fields ${JSON.stringify(alls)}, in that order; this one has ${JSON.stringify(got)}`, "validation");
    }
  }
  for (const required of alls.filter((f) => !opts.includes(f))) {
    if (!got.includes(required)) fail(`an ACDC ${major}.x '${name}' must carry '${required}'`, "validation");
  }
  if (got.includes("a") && got.includes("A")) {
    fail(`an ACDC ${major}.x '${name}' carries both an attribute and an aggregate section`, "validation");
  }
}

const ACDC_FIXED = {
  act: ["v", "t", "d", "u", "i", "rd", "s", "a", "e", "r"],
  acg: ["v", "t", "d", "u", "i", "rd", "s", "A", "e", "r"],
  sch: ["v", "t", "d", "s"],
  att: ["v", "t", "d", "a"],
  agg: ["v", "t", "d", "A"],
  edg: ["v", "t", "d", "e"],
  rul: ["v", "t", "d", "r"],
  rip: ["v", "t", "d", "u", "i", "n", "dt"],
  bup: ["v", "t", "d", "rd", "n", "p", "dt", "b"],
  upd: ["v", "t", "d", "rd", "n", "p", "dt", "td", "ts"],
};
const acdcFixedFields = (ilk) => (Object.hasOwn(ACDC_FIXED, ilk) ? ACDC_FIXED[ilk] : null);

const FIX_BODY = "F";
const MAP_BODY = "G";

/** The size of the native body at the head of `buf` (`native::body_size`). */
function bodySize(buf) {
  const counter = readCounter(buf);
  const selector = counter.code.replace(/^-+/, "");
  if (selector !== "F" && selector !== "G") nerr(`${JSON.stringify(counter.code)} is not a message body group`);
  return counter.size + counter.count * 4;
}

/**
 * Read the native body at the head of `buf` (`native::load`). The body is
 * accepted only if writing it back gives the same text.
 *
 * @param {string} buf - the stream from here, as text
 * @returns {[Map<string, any>, Version, number]}
 */
function nativeLoad(buf) {
  const size = bodySize(buf);
  if (buf.length < size) nerr(`the body needs ${size} bytes, the stream has ${buf.length}`);
  const raw = buf.slice(0, size);
  if (!isAscii(raw)) nerr("a native body is CESR text, which is ASCII");
  const [selector, content] = readGroup(raw, [FIX_BODY, MAP_BODY]);
  const isFixed = selector === FIX_BODY;
  let rest = content;
  if (!isFixed) {
    const [label, r] = readLabel(rest, true);
    if (label !== "v") nerr("a field map body starts with its version");
    rest = r;
  }
  const [ver, r0] = readVerser(rest);
  rest = r0;
  if (ver.major < 2 || (ver.genus && ver.genus[0] < 2)) nerr("native CESR serialization exists only in version 2");
  const version = {
    protocol: ver.protocol,
    major: ver.major,
    minor: ver.minor,
    kind: "CESR",
    size,
    genus: ver.genus ?? [ver.major, ver.minor],
  };
  const vs = versionString(version);
  const sad = new Map();
  if (ver.protocol === "KERI") {
    if (!isFixed) nerr("a KERI message body has fixed fields");
    const [ilk, r] = readTag(rest);
    rest = r;
    const fields = ilk.length === 3 ? keriFields(2, ilk) : null;
    if (!fields) nerr(`unexpected KERI message type ${JSON.stringify(ilk)}`);
    for (const label of fields) {
      let value;
      if (label === "v") value = vs;
      else if (label === "t") value = ilk;
      else [value, rest] = readKeriField(rest, label, ilk);
      sad.set(label, value);
    }
  } else if (ver.protocol === "ACDC") {
    let ilk = null;
    let fields = [];
    if (isFixed) {
      const [t, r] = readTag(rest);
      rest = r;
      ilk = t;
      fields = acdcFixedFields(ilk);
      if (!fields) nerr(`unexpected fixed-field ACDC type ${JSON.stringify(ilk)}`);
    } else {
      sad.set("v", vs);
      let label = null;
      let r = null;
      try {
        [label, r] = readLabel(rest, true);
      } catch {
        label = null;
      }
      if (label === "t") {
        const [t, r2] = readTag(r);
        rest = r2;
        sad.set("t", t);
        ilk = t;
      }
      if (!(ilk === null || ilk === "acm" || ilk === "ace")) nerr(`unexpected field-map ACDC type ${JSON.stringify(ilk)}`);
    }
    let k = 0;
    for (;;) {
      let label;
      if (isFixed) {
        if (k >= fields.length) break;
        label = fields[k++];
      } else {
        if (!rest.length) break;
        [label, rest] = readLabel(rest, true);
      }
      let value;
      if (label === "v" && isFixed) value = vs;
      else if (label === "t" && isFixed) value = ilk ?? "";
      else [value, rest] = readAcdcField(rest, label);
      if (sad.has(label)) nerr(`field ${JSON.stringify(label)} appears twice`);
      sad.set(label, value);
    }
  } else {
    nerr(`unsupported protocol ${JSON.stringify(ver.protocol)}`);
  }
  if (rest.length) nerr("the body has bytes after its last field");
  if (nativeDump(sad, []) !== raw) nerr("the body is not in its canonical encoding");
  return [sad, version, size];
}

function readKeriField(buf, label, ilk) {
  switch (label) {
    case "d":
    case "p":
    case "x": {
      const [m, r] = readClass(buf, DIG, "digest");
      return [m.qb64, r];
    }
    case "u":
      return readNonce(buf);
    case "i":
    case "di":
    case "ri": {
      const [m, r] = readClass(buf, PRE, "prefix");
      return [m.qb64, r];
    }
    case "s":
    case "bt":
      return readNumber(buf);
    case "kt":
    case "nt":
      return readTholder(buf);
    case "k":
    case "n":
    case "b":
    case "ba":
    case "br": {
      const [, content, rest] = readGroup(buf, [GENERIC_LIST]);
      const items = [];
      let c = content;
      while (c.length) {
        const [m, n] = readMatter(c);
        items.push(m.qb64);
        c = c.slice(n);
      }
      return [items, rest];
    }
    case "dt":
      return readDater(buf);
    case "r":
    case "rr":
      return readPather(buf);
    case "c": {
      const [, content, rest] = readGroup(buf, [GENERIC_LIST]);
      const traits = [];
      let c = content;
      while (c.length) {
        const [t, r] = readTag(c);
        if (!TRAITS.includes(t)) nerr(`unknown configuration trait ${JSON.stringify(t)}`);
        traits.push(t);
        c = r;
      }
      return [traits, rest];
    }
    case "a": {
      let counter;
      try {
        counter = readCounter(buf);
      } catch (e) {
        nerr(e.message);
      }
      const sel = counter.code.replace(/^-+/, "");
      if (sel === "I") return readMap(buf, true);
      if (sel === "J") {
        if (!["icp", "ixn", "rot", "dip", "drt"].includes(ilk)) nerr(`a '${ilk}' carries no seal list`);
        const [, content, rest] = readGroup(buf, [GENERIC_LIST]);
        return [readSeals(content), rest];
      }
      return nerr(`\`a\` is a map or a list, not ${JSON.stringify(sel)}`);
    }
    case "q":
      return readMap(buf, true);
    default:
      return nerr(`unsupported KERI field ${JSON.stringify(label)}`);
  }
}

function readAcdcField(buf, label) {
  const section = (b, strict) => {
    if (b[0] === "-") return readMap(b, strict);
    const [m, r] = readClass(b, DIG, "digest");
    return [m.qb64, r];
  };
  switch (label) {
    case "d":
    case "p":
    case "b": {
      const [m, r] = readClass(buf, DIG, "digest");
      return [m.qb64, r];
    }
    case "u":
    case "rd":
    case "td":
      return readAcdcNonce(buf);
    case "i": {
      const [m, r] = readClass(buf, PRE, "prefix");
      return [m.qb64, r];
    }
    case "n":
      return readNumber(buf);
    case "dt":
      return readDater(buf);
    case "ts": {
      const [m, n] = readMatter(buf);
      return [labelText(m), buf.slice(n)];
    }
    case "s":
      return section(buf, false);
    case "a":
    case "e":
    case "r":
      return section(buf, true);
    case "A": {
      if (buf[0] === "-") fail("an expanded aggregate section (`A`) is not supported", "unsupported");
      const [m, r] = readClass(buf, DIG, "digest");
      return [m.qb64, r];
    }
    default:
      return nerr(`unsupported ACDC field ${JSON.stringify(label)}`);
  }
}

/**
 * Write a SAD natively (`native::dump`): a message by its type's codec, any
 * other field map generically. Values of `verbatim` labels are written as
 * their text (a SAID filled with `#`).
 */
export function nativeDump(sad, verbatim) {
  if (!(sad instanceof Map)) nerr("only a field map has a native form");
  let version = null;
  const vs = str(sad.get("v"));
  if (vs !== undefined) {
    try {
      version = parseVersionString(vs);
    } catch {
      version = null;
    }
  }
  if (!version) return writeMap(sad, verbatim);
  if (version.kind !== "CESR") nerr("the message's version string does not name CESR");
  const ilk = str(sad.get("t"));
  let body = "";
  if (version.protocol === "KERI") {
    if (ilk === undefined) nerr("a KERI message has a type");
    if (!keriFields(2, ilk)) nerr(`unexpected KERI message type ${JSON.stringify(ilk)}`);
    for (const [label, value] of sad) body += writeKeriField(label, value, ilk, version);
    return enclose(FIX_BODY, body);
  }
  if (version.protocol === "ACDC") {
    const mapBody = ilk === undefined || ilk === "acm" || ilk === "ace";
    if (!mapBody && !acdcFixedFields(ilk)) nerr(`unexpected ACDC message type ${JSON.stringify(ilk)}`);
    for (const [label, value] of sad) {
      if (mapBody) body += encodeText(label);
      body += writeAcdcField(label, value, version);
    }
    return enclose(mapBody ? MAP_BODY : FIX_BODY, body);
  }
  return nerr(`unsupported protocol ${JSON.stringify(version.protocol)}`);
}

function textOf(label, value) {
  if (typeof value !== "string") nerr(`field ${JSON.stringify(label)} is not a string`);
  return value;
}

function writeKeriField(label, value, ilk, version) {
  switch (label) {
    case "v":
      return encodeVerser(version);
    case "t":
      return encodeTag(textOf(label, value));
    case "d":
    case "i":
    case "p":
    case "u":
    case "di":
    case "ri":
    case "x":
      return textOf(label, value);
    case "s":
    case "bt":
      return encodeNumber(textOf(label, value));
    case "kt":
    case "nt":
      return encodeTholder(value);
    case "k":
    case "n":
    case "b":
    case "ba":
    case "br":
      if (!Array.isArray(value)) nerr(`field ${JSON.stringify(label)} is a list`);
      return enclose(GENERIC_LIST, value.map((item) => textOf(label, item)).join(""));
    case "dt":
      return encodeDater(textOf(label, value));
    case "r":
    case "rr":
      return encodePather(textOf(label, value));
    case "c":
      if (!Array.isArray(value)) nerr('field "c" is a list');
      return enclose(GENERIC_LIST, value.map((item) => encodeTag(textOf(label, item))).join(""));
    case "a":
      if (value instanceof Map) return writeMap(value, []);
      if (Array.isArray(value)) {
        if (!["icp", "ixn", "rot", "dip", "drt"].includes(ilk)) nerr(`a '${ilk}' carries no seal list`);
        return writeSeals(value);
      }
      return nerr("`a` is a map or a list");
    case "q":
      if (value instanceof Map) return writeMap(value, []);
      return nerr("`q` is a map");
    default:
      return nerr(`unsupported KERI field ${JSON.stringify(label)}`);
  }
}

function writeAcdcField(label, value, version) {
  const section = () => {
    if (value instanceof Map) return writeMap(value, []);
    if (typeof value === "string" && value !== "") return verbatimClass(value, DIG, "digest");
    return nerr(`section ${JSON.stringify(label)} is a block or a SAID`);
  };
  switch (label) {
    case "v":
      return encodeVerser(version);
    case "t":
      return encodeTag(textOf(label, value));
    case "d":
    case "i":
    case "p":
    case "b":
      return textOf(label, value);
    case "u":
    case "rd":
    case "td":
      return encodeAcdcNonce(textOf(label, value));
    case "n":
      return encodeNumber(textOf(label, value));
    case "dt":
      return encodeDater(textOf(label, value));
    case "ts":
      return encodeText(textOf(label, value));
    case "s":
    case "a":
    case "e":
    case "r":
      return section();
    case "A":
      if (typeof value === "string" && value !== "") return verbatimClass(value, DIG, "digest");
      return fail("an expanded aggregate section (`A`) is not supported", "unsupported");
    default:
      return nerr(`unsupported ACDC field ${JSON.stringify(label)}`);
  }
}

// ─── SAIDs (affinidi-keri-core `said.rs`) ───────────────────────────────

/**
 * The SAID `label` would have over `sad`, serialized as `kind`
 * (`said::compute_said` on a copy). For an inception whose `i` equals its
 * `d`, `i` is dummied too.
 */
export function computeSaid(sad, label, code, kind) {
  if (!(sad instanceof Map)) fail("SAD must be a JSON object", "validation");
  const s = matterSizage(code);
  if (!s) fail(`unknown digest code: ${code}`, "validation");
  if (s.fs === 0) fail(`digest code ${code} has variable length, cannot compute SAID`, "validation");
  const dummy = "#".repeat(s.fs);
  if (!sad.has(label)) fail(`missing field ${label}`, "validation");
  const selfAddressing = label === "d" && sad.has("i") && sadEqual(sad.get("d"), sad.get("i"));
  const copy = new Map(sad);
  copy.set(label, dummy);
  if (selfAddressing) copy.set("i", dummy);
  let serialized;
  if (kind === "CESR") serialized = utf8(nativeDump(copy, selfAddressing ? [label, "i"] : [label]));
  else if (kind === "JSON") serialized = utf8(serializeJson(copy));
  else fail(`${kind} serialization is not supported`, "unsupported");
  return digest(code, serialized);
}

/** Verify a message's SAID (`Serder::verify_said`). */
export function verifySaid(sad, label, code, kind) {
  const current = str(get(sad, label));
  if (current === undefined) fail(`missing field ${label}`, "validation");
  if (computeSaid(sad, label, code, kind) !== current) fail("SAID mismatch", "said");
}

// ─── Serder and the stream (affinidi-keri-core `serder.rs`, `parser.rs`) ─

const VERSION_SEARCH_WINDOW = 32;

/**
 * @typedef {Object} Serder
 * @property {Uint8Array} raw - the message body's exact bytes
 * @property {Version|null} version
 * @property {"JSON"|"CESR"} kind
 * @property {Map<string, any>} sad
 */

function isCborStart(b) {
  return (b >= 0xa0 && b <= 0xb7) || b === 0xb8 || b === 0xb9 || b === 0xba || b === 0xbb || b === 0xbf;
}

function isMsgpackStart(b) {
  return (b >= 0x80 && b <= 0x8f) || b === 0xde || b === 0xdf;
}

function extractVersion(data) {
  const window = data.subarray(0, Math.min(data.length, VERSION_SEARCH_WINDOW));
  let pos = -1;
  for (const proto of ["KERI", "ACDC", "SAID"]) {
    const p = utf8(proto);
    for (let k = 0; k + 4 <= window.length; k++) {
      if (window[k] === p[0] && window[k + 1] === p[1] && window[k + 2] === p[2] && window[k + 3] === p[3]) {
        if (pos < 0 || k < pos) pos = k;
        break;
      }
    }
  }
  if (pos < 0 || pos + KERI_VER_FULLSIZE > data.length) return null;
  try {
    return parseVersionBytes(data.subarray(pos));
  } catch {
    return null;
  }
}

/**
 * Read the message body at the head of `bytes` (`Serder::from_raw`).
 *
 * @param {Uint8Array} bytes
 * @returns {Serder}
 */
export function serderFromRaw(bytes) {
  if (!bytes.length) fail("empty input");
  const first = bytes[0];
  if (first === 0x2d) {
    const text = asciiText(bytes.subarray(0, Math.min(bytes.length, bodySizeOrAll(bytes))));
    if (text === null) nerr("a native body is CESR text, which is ASCII");
    const [sad, version, size] = nativeLoad(text);
    return { raw: bytes.slice(0, size), version, kind: "CESR", sad };
  }
  if (first !== 0x7b) {
    if (isCborStart(first) || isMsgpackStart(first)) {
      fail(`${isCborStart(first) ? "CBOR" : "MessagePack"} message bodies are not supported`, "unsupported");
    }
    fail(`cannot detect serialization kind from first byte: 0x${first.toString(16).padStart(2, "0")}`);
  }
  let version = extractVersion(bytes);
  const msgLen = version ? version.size : bytes.length;
  if (bytes.length < msgLen) fail(`raw data too short: ${bytes.length} bytes but version says ${msgLen}`);
  const raw = bytes.slice(0, msgLen);
  const sad = parseJson(raw);
  if (!version) {
    const vs = str(get(sad, "v"));
    if (vs !== undefined) {
      try {
        version = parseVersionString(vs);
      } catch {
        version = null;
      }
    }
  }
  return { raw, version, kind: "JSON", sad };
}

// A native body's text: read just its counter's span, so a non-ASCII byte in
// a later message does not fail this one.
function bodySizeOrAll(bytes) {
  const head = asciiText(bytes.subarray(0, Math.min(bytes.length, 8)));
  if (head === null) return bytes.length;
  try {
    return bodySize(head);
  } catch {
    return bytes.length;
  }
}

/**
 * @typedef {Object} TransIdxSigGroup
 * @property {string} prefix
 * @property {string} sn
 * @property {string} said
 * @property {Siger[]} sigs
 */

/**
 * @typedef {Object} BlindedState
 * @property {string} blid
 * @property {string} uuid
 * @property {string} acdc
 * @property {string} state
 */

/**
 * @typedef {{ type: "ControllerSigs", sigs: Siger[] }
 *   | { type: "WitnessSigs", sigs: Siger[] }
 *   | { type: "ReceiptCouples", couples: Array<[string, Uint8Array]> }
 *   | { type: "FirstSeenReplayCouples", couples: Array<[string, string]> }
 *   | { type: "SealSourceCouples", couples: Array<[string, string]> }
 *   | { type: "TransIdxSigGroups", groups: TransIdxSigGroup[] }
 *   | { type: "BlindedStates", states: BlindedState[] }} Attachment
 */

/**
 * @typedef {Object} ParsedMessage
 * @property {Serder} serder
 * @property {Attachment[]} attachments
 */

const MAX_ATTACHMENT_COUNT = 4096;
const MIN_PRIMITIVE_SIZE = 4;

function take(text, table, kind, count, item) {
  const items = [];
  let offset = 0;
  if (countsQuadlets(table, kind)) {
    const span = quadletSpan(text, count);
    while (offset < span) {
      if (items.length >= MAX_ATTACHMENT_COUNT) fail(`${kind} holds more than ${MAX_ATTACHMENT_COUNT} items`);
      const [it, n] = item(text.slice(offset, span));
      items.push(it);
      offset += n;
    }
    if (offset !== span) fail(`${kind} declared ${span} bytes but its items accounted for ${offset}`);
  } else {
    if (count > MAX_ATTACHMENT_COUNT) fail(`${kind} count ${count} exceeds maximum of ${MAX_ATTACHMENT_COUNT}`);
    if (count * MIN_PRIMITIVE_SIZE > text.length) {
      fail(`${kind} count ${count} requires at least ${count * MIN_PRIMITIVE_SIZE} bytes, but only ${text.length} available`);
    }
    for (let k = 0; k < count; k++) {
      const [it, n] = item(text.slice(offset));
      items.push(it);
      offset += n;
    }
  }
  return [items, offset];
}

function quadletSpan(text, count) {
  const span = count * 4;
  if (span > text.length) fail(`attachment group of ${span} bytes extends past the stream (${text.length} bytes available)`);
  return span;
}

function parseQb64Pair(text) {
  const [first, a] = readAttachmentMatter(text, "couple first member");
  const [second, b] = readAttachmentMatter(text.slice(a), "couple second member");
  return [[first, second], a + b];
}

function parseBlindedState(text) {
  const [blid, a] = readAttachmentMatter(text, "blinded state BLID");
  const [uuid, b] = readAttachmentMatter(text.slice(a), "blinded state UUID");
  const [acdc, c] = readAttachmentMatter(text.slice(a + b), "blinded state ACDC");
  const [state, d] = readAttachmentMatter(text.slice(a + b + c), "blinded state state");
  return [{ blid, uuid, acdc, state }, a + b + c + d];
}

function parseReceiptCouple(text) {
  const [prefix, a] = readAttachmentMatter(text, "prefix");
  const [sig, b] = readAttachmentMatter(text.slice(a), "signature");
  let m;
  try {
    m = matterFromQb64(sig);
  } catch (e) {
    fail(`failed to parse sig matter: ${e.message}`);
  }
  return [[prefix, m.raw], a + b];
}

function parseTransIdxSigGroup(text, table) {
  let offset = 0;
  const [prefix, a] = readAttachmentMatter(text, "transferable sig group prefix");
  offset += a;
  const [sn, b] = readAttachmentMatter(text.slice(offset), "transferable sig group sn");
  offset += b;
  const [said, c] = readAttachmentMatter(text.slice(offset), "transferable sig group said");
  offset += c;
  const counter = readCounter(text.slice(offset));
  if (classify(counter.code, table) !== "ControllerIdxSigs") {
    fail(`transferable sig group has ${JSON.stringify(counter.code)} where indexed signatures were expected`);
  }
  offset += counter.size;
  const [sigs, n] = take(text.slice(offset), table, "ControllerIdxSigs", counter.count, readIndexedSig);
  offset += n;
  if (!sigs.length) fail("transferable sig group carries no signatures");
  return [{ prefix, sn, said, sigs }, offset];
}

function parseGroup(text, table) {
  const counter = readCounter(text);
  let offset = counter.size;
  const kind = classify(counter.code, table);
  if (!kind) fail(`unrecognised attachment counter code ${JSON.stringify(counter.code)} for ${table}; refusing to guess its length`);
  const body = text.slice(offset);
  const count = counter.count;
  if (kind === "AttachedMaterialQuadlets") {
    const span = quadletSpan(body, count);
    const [inner, consumed] = parseAttachments(body.slice(0, span), table);
    if (consumed !== span) fail(`attachment group declared ${span} bytes but its contents accounted for ${consumed}`);
    return [inner, offset + span];
  }
  let attachment;
  let n;
  switch (kind) {
    case "ControllerIdxSigs":
    case "WitnessIdxSigs": {
      let sigs;
      [sigs, n] = take(body, table, kind, count, readIndexedSig);
      attachment = { type: kind === "ControllerIdxSigs" ? "ControllerSigs" : "WitnessSigs", sigs };
      break;
    }
    case "NonTransReceiptCouples": {
      let couples;
      [couples, n] = take(body, table, kind, count, parseReceiptCouple);
      attachment = { type: "ReceiptCouples", couples };
      break;
    }
    case "FirstSeenReplayCouples":
    case "SealSourceCouples": {
      let couples;
      [couples, n] = take(body, table, kind, count, parseQb64Pair);
      attachment = { type: kind, couples };
      break;
    }
    case "BlindedStateQuadruples": {
      let states;
      [states, n] = take(body, table, kind, count, parseBlindedState);
      attachment = { type: "BlindedStates", states };
      break;
    }
    case "TransIdxSigGroups": {
      let groups;
      [groups, n] = take(body, table, kind, count, (t) => parseTransIdxSigGroup(t, table));
      attachment = { type: "TransIdxSigGroups", groups };
      break;
    }
    default:
      fail(`attachment group ${JSON.stringify(counter.code)} (${kind}) is not yet supported; refusing to guess its length`);
  }
  return [[attachment], offset + n];
}

function parseAttachments(text, table) {
  const attachments = [];
  let offset = 0;
  while (offset < text.length && text[offset] === "-" && !text.startsWith("-_", offset)) {
    if (table === "V2") {
      let next = null;
      try {
        next = readCounter(text.slice(offset));
      } catch {
        next = null;
      }
      const sel = next?.code.replace(/^-+/, "");
      if (sel === "F" || sel === "G") break;
    }
    const [group, consumed] = parseGroup(text.slice(offset), table);
    offset += consumed;
    attachments.push(...group);
  }
  return [attachments, offset];
}

/**
 * Parse every message of a stream (`parser::parse_all`, strict). The stream
 * starts in CESR genus 1.x; a genus-version counter switches it.
 *
 * @param {Uint8Array} stream
 * @param {Object} [limits]
 * @param {number} [limits.maxMessages]
 * @returns {ParsedMessage[]}
 */
export function parseAll(stream, { maxMessages = Infinity } = {}) {
  const messages = [];
  let offset = 0;
  let table = "V1";
  let lastNonAscii = -1;
  for (let k = stream.length - 1; k >= 0; k--) {
    if (stream[k] > 0x7f) {
      lastNonAscii = k;
      break;
    }
  }
  const asciiFrom = lastNonAscii + 1;
  let tailText = null;
  const tail = () => (tailText ??= asciiText(stream.subarray(asciiFrom)));
  const isWs = (b) => b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0c || b === 0x0d;
  while (offset < stream.length) {
    while (offset < stream.length && isWs(stream[offset])) offset++;
    if (offset >= stream.length) break;
    if (stream[offset] === 0x2d && stream[offset + 1] === 0x5f) {
      const counter = readCounter(headText(stream, offset));
      if (offset + counter.size === stream.length) break;
    }
    if (messages.length >= maxMessages) {
      fail(`the stream holds more than ${maxMessages} messages`, "unsupported");
    }
    // Genus-version counters before the message switch the genus.
    while (stream[offset] === 0x2d && stream[offset + 1] === 0x5f) {
      const counter = readCounter(headText(stream, offset));
      const gv = genusVersion(counter);
      if (!gv) fail(`${JSON.stringify(counter.code)} is not a genus-version counter this parser knows`);
      table = tableForGenus(gv[0]);
      offset += counter.size;
    }
    if (offset >= stream.length) fail("empty stream");
    const first = stream[offset];
    let isBody = first === 0x7b || isCborStart(first) || isMsgpackStart(first);
    if (!isBody && first === 0x2d) {
      const counter = readCounter(headText(stream, offset));
      const base = counter.code.replace(/^-+/, "");
      if (table === "V2" && (base === "F" || base === "G")) isBody = true;
      else if ((table === "V2" && (base === "B" || base === "H")) || (table === "V1" && (base === "U" || base === "W"))) {
        fail(`enclosed message group ${JSON.stringify(counter.code)} in a ${table} stream`, "unsupported");
      } else {
        fail(`a ${table} stream has counter ${JSON.stringify(counter.code)} where a message was expected`);
      }
    }
    if (!isBody) fail(`unrecognized stream start byte: 0x${first.toString(16).padStart(2, "0")}`);
    const serder = serderFromRaw(stream.subarray(offset));
    if (serder.version && serder.version.major >= 2 && table === "V1") {
      fail(`a version ${serder.version.major}.${serder.version.minor} message in a CESR 1.x stream: a 2.x stream opens with the genus-version counter -_AAACAA`);
    }
    offset += serder.raw.length;
    // CESR text is Base64, so attachments are ASCII; affinidi-keri-core
    // checks that everything from an attachment group to the end of the
    // stream is (`parse_attachments`), so one non-ASCII byte anywhere later
    // fails the stream there too.
    let restText = "";
    if (offset < stream.length && stream[offset] === 0x2d && !(stream[offset + 1] === 0x5f)) {
      if (offset < asciiFrom) fail("attachment data contains non-ASCII bytes");
      restText = tail().slice(offset - asciiFrom);
    }
    const [attachments, consumed] = parseAttachments(restText, table);
    if (serder.raw.length + consumed === 0) fail("parse_next consumed zero bytes");
    messages.push({ serder, attachments });
    offset += consumed;
  }
  return messages;
}

function headText(stream, offset) {
  const text = asciiText(stream.subarray(offset, Math.min(stream.length, offset + 8)));
  if (text === null) fail("counter is not ASCII");
  return text;
}

/** The controller signatures of a message. */
export function controllerSigs(msg) {
  return msg.attachments.find((a) => a.type === "ControllerSigs")?.sigs ?? [];
}

/** The seal source couples of a message. */
export function sealSourceCouples(msg) {
  return msg.attachments.find((a) => a.type === "SealSourceCouples")?.couples ?? [];
}

/** The transferable indexed signature groups of a message. */
export function transIdxSigGroups(msg) {
  return msg.attachments.find((a) => a.type === "TransIdxSigGroups")?.groups ?? [];
}

/**
 * The value of a sequence number as an attachment carries it
 * (`parser::number_value`): a 1.x `Seqner` (`0A`) or a 2.x `Number`.
 *
 * @returns {bigint}
 */
export function numberValue(qb64) {
  let hs;
  let fs;
  let rawLen;
  if (qb64.startsWith("0A")) [hs, fs, rawLen] = [2, 24, 16];
  else if (qb64.startsWith("0H")) [hs, fs, rawLen] = [2, 8, 4];
  else if (qb64.startsWith("M")) [hs, fs, rawLen] = [1, 4, 2];
  else if (qb64.startsWith("R")) [hs, fs, rawLen] = [1, 8, 5];
  else if (qb64.startsWith("N")) [hs, fs, rawLen] = [1, 12, 8];
  else fail(`${JSON.stringify(qb64)} is not a sequence number`);
  if (qb64.length !== fs) fail(`sequence number ${JSON.stringify(qb64)} is not ${fs} characters`);
  let bytes;
  try {
    bytes = b64Decode("A".repeat(hs) + qb64.slice(hs));
  } catch (e) {
    fail(`sequence number ${JSON.stringify(qb64)}: ${e.message}`);
  }
  const raw = bytes.subarray(bytes.length - rawLen);
  const highLen = Math.max(0, raw.length - 8);
  if (raw.subarray(0, highLen).some((b) => b !== 0) || bytes.subarray(0, bytes.length - rawLen).some((b) => b !== 0)) {
    fail(`sequence number ${JSON.stringify(qb64)} does not fit 64 bits`);
  }
  let n = 0n;
  for (const b of raw.subarray(highLen)) n = (n << 8n) | BigInt(b);
  return n;
}
