// Key event log verification for `./did-webs.js`.
//
// A port of `affinidi-keri-core` 0.8.1 (`kever.rs`, `key_state.rs`,
// `threshold.rs`, `delegation.rs`) and of `affinidi-did-webs` 0.13.1
// `kel.rs`: every key event of every identifier in a `keri.cesr` stream is
// verified against the key state its own log establishes — SAID, field list,
// signatures against the signing threshold, prior-event digest, pre-rotation
// commitment (`nt` over the exposed digests), witness receipts against the
// witness threshold, delegation anchored in the delegator's verified log —
// and a rotation may supersede interaction events after the last
// establishment event (recovery, P7), taking what they anchored with them.
//
// Verification results are remembered per stream, as the Rust `Kels` does,
// and so is the key state at an establishment event, which `affinidi-did-webs`
// recomputes from the start of the log for every signature it checks. That is
// the same answer, computed once; a stream of many replies over a long log
// would otherwise cost a full replay per reply.

import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import {
  KeriError,
  b64Encode,
  checkKeriFields,
  controllerSigs,
  digestMatches,
  get,
  isDigestCode,
  matterFromQb64,
  matterQb64,
  numberRaw,
  numberValue,
  parseAll,
  parseUnsigned,
  parseVersionString,
  protocolMajor,
  sealSourceCouples,
  str,
  toSafeNumber,
  verifySaid,
  SadNumber,
} from "./did-webs-cesr.js";

const fail = (message, type = "validation") => {
  throw new KeriError(message, type);
};

/** Delegation steps followed before giving up (`kel::MAX_DELEGATION_DEPTH`). */
const MAX_DELEGATION_DEPTH = 8;

/** Most messages a stream may hold (`kel::MAX_STREAM_MESSAGES`). */
export const MAX_STREAM_MESSAGES = 10_000;
/** Most signatures, receipt couples and group signatures in a stream. */
export const MAX_STREAM_SIGNATURES = 16_384;
/** Most witness entries (`b`, `ba`) across a stream's key events. */
export const MAX_STREAM_BACKERS = 1_024;
/** Most seals (`a`) across a stream's key events. */
export const MAX_STREAM_SEALS = 16_384;

// ─── Signature verification (affinidi-keri-crypto `Verfer`) ─────────────

const VERFER_CODES = new Set(["B", "D", "1AAA", "1AAB", "1AAI", "1AAJ"]);

/**
 * A verification key from its qb64 (`Verfer::from_qb64`).
 *
 * @param {string} qb64
 * @returns {{ code: string, raw: Uint8Array, qb64: string }}
 */
export function verfer(qb64) {
  const m = matterFromQb64(qb64);
  if (!VERFER_CODES.has(m.code)) fail(`unsupported verfer code: ${m.code}`, "crypto");
  return { code: m.code, raw: m.raw, qb64: matterQb64(m.code, m.raw) };
}

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

function bigOf(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/**
 * Verify `signature` over `message` (`Verfer::verify`). Returns false for a
 * signature that does not verify, and throws for a key or a signature that
 * cannot be read, as the Rust does — the callers differ in what they make of
 * that.
 */
export function verifySignature(v, message, signature) {
  // A replay verifies the same signature over the same message every time a
  // key state is read; the answer does not change, so it is kept with the
  // message's bytes (and goes when they do).
  let cache = VERIFIED.get(message);
  if (!cache) {
    cache = new Map();
    VERIFIED.set(message, cache);
  }
  const key = `${v.qb64}.${b64Encode(signature)}`;
  const hit = cache.get(key);
  if (hit !== undefined) return hit;
  const valid = verifyUncached(v, message, signature);
  cache.set(key, valid);
  return valid;
}

/** @type {WeakMap<Uint8Array, Map<string, boolean>>} */
const VERIFIED = new WeakMap();

function verifyUncached(v, message, signature) {
  if (v.code === "B" || v.code === "D") {
    try {
      // ed25519-dalek accepts any encoding that decompresses.
      ed25519.Point.fromBytes(v.raw, true);
    } catch {
      fail("invalid Ed25519 public key", "crypto");
    }
    if (signature.length !== 64) fail("invalid Ed25519 signature length", "crypto");
    try {
      return ed25519.verify(signature, message, v.raw, { zip215: false });
    } catch {
      return false;
    }
  }
  const [curve, n, lowS] = v.code === "1AAA" || v.code === "1AAB" ? [secp256k1, SECP256K1_N, true] : [p256, P256_N, false];
  try {
    curve.Point.fromBytes(v.raw);
  } catch {
    fail("invalid ECDSA public key", "crypto");
  }
  // `Signature::from_slice`: r || s, each in [1, n).
  if (signature.length !== 64) fail("invalid ECDSA signature", "crypto");
  const r = bigOf(signature.subarray(0, 32));
  const s = bigOf(signature.subarray(32));
  if (r === 0n || s === 0n || r >= n || s >= n) fail("invalid ECDSA signature", "crypto");
  try {
    // k256 refuses a high-S signature; p256 does not.
    return curve.verify(signature, message, v.raw, { lowS, prehash: true });
  } catch {
    return false;
  }
}

// ─── Thresholds (affinidi-keri-core `threshold.rs`) ─────────────────────

const U32_MAX = 0xffffffffn;
const U64_LIMIT = 1n << 64n;

/**
 * @typedef {{ type: "simple", n: bigint }
 *   | { type: "weighted", clauses: Array<Array<{ num: bigint, den: bigint }>> }} Threshold
 */

function weight(s) {
  const slash = s.indexOf("/");
  const [n, d] = slash < 0 ? [s, null] : [s.slice(0, slash), s.slice(slash + 1)];
  const num = parseUnsigned(n, 10, U32_MAX);
  if (num === null) fail(`invalid weight numerator: ${n}`);
  const den = d === null ? 1n : parseUnsigned(d, 10, U32_MAX);
  if (den === null) fail(`invalid weight denominator: ${d}`);
  if (den === 0n) fail("weight denominator cannot be zero");
  return { num, den };
}

/** Read a threshold from its field (`Threshold::from_json_value`). */
export function parseThreshold(value) {
  if (typeof value === "string") {
    // keripy reads a simple threshold as hex.
    const n = parseUnsigned(value, 16);
    if (n === null) fail(`invalid threshold string: ${value}`);
    return { type: "simple", n };
  }
  if (value instanceof SadNumber) {
    const n = value.big;
    if (n < 0n) fail(`invalid threshold number: ${value.text}`);
    return { type: "simple", n };
  }
  if (Array.isArray(value)) {
    if (!value.length) fail("weighted threshold must have at least one clause");
    let clauses;
    if (value.every((i) => typeof i === "string")) clauses = [value];
    else if (value.every((i) => Array.isArray(i))) clauses = value;
    else fail("weighted threshold mixes weights and clauses");
    return {
      type: "weighted",
      clauses: clauses.map((clause) => {
        if (!clause.length) fail("weighted threshold clause must have at least one weight");
        return clause.map((w) => (typeof w === "string" ? weight(w) : fail("weighted threshold weight must be a string")));
      }),
    };
  }
  return fail("invalid threshold value");
}

const isZero = (t) => t.type === "simple" && t.n === 0n;

/** Whether `indices` (valid signers, by key position) meet the threshold. */
export function thresholdSatisfied(t, indices, totalKeys) {
  if (t.type === "simple") return t.n > 0n && BigInt(indices.length) >= t.n;
  if (!t.clauses.length) return false;
  const has = new Set(indices);
  let keyIdx = 0;
  for (const clause of t.clauses) {
    let num = 0n;
    let den = 1n;
    for (const w of clause) {
      if (keyIdx < totalKeys && has.has(keyIdx)) {
        // u64 checked arithmetic, as the Rust: an overflow is not met.
        const a = num * w.den;
        const b = w.num * den;
        const nn = a + b;
        const nd = den * w.den;
        if (a >= U64_LIMIT || b >= U64_LIMIT || nn >= U64_LIMIT || nd >= U64_LIMIT) return false;
        num = nn;
        den = nd;
      }
      keyIdx++;
    }
    if (num < den) return false;
  }
  return true;
}

function checkSatisfiable(t, keys, what) {
  let ok;
  if (t.type === "simple") ok = t.n >= 1n && t.n <= BigInt(keys);
  else {
    const size = t.clauses.reduce((n, c) => n + c.length, 0);
    ok = size <= keys && thresholdSatisfied(t, [...Array(keys).keys()], keys);
  }
  if (!ok) fail(`${what} cannot be met by ${keys} key(s)`);
}

/** The threshold as its KERI field value (`Threshold::to_json_value`). */
export function thresholdJson(t) {
  if (t.type === "simple") return t.n.toString(16);
  return t.clauses.map((clause) => clause.map((w) => (w.den === 1n ? `${w.num}` : `${w.num}/${w.den}`)));
}

// ─── Events (affinidi-keri-core `event.rs`) ─────────────────────────────

const FIELD_TYPES = {
  v: "string", t: "string", d: "string", i: "string", s: "string", p: "string", bt: "string", di: "string",
  kt: "threshold", nt: "threshold", k: "strings", n: "strings", b: "strings", br: "strings", ba: "strings",
  c: "strings", a: "array",
};

const EVENT_FIELDS = {
  icp: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
  rot: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c?", "a"],
  ixn: ["v", "t", "d", "i", "s", "p", "a"],
  dip: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"],
  drt: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c?", "a"],
};

/** The typed fields of a key event, as serde would deserialize them. */
function eventOf(sad, ilk) {
  const out = {};
  for (const spec of EVENT_FIELDS[ilk]) {
    const optional = spec.endsWith("?");
    const label = optional ? spec.slice(0, -1) : spec;
    const value = get(sad, label);
    if (value === undefined) {
      if (optional) {
        out[label] = [];
        continue;
      }
      fail(`missing field \`${label}\``, "json");
    }
    switch (FIELD_TYPES[label]) {
      case "string":
        if (typeof value !== "string") fail(`invalid type for \`${label}\`: expected a string`, "json");
        out[label] = value;
        break;
      case "strings":
        if (!Array.isArray(value) || !value.every((x) => typeof x === "string")) {
          fail(`invalid type for \`${label}\`: expected a sequence of strings`, "json");
        }
        out[label] = value;
        break;
      case "array":
        if (!Array.isArray(value)) fail(`invalid type for \`${label}\`: expected a sequence`, "json");
        out[label] = value;
        break;
      case "threshold":
        out[label] = parseThreshold(value);
        break;
    }
  }
  return out;
}

function checkShape(sad, ilk) {
  checkKeriFields(sad, protocolMajor(sad), ilk);
}

/** A KERI sequence number (`u64::from_str_radix(s, 16)`), or null. */
export function parseSn(text) {
  return toSafeNumber(parseUnsigned(text, 16));
}

function snOf(text) {
  const sn = parseSn(text);
  if (sn === null) fail(`invalid sequence number: ${text}`);
  return sn;
}

// ─── Key state (affinidi-keri-core `key_state.rs`) ──────────────────────

/**
 * @typedef {Object} KeyState
 * @property {string} prefix
 * @property {number} sn
 * @property {string} said - the latest establishment event's SAID
 * @property {Threshold} threshold
 * @property {string[]} keys
 * @property {string[]} nextKeys
 * @property {Threshold} nextThreshold
 * @property {number} backerThreshold
 * @property {string[]} backers
 * @property {string[]} config
 * @property {string} lastEventDigest
 * @property {boolean} delegated
 * @property {string|null} delegator
 * @property {number} protocolMajor
 */

export const ESTABLISHMENT_ONLY = "EO";
export const DO_NOT_DELEGATE = "DND";
const INCEPTION_ONLY_TRAITS = [ESTABLISHMENT_ONLY, DO_NOT_DELEGATE, "DID"];

const eventMajor = (version) => parseVersionString(version).major;

function checkKeyThresholds(kt, keys, nt, nextKeys) {
  checkSatisfiable(kt, keys.length, "kt");
  if (isZero(nt)) {
    if (nextKeys.length) fail(`nt is 0 but n commits to ${nextKeys.length} next key(s)`);
    return;
  }
  checkSatisfiable(nt, nextKeys.length, "nt");
}

function backerThreshold(bt) {
  const n = toSafeNumber(parseUnsigned(bt, 16));
  if (n === null) fail(`invalid backer threshold: ${bt}`);
  return n;
}

function fromInception(e, delegated) {
  if (snOf(e.s) !== 0) fail(`${delegated ? "delegated " : ""}inception event must have sn=0, got ${e.s}`);
  if (delegated && e.di === "") fail("delegated inception names no delegator (empty `di`)");
  checkKeyThresholds(e.kt, e.k, e.nt, e.n);
  const bt = backerThreshold(e.bt);
  if (bt > e.b.length) fail(`backer threshold (${bt}) exceeds backer count (${e.b.length})`);
  return {
    prefix: e.i,
    sn: 0,
    said: e.d,
    threshold: e.kt,
    keys: e.k,
    nextKeys: e.n,
    nextThreshold: e.nt,
    backerThreshold: bt,
    backers: e.b,
    config: e.c,
    lastEventDigest: e.d,
    delegated,
    delegator: delegated ? e.di : null,
    protocolMajor: eventMajor(e.v),
  };
}

const isAbandoned = (state) => state.nextKeys.length === 0;

function rejectIfAbandoned(state) {
  if (isAbandoned(state)) {
    fail(`identifier ${state.prefix} is abandoned: its establishment event at sn ${state.sn} committed to no next keys, so no event may follow`);
  }
}

function checkVersion(state, version) {
  const major = eventMajor(version);
  if (major < state.protocolMajor) {
    fail(`event for ${state.prefix} at sn ${state.sn + 1} names KERI ${major}.x, but its KEL has reached ${state.protocolMajor}.x: a KEL never moves to a lower protocol version`);
  }
  return major;
}

function rotatedConfig(prior, major, added) {
  const config = [...prior];
  if (major >= 2) {
    for (const t of added) {
      if (INCEPTION_ONLY_TRAITS.includes(t)) continue;
      if (!config.includes(t)) config.push(t);
    }
  }
  return config;
}

function applyRotation(state, e) {
  rejectIfAbandoned(state);
  const major = checkVersion(state, e.v);
  const sn = snOf(e.s);
  if (sn !== state.sn + 1) fail(`out of order: expected sn ${state.sn + 1}, got ${sn}`);
  if (e.i !== state.prefix) fail(`rotation prefix '${e.i}' does not match state prefix '${state.prefix}'`);
  if (e.p !== state.lastEventDigest) fail(`prior SAID mismatch: expected '${state.lastEventDigest}', got '${e.p}'`);
  checkKeyThresholds(e.kt, e.k, e.nt, e.n);
  const bt = backerThreshold(e.bt);
  const backers = state.backers.filter((b) => !e.br.includes(b));
  for (const b of e.ba) if (!backers.includes(b)) backers.push(b);
  if (bt > backers.length) fail(`backer threshold (${bt}) exceeds backer count (${backers.length})`);
  return {
    prefix: state.prefix,
    sn,
    said: e.d,
    threshold: e.kt,
    keys: e.k,
    nextKeys: e.n,
    nextThreshold: e.nt,
    backerThreshold: bt,
    backers,
    config: rotatedConfig(state.config, major, e.c),
    lastEventDigest: e.d,
    delegated: state.delegated,
    delegator: state.delegator,
    protocolMajor: major,
  };
}

function applyInteraction(state, e) {
  rejectIfAbandoned(state);
  if (state.config.includes(ESTABLISHMENT_ONLY)) {
    fail("the identifier is establishment-only (EO): interaction events are not allowed");
  }
  const major = checkVersion(state, e.v);
  const sn = snOf(e.s);
  if (sn !== state.sn + 1) fail(`out of order: expected sn ${state.sn + 1}, got ${sn}`);
  if (e.i !== state.prefix) fail(`interaction prefix '${e.i}' does not match state prefix '${state.prefix}'`);
  if (e.p !== state.lastEventDigest) fail(`prior SAID mismatch: expected '${state.lastEventDigest}', got '${e.p}'`);
  return { ...state, sn, lastEventDigest: e.d, protocolMajor: major };
}

// ─── Delegation (affinidi-keri-core `delegation.rs`) ────────────────────

function delegationProofOf(snQb64, saidQb64) {
  let raw;
  try {
    raw = numberRaw(snQb64);
  } catch (e) {
    fail(`invalid seal source sequence number: ${e.message}`, "parse");
  }
  const highLen = Math.max(0, raw.length - 8);
  if (raw.subarray(0, highLen).some((b) => b !== 0)) fail("seal source sequence number exceeds u64", "parse");
  let sn = 0n;
  for (const b of raw.subarray(highLen)) sn = (sn << 8n) | BigInt(b);
  try {
    matterFromQb64(saidQb64);
  } catch (e) {
    fail(`invalid seal source SAID: ${e.message}`, "parse");
  }
  return { sn, said: saidQb64 };
}

function verifyDelegation(delegatee, sn, said, delegator, proof, source) {
  if (delegator === "") fail("delegated event names no delegator (empty `di`)");
  if (delegator === delegatee) fail("delegated event names itself as its own delegator");
  const anchors = source.anchorsAt(delegator, proof.sn, proof.said);
  if (anchors === null) {
    fail(`delegator '${delegator}' has no verified event at sn ${proof.sn} with SAID '${proof.said}' to anchor the delegation of '${delegatee}'`);
  }
  const traits = source.delegatorTraits(delegator);
  if (traits === null) fail(`delegator '${delegator}' has no verified key state to authorise the delegation of '${delegatee}'`);
  if (traits.includes(DO_NOT_DELEGATE)) fail(`delegator '${delegator}' does not delegate (DND): '${delegatee}' is refused`);
  const expected = sn.toString(16);
  const matched = anchors.some((a) => {
    // serde `SealEvent`: i, s and d strings; other members ignored.
    const i = get(a, "i");
    const s = get(a, "s");
    const d = get(a, "d");
    return typeof i === "string" && typeof s === "string" && typeof d === "string" && i === delegatee && d === said && s === expected;
  });
  if (!matched) {
    fail(`delegator '${delegator}' event at sn ${proof.sn} anchors no seal for '${delegatee}' at sn ${sn} with SAID '${said}'`);
  }
}

// ─── Kever (affinidi-keri-core `kever.rs`) ──────────────────────────────

function verifySigsStatic(message, sigs, verfers, threshold) {
  const satisfied = [];
  for (const sig of sigs) {
    if (sig.index >= verfers.length) continue;
    const valid = verifySignature(verfers[sig.index], message, sig.raw);
    if (valid && !satisfied.includes(sig.index)) satisfied.push(sig.index);
  }
  if (!thresholdSatisfied(threshold, satisfied, verfers.length)) fail("threshold not met", "threshold");
}

function compareKeys(eventKeys, verfers) {
  if (eventKeys.length !== verfers.length) {
    fail(`key count mismatch: event has ${eventKeys.length} keys, ${verfers.length} verfers provided`);
  }
  eventKeys.forEach((key, i) => {
    if (key !== verfers[i].qb64) fail(`key[${i}] mismatch: event key '${key}' != verfer '${verfers[i].qb64}'`);
  });
}

function validatePrefixDerivation(e) {
  let digest = false;
  try {
    digest = isDigestCode(matterFromQb64(e.i).code);
  } catch {
    digest = false;
  }
  if (digest) {
    if (e.i !== e.d) fail("self-addressing prefix does not match event SAID (i != d)");
    return;
  }
  let basic = false;
  try {
    verfer(e.i);
    basic = true;
  } catch {
    basic = false;
  }
  if (basic) {
    if (!e.k.length || e.i !== e.k[0]) fail("basic prefix does not match first public key");
    return;
  }
  fail("prefix is neither a valid digest code nor a valid key code");
}

/** Verifies one identifier's KEL event by event. */
class Kever {
  constructor(state, est, since) {
    this.state = state;
    this.est = est;
    this.since = since;
  }

  static incept(serder, sigs, verfers) {
    const ilk = str(get(serder.sad, "t"));
    if (ilk === undefined) fail("missing field t");
    if (ilk === "dip") fail("'dip' is a delegated inception; use Kever::new_delegated, which verifies the delegator's anchoring seal");
    if (ilk !== "icp") fail(`expected 'icp', got '${ilk}'`);
    verifySaid(serder.sad, "d", "E", serder.kind);
    checkShape(serder.sad, "icp");
    const e = eventOf(serder.sad, "icp");
    compareKeys(e.k, verfers);
    verifySigsStatic(serder.raw, sigs, verfers, e.kt);
    validatePrefixDerivation(e);
    const state = fromInception(e, false);
    return new Kever(state, state, []);
  }

  static inceptDelegated(serder, sigs, verfers, proof, source) {
    const ilk = str(get(serder.sad, "t"));
    if (ilk === undefined) fail("missing field t");
    if (ilk !== "dip") fail(`expected 'dip', got '${ilk}'`);
    verifySaid(serder.sad, "d", "E", serder.kind);
    checkShape(serder.sad, "dip");
    const e = eventOf(serder.sad, "dip");
    compareKeys(e.k, verfers);
    verifySigsStatic(serder.raw, sigs, verfers, e.kt);
    if (e.i !== e.d) fail("delegated inception prefix does not match event SAID (i != d)");
    verifyDelegation(e.i, 0n, e.d, e.di, proof, source);
    const state = fromInception(e, true);
    return new Kever(state, state, []);
  }

  /** Verify the next event, returning the state it would install. */
  verifyUpdate(serder, sigs) {
    verifySaid(serder.sad, "d", "E", serder.kind);
    const ilk = str(get(serder.sad, "t"));
    if (ilk === undefined) fail("missing field t");
    const sn = parseSn(str(get(serder.sad, "s")));
    if (sn === null) fail("missing field s");
    if (ilk === "rot" && sn <= this.state.sn) return this.recoveryBase(sn).verifyUpdate(serder, sigs);
    if (sn !== this.state.sn + 1) fail(`out of order: expected sn ${this.state.sn + 1}, got ${sn}`);
    if (ilk === "rot") {
      if (this.state.delegated) fail("identifier is delegated and must rotate with 'drt', not 'rot'");
      checkShape(serder.sad, "rot");
      const e = eventOf(serder.sad, "rot");
      this.verifyRotationSigs(serder.raw, sigs, e.k, e.kt);
      return applyRotation(this.state, e);
    }
    if (ilk === "ixn") {
      const verfers = this.state.keys.map(verfer);
      verifySigsStatic(serder.raw, sigs, verfers, this.state.threshold);
      checkShape(serder.sad, "ixn");
      return applyInteraction(this.state, eventOf(serder.sad, "ixn"));
    }
    if (ilk === "drt") {
      fail("'drt' is a delegated rotation; use Kever::verify_update_delegated, which verifies the delegator's anchoring seal");
    }
    return fail(`expected 'rot' or 'ixn' for update, got '${ilk}'`);
  }

  verifyUpdateDelegated(serder, sigs, proof, source) {
    verifySaid(serder.sad, "d", "E", serder.kind);
    const ilk = str(get(serder.sad, "t"));
    if (ilk === undefined) fail("missing field t");
    if (ilk !== "drt") fail(`expected 'drt', got '${ilk}'`);
    const sn = parseSn(str(get(serder.sad, "s")));
    if (sn === null) fail("missing field s");
    if (sn <= this.state.sn) {
      fail(`a delegated rotation at sn ${sn} would supersede the event there: superseding delegated rotations (KERI recovery rule B) are not supported`, "unsupported");
    }
    if (sn !== this.state.sn + 1) fail(`out of order: expected sn ${this.state.sn + 1}, got ${sn}`);
    checkShape(serder.sad, "drt");
    const e = eventOf(serder.sad, "drt");
    const delegator = this.state.delegator;
    if (!delegator) fail("delegated identifier has no recorded delegator");
    this.verifyRotationSigs(serder.raw, sigs, e.k, e.kt);
    verifyDelegation(e.i, BigInt(sn), e.d, delegator, proof, source);
    if (!this.state.delegated) fail("delegated rotation applied to an identifier that was not delegated");
    return applyRotation(this.state, e);
  }

  applyVerifiedUpdate(next) {
    if (next.said === next.lastEventDigest) {
      this.est = next;
      this.since = [];
    } else {
      this.since.push([next.lastEventDigest, next.protocolMajor]);
    }
    this.state = next;
  }

  /** The log as it stood at `sn - 1`, for a superseding rotation at `sn`. */
  recoveryBase(sn) {
    if (sn <= this.est.sn) {
      fail(`stale rotation at sn ${sn}: the last establishment event is at sn ${this.est.sn}, and a rotation supersedes only interaction events after it`);
    }
    const kept = sn - 1 - this.est.sn;
    const base = { ...this.est, sn: sn - 1 };
    if (kept >= 1 && this.since[kept - 1]) {
      base.lastEventDigest = this.since[kept - 1][0];
      base.protocolMajor = this.since[kept - 1][1];
    }
    return new Kever(base, this.est, this.since.slice(0, kept));
  }

  /**
   * A rotation is signed by the keys it installs and must meet its own `kt`
   * over them, and the prior `nt` over the committed digests its signatures
   * expose (keripy `Kever.exposeds`).
   */
  verifyRotationSigs(raw, sigs, keys, kt) {
    if (isAbandoned(this.state)) {
      fail(`identifier ${this.state.prefix} is abandoned: its last establishment event committed to no next keys, so it cannot rotate`);
    }
    const verfers = keys.map(verfer);
    verifySigsStatic(raw, sigs, verfers, kt);
    const prior = this.state.nextKeys;
    const exposed = [];
    for (const sig of sigs) {
      if (sig.ondex === null || sig.index >= keys.length) continue;
      const digestQb64 = prior[sig.ondex];
      if (digestQb64 === undefined) continue;
      if (exposed.includes(sig.ondex) || !verifySignature(verfers[sig.index], raw, sig.raw)) continue;
      let matches;
      try {
        matches = digestMatches(digestQb64, new TextEncoder().encode(keys[sig.index]));
      } catch (e) {
        fail(`invalid prior next-key digest at ${sig.ondex}: ${e.message}`);
      }
      if (matches) exposed.push(sig.ondex);
    }
    if (!thresholdSatisfied(this.state.nextThreshold, exposed, prior.length)) fail("threshold not met", "threshold");
  }
}

function verifyWitnessReceipts(message, couples, backers, threshold) {
  if (threshold === 0) return;
  const valid = [];
  for (const [prefix, sig] of couples) {
    if (!backers.includes(prefix) || valid.includes(prefix)) continue;
    if (verifySignature(verfer(prefix), message, sig)) valid.push(prefix);
  }
  if (valid.length < threshold) {
    fail(`witness receipt threshold not met: need ${threshold}, got ${valid.length}`);
  }
}

// ─── Kels (affinidi-did-webs `kel.rs`) ──────────────────────────────────

const KEY_EVENT_ILKS = new Set(["icp", "rot", "ixn", "dip", "drt"]);
const ESTABLISHMENT_ILKS = new Set(["icp", "rot", "dip", "drt"]);

/** Thrown for a key event log that does not verify (`DidWebsError::Kel`). */
export class KelError extends Error {
  constructor(message) {
    super(message);
    this.name = "KelError";
  }
}

/** Thrown for a stream that cannot be parsed (`DidWebsError::Stream`). */
export class StreamError extends Error {
  constructor(message) {
    super(message);
    this.name = "StreamError";
  }
}

const kelFail = (message) => {
  throw new KelError(message);
};

const ilkOf = (msg) => str(get(msg.serder.sad, "t"));
const saidOf = (msg) => str(get(msg.serder.sad, "d"));
const prefixOf = (msg) => str(get(msg.serder.sad, "i"));
const snOfMsg = (msg) => parseSn(str(get(msg.serder.sad, "s")));

/** An accepted event as the registry reader takes it (`LoggedEvent`). */
function logged(msg, state, establishment) {
  const said = saidOf(msg);
  if (said === undefined) kelFail("key event has no SAID: missing field d");
  const a = get(msg.serder.sad, "a");
  return { sn: state.sn, said, seals: Array.isArray(a) ? a : [], establishment: establishment ? state : null };
}

/**
 * The key event logs of a `keri.cesr` stream, grouped by identifier, with
 * verification results remembered as they are computed.
 */
export class Kels {
  /**
   * @param {import("./did-webs-cesr.js").ParsedMessage[]} messages
   * @param {Map<string, number[]>} byPrefix
   * @param {Map<string, number[]>} fullByPrefix
   * @param {Map<string, number>} limits
   */
  constructor(messages, byPrefix, fullByPrefix, limits) {
    this.messages = messages;
    this.byPrefix = byPrefix;
    this.fullByPrefix = fullByPrefix;
    this.limits = limits;
    /** @type {Map<string, KeyState>} */
    this.verified = new Map();
    /** @type {string[]} */
    this.inProgress = [];
    /** @type {Map<string, number[]>} */
    this.superseded = new Map();
    this.atCache = new Map();
    this.issuerLogs = new Map();
    this.receipts = null;
  }

  /**
   * Parse a stream and group its key events by identifier (`Kels::parse`).
   *
   * @param {Uint8Array} stream
   * @param {{ maxMessages?: number }} [limits]
   */
  static parse(stream, limits = { maxMessages: MAX_STREAM_MESSAGES }) {
    let messages;
    try {
      messages = parseAll(stream, limits);
    } catch (e) {
      throw new StreamError(`could not parse keri.cesr: ${e.message}`);
    }
    // Bounds checked before anything is verified (`kel::MAX_STREAM_*`).
    let signatures = 0;
    let backers = 0;
    let seals = 0;
    for (const msg of messages) {
      for (const a of msg.attachments) {
        if (a.type === "ControllerSigs" || a.type === "WitnessSigs") signatures += a.sigs.length;
        else if (a.type === "ReceiptCouples") signatures += a.couples.length;
        else if (a.type === "TransIdxSigGroups") signatures += a.groups.reduce((n, g) => n + g.sigs.length, 0);
      }
      if (!KEY_EVENT_ILKS.has(ilkOf(msg))) continue;
      const entries = (label) => {
        const v = get(msg.serder.sad, label);
        return Array.isArray(v) ? v.length : 0;
      };
      backers += entries("b") + entries("ba");
      seals += entries("a");
    }
    if (signatures > MAX_STREAM_SIGNATURES) {
      throw new StreamError(`keri.cesr carries more than the ${MAX_STREAM_SIGNATURES} signatures this resolver checks`);
    }
    if (backers > MAX_STREAM_BACKERS) {
      throw new StreamError(`keri.cesr's key events name ${backers} witnesses, more than the ${MAX_STREAM_BACKERS} this resolver reads`);
    }
    if (seals > MAX_STREAM_SEALS) {
      throw new StreamError(`keri.cesr's key events anchor ${seals} seals, more than the ${MAX_STREAM_SEALS} this resolver reads`);
    }
    const byPrefix = new Map();
    messages.forEach((msg, i) => {
      const ilk = ilkOf(msg);
      if (!KEY_EVENT_ILKS.has(ilk)) return;
      const prefix = prefixOf(msg);
      if (prefix === undefined) return;
      if (!byPrefix.has(prefix)) byPrefix.set(prefix, []);
      byPrefix.get(prefix).push(i);
    });
    const full = new Map([...byPrefix].map(([k, v]) => [k, [...v]]));
    return new Kels(messages, byPrefix, full, new Map());
  }

  /** The SAID of `prefix`'s first key event. */
  inceptionSaid(prefix) {
    const first = this.byPrefix.get(prefix)?.[0];
    return first === undefined ? null : (saidOf(this.messages[first]) ?? null);
  }

  /** The sequence numbers of `prefix`'s key events, in stream order. */
  sequenceNumbers(prefix) {
    return (this.byPrefix.get(prefix) ?? []).map((i) => snOfMsg(this.messages[i])).filter((sn) => sn !== null);
  }

  /** This stream with `prefix`'s events after `sn` set aside (`versionId`). */
  asOf(prefix, sn) {
    if (!this.sequenceNumbers(prefix).includes(sn)) kelFail(`${prefix} has no key event at sequence number ${sn}`);
    const byPrefix = new Map([...this.byPrefix].map(([k, v]) => [k, [...v]]));
    if (byPrefix.has(prefix)) {
      byPrefix.set(prefix, byPrefix.get(prefix).filter((i) => {
        const s = snOfMsg(this.messages[i]);
        return s !== null && s <= sn;
      }));
    }
    const limits = new Map(this.limits);
    limits.set(prefix, sn);
    return new Kels(this.messages, byPrefix, this.fullByPrefix, limits);
  }

  /** Whether `prefix`'s latest establishment event is a rotation to no next keys. */
  isDeactivated(prefix) {
    const est = (this.byPrefix.get(prefix) ?? []).map((i) => this.messages[i]).filter((m) => ESTABLISHMENT_ILKS.has(ilkOf(m)));
    const last = est[est.length - 1];
    if (!last) return false;
    const ilk = ilkOf(last);
    const n = get(last.serder.sad, "n");
    return (ilk === "rot" || ilk === "drt") && Array.isArray(n) && n.length === 0;
  }

  /**
   * Verify `prefix`'s key event log and return its key state.
   *
   * @returns {KeyState}
   */
  keyState(prefix) {
    const cached = this.verified.get(prefix);
    if (cached) return cached;
    if (this.inProgress.includes(prefix)) {
      kelFail(`delegation cycle: ${prefix} is its own delegator, directly or through ${this.inProgress.length - 1} intermediate identifiers`);
    }
    if (this.inProgress.length >= MAX_DELEGATION_DEPTH) kelFail(`delegation chain deeper than ${MAX_DELEGATION_DEPTH}`);
    this.inProgress.push(prefix);
    let state;
    try {
      state = this.replay(prefix, null);
    } finally {
      this.inProgress.pop();
    }
    this.verified.set(prefix, state);
    return state;
  }

  /**
   * The digests (`d`) of every seal `aid`'s verified key events anchor, as
   * far as this read sees, superseded events included (`anchored_digests`).
   */
  anchoredDigests(aid) {
    this.keyState(aid);
    const out = new Set();
    for (const i of this.byPrefix.get(aid) ?? []) {
      const a = get(this.messages[i].serder.sad, "a");
      if (!Array.isArray(a)) continue;
      for (const seal of a) {
        const d = str(get(seal, "d"));
        if (d !== undefined) out.add(d);
      }
    }
    return out;
  }

  /** Every message whose `t` is `ilk`. */
  messagesWithIlk(ilk) {
    return this.messages.filter((m) => ilkOf(m) === ilk);
  }

  /** The key state at a named establishment event (`Kels::key_state_at`). */
  keyStateAt(aid, said) {
    this.keyState(aid);
    const key = `${aid}\u0000${said}`;
    if (this.atCache.has(key)) {
      const hit = this.atCache.get(key);
      if (hit.error) throw hit.error;
      return hit.state;
    }
    try {
      const named = (this.byPrefix.get(aid) ?? []).map((i) => this.messages[i]).find((m) => saidOf(m) === said);
      if (!named) kelFail(`${aid} has no event with SAID ${said} to sign under`);
      const ilk = ilkOf(named) ?? "";
      if (!ESTABLISHMENT_ILKS.has(ilk)) {
        kelFail(`${said} is a ${JSON.stringify(ilk)} event, not an establishment event, so it names no key state`);
      }
      const state = this.replay(aid, said);
      this.atCache.set(key, { state });
      return state;
    } catch (error) {
      this.atCache.set(key, { error });
      throw error;
    }
  }

  /**
   * Verify a transferable signature group from `signer` over `raw`, under the
   * key state of the establishment event it names, meeting that state's
   * threshold (`Kels::verify_signature_group`).
   */
  verifySignatureGroup(signer, raw, group) {
    if (group.prefix !== signer) kelFail(`signature group is from ${group.prefix}, not ${signer}`);
    const state = this.keyStateAt(signer, group.said);
    let sn;
    try {
      sn = numberValue(group.sn);
    } catch (e) {
      kelFail(`signature group from ${signer}: ${e.message}`);
    }
    if (sn !== BigInt(state.sn)) {
      kelFail(`signature group from ${signer} names establishment event ${group.said} at sn ${sn}, but it is at sn ${state.sn}`);
    }
    const verified = [];
    for (const sig of group.sigs) {
      if (verified.includes(sig.index)) continue;
      const key = state.keys[sig.index];
      if (key === undefined) continue;
      let v;
      try {
        v = verfer(key);
      } catch (e) {
        kelFail(`${signer} key state has an unusable key: ${e.message}`);
      }
      let ok = false;
      try {
        ok = verifySignature(v, raw, sig.raw);
      } catch {
        ok = false;
      }
      if (ok) verified.push(sig.index);
    }
    if (!thresholdSatisfied(state.threshold, verified, state.keys.length)) {
      kelFail(`${verified.length} valid signature(s) from ${signer} do not meet its signing threshold at sn ${state.sn}`);
    }
    return state;
  }

  /**
   * `aid`'s verified KEL as the registry reader takes it: every event of the
   * whole stream, limited to what this read may see (`Kels::issuer_log`).
   */
  issuerLog(aid) {
    this.keyState(aid);
    const cached = this.issuerLogs.get(aid);
    if (cached) return cached;
    const indices = this.fullByPrefix.get(aid);
    if (!indices) kelFail(`keri.cesr carries no key events for ${aid}`);
    const recorded = { events: [], superseded: [] };
    this.replayOver(aid, indices, null, recorded);
    const log = { prefix: aid, events: recorded.events, superseded: recorded.superseded, limit: this.limits.get(aid) ?? null };
    this.issuerLogs.set(aid, log);
    return log;
  }

  replay(prefix, stopAfter) {
    const indices = this.byPrefix.get(prefix);
    if (!indices) kelFail(`keri.cesr carries no key events for ${prefix}`);
    return this.replayOver(prefix, indices, stopAfter, null);
  }

  replayOver(prefix, indices, stopAfter, log) {
    if (!indices.length) kelFail(`keri.cesr carries no events for ${prefix}`);
    const [firstIndex, ...restIndices] = indices;
    const first = this.messages[firstIndex];
    const kever = this.incept(prefix, first);
    this.requireWitnessReceipts(prefix, first, kever.state);
    if (log) log.events.push(logged(first, kever.state, true));
    let accepted = [[firstIndex, 0]];
    const superseded = [];
    if (stopAfter !== null && saidOf(first) === stopAfter) return kever.state;
    let reached = false;
    for (const [n, index] of restIndices.entries()) {
      const msg = this.messages[index];
      const ilk = ilkOf(msg);
      if (ilk === undefined) kelFail(`event ${n + 1} has no ilk: missing field t`);
      const sigs = controllerSigs(msg);
      let state;
      if (ilk === "drt") {
        const proof = this.delegationProof(msg);
        try {
          state = kever.verifyUpdateDelegated(msg.serder, sigs, proof, this);
        } catch (e) {
          if (e instanceof KelError) throw e;
          kelFail(`${prefix} delegated rotation ${n + 1}: ${e.message}`);
        }
      } else {
        try {
          state = kever.verifyUpdate(msg.serder, sigs);
        } catch (e) {
          if (e instanceof KelError) throw e;
          kelFail(`${prefix} event ${n + 1}: ${e.message}`);
        }
      }
      this.requireWitnessReceipts(prefix, msg, state);
      const before = kever.state.sn;
      kever.applyVerifiedUpdate(state);
      const sn = kever.state.sn;
      if (sn <= before) {
        // A superseding rotation: what it superseded leaves the log.
        superseded.push(...accepted.filter(([, s]) => s >= sn).map(([i]) => i));
        accepted = accepted.filter(([, s]) => s < sn);
        if (log) {
          log.superseded.push(...log.events.filter((e) => e.sn >= sn));
          log.events = log.events.filter((e) => e.sn < sn);
        }
      }
      accepted.push([index, sn]);
      if (log) log.events.push(logged(msg, kever.state, ilk !== "ixn"));
      if (stopAfter !== null && saidOf(msg) === stopAfter) {
        reached = true;
        break;
      }
    }
    if (stopAfter === null && !log) this.superseded.set(prefix, superseded);
    if (stopAfter !== null && !reached) kelFail(`${prefix} has no event with SAID ${stopAfter} to verify a signature against`);
    return kever.state;
  }

  requireWitnessReceipts(prefix, msg, state) {
    if (state.backerThreshold === 0) return;
    try {
      verifyWitnessReceipts(msg.serder.raw, this.receiptCouplesFor(msg), state.backers, state.backerThreshold);
    } catch (e) {
      kelFail(`${prefix} event at sn ${state.sn} declares ${state.backerThreshold} of ${state.backers.length} witnesses but ${e.message}`);
    }
  }

  /** Receipt couples attached to `msg`, and those of every `rct` naming it. */
  receiptCouplesFor(msg) {
    const couples = msg.attachments.filter((a) => a.type === "ReceiptCouples").flatMap((a) => a.couples);
    const said = saidOf(msg);
    const prefix = prefixOf(msg);
    const sn = snOfMsg(msg);
    if (said === undefined || prefix === undefined || sn === null) return couples;
    if (!this.receipts) {
      this.receipts = new Map();
      for (const rct of this.messagesWithIlk("rct")) {
        const key = [str(get(rct.serder.sad, "d")), str(get(rct.serder.sad, "i")), str(get(rct.serder.sad, "s"))].join("\u0000");
        if (!this.receipts.has(key)) this.receipts.set(key, []);
        this.receipts.get(key).push(...rct.attachments.filter((a) => a.type === "ReceiptCouples").flatMap((a) => a.couples));
      }
    }
    return couples.concat(this.receipts.get([said, prefix, sn.toString(16)].join("\u0000")) ?? []);
  }

  incept(prefix, msg) {
    const ilk = ilkOf(msg);
    if (ilk === undefined) kelFail(`${prefix} first event has no ilk: missing field t`);
    const verfers = verfersFromEvent(msg.serder.sad);
    const sigs = controllerSigs(msg);
    if (ilk === "icp") {
      try {
        return Kever.incept(msg.serder, sigs, verfers);
      } catch (e) {
        if (e instanceof KelError) throw e;
        return kelFail(`${prefix} inception: ${e.message}`);
      }
    }
    if (ilk === "dip") {
      const proof = this.delegationProof(msg);
      try {
        return Kever.inceptDelegated(msg.serder, sigs, verfers, proof, this);
      } catch (e) {
        if (e instanceof KelError) throw e;
        return kelFail(`${prefix} delegated inception: ${e.message}`);
      }
    }
    return kelFail(`${prefix}'s key event log starts with a ${JSON.stringify(ilk)} event, not an inception`);
  }

  delegationProof(msg) {
    const couples = sealSourceCouples(msg);
    if (!couples.length) {
      kelFail("delegated event carries no seal source couple, so there is nothing pointing at the delegator's authorisation");
    }
    try {
      return delegationProofOf(couples[0][0], couples[0][1]);
    } catch (e) {
      return kelFail(`unreadable seal source couple: ${e.message}`);
    }
  }

  // The delegator lookup (`DelegatorAnchors`): only ever answers from a KEL
  // this stream has verified.

  anchorsAt(delegator, sn, said) {
    try {
      this.keyState(delegator);
    } catch {
      return null;
    }
    const indices = this.byPrefix.get(delegator);
    if (!indices) return null;
    const superseded = this.superseded.get(delegator) ?? [];
    for (const i of indices) {
      if (superseded.includes(i)) continue;
      const msg = this.messages[i];
      const msn = snOfMsg(msg);
      if (msn === null || BigInt(msn) !== sn) continue;
      if (saidOf(msg) !== said) continue;
      const a = get(msg.serder.sad, "a");
      return Array.isArray(a) ? a : [];
    }
    return null;
  }

  delegatorTraits(delegator) {
    try {
      return this.keyState(delegator).config;
    } catch {
      return null;
    }
  }
}

function verfersFromEvent(sad) {
  const keys = get(sad, "k");
  if (!Array.isArray(keys)) kelFail("establishment event has no key list");
  return keys.map((k) => {
    if (typeof k !== "string") kelFail("key list contains a non-string");
    try {
      return verfer(k);
    } catch (e) {
      return kelFail(`key ${JSON.stringify(k)} is not usable: ${e.message}`);
    }
  });
}

