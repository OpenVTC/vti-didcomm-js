// Designations for `./did-webs.js`: credentials an AID issues to itself to
// say something about its own DID document, and the registries that say
// whether each still stands.
//
// A port of `affinidi-keri-core` 0.8.1 `registry.rs` (both registry versions:
// ACDC 1.x credentials in `vcp`/`iss`/`rev` TELs, ACDC 2.x credentials bound
// to `rip`/`bup` blindable registries) and of `affinidi-did-webs` 0.13.1
// `designation.rs`, `aliases.rs`, `key_agreement.rs`,
// `designated_services.rs` and `key_roles.rs`.
//
// Every link is checked. A credential that does not verify contributes
// nothing and is reported as `rejected`. A fault that makes a registry
// meaningless — above all a registry event the issuer's KEL anchors that the
// stream leaves out, which would let a host withhold a revocation — fails
// resolution (`RegistryError`).

import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import {
  b64Encode,
  checkAcdcFields,
  computeSaid,
  digest,
  get,
  matterFromQb64,
  matterQb64,
  numberValue,
  parseUnsigned,
  parseVersionString,
  sadEqual,
  serializeJson,
  str,
  toSafeNumber,
  utf8,
  versionString,
} from "./did-webs-cesr.js";
import { StreamError, thresholdSatisfied, verfer, verifySignature } from "./did-webs-kel.js";

/** A designation registry is broken, or withheld (`DidWebsError::Registry`). */
export class RegistryError extends Error {
  constructor(message) {
    super(message);
    this.name = "RegistryError";
  }
}

/** A key a designation names cannot be published (`DidWebsError::InvalidKey`). */
export class InvalidKeyError extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidKeyError";
  }
}

const registryFail = (message) => {
  throw new RegistryError(message);
};

const isKeri = (m) => m.serder.version?.protocol === "KERI";
const isAcdc = (m) => m.serder.version?.protocol === "ACDC";
const ilkOf = (m) => str(get(m.serder.sad, "t"));
const saidOf = (m) => str(get(m.serder.sad, "d"));
const field = (m, label) => str(get(m.serder.sad, label));

// ─── Registries (affinidi-keri-core `registry.rs`) ──────────────────────

/**
 * @typedef {Object} IssuerLog
 * @property {string} prefix
 * @property {Array<{ sn: number, said: string, seals: any[], establishment: Object|null }>} events
 * @property {Array<{ sn: number, said: string, seals: any[] }>} superseded
 * @property {number|null} limit
 */

function visible(log) {
  return log.events.filter((e) => log.limit === null || e.sn <= log.limit);
}

/** Where the first seal matching `matches` is anchored. */
function anchoring(log, matches) {
  const found = log.events.find((e) => e.seals.some(matches));
  if (found) {
    return log.limit === null || found.sn <= log.limit ? { within: { sn: found.sn, said: found.said } } : { later: true };
  }
  if (log.superseded.some((e) => e.seals.some(matches))) return { later: true };
  return { absent: true };
}

function keyStateAt(log, said) {
  return log.events.find((e) => e.said === said)?.establishment ?? null;
}

function schemaSaid(sad) {
  const s = get(sad, "s");
  if (typeof s === "string") return s;
  if (s instanceof Map) return str(s.get("$id")) ?? null;
  return null;
}

function isCredential(m) {
  if (!isAcdc(m)) return false;
  const t = ilkOf(m);
  return t === undefined || t === "acm";
}

/** Every registry event the issuer's KEL anchors must be in the stream. */
function checkAnchoredEventsPresent(stream, log, saids) {
  const subjects = new Set();
  for (const m of stream) {
    if (!isKeri(m) || !["vcp", "iss", "bis"].includes(ilkOf(m))) continue;
    const d = saidOf(m);
    const i = field(m, "i");
    if (d !== undefined) subjects.add(d);
    if (i !== undefined) subjects.add(i);
  }
  for (const event of visible(log)) {
    for (const seal of event.seals) {
      if (!(seal instanceof Map)) continue;
      const d = str(seal.get("d"));
      if (d === undefined) continue;
      const keys = [...seal.keys()];
      let attributable = false;
      if (keys.length === 2 && keys[0] === "s" && keys[1] === "d") attributable = true;
      else if (keys.length === 3 && keys[0] === "i" && keys[1] === "s" && keys[2] === "d") {
        const i = str(seal.get("i"));
        attributable = i !== undefined && subjects.has(i);
      }
      if (attributable && !saids.has(d)) {
        registryFail(`the issuer's KEL anchors registry event ${d} at sn ${event.sn}, but the stream does not carry it`);
      }
    }
  }
}

function digestCode(said) {
  if (said.startsWith("E")) return "E";
  throw new Error(`${said} is not a Blake3-256 SAID`);
}

function recompute(sad, label, code, kind) {
  try {
    return computeSaid(sad, label, code, kind);
  } catch (e) {
    throw new Error(`cannot compute the SAID: ${e.message}`);
  }
}

function verifyPlainSaid(m) {
  const said = saidOf(m);
  if (said === undefined) throw new Error("the message has no SAID");
  const computed = recompute(m.serder.sad, "d", digestCode(said), m.serder.kind);
  if (computed !== said) throw new Error(`the message's SAID is ${said}, but its content gives ${computed}`);
  return said;
}

/** ACDC 1.x: a signed credential in a 1.x TEL. Returns a credential, null, or a rejection. */
function credentialV1(stream, log, m) {
  const sad = m.serder.sad;
  let said;
  try {
    checkAcdcFields(sad, 1, null);
    said = verifyPlainSaid(m);
    verifySignedBy(log, m);
  } catch (e) {
    return { rejected: e.message };
  }
  const registry = field(m, "ri");
  if (registry === undefined) return { rejected: "the credential names no registry (`ri`)" };
  const vcp = stream.find((x) => isKeri(x) && ilkOf(x) === "vcp" && saidOf(x) === registry);
  if (!vcp) return { rejected: `registry ${registry} has no inception event in the stream` };
  if (field(vcp, "ii") !== log.prefix) return { rejected: `registry ${registry} was not incepted by ${log.prefix}` };
  const inception = anchoredV1(log, registry, 0, registry);
  if (inception.later) return null;
  if (inception.absent) registryFail(`registry event ${registry} is not anchored in the issuer's KEL`);

  const iss = stream.find((x) => isKeri(x) && ilkOf(x) === "iss" && field(x, "i") === said);
  if (!iss) return { rejected: `no issuance event for credential ${said}` };
  if (field(iss, "ri") !== registry) return { rejected: `credential ${said} was issued in another registry than it names` };
  const issSaid = saidOf(iss) ?? "";
  const issued = anchoredV1(log, said, 0, issSaid);
  if (issued.later) return null;
  if (issued.absent) registryFail(`registry event ${issSaid} is not anchored in the issuer's KEL`);

  for (const rev of stream.filter((x) => isKeri(x) && ["rev", "brv"].includes(ilkOf(x)) && field(x, "i") === said)) {
    const revSaid = saidOf(rev) ?? "";
    // A sequence number that does not parse is taken as 1, as the Rust does.
    const sn = parseUnsigned(field(rev, "s"), 16) ?? 1n;
    const revoked = anchoredV1(log, said, sn, revSaid);
    if (revoked.within) {
      return { credential: { said, version: 1, registry, anchor: revoked.within, event: revSaid, status: "revoked", sad } };
    }
    if (revoked.absent) registryFail(`registry event ${revSaid} is not anchored in the issuer's KEL`);
  }
  return { credential: { said, version: 1, registry, anchor: issued.within, event: issSaid, status: "issued", sad } };
}

function anchoredV1(log, i, sn, d) {
  const s = sn.toString(16);
  return anchoring(log, (seal) => str(get(seal, "i")) === i && str(get(seal, "s")) === s && str(get(seal, "d")) === d);
}

/** The credential carries the issuer's signatures, meeting its threshold then. */
function verifySignedBy(log, m) {
  let group = null;
  for (const a of m.attachments) {
    if (a.type !== "TransIdxSigGroups") continue;
    group = a.groups.find((g) => g.prefix === log.prefix) ?? null;
    if (group) break;
  }
  if (!group) throw new Error(`the credential carries no signature group from ${log.prefix}`);
  const state = keyStateAt(log, group.said);
  if (!state) throw new Error(`the signature group names establishment event ${group.said}, which the KEL does not hold`);
  const sn = numberValue(group.sn);
  if (sn !== BigInt(state.sn)) {
    throw new Error(`the signature group names establishment event ${group.said} at sn ${sn}, but it is at sn ${state.sn}`);
  }
  const indices = [];
  for (const sig of group.sigs) {
    const key = state.keys[sig.index];
    if (key === undefined) throw new Error(`signature index ${sig.index} is out of range`);
    if (verifySignature(verfer(key), m.serder.raw, sig.raw) && !indices.includes(sig.index)) indices.push(sig.index);
  }
  if (!thresholdSatisfied(state.threshold, indices, state.keys.length)) {
    throw new Error("the credential's signatures do not meet the signing threshold");
  }
}

/** ACDC 2.x: an unsigned credential bound to a `rip` + `bup` registry. */
function credentialV2(stream, log, m) {
  const sad = m.serder.sad;
  let said;
  try {
    checkAcdcFields(sad, 2, ilkOf(m) ?? null);
    said = verifyCompactSaid(sad, m.serder.kind);
  } catch (e) {
    return { rejected: e.message };
  }
  const registry = field(m, "rd");
  if (registry === undefined) return { rejected: "the credential names no registry (`rd`)" };
  const rip = stream.find((x) => isAcdc(x) && ilkOf(x) === "rip" && saidOf(x) === registry);
  if (!rip) return { rejected: `registry ${registry} has no inception event in the stream` };
  try {
    registryEvent(rip, "rip");
  } catch (e) {
    return { rejected: e.message };
  }
  if (field(rip, "i") !== log.prefix) return { rejected: `registry ${registry} was not incepted by ${log.prefix}` };
  if (field(rip, "n") !== "0") registryFail(`registry ${registry} is broken: its inception is not at n 0`);
  const inception = anchoredV2(log, registry);
  if (inception.later) return null;
  if (inception.absent) registryFail(`registry event ${registry} is not anchored in the issuer's KEL`);

  const updates = chain(stream, log, registry);
  for (let k = updates.length - 1; k >= 0; k--) {
    const [update, anchor] = updates[k];
    const b = field(update, "b") ?? "";
    const updateSaid = saidOf(update) ?? "";
    const disclosed = update.attachments.filter((a) => a.type === "BlindedStates").flatMap((a) => a.states).filter((s) => s.blid === b);
    if (disclosed.length !== 1) registryFail(`registry update ${updateSaid} carries no disclosure of its state`);
    const [state] = disclosed;
    try {
      verifyBlid(state);
    } catch (e) {
      registryFail(`registry ${registry} is broken: update ${updateSaid}: ${e.message}`);
    }
    const td = state.acdc === "1AAP" ? null : state.acdc;
    const ts = labelText(state.state);
    if (td === null && ts === "") continue; // vacuous: a placeholder
    let status;
    if (ts === "issued") status = "issued";
    else if (ts === "revoked") status = "revoked";
    else registryFail(`registry update ${updateSaid} discloses state ${JSON.stringify(state.state)}, which is neither issued nor revoked`);
    if (td !== said) return { rejected: `registry ${registry}'s latest state binds ${td ?? ""}, not this credential` };
    return { credential: { said, version: 2, registry, anchor, event: updateSaid, status, sad } };
  }
  return null;
}

function registryEvent(m, ilk) {
  checkAcdcFields(m.serder.sad, 2, ilk);
  verifyPlainSaid(m);
}

/** A 2.x registry event is anchored by any seal carrying its SAID, or its SAID alone. */
function anchoredV2(log, said) {
  return anchoring(log, (seal) => (typeof seal === "string" ? seal === said : str(get(seal, "d")) === said));
}

/** The registry's updates the read may see, in order, each with its anchor. */
function chain(stream, log, registry) {
  const broken = (reason) => registryFail(`registry ${registry} is broken: ${reason}`);
  const seen = [];
  for (const m of stream) {
    if (!(isAcdc(m) && ilkOf(m) === "bup" && field(m, "rd") === registry)) continue;
    try {
      registryEvent(m, "bup");
    } catch (e) {
      broken(e.message);
    }
    const said = saidOf(m) ?? "";
    const n = toSafeNumber(parseUnsigned(field(m, "n"), 16));
    if (n === null) broken(`update ${said} has no hex sequence number`);
    if (n === 0) broken(`update ${said} is at n 0, which is the inception's`);
    const a = anchoredV2(log, said);
    if (a.within) seen.push([n, m, a.within]);
    else if (a.absent) registryFail(`registry event ${said} is not anchored in the issuer's KEL`);
  }
  seen.sort((x, y) => x[0] - y[0]);
  const out = [];
  let prior = registry;
  let expect = 1;
  for (let k = 0; k < seen.length; ) {
    const n = seen[k][0];
    let end = k;
    while (end < seen.length && seen[end][0] === n) end++;
    if (n !== expect) broken(`no update at n ${expect}, but one at n ${n}`);
    const saids = seen.slice(k, end).map(([, m]) => saidOf(m)).filter((s) => s !== undefined);
    if (saids.some((s) => s !== saids[0])) registryFail(`registry ${registry} has more than one anchored event at n ${n}`);
    const [, m, a] = seen[k];
    if (field(m, "p") !== prior) broken(`the update at n ${n} does not name the one before it`);
    prior = saidOf(m) ?? "";
    out.push([m, a]);
    expect++;
    k = end;
  }
  return out;
}

function verifyBlid(state) {
  const code = digestCode(state.blid);
  const text = "#".repeat(state.blid.length) + state.uuid + state.acdc + state.state;
  if (digest(code, utf8(text)) !== state.blid) {
    throw new Error(`its disclosed state does not reproduce its BLID ${state.blid}`);
  }
}

/** The text of a CESR label: empty, or a fixed-size tag. */
function labelText(qb64) {
  if (qb64 === "1AAP") return "";
  let start;
  if (qb64.startsWith("0J") || qb64.startsWith("0L")) start = 3;
  else if (qb64.startsWith("0K") || qb64.startsWith("0M")) start = 2;
  else if (qb64.startsWith("X") || qb64.startsWith("Y")) start = 1;
  else if (qb64.startsWith("1AAF") || qb64.startsWith("1AAN")) start = 4;
  else return null;
  return qb64.length >= start ? qb64.slice(start) : null;
}

/**
 * An ACDC 2.x SAID is computed over its most compact form: each expanded
 * section replaced by its own SAID, the version string sized for that form.
 */
function verifyCompactSaid(sad, kind) {
  const said = str(get(sad, "d"));
  if (said === undefined) throw new Error("the credential has no SAID");
  const code = digestCode(said);
  const compact = new Map(sad);
  for (const label of ["s", "a", "e", "r"]) {
    const section = compact.get(label);
    if (!(section instanceof Map)) continue;
    compact.set(label, label === "s" ? recompute(section, "$id", code, kind) : compactSection(section, code, kind));
  }
  if (compact.has("A") && typeof compact.get("A") !== "string") {
    throw new Error("an expanded aggregate section (`A`) is not supported");
  }
  if (kind !== "CESR") {
    compact.set("d", "#".repeat(said.length));
    const size = utf8(serializeJson(compact)).length;
    const vs = str(compact.get("v"));
    if (vs === undefined) throw new Error("the credential has no version");
    const version = parseVersionString(vs);
    compact.set("v", versionString({ ...version, size }));
  }
  const computed = recompute(compact, "d", code, kind);
  if (computed !== said) throw new Error(`the credential's SAID is ${said}, but its compact form gives ${computed}`);
  return said;
}

function compactSection(section, code, kind) {
  const copy = new Map(section);
  for (const [k, v] of copy) {
    if (v instanceof Map && v.has("d")) copy.set(k, compactSection(v, code, kind));
  }
  return recompute(copy, "d", code, kind);
}

/**
 * The credentials of `schema` the log's issuer issued, each with its status,
 * as of the log's limit (`registry::designations`).
 */
function registryDesignations(stream, log, schema, saids) {
  checkAnchoredEventsPresent(stream, log, saids);
  const out = { credentials: [], rejected: [] };
  for (const m of stream) {
    if (!isCredential(m)) continue;
    const sad = m.serder.sad;
    if (str(get(sad, "i")) !== log.prefix) continue;
    if (schemaSaid(sad) !== schema) continue;
    const said = str(get(sad, "d")) ?? "";
    const major = m.serder.version?.major;
    let found;
    if (major === 1) found = credentialV1(stream, log, m);
    else if (major === 2) found = credentialV2(stream, log, m);
    else found = { rejected: `ACDC protocol version ${major ?? "None"} is not supported` };
    if (found?.credential) out.credentials.push(found.credential);
    else if (found?.rejected !== undefined) out.rejected.push([said, found.rejected]);
  }
  return out;
}

// ─── Designations (affinidi-did-webs `designation.rs`) ──────────────────

/** Schema SAIDs, both versions of each designation. */
export const DESIGNATED_ALIASES_SCHEMA = "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5";
export const DESIGNATED_ALIASES_SCHEMA_V2 = "EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA";
export const KEY_AGREEMENT_SCHEMA = "EJZrf6N4vbhA1hQIujWiIiQmNi455EGS3iXdhxLSwvAi";
export const KEY_AGREEMENT_SCHEMA_V2 = "EIW1ONwnh_dkiDZ3_xmUsBxh7X5u7luVOuCoRdCl3jPZ";
export const SERVICE_SCHEMA = "ELj0Sdf2Boi7BMiIFAEJ9_MSFJU8t-LavLN-gMb8oXM8";
export const SERVICE_SCHEMA_V2 = "EJVZ789syil6R--yix7j8X4g_mHZCDIaSWM15MgkFQgG";
export const KEY_ROLE_SCHEMA = "EPulJFl5SEb8qb3ca5teXHRGiWmTsTkylGTrS2vB4ZQx";
export const KEY_ROLE_SCHEMA_V2 = "EBMCaUhHZqulCtix3fzRRsdW0_gfT3bMLsrp3c3ixpxx";

/** Every designation schema this resolver implements. */
export const IMPLEMENTED_SCHEMAS = Object.freeze([
  DESIGNATED_ALIASES_SCHEMA,
  DESIGNATED_ALIASES_SCHEMA_V2,
  KEY_AGREEMENT_SCHEMA,
  KEY_AGREEMENT_SCHEMA_V2,
  SERVICE_SCHEMA,
  SERVICE_SCHEMA_V2,
  KEY_ROLE_SCHEMA,
  KEY_ROLE_SCHEMA_V2,
]);

function streamSaids(kels) {
  kels.saidSet ??= new Set(kels.messages.map((m) => saidOf(m)).filter((d) => d !== undefined));
  return kels.saidSet;
}

/**
 * Every credential of one of `schemas` `aid` issued to itself that verifies,
 * each with whether it has since been revoked (`issued_designations`).
 * `rejected.reason` keeps the first reason one did not verify.
 */
export function issuedDesignations(kels, aid, schemas, rejected) {
  kels.keyState(aid);
  const log = kels.issuerLog(aid);
  const out = [];
  for (const schema of schemas) {
    const found = registryDesignations(kels.messages, log, schema, streamSaids(kels));
    if (found.rejected.length) {
      const [said, reason] = found.rejected[0];
      rejected.reason ??= `designation ${said}: ${reason}`;
    }
    for (const credential of found.credentials) {
      const attributes = get(credential.sad, "a");
      if (!(attributes instanceof Map)) {
        rejected.reason ??= `designation ${credential.said} carries no attribute block`;
        continue;
      }
      out.push([{ said: credential.said, version: credential.version, registry: credential.registry, event: credential.event, attributes }, credential.status === "revoked"]);
    }
  }
  return out;
}

/** The standing (unrevoked) designations of `schemas`. */
export function designations(kels, aid, schemas, rejected) {
  return issuedDesignations(kels, aid, schemas, rejected).filter(([, withdrawn]) => !withdrawn).map(([d]) => d);
}

/** The most schemas `unsupportedCritical` checks for a standing critical designation. */
const MAX_UNIMPLEMENTED_CRITICAL_SCHEMAS = 16;

/**
 * The schema of the first standing designation `aid` issued that is marked
 * `critical` and that this resolver does not implement, or null (P6).
 */
export function unsupportedCritical(kels, aid, implemented = IMPLEMENTED_SCHEMAS) {
  const anchored = kels.anchoredDigests(aid);
  const schemas = [];
  for (const m of kels.messages) {
    if (!isAcdc(m) || field(m, "i") !== aid) continue;
    const sad = m.serder.sad;
    const s = get(sad, "s");
    let schema;
    if (typeof s === "string") schema = s;
    else if (s === undefined) continue;
    else {
      schema = str(get(s, "$id"));
      if (schema === undefined) continue;
    }
    // Only a credential marked critical, in a registry whose inception the
    // verified log anchors, can stand as a critical designation.
    const markedCritical = get(get(sad, "a"), "critical") === true;
    const registryAnchored = ["ri", "rd"].some((f) => {
      const r = str(get(sad, f));
      return r !== undefined && anchored.has(r);
    });
    if (markedCritical && registryAnchored && !implemented.includes(schema) && !schemas.includes(schema)) {
      if (schemas.length === MAX_UNIMPLEMENTED_CRITICAL_SCHEMAS) {
        throw new StreamError(
          `keri.cesr carries credentials marked critical under more than ${MAX_UNIMPLEMENTED_CRITICAL_SCHEMAS} schemas this resolver does not implement`,
        );
      }
      schemas.push(schema);
    }
  }
  for (const schema of schemas) {
    const standing = designations(kels, aid, [schema], {});
    if (standing.some((d) => d.attributes.get("critical") === true)) return schema;
  }
  return null;
}

// ─── Designated aliases (affinidi-did-webs `aliases.rs`) ────────────────

/** The aliases `aid` has designated (`a.ids` of every standing attestation). */
export function designatedAliases(kels, aid) {
  const rejected = {};
  const aliases = [];
  for (const attestation of designations(kels, aid, [DESIGNATED_ALIASES_SCHEMA, DESIGNATED_ALIASES_SCHEMA_V2], rejected)) {
    const ids = get(attestation.attributes, "ids");
    if (!Array.isArray(ids)) {
      rejected.reason ??= "attestation carries no `a.ids` list";
      continue;
    }
    for (const alias of ids) {
      if (typeof alias === "string" && !aliases.includes(alias)) aliases.push(alias);
    }
  }
  return { aliases, rejected: rejected.reason ?? null };
}

// ─── Keys and JWKs ──────────────────────────────────────────────────────

/** A JWK as `affinidi-crypto` renders a public key, with its CESR form as `kid`. */
function okpJwk(crv, raw, kid) {
  return { crv, kid, kty: "OKP", x: b64Encode(raw) };
}

function ecJwk(code, raw, kid) {
  const curve = code === "1AAA" || code === "1AAB" ? secp256k1 : p256;
  let point;
  try {
    point = curve.Point.fromBytes(raw);
  } catch (e) {
    throw new InvalidKeyError(`not a valid public key: ${e.message}`);
  }
  const bytes = point.toBytes(false);
  return { crv: curve === secp256k1 ? "secp256k1" : "P-256", kid, kty: "EC", x: b64Encode(bytes.subarray(1, 33)), y: b64Encode(bytes.subarray(33)) };
}

/**
 * A key-state key as a JWK (`document::jwk_from_cesr_key`). Throws a plain
 * Error, which the document builder reports as a key event log failure.
 */
export function jwkFromCesrKey(qb64) {
  let m;
  try {
    m = matterFromQb64(qb64);
  } catch (e) {
    throw new Error(`key ${JSON.stringify(qb64)} is not a CESR primitive: ${e.message}`);
  }
  switch (m.code) {
    case "B":
    case "D":
      return okpJwk("Ed25519", m.raw, qb64);
    case "1AAA":
    case "1AAB":
    case "1AAI":
    case "1AAJ":
      try {
        return ecJwk(m.code, m.raw, qb64);
      } catch (e) {
        throw new Error(`key ${JSON.stringify(qb64)} is not a valid public key: ${e.message}`);
      }
    default:
      throw new Error(`key ${JSON.stringify(qb64)} uses CESR code ${JSON.stringify(m.code)}, which this implementation cannot express as a JWK`);
  }
}

/** A key designated for key agreement (`KeyAgreementKey::from_cesr`). */
export function keyAgreementKey(qb64) {
  let m;
  try {
    m = matterFromQb64(qb64);
  } catch (e) {
    throw new InvalidKeyError(`${JSON.stringify(qb64)} is not a CESR primitive: ${e.message}`);
  }
  switch (m.code) {
    case "C":
      if (m.raw.length !== 32) throw new InvalidKeyError(`${JSON.stringify(qb64)} is not 32 bytes`);
      return { code: "C", raw: m.raw };
    case "1AAI":
    case "1AAJ":
      return { code: "1AAJ", raw: m.raw };
    case "1AAA":
    case "1AAB":
      return { code: "1AAB", raw: m.raw };
    default:
      throw new InvalidKeyError(`${JSON.stringify(qb64)} uses CESR code ${JSON.stringify(m.code)}, which is not a key agreement key type`);
  }
}

/** A key agreement key as a JWK, `kid` its CESR encoding (`public_jwk`). */
export function keyAgreementJwk(key) {
  let kid;
  try {
    kid = matterQb64(key.code, key.raw);
  } catch (e) {
    throw new InvalidKeyError(`cannot encode the key: ${e.message}`);
  }
  if (key.code === "C") return okpJwk("X25519", key.raw, kid);
  return ecJwk(key.code, key.raw, kid);
}

/** A key that signs (`VerificationKey::from_cesr`). */
function verificationKey(qb64) {
  let m;
  try {
    m = matterFromQb64(qb64);
  } catch (e) {
    throw new InvalidKeyError(`${JSON.stringify(qb64)} is not a CESR primitive: ${e.message}`);
  }
  if (["B", "D", "1AAI", "1AAJ", "1AAA", "1AAB"].includes(m.code)) return m;
  throw new InvalidKeyError(`${JSON.stringify(qb64)} uses CESR code ${JSON.stringify(m.code)}, which is not a verification key`);
}

const P = 2n ** 255n - 19n;

function modPow(b, e, m) {
  let r = 1n;
  let x = b % m;
  let k = e;
  while (k > 0n) {
    if (k & 1n) r = (r * x) % m;
    x = (x * x) % m;
    k >>= 1n;
  }
  return r;
}

/**
 * The X25519 keys converted from a key state's Ed25519 keys, CESR-encoded
 * (`converted_key_agreement`). A key that does not decode to a curve point,
 * or is of small order, converts to nothing.
 */
export function convertedKeyAgreement(stateKeys) {
  const out = [];
  for (const key of stateKeys) {
    let m;
    try {
      m = matterFromQb64(key);
    } catch {
      continue;
    }
    if (m.code !== "D" && m.code !== "B") continue;
    if (m.raw.length !== 32) continue;
    let point;
    try {
      point = ed25519.Point.fromBytes(m.raw, true);
    } catch {
      continue;
    }
    if (point.isSmallOrder()) continue;
    // u = (1 + y) / (1 - y), as ed25519-dalek `to_montgomery`.
    const { y } = point.toAffine();
    const u = (((1n + y) % P) * modPow((P + 1n - y) % P, P - 2n, P)) % P;
    const bytes = new Uint8Array(32);
    let v = u;
    for (let k = 0; k < 32; k++) {
      bytes[k] = Number(v & 255n);
      v >>= 8n;
    }
    const qb64 = matterQb64("C", bytes);
    if (!out.includes(qb64)) out.push(qb64);
  }
  return out;
}

// ─── Key agreement designations (affinidi-did-webs `key_agreement.rs`) ─

/** The key agreement keys `aid` has designated. */
export function designatedKeyAgreement(kels, aid) {
  const rejected = {};
  const issued = issuedDesignations(kels, aid, [KEY_AGREEMENT_SCHEMA, KEY_AGREEMENT_SCHEMA_V2], rejected);
  const keys = [];
  for (const [designation, withdrawn] of issued) {
    if (withdrawn) continue;
    let found;
    try {
      found = readKeys(designation.attributes);
    } catch (e) {
      rejected.reason ??= e.message;
      continue;
    }
    for (const key of found) if (!keys.includes(key)) keys.push(key);
  }
  return { keys, rejected: rejected.reason ?? null, issued: issued.length > 0 };
}

function readKeys(attributes) {
  const keys = get(attributes, "keys");
  if (!Array.isArray(keys) || !keys.length) throw new Error("key agreement designation carries no `a.keys`");
  return keys.map((k) => {
    if (typeof k !== "string") throw new Error("a designated key is not a string");
    keyAgreementJwk(keyAgreementKey(k));
    return k;
  });
}

// ─── Designated services (affinidi-did-webs `designated_services.rs`) ───

/** The services `aid` has designated, as plain JSON entries. */
export function designatedServices(kels, aid) {
  const rejected = {};
  const services = [];
  for (const designation of designations(kels, aid, [SERVICE_SCHEMA, SERVICE_SCHEMA_V2], rejected)) {
    let found;
    try {
      found = readServices(designation.attributes);
    } catch (e) {
      rejected.reason ??= e.message;
      continue;
    }
    for (const service of found) {
      if (services.some((s) => sadEqual(s.get("id"), service.get("id")))) continue;
      services.push(service);
    }
  }
  return { services, rejected: rejected.reason ?? null };
}

function readServices(attributes) {
  const services = get(attributes, "services");
  if (!Array.isArray(services) || !services.length) throw new Error("service designation carries no `a.services`");
  for (const s of services) checkService(s);
  return services;
}

/** Whether an entry is a service a DID document can carry (`check_service`). */
export function checkService(service) {
  const id = str(get(service, "id"));
  if (id === undefined) throw new Error("a designated service has no `id`");
  if (!id.startsWith("#") || utf8(id).length < 2 || id.slice(1).includes("#")) {
    throw new Error(`designated service id ${JSON.stringify(id)} is not a relative DID URL fragment`);
  }
  const type = get(service, "type");
  const typeOk =
    (typeof type === "string" && type !== "") ||
    (Array.isArray(type) && type.length > 0 && type.every((t) => typeof t === "string" && t !== ""));
  if (!typeOk) throw new Error(`designated service ${id} has no usable \`type\``);
  const endpoint = get(service, "serviceEndpoint");
  if (!(typeof endpoint === "string" || endpoint instanceof Map || Array.isArray(endpoint))) {
    throw new Error(`designated service ${id} has no \`serviceEndpoint\``);
  }
}

// ─── Key roles (affinidi-did-webs `key_roles.rs`) ───────────────────────

/** The registered key roles, in the order a document lists them. */
export const KEY_ROLES = Object.freeze([
  { name: "attestation", relationship: "assertionMethod" },
  { name: "operational", relationship: "authentication" },
  { name: "messaging", relationship: "keyAgreement" },
]);

/** The JWK of a key bound to `role`, or a throw saying why it cannot be. */
export function roleKeyJwk(role, qb64) {
  if (role === "messaging") return keyAgreementJwk(keyAgreementKey(qb64));
  verificationKey(qb64);
  return jwkFromCesrKey(qb64);
}

/** The JWK of a revoked key, whichever kind it was. */
export function revokedKeyJwk(qb64) {
  try {
    return roleKeyJwk("operational", qb64);
  } catch {
    return roleKeyJwk("messaging", qb64);
  }
}

function rawOf(qb64) {
  try {
    return matterFromQb64(qb64).raw;
  } catch {
    return null;
  }
}

const sameBytes = (a, b) => a !== null && b !== null && a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Parse an RFC 3339 date-time as `chrono::DateTime::parse_from_rfc3339`
 * does, to an instant `[seconds since the epoch, nanoseconds]`, or null.
 */
export function parseRfc3339(s) {
  if (typeof s !== "string") return null;
  const bytes = utf8(s);
  if (bytes.length < 19) return null;
  const d = (k) => (bytes[k] >= 0x30 && bytes[k] <= 0x39 ? bytes[k] - 0x30 : null);
  const two = (k) => {
    const a = d(k);
    const b = d(k + 1);
    return a === null || b === null ? null : a * 10 + b;
  };
  const y = [0, 1, 2, 3].map(d);
  if (y.includes(null)) return null;
  const year = y[0] * 1000 + y[1] * 100 + y[2] * 10 + y[3];
  if (bytes[4] !== 0x2d) return null;
  const month = two(5);
  if (month === null || bytes[7] !== 0x2d) return null;
  const day = two(8);
  if (day === null) return null;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1]) return null;
  if (![0x74, 0x54, 0x20].includes(bytes[10])) return null;
  const hour = two(11);
  if (hour === null || bytes[13] !== 0x3a) return null;
  const minute = two(14);
  if (minute === null || bytes[16] !== 0x3a) return null;
  let sec = two(17);
  if (sec === null) return null;
  let nano = 0;
  if (sec === 60) {
    sec = 59;
    nano = 1_000_000_000;
  }
  let k = 19;
  if (bytes[19] === 0x2e) {
    k = 20;
    let digits = "";
    while (k < bytes.length && d(k) !== null) {
      if (digits.length < 9) digits += String(d(k));
      k++;
    }
    if (!digits.length) return null;
    nano += Number(digits.padEnd(9, "0"));
  }
  if (hour > 23 || minute > 59 || sec > 59 || nano >= 2_000_000_000 || (nano >= 1_000_000_000 && sec !== 59)) return null;
  let offset;
  const rest = s.slice(new TextDecoder().decode(bytes.subarray(0, k)).length);
  if (rest === "Z" || rest === "z") offset = 0;
  else {
    const m = /^([+\-\u2212])([0-9]{2}):([0-9]{2})$/.exec(rest);
    if (!m) return null;
    const oh = Number(m[2]);
    const om = Number(m[3]);
    if (om > 59) return null;
    offset = (oh * 3600 + om * 60) * (m[1] === "+" ? 1 : -1);
    if (Math.abs(offset) >= 86400) return null;
  }
  // Days from the civil date (proleptic Gregorian), then the instant.
  const yy = month <= 2 ? year - 1 : year;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const mp = (month + 9) % 12;
  const doy = Math.floor((153 * mp + 2) / 5) + day - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  const epochDays = era * 146097 + doe - 719468;
  return [epochDays * 86400 + hour * 3600 + minute * 60 + sec - offset, nano];
}

/** Order two instants from {@link parseRfc3339}. */
export function compareInstants(a, b) {
  return a[0] !== b[0] ? a[0] - b[0] : a[1] - b[1];
}

/** What resolution reads from `aid`'s key role designations. */
export function designatedKeyRoles(kels, aid) {
  const state = kels.keyState(aid);
  const rejected = {};
  let issued = issuedDesignations(kels, aid, [KEY_ROLE_SCHEMA, KEY_ROLE_SCHEMA_V2], rejected);
  const out = { issued: issued.length > 0, roles: [], revoked: [], rejected: null };
  issued = issued.filter(([designation]) => {
    const marked = designation.attributes.get("critical") === true;
    if (designation.version >= 2 && !marked) {
      rejected.reason ??= `key role designation ${designation.said} is not marked critical`;
      return false;
    }
    return true;
  });

  const revoked = [];
  for (const [designation] of issued) {
    let entries;
    try {
      entries = readRevoked(designation.attributes);
    } catch (e) {
      rejected.reason ??= e.message;
      continue;
    }
    for (const [entry, at] of entries) {
      const existing = revoked.find(([r]) => r.key === entry.key);
      if (!existing) revoked.push([entry, at]);
      else if (compareInstants(at, existing[1]) < 0) {
        existing[0] = entry;
        existing[1] = at;
      }
    }
  }
  out.revoked = revoked.map(([r]) => r);

  const standing = issued.filter(([, withdrawn]) => !withdrawn);
  if (standing.length === 1) {
    try {
      out.roles = readRoles(standing[0][0].attributes, state.keys, state.nextKeys, out.revoked);
    } catch (e) {
      rejected.reason ??= e.message;
    }
  } else if (standing.length > 1) {
    rejected.reason ??= "more than one key role designation stands";
  }
  out.rejected = rejected.reason ?? null;
  return out;
}

function readRevoked(attributes) {
  const entries = get(attributes, "revoked");
  if (entries === undefined) return [];
  if (!Array.isArray(entries)) throw new Error("`a.revoked` is not a list");
  return entries.map((entry) => {
    const key = str(get(entry, "key"));
    if (key === undefined) throw new Error("a revoked entry names no key");
    try {
      revokedKeyJwk(key);
    } catch (e) {
      throw new Error(`revoked key ${key}: ${e.message}`);
    }
    const at = str(get(entry, "compromisedAt"));
    if (at === undefined) throw new Error(`revoked key ${key} has no compromise time`);
    const parsed = parseRfc3339(at);
    if (!parsed) throw new Error(`revoked key ${key}: compromise time ${JSON.stringify(at)} is not RFC 3339`);
    return [{ key, compromisedAt: at }, parsed];
  });
}

function readRoles(attributes, keysInState, nextKeys, revoked) {
  const roles = get(attributes, "roles");
  if (!(roles instanceof Map)) throw new Error("key role designation carries no `a.roles`");
  const seen = [];
  const out = [];
  for (const role of KEY_ROLES) {
    // A role the reader does not recognise is never asked for (VTI-KEY-074).
    const keys = roles.get(role.name);
    if (keys === undefined) continue;
    if (!Array.isArray(keys) || !keys.length) throw new Error(`role ${role.name} lists no keys`);
    const listed = [];
    for (const key of keys) {
      if (typeof key !== "string") throw new Error(`a ${role.name} key is not a string`);
      try {
        roleKeyJwk(role.name, key);
      } catch (e) {
        throw new Error(`${role.name} key ${key}: ${e.message}`);
      }
      checkRoleKey(key, keysInState, nextKeys, revoked);
      const raw = rawOf(key);
      if (raw === null) throw new Error(`${key} is not a CESR primitive`);
      if (seen.some((s) => sameBytes(s, raw))) throw new Error(`${key} is bound to more than one role`);
      seen.push(raw);
      listed.push(key);
    }
    out.push([role, listed]);
  }
  return out;
}

/** A role key is never a key-state key, a committed next key, or revoked. */
function checkRoleKey(qb64, keysInState, nextKeys, revoked) {
  const raw = rawOf(qb64);
  if (raw === null) throw new Error(`${qb64} is not a CESR primitive`);
  if (keysInState.some((k) => sameBytes(rawOf(k), raw))) throw new Error(`${qb64} is a key of the identifier's key state`);
  let committed = false;
  try {
    committed = nextKeys.includes(digest("E", utf8(qb64)));
  } catch {
    committed = false;
  }
  if (committed) throw new Error(`${qb64} is a key the identifier's key state has committed to rotate to`);
  if (revoked.some((r) => sameBytes(rawOf(r.key), raw))) throw new Error(`${qb64} is revoked for compromise`);
}

