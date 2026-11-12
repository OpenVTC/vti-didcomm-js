// Conformance vectors recorded from `affinidi-did-webs` 0.13.1, the Rust
// reference this library's did:webs resolver is ported from. See
// `test/fixtures/did-webs/rust-vectors/README.md` for how they were made.
//
// Each record is one call the Rust crate answered — a resolution, a key state,
// a set of endpoints or designations — with its inputs and its answer. A
// record with `mutation` names a change to its base stream; it is applied here
// exactly as the generator applied it, so a mutated stream need not be stored.

import { readFileSync, readdirSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveFromArtifacts, internals } from "../src/did-webs.js";
import { thresholdJson } from "../src/did-webs-kel.js";

const HERE = dirname(fileURLToPath(import.meta.url));
export const VECTORS = resolve(HERE, "fixtures", "did-webs", "rust-vectors");

/** Every record, by the Rust test file it came from. */
export function loadVectors() {
  const out = new Map();
  for (const name of readdirSync(VECTORS).sort()) {
    let text;
    if (name.endsWith(".jsonl")) text = readFileSync(resolve(VECTORS, name), "utf8");
    else if (name.endsWith(".jsonl.gz")) text = gunzipSync(readFileSync(resolve(VECTORS, name))).toString("utf8");
    else continue;
    const records = text.split("\n").filter(Boolean).map((line) => JSON.parse(line));
    out.set(name.replace(/\.jsonl(\.gz)?$/, ""), records);
  }
  return out;
}

const blobs = new Map();
function blob(name) {
  if (name === null || name === undefined) return null;
  if (!blobs.has(name)) blobs.set(name, new Uint8Array(readFileSync(resolve(VECTORS, "blobs", name))));
  return blobs.get(name);
}

/** Apply a recorded mutation to its base stream. */
export function mutate(base, m) {
  if (!m) return base;
  if (m.type === "replace") {
    const out = base.slice();
    out[m.at] = m.byte;
    return out;
  }
  if (m.type === "splice") {
    const insert = m.insert ? base.slice(m.insert[0], m.insert[1]) : new Uint8Array(0);
    const out = new Uint8Array(m.start + insert.length + base.length - m.end);
    out.set(base.subarray(0, m.start));
    out.set(insert, m.start);
    out.set(base.subarray(m.end), m.start + insert.length);
    return out;
  }
  if (m.type === "swap") {
    const [as, ae] = m.a;
    const [bs, be] = m.b;
    const parts = [base.subarray(0, as), base.subarray(bs, be), base.subarray(as, ae), base.subarray(be)];
    const out = new Uint8Array(base.length);
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }
  throw new Error(`unknown mutation ${m.type}`);
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys(value[k])]));
  }
  return value;
}

/**
 * A resolved document as `affinidi_did_common::Document` serializes it: a
 * service `type` is always a list, and a service endpoint that is a URL is
 * written as the URL parser normalizes it. Both are properties of that Rust
 * type, not of did:webs; everything else is compared as it stands.
 */
export function asRustDocument(doc) {
  const d = structuredClone(doc);
  for (const s of d.service ?? []) {
    if (typeof s.type === "string") s.type = [s.type];
    if (typeof s.serviceEndpoint === "string" && URL.canParse(s.serviceEndpoint)) s.serviceEndpoint = new URL(s.serviceEndpoint).href;
  }
  return sortKeys(d);
}

const same = (a, b) => JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));

function runOp(rec) {
  const { Kels, kel } = internals;
  const stream = mutate(blob(rec.keri_cesr), rec.mutation);
  if (rec.op === "resolve") {
    const r = resolveFromArtifacts(rec.did, stream, blob(rec.did_json));
    return { document: r.didDocument, metadata: r.didDocumentMetadata };
  }
  let kels = kel(() => Kels.parse(stream));
  if (rec.as_of) kels = kel(() => kels.asOf(rec.as_of[0], rec.as_of[1]));
  switch (rec.op) {
    case "parse":
      return true;
    case "key_state": {
      const s = kel(() => kels.keyState(rec.prefix));
      return {
        prefix: s.prefix,
        sn: s.sn,
        said: s.said,
        lastEventDigest: s.lastEventDigest,
        keys: s.keys,
        nextKeys: s.nextKeys,
        threshold: thresholdJson(s.threshold),
        nextThreshold: thresholdJson(s.nextThreshold),
        backers: s.backers,
        backerThreshold: s.backerThreshold,
        config: s.config,
        delegator: s.delegator,
        deactivated: kels.isDeactivated(rec.prefix),
      };
    }
    case "service_endpoints":
      return kel(() => internals.serviceEndpoints(kels, rec.aid)).map((e) => ({ eid: e.eid, role: e.role, urls: Object.fromEntries(e.urls) }));
    case "delegator_service":
      return kel(() => internals.delegatorService(kels, rec.aid));
    case "designated_aliases": {
      const v = kel(() => internals.designatedAliases(kels, rec.aid));
      return { aliases: v.aliases, rejected: v.rejected !== null };
    }
    case "designated_key_agreement": {
      const v = kel(() => internals.designatedKeyAgreement(kels, rec.aid));
      return { keys: v.keys, issued: v.issued, rejected: v.rejected !== null };
    }
    case "designated_services": {
      const v = kel(() => internals.designatedServices(kels, rec.aid));
      return { services: v.services.map((s) => JSON.parse(JSON.stringify(Object.fromEntries(s)))), rejected: v.rejected !== null };
    }
    default:
      throw new Error(`unknown op ${rec.op}`);
  }
}

function expected(rec) {
  if (rec.op === "resolve") return { document: rec.document, metadata: rec.metadata };
  if (rec.op === "key_state") return rec.state;
  return Object.hasOwn(rec, "result") ? rec.result : true;
}

/**
 * Run one record and say how this implementation's answer differs from the
 * Rust crate's, or return null when they agree: the same verdict, the same
 * error kind on a refusal, and the same result on an acceptance.
 */
export function disagreement(rec) {
  let got;
  let error;
  try {
    got = runOp(rec);
  } catch (e) {
    error = e;
  }
  const label = `${rec.source}${rec.mutation ? ` ${JSON.stringify(rec.mutation)}` : ""} [${rec.op}]`;
  if (!rec.ok) {
    if (!error) return `${label}: Rust refused it (${rec.error.kind}: ${rec.error.message}), this accepted it`;
    if (error.kind !== rec.error.kind) {
      return `${label}: refused as ${error.kind ?? error.name} (${error.message}), Rust as ${rec.error.kind} (${rec.error.message})`;
    }
    return null;
  }
  if (error) return `${label}: Rust accepted it, this refused it: ${error.kind ?? error.name}: ${error.message}`;
  const want = expected(rec);
  if (rec.op === "resolve") {
    if (!same(asRustDocument(got.document), want.document)) {
      return `${label}: documents differ\n  js:   ${JSON.stringify(asRustDocument(got.document))}\n  rust: ${JSON.stringify(sortKeys(want.document))}`;
    }
    if (!same(got.metadata, want.metadata)) return `${label}: metadata ${JSON.stringify(got.metadata)}, Rust ${JSON.stringify(want.metadata)}`;
    return null;
  }
  if (!same(got, want)) return `${label}: result ${JSON.stringify(got)}, Rust ${JSON.stringify(want)}`;
  return null;
}

/** Counts of accepted and refused records. */
export function tally(records) {
  return { accepted: records.filter((r) => r.ok).length, refused: records.filter((r) => !r.ok).length };
}
