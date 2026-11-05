// `did:webvh` resolver. The log walk, hash chain and Data-Integrity
// proof verification come from the DIF-maintained `didwebvh-ts`; the
// network I/O is ours.
//
// Why we no longer call its `resolveDID`: a webvh log's network location
// is derived from the identifier, and identifiers reach this library from
// whoever it is talking to. An inbound frame's `skid` is the sharpest
// case — `unpackInbound` resolves it *before* anything about the frame
// has been authenticated — so any party that can route a frame through
// the mediator chooses a host this client will GET. That host has to be
// checked before it is dialed, and `didwebvh-ts` 2.7.4 dials through the
// global `fetch` at three points with nothing to inject:
//
//   - `fetchLogFromIdentifier` → `<base>/did.jsonl`
//   - `fetchWitnessProofs` → `<base>/did-witness.json`
//   - `resolveVM` → another did:webvh named in a log entry's
//     `proof[].verificationMethod`
//
// We take the first two over: compute the log URL here, vet it with
// `net-guard`, fetch through `guardedFetch`, and hand the log to the
// library's exported `resolveDIDFromLog` with `witnessProofs` already
// supplied so its own fetch never runs. The third cannot be intercepted,
// so every nested did:webvh verification method in the log (and in the
// witness file) is pre-scanned and its host vetted *before* the log is
// handed over. That is host-level only: the library builds the nested URL
// with its own `getBaseUrl`, so it may still fetch a vetted host over
// plaintext. Both gaps close upstream.
//
// Its `getBaseUrl` also picks plaintext `http` when the identifier merely
// *contains* `localhost`, which covers `localhost.attacker.example` too.
// `webvhLogUrl` downgrades only for an exact `localhost` host, and only
// when the policy admits private hosts at all.
//
// Upstream, so the pre-scan and this URL copy can eventually go away:
//   - injectable fetch for all three egress points:
//     https://github.com/decentralized-identity/didwebvh-ts/issues/158
//   - the substring-`localhost` plaintext downgrade:
//     https://github.com/decentralized-identity/didwebvh-ts/issues/185
//
// If we ever need to vendor the implementation (e.g. for a strict
// Content Security Policy), the swap-out point is still this module.

import { resolveDIDFromLog } from "didwebvh-ts";
import { BlockedEndpointError, assertSafeEndpoint, guardedFetch } from "./net-guard.js";

/** Default upper bound on one `did.jsonl` / `did-witness.json` fetch (ms). */
export const DEFAULT_WEBVH_TIMEOUT_MS = 10000;

/** `code` of a {@link DidVersionNotFoundError}. */
export const DID_VERSION_NOT_FOUND = "E_DID_VERSION_NOT_FOUND";

/**
 * A resolution as of a `versionTime` found no version of the DID in force
 * then: the instant precedes the log's first entry, so the DID did not yet
 * exist. The log itself verified — this is an answer about the DID, not a
 * failure to resolve it. Match on `code` ({@link DID_VERSION_NOT_FOUND}).
 */
export class DidVersionNotFoundError extends Error {
  /**
   * @param {string} message
   * @param {Object} [details]
   * @param {string} [details.did]
   * @param {string} [details.versionTime] - the requested instant, ISO 8601.
   * @param {string} [details.created] - the `versionTime` of the log's first entry.
   */
  constructor(message, { did, versionTime, created } = {}) {
    super(message);
    this.name = "DidVersionNotFoundError";
    /** @type {"E_DID_VERSION_NOT_FOUND"} */
    this.code = DID_VERSION_NOT_FOUND;
    /** @type {string | undefined} */
    this.did = did;
    /** @type {string | undefined} */
    this.versionTime = versionTime;
    /** @type {string | undefined} */
    this.created = created;
  }
}

const LOG_LABEL = "did:webvh log";
const WITNESS_LABEL = "did:webvh witness file";
const VM_LABEL = "did:webvh proof verification method";

/**
 * The `did.jsonl` URL a `did:webvh` identifier points at, with its host
 * checked against the egress policy.
 *
 * A port is percent-encoded in the identifier (`example.com%3A8443`), and
 * everything after the host is a path, so `did:webvh:<scid>:example.com`
 * resolves at `/.well-known/did.jsonl` while
 * `did:webvh:<scid>:example.com:users:alice` resolves at
 * `/users/alice/did.jsonl`.
 *
 * @param {string} did
 * @param {import("./net-guard.js").EndpointPolicy} [policy]
 * @returns {URL} the parsed, vetted URL.
 * @throws {BlockedEndpointError} if the host fails the policy.
 * @throws {Error} if the identifier is not a usable did:webvh.
 */
export function webvhLogUrl(did, policy = {}) {
  const label = policy?.label ?? LOG_LABEL;
  const parts = typeof did === "string" ? did.split(":") : [];
  const invalid = () =>
    new Error(
      `did:webvh resolve: ${JSON.stringify(String(did).slice(0, 80))} is not a usable did:webvh identifier`,
    );
  if (parts.length < 4 || parts[0] !== "did" || parts[1] !== "webvh" || !parts[2] || !parts[3]) {
    throw invalid();
  }

  // Mirrors didwebvh-ts `getBaseUrl`/`getFileUrl`: everything after the
  // SCID is the host followed by an optional path.
  const remainder = decodeURIComponent(parts.slice(3).join("/"));
  const [hostPart, ...pathParts] = remainder.split("/");
  const hostAndPort = decodeURIComponent(hostPart).split(":");
  // More than one colon would be an IPv6 literal, which the library
  // mangles and the webvh identifier syntax has no form for. Fail closed
  // rather than guess at what it would dial.
  if (hostAndPort.length > 2 || !hostAndPort[0]) throw invalid();
  const host = hostAndPort[0].normalize("NFC").toLowerCase();
  const port = hostAndPort[1];

  const allowPrivate = policy?.allowPrivate === true;
  // didwebvh-ts downgrades to plaintext whenever the identifier merely
  // *contains* "localhost". Only an exact `localhost` host may, and only
  // when the policy admits private hosts; a host that just has
  // "localhost" somewhere in it is refused outright, because upstream
  // would fetch it over http and it is not a name a public webvh DID
  // has any reason to use.
  const plaintext = allowPrivate && (host === "localhost" || policy?.allowInsecure === true);
  if (!allowPrivate && host.includes("localhost")) {
    throw new BlockedEndpointError(
      `net-guard: ${label} host ${host} refused: a did:webvh host containing "localhost" is local-only (set allowPrivate for local development)`,
      { reason: "private_name", host, label },
    );
  }

  const authority = port ? `${host}:${port}` : host;
  const path = pathParts.filter((segment) => segment !== "").join("/");
  const base = `${plaintext ? "http" : "https"}://${authority}${path ? `/${path}` : ""}`;
  const fileUrl = path ? `${base}/did.jsonl` : `${base}/.well-known/did.jsonl`;

  return assertSafeEndpoint(fileUrl, {
    ...policy,
    label,
    schemes: ["https:"],
    allowInsecure: plaintext,
  });
}

/**
 * Resolve a `did:webvh:…` identifier to its current DID document, or to
 * the document in force at `options.versionTime`.
 *
 * Fetches `did.jsonl` (and `did-witness.json` when the log declares
 * witnesses) from the vetted host, walks the log, verifies the hash
 * chain and every Data Integrity proof, and returns the latest valid
 * `state` — or, with `versionTime`, the `state` of the last entry whose
 * `versionTime` is at or before it (see {@link resolveLog}).
 *
 * @param {string} did
 * @param {Object} [options]
 * @param {import("./net-guard.js").NetPolicy} [options.netPolicy] - egress
 *   policy for the host the identifier names. Defaults to `https:` on a
 *   public host; a local webvh server needs
 *   `{ allowInsecure: true, allowPrivate: true }`.
 * @param {Function} [options.fetch] - fetch impl; defaults to global. It
 *   is wrapped rather than trusted: every URL is re-checked and a 3xx is
 *   refused, so it must honour `redirect: "manual"`.
 * @param {number} [options.timeoutMs=10000] - per-request timeout. `0`
 *   disables it.
 * @param {Function} [options.verifier] - override the Ed25519
 *   verifier. Defaults to `@noble/curves`. Mainly useful for tests
 *   that want to inject a failing verifier and confirm we propagate
 *   the error.
 * @param {Date|string} [options.versionTime] - resolve the document as it
 *   stood at this instant (an RFC 3339 date-time with an offset, or a
 *   `Date`).
 * @returns {Promise<{
 *   didDocument: Object,
 *   didResolutionMetadata: Object,
 *   didDocumentMetadata: Object,
 * }>}
 * @throws {BlockedEndpointError} if the identifier's host, or the host of
 *   a did:webvh verification method inside its log, fails the policy.
 * @throws {DidVersionNotFoundError} if `versionTime` precedes the DID's
 *   creation.
 */
export async function resolve(did, options = {}) {
  const at = versionTimeOf(options);
  if (typeof did !== "string") {
    throw new TypeError("did:webvh resolve: input must be a string");
  }
  if (!did.startsWith("did:webvh:")) {
    throw new Error(`did:webvh resolve: identifier must start with "did:webvh:"`);
  }

  const policy = netPolicyOf(options);
  const logUrl = webvhLogUrl(did, { ...policy, label: LOG_LABEL });
  const plaintext = logUrl.protocol === "http:";
  const fetchGuarded = guardedFetch(options.fetch ?? globalThis.fetch, {
    ...policy,
    label: LOG_LABEL,
    schemes: ["https:"],
    allowInsecure: plaintext,
  });

  const log = parseLog(await fetchBody(fetchGuarded, logUrl, options, LOG_LABEL), logUrl);
  // Supply `witnessProofs` either way: an empty array is what stops
  // `fetchWitnessProofs` from reaching for the global fetch, and a log
  // whose `witness` parameter is present-but-empty is enough to trigger
  // it upstream.
  const witnessProofs = declaresWitnesses(log)
    ? await fetchWitnessProofs(fetchGuarded, logUrl, options)
    : [];

  assertNestedVerificationMethods(log, witnessProofs, policy);

  const verifier = options.verifier ?? (await defaultEd25519Verifier());
  // `scid` binds the log to the identifier we asked for: the SCID is a
  // hash of the genesis entry, so a log that verifies under it is the log
  // for this DID. (The host can legitimately differ from the one we
  // fetched from when the DID is portable and has moved, which is why
  // there is no host equality check here.)
  return resolveVerified(log, { verifier, witnessProofs, scid: did.split(":")[2] }, at, did);
}

/**
 * Resolve from an already-loaded log (skip the HTTP step). Useful
 * for tests and replay.
 *
 * Nested did:webvh verification methods are still vetted, because
 * `didwebvh-ts` fetches those itself while verifying the log.
 *
 * @param {Object[]} log - parsed LogEntry objects in order
 * @param {Object} [options]
 * @param {import("./net-guard.js").NetPolicy} [options.netPolicy]
 * @param {Object[]} [options.witnessProofs] - `did-witness.json` content.
 *   Required when the log declares witnesses: this function does no I/O,
 *   and upstream would otherwise fetch the file itself, unchecked.
 * @param {string} [options.scid] - bind the log to an expected SCID.
 * @param {Function} [options.verifier]
 * @param {Date|string} [options.versionTime] - resolve the document as it
 *   stood at this instant: the `state` of the last entry whose
 *   `versionTime` is at or before it (did:webvh v1.0, *DID Resolution*).
 *   The whole log is verified first, exactly as for current resolution —
 *   SCID, hash chain, every entry's proof under the update keys in force,
 *   pre-rotation commitments and every witness threshold — so a log that
 *   would not resolve now does not resolve as of any time either.
 * @throws {DidVersionNotFoundError} if `versionTime` precedes the log's
 *   first entry.
 */
export async function resolveLog(log, options = {}) {
  const at = versionTimeOf(options);
  const policy = netPolicyOf(options);
  const witnessProofs = options.witnessProofs ?? [];
  if (!Array.isArray(witnessProofs)) {
    throw new TypeError("did:webvh resolveLog: witnessProofs must be an array");
  }
  if (witnessProofs.length === 0 && declaresWitnesses(log)) {
    throw new Error(
      "did:webvh resolveLog: this log declares witnesses — pass `witnessProofs`, or use resolve(did), which fetches did-witness.json through the egress guard",
    );
  }

  assertNestedVerificationMethods(log, witnessProofs, policy);

  const verifier = options.verifier ?? (await defaultEd25519Verifier());
  const resolveOptions = { verifier, witnessProofs };
  if (options.scid) resolveOptions.scid = options.scid;
  return resolveVerified(log, resolveOptions, at);
}

// ─── Resolution as of a time ────────────────────────────────────────────

// RFC 3339 `date-time`: a time zone is required, so the instant is never
// read in the resolver's local zone.
const RFC3339_DATE_TIME = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

/** `options.versionTime` as a `Date`, or undefined when absent. */
function versionTimeOf(options) {
  const value = options?.versionTime;
  if (value === undefined) return undefined;
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new TypeError("did:webvh: versionTime is an invalid Date");
    return value;
  }
  if (typeof value === "string" && RFC3339_DATE_TIME.test(value)) {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  throw new TypeError(
    `did:webvh: versionTime must be a Date or an RFC 3339 date-time with an offset, not ${JSON.stringify(String(value).slice(0, 64))}`,
  );
}

/**
 * Verify `log` and return the current document, or the one in force at `at`.
 *
 * Why not `resolveDIDFromLog`'s own `versionTime` selector, which
 * `didwebvh-ts` 2.8 has:
 *
 *   - it selects an entry only when the time is strictly after it and
 *     strictly before the next one, so an instant equal to an entry's
 *     `versionTime` selects nothing; the specification's rule is the last
 *     entry at or before the instant;
 *   - once it has selected an entry, any later failure is swallowed, and a
 *     failure in the walk skips the witness checks that run after it, so a
 *     log with a broken entry appended after the selected one would resolve
 *     without its witness thresholds ever being counted.
 *
 * So the whole log is verified as current resolution verifies it, the entry
 * is chosen here, and upstream is asked for that version by number — which
 * shapes the document (the implicit `#files` / `#whois` services) exactly as
 * a current resolution does.
 */
async function resolveVerified(log, resolveOptions, at, requested) {
  const current = await resolveDIDFromLog(log, resolveOptions);
  if (at === undefined) return adaptResolutionResult(current);
  // A deactivated DID resolves now to no document, without an error; its
  // earlier versions still resolve by time.
  if (current?.meta?.error) adaptResolutionResult(current); // throws
  const did = requested ?? current?.did;

  // The walk above checked every `versionTime` parses and strictly increases.
  let versionNumber = 0;
  for (const entry of log) {
    if (Date.parse(entry.versionTime) > at.getTime()) break;
    versionNumber++;
  }
  if (versionNumber === 0) {
    const created = log[0]?.versionTime;
    throw new DidVersionNotFoundError(
      `did:webvh resolve: ${did ?? "the DID"} has no version at ${at.toISOString()}: its log begins at ${created}`,
      { ...(did ? { did } : {}), versionTime: at.toISOString(), ...(created ? { created } : {}) },
    );
  }
  return adaptResolutionResult(await resolveDIDFromLog(log, { ...resolveOptions, versionNumber }));
}

/**
 * Build a `Verifier` that uses `@noble/curves`' Ed25519
 * implementation. Lazy-loaded so the module doesn't pull
 * `@noble/curves/ed25519` until someone actually resolves a DID.
 */
async function defaultEd25519Verifier() {
  const { ed25519 } = await import("@noble/curves/ed25519.js");
  return {
    async verify(signature, message, publicKey) {
      return ed25519.verify(signature, message, publicKey);
    },
  };
}

// ─── Egress ─────────────────────────────────────────────────────────────

function netPolicyOf(options) {
  const netPolicy = options?.netPolicy;
  if (netPolicy != null && typeof netPolicy !== "object") {
    throw new TypeError("did:webvh: netPolicy must be an object");
  }
  return {
    allowInsecure: Boolean(netPolicy?.allowInsecure),
    allowPrivate: Boolean(netPolicy?.allowPrivate),
    allowHosts: netPolicy?.allowHosts ?? null,
  };
}

async function fetchBody(fetchGuarded, url, options, label) {
  const timeoutMs = options?.timeoutMs ?? DEFAULT_WEBVH_TIMEOUT_MS;
  const init = { method: "GET", redirect: "manual" };
  if (timeoutMs > 0 && typeof AbortSignal?.timeout === "function") {
    init.signal = AbortSignal.timeout(timeoutMs);
  }

  let response;
  try {
    response = await fetchGuarded(url.href, init);
  } catch (err) {
    // A refusal keeps its own type and `code`, so callers can branch on
    // it; anything else becomes a resolution failure naming the URL.
    if (err instanceof BlockedEndpointError) throw err;
    throw new Error(`did:webvh resolve failed: ${label} ${url.href} — ${err?.message ?? err}`);
  }
  if (!response?.ok) {
    const err = new Error(`did:webvh resolve failed: ${label} ${url.href} — HTTP ${response?.status}`);
    err.status = response?.status;
    throw err;
  }
  return response.text();
}

function witnessUrl(logUrl) {
  return new URL(logUrl.href.replace(/did\.jsonl$/, "did-witness.json"));
}

async function fetchWitnessProofs(fetchGuarded, logUrl, options) {
  let text;
  try {
    text = await fetchBody(fetchGuarded, witnessUrl(logUrl), options, WITNESS_LABEL);
  } catch (err) {
    // A refusal is a policy decision and must not be swallowed. An
    // absent or unreachable witness file is not: upstream treats it as
    // "no proofs", and the log's own threshold then decides whether the
    // resolution can still succeed.
    if (err instanceof BlockedEndpointError) throw err;
    return [];
  }
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function parseLog(text, logUrl) {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error(`did:webvh resolve failed: empty DID log at ${logUrl.href}`);
  }
  const log = [];
  for (const line of trimmed.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      log.push(JSON.parse(line));
    } catch (err) {
      throw new Error(
        `did:webvh resolve failed: DID log at ${logUrl.href} has a line that is not JSON — ${err.message}`,
      );
    }
  }
  return log;
}

// Present-and-non-empty witnesses, in either the 1.0 (`witness`) or the
// 0.5 (`witnesses`) parameter shape.
function declaresWitnesses(log) {
  for (const entry of Array.isArray(log) ? log : []) {
    const parameters = entry?.parameters;
    if (Array.isArray(parameters?.witness?.witnesses) && parameters.witness.witnesses.length > 0) {
      return true;
    }
    if (Array.isArray(parameters?.witnesses) && parameters.witnesses.length > 0) return true;
  }
  return false;
}

// Every did:webvh named as a proof's verificationMethod, in the log and
// in the witness file. `didwebvh-ts` `resolveVM` fetches each of these
// itself, through the global fetch, so their hosts are vetted here
// before the log is handed over.
function nestedWebvhVerificationMethods(log, witnessProofs) {
  const dids = new Set();
  const collect = (proofs) => {
    const list = Array.isArray(proofs) ? proofs : proofs ? [proofs] : [];
    for (const proof of list) {
      const vm = proof?.verificationMethod;
      if (typeof vm === "string" && vm.startsWith("did:webvh:")) dids.add(vm.split("#")[0]);
    }
  };
  for (const entry of Array.isArray(log) ? log : []) collect(entry?.proof);
  for (const entry of Array.isArray(witnessProofs) ? witnessProofs : []) collect(entry?.proof);
  return [...dids];
}

function assertNestedVerificationMethods(log, witnessProofs, policy) {
  for (const vmDid of nestedWebvhVerificationMethods(log, witnessProofs)) {
    webvhLogUrl(vmDid, { ...policy, label: VM_LABEL });
  }
}

/**
 * Map `didwebvh-ts`'s `{did, doc, meta}` shape onto the W3C DID
 * Resolution result shape we use elsewhere in this library.
 *
 * `resolveDIDFromLog` throws on a verification failure, but it can also
 * return a result whose `meta.error` carries the reason and whose `doc`
 * is empty/null. We turn that into a thrown error so callers don't trip
 * over a null `didDocument` downstream with an opaque "Cannot read
 * properties of null" message.
 */
function adaptResolutionResult(result) {
  const err = result?.meta?.error;
  if (err) {
    const detail = result?.meta?.problemDetails?.detail;
    throw new Error(
      `did:webvh resolve failed: ${err}${detail ? ` — ${detail}` : ""}`,
    );
  }
  if (!result?.doc || typeof result.doc !== "object") {
    throw new Error(
      "did:webvh resolve: resolver returned no DID document (and no error) — the log may be empty or unreachable",
    );
  }
  return {
    didDocument: result.doc,
    didResolutionMetadata: { contentType: "application/did+ld+json" },
    didDocumentMetadata: result.meta ?? {},
  };
}
