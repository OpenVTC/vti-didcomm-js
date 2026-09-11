// Mediator (ATM) authentication — challenge-response → mediator JWT.
//
// This is the auth handshake that authorizes a client to USE the
// mediator as a relay (send via /inbound or WS, receive via live
// delivery). It is distinct from VTA auth:
//   - VTA REST auth (`vta-rest-auth.js`) authenticates the client TO
//     the VTA and yields a VTA JWT.
//   - Mediator auth (here) authenticates the client to the MEDIATOR
//     and yields a mediator JWT used for the WS subprotocol bearer
//     and /inbound|/fetch bearer header.
//
// Over DIDComm-via-mediator there is NO separate VTA auth — each
// authcrypt'd message forwarded to the VTA is self-authenticating
// (the VTA ACL-checks the `from` DID). So the only handshake on the
// mediator path is THIS one.
//
// Wire flow (matches affinidi-messaging-mediator):
//   1. POST {authEndpoint}/challenge  body `{ "did": <client_did> }`
//      → SuccessResponse<AuthenticationChallenge>:
//        { sessionId, data: { challenge, session_id } }
//        (note: top-level `sessionId` camelCase; `data` fields
//         snake_case — different from the VTA's camelCase data).
//   2. Build DIDComm v2 plaintext, type
//      `https://affinidi.com/atm/1.0/authenticate`,
//      body `{ challenge, session_id }`, authcrypt-packed to the
//      mediator's keyAgreement (the mediator requires the auth
//      message be BOTH signed and encrypted — authcrypt satisfies
//      both).
//   3. POST {authEndpoint}  body = the JWE JSON (text/plain)
//      → SuccessResponse<AuthorizationResponse>:
//        { sessionId, data: { access_token, access_expires_at,
//          refresh_token, refresh_expires_at } }.
//
// The client DID must be permitted by the mediator's ACL (its
// /authenticate/challenge gate registers/blocks DIDs per acl_mode).
//
// Every endpoint here comes out of the mediator's DID document, which
// the caller did not write. They pass the egress policy in
// `net-guard.js` before anything is dialed, and no request follows a
// redirect.

import { resolve as resolveDid } from "./resolver.js";
import { pack } from "./pack.js";
import { assertSafeEndpoint, guardedFetch } from "./net-guard.js";
import * as multibase from "./multibase.js";
import * as jwk from "./jwk.js";

const AUTH_MESSAGE_TYPE = "https://affinidi.com/atm/1.0/authenticate";

/**
 * Authenticate to a mediator and obtain its access/refresh tokens.
 *
 * @param {Object} args
 * @param {string} args.mediatorDid - the mediator's DID (resolved for
 *   its auth endpoint + keyAgreement).
 * @param {string} args.clientDid - the caller's DID (must be in the
 *   mediator's ACL).
 * @param {Uint8Array} args.clientX25519Private - 32-byte X25519 secret.
 * @param {Uint8Array} args.clientX25519Public - 32-byte X25519 public.
 * @param {string} [args.clientKid] - caller's full kid; defaults to
 *   `${clientDid}#${x25519_multikey}`.
 * @param {Function} [args.fetch] - fetch impl; defaults to global. It
 *   must honour `redirect: "manual"`.
 * @param {import("./net-guard.js").NetPolicy} [args.netPolicy] - egress
 *   policy for the endpoints the mediator's DID document advertises.
 *   Defaults to https/wss and public hosts. Local development against
 *   `http://localhost` needs `{ allowInsecure: true, allowPrivate: true }`.
 * @param {boolean} [args.allowInsecure] - **Deprecated:** use
 *   `netPolicy.allowInsecure`, which wins when both are set. Permits
 *   plaintext schemes only; it no longer admits private hosts.
 * @param {Function} [args.resolve] - DID resolver (default: the
 *   built-in dispatcher).
 * @returns {Promise<{
 *   accessToken: string,
 *   accessExpiresAt: number,
 *   refreshToken: string,
 *   refreshExpiresAt: number,
 *   sessionId?: string,
 *   mediator: { did: string, restEndpoint: string, wsEndpoint: string | null, authEndpoint: string, kid: string, x25519Pub: Uint8Array },
 * }>}
 * @throws {import("./net-guard.js").BlockedEndpointError} if an advertised
 *   endpoint fails the policy, or an endpoint answers with a redirect.
 */
export async function authenticateToMediator({
  mediatorDid,
  clientDid,
  clientX25519Private,
  clientX25519Public,
  clientKid,
  fetch: customFetch,
  netPolicy,
  allowInsecure,
  resolve,
}) {
  assertNonEmptyString("mediatorDid", mediatorDid);
  assertNonEmptyString("clientDid", clientDid);
  assertBytes("clientX25519Private", clientX25519Private, 32);
  assertBytes("clientX25519Public", clientX25519Public, 32);

  const fetchFn = customFetch ?? globalThis.fetch;
  if (typeof fetchFn !== "function") {
    throw new Error("mediator-auth: no fetch implementation available");
  }

  const policy = mergeNetPolicy(netPolicy, allowInsecure);
  const resolveOpts = { netPolicy: policy };
  if (resolve) resolveOpts.resolve = resolve;
  const mediator = await resolveMediator(mediatorDid, resolveOpts);
  const resolvedClientKid = clientKid ?? defaultClientKid(clientDid, clientX25519Public);

  // Each request re-checks its URL and refuses redirects, so a 3xx from
  // the auth endpoint cannot carry the handshake to a host the policy
  // never saw.
  const safeFetch = guardedFetch(fetchFn, { ...policy, label: "mediator auth", schemes: ["https:"] });

  // ── Step 1: challenge ────────────────────────────────────────────
  const challenge = await postJson(safeFetch, `${mediator.authEndpoint}/challenge`, {
    did: clientDid,
  });
  const challengeStr = challenge?.data?.challenge;
  const sessionId = challenge?.data?.session_id ?? challenge?.sessionId;
  if (!challengeStr || !sessionId) {
    throw responseError("mediator-auth: challenge response missing challenge or session_id", challenge);
  }

  // ── Step 2: pack the authenticate response ───────────────────────
  // The mediator requires `created_time` + `expires_time` on auth
  // messages (rejects with `e.p.message.expires_time.missing`
  // otherwise). 5-minute validity window, matching the SDK.
  const now = Math.floor(Date.now() / 1000);
  const message = {
    id: `urn:uuid:${randomUuid()}`,
    typ: "application/didcomm-plain+json",
    type: AUTH_MESSAGE_TYPE,
    from: clientDid,
    to: [mediatorDid],
    created_time: now,
    expires_time: now + 300,
    body: { challenge: challengeStr, session_id: sessionId },
  };
  const senderPrivateJwk = jwk.privateJwk("X25519", clientX25519Private, clientX25519Public);
  const recipientPublicJwk = jwk.publicJwk("X25519", mediator.x25519Pub);
  const jweJson = await pack({
    message,
    sender: { kid: resolvedClientKid, privateJwk: senderPrivateJwk },
    recipient: { kid: mediator.kid, publicJwk: recipientPublicJwk },
  });

  // ── Step 3: POST /authenticate ───────────────────────────────────
  // The mediator's /authenticate takes `Json<InboundMessage>`, so the
  // JWE goes as `application/json` (the JWE string is already valid
  // JSON). This differs from the VTA's /auth/, which takes a raw
  // `String` body (text/plain).
  const auth = await postRaw(safeFetch, mediator.authEndpoint, jweJson, "application/json");
  const data = auth?.data;
  if (!data?.access_token) {
    throw responseError("mediator-auth: authenticate response missing access_token", auth);
  }
  return {
    accessToken: data.access_token,
    accessExpiresAt: data.access_expires_at,
    refreshToken: data.refresh_token,
    refreshExpiresAt: data.refresh_expires_at,
    sessionId: auth.sessionId,
    mediator,
  };
}

/**
 * Resolve a mediator DID into its endpoints + keyAgreement.
 *
 * Reads the `DIDCommMessaging` service for the REST + WS URIs and the
 * `Authentication` service for the auth endpoint. Falls back to
 * deriving the auth endpoint from the REST URI (`${rest}/authenticate`)
 * if no explicit `Authentication` service is present.
 *
 * @param {string} mediatorDid
 * @param {Object} [options]
 * @param {import("./net-guard.js").NetPolicy} [options.netPolicy] - egress
 *   policy for the advertised endpoints (see {@link authenticateToMediator}).
 * @param {boolean} [options.allowInsecure] - **Deprecated** alias for
 *   `netPolicy.allowInsecure`.
 * @param {Function} [options.resolve] - DID resolver (default: the
 *   built-in dispatcher). Injectable for tests.
 * @returns {Promise<{
 *   did: string, restEndpoint: string, wsEndpoint: string | null,
 *   authEndpoint: string, kid: string, x25519Pub: Uint8Array,
 * }>}
 */
export async function resolveMediator(mediatorDid, { allowInsecure, netPolicy, resolve = resolveDid } = {}) {
  const { didDocument } = await resolve(mediatorDid);
  if (!didDocument || typeof didDocument !== "object") {
    throw new Error(`mediator-auth: could not resolve mediator DID ${mediatorDid}`);
  }
  return parseMediatorEndpoints(didDocument, mediatorDid, { allowInsecure, netPolicy });
}

/**
 * Parse a resolved mediator DID document into its endpoints +
 * keyAgreement. Pure (no I/O) — exported so the parsing is unit-
 * testable without a live resolver.
 *
 * The whole document is rejected if any endpoint that would be dialed
 * fails the egress policy.
 *
 * @param {Object} didDocument
 * @param {string} mediatorDid
 * @param {Object} [options]
 * @param {import("./net-guard.js").NetPolicy} [options.netPolicy]
 * @param {boolean} [options.allowInsecure] - **Deprecated** alias for
 *   `netPolicy.allowInsecure`.
 * @returns {{did:string, restEndpoint:string, wsEndpoint:string|null,
 *   authEndpoint:string, kid:string, x25519Pub:Uint8Array}}
 * @throws {import("./net-guard.js").BlockedEndpointError}
 */
export function parseMediatorEndpoints(didDocument, mediatorDid, { allowInsecure, netPolicy } = {}) {
  const policy = mergeNetPolicy(netPolicy, allowInsecure);
  if (!didDocument || typeof didDocument !== "object") {
    throw new Error(`mediator-auth: invalid DID document for ${mediatorDid}`);
  }
  const services = Array.isArray(didDocument.service) ? didDocument.service : [];

  // DIDCommMessaging service: REST + WS endpoints live in its
  // serviceEndpoint array (each entry has a `uri`; ws(s):// is the
  // WebSocket one, http(s):// is REST).
  const messaging = services.find((s) => serviceTypeIncludes(s, "DIDCommMessaging"));
  let restEndpoint;
  let wsEndpoint;
  if (messaging) {
    const eps = normalizeServiceEndpoints(messaging.serviceEndpoint);
    for (const ep of eps) {
      const uri = typeof ep === "string" ? ep : ep?.uri;
      if (typeof uri !== "string") continue;
      if (uri.startsWith("ws://") || uri.startsWith("wss://")) wsEndpoint = uri;
      else if (uri.startsWith("http://") || uri.startsWith("https://")) restEndpoint = uri;
    }
  }

  // Authentication service: explicit auth endpoint.
  const authService = services.find((s) => serviceTypeIncludes(s, "Authentication"));
  let authEndpoint;
  if (authService && typeof authService.serviceEndpoint === "string") {
    authEndpoint = authService.serviceEndpoint;
  } else if (restEndpoint) {
    authEndpoint = `${restEndpoint.replace(/\/+$/, "")}/authenticate`;
  }

  if (!restEndpoint) {
    throw new Error(`mediator-auth: ${mediatorDid} has no REST DIDCommMessaging endpoint`);
  }
  if (!authEndpoint) {
    throw new Error(`mediator-auth: ${mediatorDid} has no resolvable authenticate endpoint`);
  }

  // Refuse plaintext transports by default: a tampered/stale DID
  // document must not be able to downgrade us to `ws://` / `http://`,
  // which would leak the bearer JWT and traffic. Opt out only for
  // local dev with `{ netPolicy: { allowInsecure: true } }`.
  if (!policy.allowInsecure) {
    for (const [label, url] of [
      ["REST", restEndpoint],
      ["auth", authEndpoint],
      ["WebSocket", wsEndpoint],
    ]) {
      if (typeof url === "string" && (url.startsWith("http://") || url.startsWith("ws://"))) {
        throw new Error(
          `mediator-auth: ${mediatorDid} advertises an insecure ${label} endpoint (${url}); pass { netPolicy: { allowInsecure: true } } to permit it`,
        );
      }
    }
  }

  // The document chooses the host as well as the scheme. Refuse
  // loopback, private, link-local / metadata and local-only names unless
  // the caller opted in, and apply the caller's allow-list.
  for (const [label, url, scheme] of [
    ["REST", restEndpoint, "https:"],
    ["auth", authEndpoint, "https:"],
    ["WebSocket", wsEndpoint, "wss:"],
  ]) {
    if (typeof url === "string") {
      assertSafeEndpoint(url, { ...policy, label: `mediator ${label}`, schemes: [scheme] });
    }
  }

  const { kid, x25519Pub } = extractX25519KeyAgreement(didDocument, mediatorDid);

  return {
    did: mediatorDid,
    restEndpoint: restEndpoint.replace(/\/+$/, ""),
    wsEndpoint: wsEndpoint ?? null,
    authEndpoint,
    kid,
    x25519Pub,
  };
}

// ─── Internals ──────────────────────────────────────────────────────────

// `netPolicy` is the current option; the top-level `allowInsecure` flag is
// its deprecated alias. An explicit `netPolicy.allowInsecure` wins.
function mergeNetPolicy(netPolicy, legacyAllowInsecure) {
  if (netPolicy != null && typeof netPolicy !== "object") {
    throw new TypeError("mediator-auth: netPolicy must be an object");
  }
  return {
    allowInsecure: Boolean(netPolicy?.allowInsecure ?? legacyAllowInsecure ?? false),
    allowPrivate: Boolean(netPolicy?.allowPrivate ?? false),
    allowHosts: netPolicy?.allowHosts ?? null,
  };
}

function extractX25519KeyAgreement(didDocument, did) {
  const ka = didDocument.keyAgreement;
  if (!ka || ka.length === 0) {
    throw new Error(`mediator-auth: ${did} has no keyAgreement entries`);
  }
  let vm = ka[0];
  if (typeof vm === "string") {
    const found = (didDocument.verificationMethod ?? []).find((v) => v.id === vm);
    if (!found) throw new Error(`mediator-auth: keyAgreement ref ${vm} not resolvable`);
    vm = found;
  }
  if (!vm.publicKeyMultibase) {
    throw new Error("mediator-auth: keyAgreement entry has no publicKeyMultibase");
  }
  const { codec, key } = multibase.decodeMultikey(vm.publicKeyMultibase);
  if (codec[0] !== 0xec || codec[1] !== 0x01) {
    throw new Error(
      `mediator-auth: keyAgreement not X25519 (multicodec 0x${codec[0].toString(16)}${codec[1].toString(16)})`,
    );
  }
  return { kid: vm.id, x25519Pub: key };
}

function serviceTypeIncludes(service, wanted) {
  const t = service?.type;
  if (typeof t === "string") return t === wanted;
  if (Array.isArray(t)) return t.includes(wanted);
  return false;
}

function normalizeServiceEndpoints(serviceEndpoint) {
  if (Array.isArray(serviceEndpoint)) return serviceEndpoint;
  if (serviceEndpoint == null) return [];
  return [serviceEndpoint];
}

function defaultClientKid(did, x25519Public) {
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, x25519Public);
  return `${did}#${mb}`;
}

async function postJson(fetchFn, url, body) {
  const resp = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    redirect: "manual",
  });
  return parseResponse(resp, url);
}

async function postRaw(fetchFn, url, body, contentType) {
  const resp = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": contentType },
    body,
    redirect: "manual",
  });
  return parseResponse(resp, url);
}

async function parseResponse(resp, url) {
  const text = await resp.text();
  if (!resp.ok) {
    throw responseError(`mediator-auth: ${resp.status} from ${url}`, text, resp.status);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw responseError(`mediator-auth: ${url} returned a non-JSON body`, text, resp.status);
  }
}

// Response content stays out of the message: from a hostile endpoint it
// is attacker-chosen text, and messages end up in logs and UI. It is kept
// on `err.body` (and the HTTP status on `err.status`) for debugging.
function responseError(message, body, status) {
  const err = new Error(message);
  if (status !== undefined) err.status = status;
  err.body = body;
  return err;
}

function randomUuid() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b).map((v) => v.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function assertNonEmptyString(name, value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`mediator-auth: ${name} must be a non-empty string`);
  }
}

function assertBytes(name, value, exactLen) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`mediator-auth: ${name} must be Uint8Array`);
  }
  if (exactLen !== undefined && value.length !== exactLen) {
    throw new Error(`mediator-auth: ${name} must be ${exactLen} bytes, got ${value.length}`);
  }
}
