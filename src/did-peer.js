// `did:peer` resolver — numalgo 2 only (the variant DIDComm uses).
//
// Spec: https://identity.foundation/peer-did-method-spec/ (Method 2)
//       https://github.com/decentralized-identity/did-peer-2
//
// A numalgo-2 peer DID is a self-describing, registry-less DID whose
// document is encoded entirely in the identifier:
//
//   did:peer:2.Ez6LS….Vz6Mk….SeyJ0Ijoi…
//   └ method ┘│└ keyAgreement ┘│└ auth ┘│└ service (base64url JSON) ┘
//             └ purpose code   …
//
// Each element after `did:peer:2` is `.` + a single purpose-code
// character + a value:
//
//   A = assertionMethod          V = authentication
//   E = keyAgreement             I = capabilityInvocation
//   D = capabilityDelegation     S = service
//
// For key purposes (A/E/V/I/D) the value is a multibase-multicodec
// multikey (`z…`), exactly the form `did:key` uses — so Ed25519,
// X25519, P-256 and secp256k1 keys all carry through unchanged.
//
// For S the value is base64url(JSON) of a service (or array of
// services), with the abbreviations `t`→type (`dm`→DIDCommMessaging),
// `s`→serviceEndpoint, `r`→routingKeys, `a`→accept expanded.
//
// Verification-method `id`s: the peer-did spec numbers keys `#key-N`
// (N incrementing across ALL key elements in string order). We emit
// the fragment exactly as the spec mandates but as an ABSOLUTE DID
// URL (`did:peer:2…#key-N`) — matching this package's `did:key`
// resolver and giving callers a ready-to-use DIDComm `kid`.
//
// numalgo 0/1/4 are intentionally out of scope (numalgo 2 is the form
// DIDComm mediators and our flows use).

import * as multibase from "./multibase.js";
import * as b64u from "./base64url.js";

const PREFIX = "did:peer:";

const PURPOSE_RELATIONSHIP = {
  A: "assertionMethod",
  E: "keyAgreement",
  V: "authentication",
  I: "capabilityInvocation",
  D: "capabilityDelegation",
};

const SERVICE_FIELD = { t: "type", s: "serviceEndpoint", r: "routingKeys", a: "accept" };
const SERVICE_TYPE = { dm: "DIDCommMessaging" };

/**
 * Resolve a `did:peer:2.…` identifier into a DID document.
 *
 * @param {string} did - the full `did:peer:2…` string
 * @returns {{
 *   didDocument: Object,
 *   didResolutionMetadata: Object,
 *   didDocumentMetadata: Object,
 * }}
 */
export function resolve(did) {
  if (typeof did !== "string") {
    throw new TypeError("did:peer resolve: input must be a string");
  }
  if (!did.startsWith(PREFIX)) {
    throw new Error(`did:peer resolve: identifier must start with "did:peer:" (got ${JSON.stringify(did.slice(0, 32))}…)`);
  }
  const body = did.slice(PREFIX.length);
  const numalgo = body[0];
  if (numalgo !== "2") {
    throw new Error(`did:peer resolve: only numalgo 2 is supported (got numalgo ${JSON.stringify(numalgo)})`);
  }
  // After the numalgo digit the body is a run of `.`-prefixed
  // elements: ".Ez…​.Vz…​.SeyJ…". Splitting on "." yields a leading
  // empty string we drop.
  const elements = body.slice(1).split(".");
  if (elements.length < 2 || elements[0] !== "") {
    throw new Error("did:peer resolve: malformed numalgo-2 identifier (expected '.'-prefixed elements)");
  }

  const verificationMethod = [];
  const relationships = {
    authentication: [],
    assertionMethod: [],
    keyAgreement: [],
    capabilityInvocation: [],
    capabilityDelegation: [],
  };
  const services = [];
  let keyN = 0;
  let serviceN = 0;

  for (let i = 1; i < elements.length; i++) {
    const element = elements[i];
    if (element.length < 2) {
      throw new Error(`did:peer resolve: empty element at position ${i}`);
    }
    const code = element[0];
    const value = element.slice(1);

    if (code === "S") {
      for (const svc of decodeService(value, did, () => serviceN++)) {
        services.push(svc);
      }
      continue;
    }

    const relationship = PURPOSE_RELATIONSHIP[code];
    if (!relationship) {
      throw new Error(`did:peer resolve: unknown purpose code ${JSON.stringify(code)} at position ${i}`);
    }
    // Validate the multikey decodes (catches a truncated/garbled DID
    // early) but keep the original multibase string on the document.
    multibase.decodeMultikey(value);
    keyN += 1;
    const id = `${did}#key-${keyN}`;
    verificationMethod.push({
      id,
      type: "Multikey",
      controller: did,
      publicKeyMultibase: value,
    });
    relationships[relationship].push(id);
  }

  const didDocument = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1",
    ],
    id: did,
    verificationMethod,
  };
  // Only emit relationships that have members, matching did:key's
  // shape (no empty arrays).
  for (const [name, refs] of Object.entries(relationships)) {
    if (refs.length > 0) didDocument[name] = refs;
  }
  if (services.length > 0) didDocument.service = services;

  return {
    didDocument,
    didResolutionMetadata: { contentType: "application/did+ld+json" },
    didDocumentMetadata: {},
  };
}

/**
 * Decode an `S` element: base64url(JSON) of one service or an array
 * of services, expanding the peer-did abbreviations.
 *
 * @param {string} value - the base64url payload (without the 'S')
 * @param {string} did
 * @param {() => number} nextIndex - returns the running service index
 *   (0, 1, 2 …) so the first id is `#service` and the rest are
 *   `#service-1`, `#service-2`, …
 * @returns {Object[]}
 */
function decodeService(value, did, nextIndex) {
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(b64u.decode(value)));
  } catch (e) {
    throw new Error(`did:peer resolve: service element is not base64url JSON: ${e.message}`);
  }
  const list = Array.isArray(parsed) ? parsed : [parsed];
  return list.map((svc) => {
    const expanded = expandService(svc);
    if (!expanded.id) {
      const n = nextIndex();
      expanded.id = n === 0 ? `${did}#service` : `${did}#service-${n}`;
    }
    return expanded;
  });
}

/** Expand the top-level abbreviated keys of one service object. */
function expandService(svc) {
  if (!svc || typeof svc !== "object") {
    throw new Error("did:peer resolve: service element must be a JSON object");
  }
  const out = {};
  for (const [k, v] of Object.entries(svc)) {
    const key = SERVICE_FIELD[k] ?? k;
    out[key] = key === "type" && typeof v === "string" ? (SERVICE_TYPE[v] ?? v) : v;
  }
  return out;
}
