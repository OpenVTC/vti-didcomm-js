// Public re-exports.
//
// B1: crypto primitives (base64url, multibase, jwk, concat-kdf).
// B2: ECDH-1PU + AES + A256CBC-HS512 + pack/unpack. Key agreement
//     over X25519 or P-256 (key-agreement.js dispatches by curve).
// B3: DID resolver (did:key + did:peer in-tree, did:webvh via
//     didwebvh-ts).
// B4: VTA REST auth via DIDComm-packed /auth/.
// M1-M4: mediator transport — mediator auth, routing/2.0/forward,
//        WebSocket + message-pickup 3.0 live delivery, sendAndWait.

export * as base64url from "./base64url.js";
export * as multibase from "./multibase.js";
export * as jwk from "./jwk.js";
export * as concatKdf from "./concat-kdf.js";
export * as x25519 from "./x25519.js";
export * as p256 from "./p256.js";
export * as keyAgreement from "./key-agreement.js";
export * as ecdh1pu from "./ecdh-1pu.js";
export * as ecdhEs from "./ecdh-es.js";
export * as aes from "./aes.js";
export * as a256cbcHs512 from "./a256cbc-hs512.js";
export { pack } from "./pack.js";
export { packAnoncrypt } from "./anoncrypt.js";
export { unpack } from "./unpack.js";
export * as didKey from "./did-key.js";
export * as didWebvh from "./did-webvh.js";
export * as didPeer from "./did-peer.js";
export { createResolver, defaultResolver, resolve } from "./resolver.js";
export * as vtaRestAuth from "./vta-rest-auth.js";
export { buildForward } from "./forward.js";
export { authenticateToMediator, resolveMediator, parseMediatorEndpoints } from "./mediator-auth.js";
export { MediatorSession, buildLiveDeliveryChange, buildMessagesReceived, peekSkid, unpackInbound } from "./mediator-transport.js";
export { connectVtaViaMediator, VtaMediatorClient, resolveX25519KeyAgreement } from "./vta-didcomm.js";
