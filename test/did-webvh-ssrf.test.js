// A did:webvh identifier names the host its log is fetched from, and
// identifiers are not all caller-chosen: `unpackInbound` resolves an
// inbound frame's `skid` before the frame is authenticated, so a sender
// that can route a frame through the mediator picks a host this client
// would GET. Resolution must therefore produce no request at all to a
// host the policy refuses.
//
// Ported from the live SSRF harness, whose listener used to receive the
// GET for `did:webvh:<scid>:localhost%3A<port>`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

import * as didWebvh from "../src/did-webvh.js";
import { resolve as resolveDid } from "../src/resolver.js";
import { resolveX25519KeyAgreement } from "../src/vta-didcomm.js";
import { unpackInbound } from "../src/mediator-transport.js";
import { pack } from "../src/pack.js";
import { generateEphemeralClient } from "../src/vta-rest-auth.js";
import { BLOCKED_ENDPOINT } from "../src/net-guard.js";
import * as jwk from "../src/jwk.js";

const SCID = "QmbogusSCIDforTestsOnly0000000000000000000000";
const DEV = { allowInsecure: true, allowPrivate: true };

function blocked(reason) {
  return (err) => {
    assert.equal(err.code, BLOCKED_ENDPOINT, `expected ${BLOCKED_ENDPOINT}, got: ${err.message}`);
    if (reason) assert.equal(err.reason, reason);
    return true;
  };
}

// Stand-in for an internal-only service, recording every request that
// arrives. It answers with a syntactically valid but bogus log line, so
// reaching it gets as far as verification — which is how the positive
// control tells "dialed" apart from "refused".
async function listener() {
  const hits = [];
  let connections = 0;
  const server = createServer((req, res) => {
    hits.push({ method: req.method, path: req.url, host: req.headers.host });
    res.setHeader("content-type", "application/jsonl");
    res.end(`${JSON.stringify(["1-bogus", "2026-01-01T00:00:00Z", {}, { value: {} }])}\n`);
  });
  // A socket opened and then abandoned is still a dial the guard should
  // have refused, and it never shows up as a request.
  server.on("connection", () => {
    connections += 1;
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    hits,
    port,
    get connections() {
      return connections;
    },
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(resolve);
      }),
  };
}

// ─── webvhLogUrl derivation ─────────────────────────────────────────────

test("webvhLogUrl: the log URL follows the identifier, over https", () => {
  const url = (did, policy) => didWebvh.webvhLogUrl(did, policy).href;
  assert.equal(url(`did:webvh:${SCID}:example.com`), `https://example.com/.well-known/did.jsonl`);
  assert.equal(url(`did:webvh:${SCID}:example.com%3A8443`), `https://example.com:8443/.well-known/did.jsonl`);
  assert.equal(url(`did:webvh:${SCID}:example.com:users:alice`), `https://example.com/users/alice/did.jsonl`);
  // `localhost` in the PATH is not a reason to downgrade the scheme:
  // upstream `getBaseUrl` matches the substring anywhere and would have
  // fetched this in the clear.
  assert.equal(url(`did:webvh:${SCID}:example.com:localhost`), `https://example.com/localhost/did.jsonl`);
  // IDN hosts canonicalise like any other URL host.
  assert.equal(url(`did:webvh:${SCID}:b%C3%BCcher.example`), `https://xn--bcher-kva.example/.well-known/did.jsonl`);
});

test("webvhLogUrl: a non-public host is refused before any URL is handed back", () => {
  for (const [suffix, reason] of [
    ["localhost%3A8000", "private_name"],
    ["localhost", "private_name"],
    // The substring case: upstream treats this as local and uses http.
    ["localhost.example%3A8000", "private_name"],
    ["my-localhost.example.com", "private_name"],
    ["printer.local", "private_name"],
    ["127.0.0.1", "private_address"],
    ["127.0.0.1%3A9099", "private_address"],
    ["2130706433", "private_address"],
    ["169.254.169.254%3A80", "private_address"],
    ["10.0.0.5", "private_address"],
  ]) {
    const did = `did:webvh:${SCID}:${suffix}`;
    assert.throws(() => didWebvh.webvhLogUrl(did), blocked(reason), did);
  }
});

test("webvhLogUrl: allowPrivate admits local development, and only exact localhost is plaintext", () => {
  const url = (did, policy) => didWebvh.webvhLogUrl(did, policy).href;
  assert.equal(url(`did:webvh:${SCID}:localhost%3A8000`, DEV), "http://localhost:8000/.well-known/did.jsonl");
  // allowPrivate alone keeps https for a host that is not exactly localhost.
  assert.equal(url(`did:webvh:${SCID}:127.0.0.1%3A9099`, { allowPrivate: true }), "https://127.0.0.1:9099/.well-known/did.jsonl");
  assert.equal(url(`did:webvh:${SCID}:127.0.0.1%3A9099`, DEV), "http://127.0.0.1:9099/.well-known/did.jsonl");
  // An allow-list still narrows, and never re-admits a private address.
  assert.throws(
    () => didWebvh.webvhLogUrl(`did:webvh:${SCID}:example.com`, { allowHosts: ["other.example"] }),
    blocked("not_allowlisted"),
  );
  assert.throws(
    () => didWebvh.webvhLogUrl(`did:webvh:${SCID}:127.0.0.1`, { allowHosts: ["127.0.0.1"] }),
    blocked("private_address"),
  );
});

test("webvhLogUrl: an unusable identifier is rejected, not guessed at", () => {
  for (const did of [
    "did:webvh:", `did:webvh:${SCID}`, `did:webvh::example.com`, `did:webvh:${SCID}:`,
    // More than one colon in the host would be an IPv6 literal, which
    // upstream mangles; fail closed instead.
    `did:webvh:${SCID}:%5B%3A%3A1%5D%3A8000`, `did:webvh:${SCID}:a%3Ab%3Ac`,
    "did:web:example.com", 42, null,
  ]) {
    assert.throws(() => didWebvh.webvhLogUrl(did), /not a usable did:webvh identifier/, JSON.stringify(did));
  }
});

// ─── resolve() against a real listener ──────────────────────────────────

test("did:webvh resolve: the whole bypass vector set gets zero TCP connections", async () => {
  const internal = await listener();
  try {
    // The same bypass table the mediator gate uses, in the spelling a
    // did:webvh identifier can carry: the host is a DID segment, so the
    // port is percent-encoded and a bracketed IPv6 literal cannot be
    // expressed at all (it fails closed instead — see the "unusable
    // identifier" case above). Each host that folds onto 127.0.0.1
    // carries the listener's real port, so a vector that got through
    // would land on it.
    const port = `%3A${internal.port}`;
    const outcomes = [];
    for (const [host, reason] of [
      // Special-use names, and the root-dot form of each.
      [`localhost${port}`, "private_name"],
      [`localhost.${port}`, "private_name"],
      [`log.localhost${port}`, "private_name"],
      [`log.localhost.${port}`, "private_name"],
      // The substring case the upstream downgrade turns into plaintext.
      [`localhost.example${port}`, "private_name"],
      ["log.local", "private_name"],
      ["log.local.", "private_name"],
      ["log.internal", "private_name"],
      ["log.home.arpa", "private_name"],
      // Loopback, and its alternate IPv4 spellings.
      [`127.0.0.1${port}`, "private_address"],
      [`127.0.0.1.${port}`, "private_address"],
      [`127.1${port}`, "private_address"],
      [`0x7f000001${port}`, "private_address"],
      [`2130706433${port}`, "private_address"],
      [`0177.0.0.1${port}`, "private_address"],
      // Link-local and cloud metadata, CGNAT, RFC 1918, "this network".
      ["169.254.169.254", "private_address"],
      ["100.64.0.1", "private_address"],
      ["100.100.100.200", "private_address"],
      ["10.0.0.5", "private_address"],
      ["172.16.0.1", "private_address"],
      ["192.168.1.1", "private_address"],
      ["0.0.0.0", "private_address"],
    ]) {
      const did = `did:webvh:${SCID}:${host}`;
      // Directly, and through the method dispatcher the way callers
      // reach it — `resolve(did)` is what `unpackInbound` calls on an
      // unauthenticated frame's `skid`.
      for (const call of [() => didWebvh.resolve(did), () => resolveDid(did)]) {
        let err;
        try {
          await call();
        } catch (e) {
          err = e;
        }
        outcomes.push({ did, reason, err });
      }
    }
    // The dial first: no vector may get as far as a socket.
    assert.equal(internal.connections, 0, "no vector may open a socket to the internal listener");
    assert.equal(internal.hits.length, 0, "no request may reach the internal listener");
    const wrong = outcomes.filter(({ reason, err }) => err?.code !== BLOCKED_ENDPOINT || err.reason !== reason);
    assert.deepEqual(
      wrong.map(({ did, reason, err }) => `${did} -> want ${reason}, got ${err?.reason ?? err?.message ?? "resolved"}`),
      [],
    );
  } finally {
    await internal.close();
  }
});

test("did:webvh resolve: an injected fetch is never called for a refused host", async () => {
  const calls = [];
  const spy = async (...args) => {
    calls.push(args);
    return new Response("", { status: 200 });
  };
  await assert.rejects(
    () => didWebvh.resolve(`did:webvh:${SCID}:169.254.169.254`, { fetch: spy }),
    blocked("private_address"),
  );
  assert.equal(calls.length, 0);
});

test("did:webvh resolve: positive control — allowPrivate reaches the listener", async () => {
  const internal = await listener();
  try {
    // The log is bogus, so resolution still fails — after the fetch.
    await assert.rejects(
      () => didWebvh.resolve(`did:webvh:${SCID}:localhost%3A${internal.port}`, { netPolicy: DEV }),
      (err) => {
        assert.notEqual(err.code, BLOCKED_ENDPOINT, `should fail on the log, not the policy: ${err.message}`);
        return true;
      },
    );
    assert.equal(internal.hits.length, 1);
    assert.equal(internal.hits[0].method, "GET");
    assert.equal(internal.hits[0].path, "/.well-known/did.jsonl");
    assert.equal(internal.hits[0].host, `localhost:${internal.port}`);
  } finally {
    await internal.close();
  }
});

test("did:webvh resolve: a redirect from an allowed host is not followed", async () => {
  const target = await listener();
  const redirector = await listener();
  const server = createServer((req, res) => {
    res.writeHead(302, { location: `http://127.0.0.1:${target.port}/.well-known/did.jsonl` });
    res.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    await assert.rejects(
      () => didWebvh.resolve(`did:webvh:${SCID}:localhost%3A${port}`, { netPolicy: DEV }),
      blocked("redirect"),
    );
    assert.equal(target.hits.length, 0, "the redirect target must not be requested");
    assert.equal(target.connections, 0, "the redirect target must not be dialed at all");
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
    await redirector.close();
    await target.close();
  }
});

// ─── nested verification methods (the resolveVM egress) ─────────────────

// A log entry whose proof names another did:webvh. `didwebvh-ts` fetches
// that identifier's own log itself, through the global fetch, so its host
// has to be vetted before the log is handed over.
function logWithProofVm(vm) {
  return [
    {
      versionId: "1-QmBogusEntryHashForTestsOnly000000000000000",
      versionTime: "2026-01-01T00:00:00Z",
      parameters: {
        method: "did:webvh:1.0",
        scid: SCID,
        updateKeys: [],
        portable: false,
        nextKeyHashes: [],
      },
      state: { id: `did:webvh:${SCID}:example.com` },
      proof: [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          proofPurpose: "authentication",
          verificationMethod: vm,
          created: "2026-01-01T00:00:00Z",
          proofValue: "z2bogus",
        },
      ],
    },
  ];
}

test("did:webvh resolveLog: a nested verification-method host is refused before any fetch", async () => {
  const internal = await listener();
  try {
    for (const [vm, reason] of [
      [`did:webvh:${SCID}:127.0.0.1%3A${internal.port}#key-1`, "private_address"],
      [`did:webvh:${SCID}:localhost%3A${internal.port}#key-1`, "private_name"],
      [`did:webvh:${SCID}:169.254.169.254#key-1`, "private_address"],
    ]) {
      await assert.rejects(() => didWebvh.resolveLog(logWithProofVm(vm)), blocked(reason), vm);
    }
    assert.equal(internal.hits.length, 0);
  } finally {
    await internal.close();
  }
});

test("did:webvh resolveLog: a did:key verification method is not treated as an endpoint", async () => {
  // Nothing to vet, so the log gets through to verification and fails
  // there — on the bogus proof, not on the egress policy.
  await assert.rejects(
    () => didWebvh.resolveLog(logWithProofVm("did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG#z6Mk")),
    (err) => {
      assert.notEqual(err.code, BLOCKED_ENDPOINT, err.message);
      return true;
    },
  );
});

test("did:webvh resolveLog: a log declaring witnesses needs its proofs passed in", async () => {
  const log = logWithProofVm("did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG#z6Mk");
  log[0].parameters.witness = {
    threshold: 1,
    witnesses: [{ id: `did:webvh:${SCID}:witness.example` }],
  };
  // Without this, `didwebvh-ts` would fetch did-witness.json itself,
  // unchecked, from a host named inside the log.
  await assert.rejects(
    () => didWebvh.resolveLog(log),
    /declares witnesses/,
  );
});

// ─── the inbound path ───────────────────────────────────────────────────

test("unpackInbound: a webvh skid on an internal host is refused, and netPolicy reaches the resolver", async () => {
  const internal = await listener();
  const me = generateEphemeralClient();
  const stranger = generateEphemeralClient();
  const senderDid = `did:webvh:${SCID}:localhost%3A${internal.port}`;
  const recipient = { kid: me.kid, privateJwk: jwk.privateJwk("X25519", me.privateKey, me.publicKey) };

  try {
    // A frame whose skid names the internal host. Nothing about it is
    // authenticated yet: resolving the skid is what happens first.
    const frame = await pack({
      message: { id: "1", type: "t", from: senderDid, to: [me.did], body: {} },
      sender: {
        kid: `${senderDid}#key-1`,
        privateJwk: jwk.privateJwk("X25519", stranger.privateKey, stranger.publicKey),
      },
      recipient: { kid: me.kid, publicJwk: jwk.publicJwk("X25519", me.publicKey) },
    });

    // The resolveSender that `connectVtaViaMediator` installs, under the
    // default policy.
    const resolveSender = (netPolicy) => async (did) => {
      const { x25519Pub } = await resolveX25519KeyAgreement(did, { netPolicy });
      return { publicJwk: jwk.publicJwk("X25519", x25519Pub) };
    };

    await assert.rejects(
      () => unpackInbound(frame, { recipient, senderKeys: new Map(), resolveSender: resolveSender(undefined) }),
      blocked("private_name"),
    );
    assert.equal(internal.hits.length, 0, "an inbound frame must not dial the host it names");

    // Positive control: the policy is what decides, and it does reach
    // the resolver through resolveSender.
    await assert.rejects(
      () => unpackInbound(frame, { recipient, senderKeys: new Map(), resolveSender: resolveSender(DEV) }),
      (err) => {
        assert.notEqual(err.code, BLOCKED_ENDPOINT, err.message);
        return true;
      },
    );
    assert.equal(internal.hits.length, 1);
    assert.equal(internal.hits[0].path, "/.well-known/did.jsonl");
  } finally {
    await internal.close();
  }
});
