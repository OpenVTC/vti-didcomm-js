// A hostname is not an address. `assertSafeEndpoint` can only judge the
// URL text, so `https://mediator.rebind.test/` — a name with nothing
// local-looking about it — passes the parse-time check and the DNS answer
// alone decides what the socket dials. That is the SSRF bypass the live
// SEC-4045 harness left open: block the literals and an attacker just
// publishes an A record for 127.0.0.1 or 169.254.169.254.
//
// `guardedLookup` (../src/net-guard-node.js) is the connect-time half of
// the guard, and this file is its end-to-end gate: the library's own
// mediator-auth and did:webvh fetch paths, driven by the fetch recipe the
// README documents, must produce **zero TCP connections** to a name that
// resolves to loopback — refused before dialing, not after.
//
// Hermetic: the resolver is a stub table, so nothing here touches real
// DNS, and the only listener is bound to 127.0.0.1.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

import { authenticateToMediator } from "../src/mediator-auth.js";
import * as didWebvh from "../src/did-webvh.js";
import { guardedLookup } from "../src/net-guard-node.js";
import { BLOCKED_ENDPOINT } from "../src/net-guard.js";
import { generateEphemeralClient } from "../src/vta-rest-auth.js";
import * as x25519 from "../src/x25519.js";
import * as multibase from "../src/multibase.js";

const SCID = "QmbogusSCIDforTestsOnly0000000000000000000000";

// The name an attacker controls: public-looking, so the URL-text check
// has no reason to refuse it. Only its DNS answer is hostile.
const REBIND = "mediator.rebind.test";

function blocked(reason) {
  return (err) => {
    assert.equal(err.code, BLOCKED_ENDPOINT, `expected ${BLOCKED_ENDPOINT}, got: ${err.message}`);
    if (reason) assert.equal(err.reason, reason);
    return true;
  };
}

// A dns.lookup stand-in answering from a fixed table, so the test never
// asks the real resolver anything.
function stubResolver(table) {
  const calls = [];
  const lookup = (hostname, options, callback) => {
    calls.push({ hostname, options });
    const list = (table[hostname] ?? []).map((address) => ({
      address,
      family: address.includes(":") ? 6 : 4,
    }));
    process.nextTick(callback, null, list);
  };
  return { lookup, calls };
}

// The internal service. It counts TCP connections as well as requests:
// a connection that is opened and then fails (a TLS handshake against a
// plaintext listener, say) still means the guard did not stop the dial.
async function listener() {
  const hits = [];
  let connections = 0;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      hits.push({ method: req.method, path: req.url, host: req.headers.host });
      res.setHeader("content-type", "application/json");
      if (req.url.endsWith("/challenge")) {
        res.end(JSON.stringify({ sessionId: "s", data: { challenge: "c", session_id: "s" } }));
      } else {
        res.end(
          JSON.stringify({
            sessionId: "s",
            data: { access_token: "a", access_expires_at: 1, refresh_token: "r", refresh_expires_at: 2 },
          }),
        );
      }
    });
  });
  server.on("connection", () => {
    connections += 1;
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    hits,
    port: server.address().port,
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

// The recipe from the README, minus undici: a `fetch` whose sockets
// resolve names through `lookup`. `agent: false` so every request does
// its own connect, and nothing is pooled between cases.
function lookupFetch(lookup) {
  return (input, init = {}) =>
    new Promise((resolve, reject) => {
      const url = new URL(String(typeof input === "string" || input instanceof URL ? input : input?.url));
      const send = url.protocol === "https:" ? httpsRequest : httpRequest;
      const req = send(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port,
          path: `${url.pathname}${url.search}`,
          method: init.method ?? "GET",
          headers: init.headers ?? {},
          lookup,
          agent: false,
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () =>
            resolve(
              new Response(Buffer.concat(chunks).toString("utf8"), {
                status: res.statusCode,
                headers: { "content-type": res.headers["content-type"] ?? "application/json" },
              }),
            ),
          );
        },
      );
      req.on("error", reject);
      if (init.body) req.write(init.body);
      req.end();
    });
}

function mediatorDoc(did, endpoints) {
  const kp = x25519.generateKeyPair();
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
  return {
    id: did,
    service: [
      {
        id: `${did}#dm`,
        type: "DIDCommMessaging",
        serviceEndpoint: endpoints.map((uri) => ({ uri, accept: ["didcomm/v2"], routingKeys: [] })),
      },
    ],
    keyAgreement: [{ id: `${did}#${mb}`, type: "Multikey", controller: did, publicKeyMultibase: mb }],
  };
}

function clientArgs() {
  const c = generateEphemeralClient();
  return {
    clientDid: c.did,
    clientX25519Private: c.privateKey,
    clientX25519Public: c.publicKey,
    clientKid: c.kid,
  };
}

// ─── the mediator forced-auth path ──────────────────────────────────────

test("DNS rebinding: a mediator endpoint whose name resolves to loopback gets zero connections", async () => {
  const internal = await listener();
  const did = "did:peer:2.rebinding-mediator";
  // Every answer in the table is loopback, which is the whole point: the
  // endpoint URL is indistinguishable from a public one until it is
  // resolved. The policy below is the *permissive* one — plaintext
  // allowed, private hosts not — so the only thing left to refuse this
  // is the connect-time address check.
  const { lookup, calls } = stubResolver({ [REBIND]: ["127.0.0.1"] });
  const doc = mediatorDoc(did, [`http://${REBIND}:${internal.port}`]);
  const args = {
    mediatorDid: did,
    ...clientArgs(),
    resolve: async () => ({ didDocument: doc }),
    netPolicy: { allowInsecure: true },
  };

  try {
    // The dial is asserted before the error, so that a guard which let
    // this through reports the socket it opened rather than only the
    // rejection it failed to raise.
    let err;
    try {
      await authenticateToMediator({ ...args, fetch: lookupFetch(guardedLookup({ lookup })) });
    } catch (e) {
      err = e;
    }
    assert.equal(internal.connections, 0, "the guard must refuse before the socket is dialed");
    assert.equal(internal.hits.length, 0);
    assert.ok(calls.length > 0, "the name was resolved — the refusal is the address, not a lookup failure");
    assert.ok(err, "the rebinding endpoint must be refused");
    blocked("private_address")(err);

    // Positive control: nothing but the address check was in the way.
    // The same document, the same policy, the same listener — with the
    // address check off, the handshake completes against loopback.
    const result = await authenticateToMediator({
      ...args,
      fetch: lookupFetch(guardedLookup({ lookup, allowPrivate: true })),
    });
    assert.equal(result.accessToken, "a");
    assert.deepEqual(
      internal.hits.map((h) => `${h.method} ${h.path}`),
      ["POST /authenticate/challenge", "POST /authenticate"],
    );
    assert.equal(internal.hits[0].host, `${REBIND}:${internal.port}`, "the Host header is the attacker's name");
  } finally {
    await internal.close();
  }
});

test("DNS rebinding: every non-public answer is refused, whichever form it arrives in", async () => {
  // The answer classes, driven at the lookup itself rather than through a
  // socket. Only loopback is safe to let a socket attempt — these answers
  // are real addresses on a real network, and a guard that stopped
  // refusing them would have the test dialing a metadata service. Calling
  // `guardedLookup` directly cannot leave the process at all, whatever
  // state the guard is in, and the address decision is the whole thing
  // under test: the end-to-end proof that the decision reaches the socket
  // is the loopback case above and the did:webvh case below.
  //
  // One name per case, because the answer is what varies: loopback, the
  // cloud metadata address, CGNAT, RFC 1918, and the IPv4-mapped IPv6
  // spelling of loopback that the dependencies' own `guard_public_url`
  // still lets through.
  const answers = {
    "a.rebind.test": ["127.0.0.1"],
    "b.rebind.test": ["169.254.169.254"],
    "c.rebind.test": ["100.64.0.1"],
    "d.rebind.test": ["10.0.0.5"],
    "e.rebind.test": ["::ffff:127.0.0.1"],
    "f.rebind.test": ["192.168.1.1"],
    "h.rebind.test": ["172.16.0.1"],
    "i.rebind.test": ["0.0.0.0"],
    "j.rebind.test": ["fd00:ec2::254"],
    // A single hostile answer among public ones refuses the whole name:
    // otherwise the socket picks, and it may pick the private one.
    "g.rebind.test": ["93.184.216.34", "127.0.0.1"],
  };
  const { lookup } = stubResolver(answers);
  const resolveThrough = (impl, hostname, options = {}) =>
    new Promise((done) => impl(hostname, options, (err, ...rest) => done({ err, rest })));

  const guarded = guardedLookup({ lookup });
  const outcomes = [];
  for (const host of Object.keys(answers)) {
    outcomes.push({ host, ...(await resolveThrough(guarded, host)) });
  }
  const wrong = outcomes.filter(({ err }) => err?.code !== BLOCKED_ENDPOINT || err.reason !== "private_address");
  assert.deepEqual(
    wrong.map(
      ({ host, err, rest }) =>
        `${host} -> ${answers[host].join(", ")}: got ${err?.reason ?? err?.message ?? `addresses ${JSON.stringify(rest)}`}`,
    ),
    [],
  );

  // The name is what is refused, not one address of it: nothing is handed
  // back for the socket to pick from.
  for (const { rest } of outcomes) assert.deepEqual(rest, []);

  // Positive control: a wholly public answer passes through untouched, so
  // the refusals above are the address check and not a broken stub.
  const { lookup: publicLookup } = stubResolver({ "ok.rebind.test": ["93.184.216.34"] });
  const ok = await resolveThrough(guardedLookup({ lookup: publicLookup }), "ok.rebind.test");
  assert.equal(ok.err, null);
  assert.deepEqual(ok.rest, ["93.184.216.34", 4]);
  // …and allowPrivate is what a local-development caller opts into.
  const dev = await resolveThrough(guardedLookup({ lookup, allowPrivate: true }), "a.rebind.test");
  assert.equal(dev.err, null);
  assert.deepEqual(dev.rest, ["127.0.0.1", 4]);
});

// ─── the did:webvh path ─────────────────────────────────────────────────

test("DNS rebinding: a did:webvh host that resolves to loopback gets zero connections", async () => {
  const internal = await listener();
  // https, because `webvhLogUrl` only downgrades for local development —
  // so the positive control's TLS handshake fails against this plaintext
  // listener. The connection counter is what matters: it records the
  // dial that the blocked case must not make.
  const { lookup } = stubResolver({ [REBIND]: ["127.0.0.1"] });
  const did = `did:webvh:${SCID}:${REBIND}%3A${internal.port}`;

  try {
    await assert.rejects(
      () => didWebvh.resolve(did, { fetch: lookupFetch(guardedLookup({ lookup })) }),
      blocked("private_address"),
    );
    assert.equal(internal.connections, 0, "the log fetch must not reach the internal listener");

    // Positive control: with the address check off the same identifier
    // does dial it (and then fails on the handshake, having connected).
    await assert.rejects(
      () => didWebvh.resolve(did, { fetch: lookupFetch(guardedLookup({ lookup, allowPrivate: true })) }),
      (err) => {
        assert.notEqual(err.code, BLOCKED_ENDPOINT, `should fail on the transport, not the policy: ${err.message}`);
        return true;
      },
    );
    assert.ok(internal.connections >= 1, "the control must actually have connected");
  } finally {
    await internal.close();
  }
});
