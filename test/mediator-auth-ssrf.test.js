// Mediator DID-document endpoints are chosen by whoever controls the
// document. A document naming an internal host must not produce a single
// request to it unless the caller opted in to private hosts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

import { authenticateToMediator, parseMediatorEndpoints, resolveMediator } from "../src/mediator-auth.js";
import { connectVtaViaMediator } from "../src/vta-didcomm.js";
import { generateEphemeralClient } from "../src/vta-rest-auth.js";
import { BLOCKED_ENDPOINT } from "../src/net-guard.js";
import * as x25519 from "../src/x25519.js";
import * as multibase from "../src/multibase.js";

const DEV = { allowInsecure: true, allowPrivate: true };

function blocked(reason) {
  return (err) => {
    assert.equal(err.code, BLOCKED_ENDPOINT, `expected ${BLOCKED_ENDPOINT}, got: ${err.message}`);
    if (reason) assert.equal(err.reason, reason);
    return true;
  };
}

function x25519Multikey() {
  const kp = x25519.generateKeyPair();
  return multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
}

// A mediator DID document with a usable X25519 keyAgreement, so a client
// that is not stopped would get as far as dialing the endpoints.
function mediatorDoc(did, { endpoints, auth }) {
  const mb = x25519Multikey();
  const service = [
    {
      id: `${did}#dm`,
      type: "DIDCommMessaging",
      serviceEndpoint: Array.isArray(endpoints)
        ? endpoints.map((uri) => ({ uri, accept: ["didcomm/v2"], routingKeys: [] }))
        : endpoints,
    },
  ];
  if (auth) service.push({ id: `${did}#auth`, type: "Authentication", serviceEndpoint: auth });
  return {
    id: did,
    service,
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

// Plain-HTTP stand-in for an internal service that happens to speak the
// mediator auth protocol. Records every request that arrives, and every
// TCP connection: a socket that is opened and then fails on the response
// is still a socket the guard should never have let be dialed.
async function listener(handler = mediatorResponses) {
  const hits = [];
  let connections = 0;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      hits.push({ method: req.method, path: req.url, bodyLen: Buffer.concat(chunks).length });
      handler(req, res);
    });
  });
  server.on("connection", () => {
    connections += 1;
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    hits,
    port,
    origin: `http://127.0.0.1:${port}`,
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

function mediatorResponses(req, res) {
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
}

// ─── authenticateToMediator against a real listener ─────────────────────

test("authenticateToMediator: a document naming a loopback listener gets zero requests, even with allowInsecure", async () => {
  const internal = await listener();
  const did = "did:peer:2.attacker-controlled-mediator";
  try {
    const cases = [
      // Plaintext allowed, private hosts not: the host block is independent of the scheme gate.
      { endpoints: [internal.origin], opts: { netPolicy: { allowInsecure: true } }, reason: "private_address" },
      // The deprecated top-level flag behaves the same way.
      { endpoints: [internal.origin], opts: { allowInsecure: true }, reason: "private_address" },
      // An allow-list entry does not re-admit a private address.
      {
        endpoints: [internal.origin],
        opts: { netPolicy: { allowInsecure: true, allowHosts: ["127.0.0.1"] } },
        reason: "private_address",
      },
      // Default policy, https scheme: the host is still refused.
      { endpoints: [`https://127.0.0.1:${internal.port}`], opts: {}, reason: "private_address" },
      { endpoints: [`https://[::ffff:7f00:1]:${internal.port}`], opts: {}, reason: "private_address" },
      { endpoints: [`http://localhost:${internal.port}`], opts: { netPolicy: { allowInsecure: true } }, reason: "private_name" },
    ];
    for (const { endpoints, opts, reason } of cases) {
      const doc = mediatorDoc(did, { endpoints });
      await assert.rejects(
        () => authenticateToMediator({ mediatorDid: did, ...clientArgs(), resolve: async () => ({ didDocument: doc }), ...opts }),
        blocked(reason),
        JSON.stringify({ endpoints, opts }),
      );
    }
    assert.equal(internal.hits.length, 0, "no request may reach the internal listener");
  } finally {
    await internal.close();
  }
});

test("authenticateToMediator: positive control, allowPrivate lets the same handshake reach the listener", async () => {
  const internal = await listener();
  const did = "did:peer:2.local-dev-mediator";
  try {
    const doc = mediatorDoc(did, { endpoints: [internal.origin] });
    const result = await authenticateToMediator({
      mediatorDid: did,
      ...clientArgs(),
      resolve: async () => ({ didDocument: doc }),
      netPolicy: DEV,
    });
    assert.equal(result.accessToken, "a");
    assert.deepEqual(
      internal.hits.map((h) => `${h.method} ${h.path}`),
      ["POST /authenticate/challenge", "POST /authenticate"],
    );
    assert.ok(internal.hits[1].bodyLen > 0, "the packed auth message was posted");
  } finally {
    await internal.close();
  }
});

test("authenticateToMediator: redirects from the auth endpoint are not followed", async () => {
  const did = "did:peer:2.redirecting-mediator";
  for (const redirectOn of ["/authenticate/challenge", "/authenticate"]) {
    const second = await listener();
    const first = await listener((req, res) => {
      if (req.url === redirectOn) {
        res.writeHead(req.url.endsWith("/challenge") ? 302 : 307, { location: `${second.origin}${req.url}` });
        res.end();
      } else {
        mediatorResponses(req, res);
      }
    });
    try {
      const doc = mediatorDoc(did, { endpoints: [first.origin] });
      await assert.rejects(
        () =>
          authenticateToMediator({
            mediatorDid: did,
            ...clientArgs(),
            resolve: async () => ({ didDocument: doc }),
            netPolicy: DEV,
          }),
        blocked("redirect"),
        redirectOn,
      );
      assert.equal(first.hits.at(-1).path, redirectOn);
      assert.equal(second.hits.length, 0, `redirect target must see no request (${redirectOn})`);
    } finally {
      await first.close();
      await second.close();
    }
  }
});

test("authenticateToMediator: a caller-supplied fetch is guarded too", async () => {
  const calls = [];
  const spy = async (url, init) => {
    calls.push({ url, init });
    return new Response("{}", { status: 200 });
  };
  const did = "did:x:metadata-mediator";
  const doc = mediatorDoc(did, { endpoints: ["https://169.254.169.254/latest"] });
  await assert.rejects(
    () => authenticateToMediator({ mediatorDid: did, ...clientArgs(), resolve: async () => ({ didDocument: doc }), fetch: spy }),
    blocked("private_address"),
  );
  assert.equal(calls.length, 0);
});

// ─── mediatorDoc vectors (pure parsing) ─────────────────────────────────

test("parseMediatorEndpoints mediatorDoc vectors: any non-public endpoint rejects the document", () => {
  const did = "did:x:m";
  const refused = [
    [{ endpoints: ["https://127.0.0.1:7037"] }, {}, "private_address"],
    [{ endpoints: ["https://m.example/v1", "wss://10.0.0.5/ws"] }, {}, "private_address"],
    [{ endpoints: "https://169.254.169.254/" }, {}, "private_address"],
    [{ endpoints: ["https://m.example/v1"], auth: "https://[fd00:ec2::254]/" }, {}, "private_address"],
    [{ endpoints: ["https://m.example/v1", "wss://mediator.internal/ws"] }, {}, "private_name"],
    [{ endpoints: ["http://10.0.0.5"] }, { netPolicy: { allowInsecure: true } }, "private_address"],
    [{ endpoints: ["http://10.0.0.5"] }, { allowInsecure: true }, "private_address"],
    [{ endpoints: ["https://m.example/v1"], auth: "ftp://m.example/auth" }, {}, "scheme"],
    [{ endpoints: ["https://u:p@m.example/v1"] }, {}, "userinfo"],
  ];
  for (const [shape, opts, reason] of refused) {
    assert.throws(
      () => parseMediatorEndpoints(mediatorDoc(did, shape), did, opts),
      blocked(reason),
      JSON.stringify({ shape, opts }),
    );
  }
  // Plaintext without allowInsecure is still refused by the scheme gate.
  assert.throws(
    () => parseMediatorEndpoints(mediatorDoc(did, { endpoints: ["http://mediator.example.com"] }), did),
    /insecure REST endpoint/,
  );
});

test("parseMediatorEndpoints: allowHosts must cover every advertised endpoint", () => {
  const did = "did:x:m";
  const doc = mediatorDoc(did, { endpoints: ["https://m.example/v1", "wss://relay.example.net/ws"] });
  assert.throws(
    () => parseMediatorEndpoints(doc, did, { netPolicy: { allowHosts: ["m.example"] } }),
    (err) => blocked("not_allowlisted")(err) && err.host === "relay.example.net",
  );
  const m = parseMediatorEndpoints(doc, did, { netPolicy: { allowHosts: ["m.example", "*.example.net"] } });
  assert.equal(m.wsEndpoint, "wss://relay.example.net/ws");
  assert.throws(() => parseMediatorEndpoints(doc, did, { netPolicy: "strict" }), TypeError);
});

test("resolveMediator: netPolicy reaches the endpoint check", async () => {
  const did = "did:x:m";
  const doc = mediatorDoc(did, { endpoints: ["https://127.0.0.1:7037", "wss://127.0.0.1:7037/ws"] });
  const resolve = async () => ({ didDocument: doc });
  await assert.rejects(() => resolveMediator(did, { resolve }), blocked("private_address"));
  const m = await resolveMediator(did, { resolve, netPolicy: { allowPrivate: true } });
  assert.equal(m.restEndpoint, "https://127.0.0.1:7037");
  assert.equal(m.wsEndpoint, "wss://127.0.0.1:7037/ws");
});

// ─── connectVtaViaMediator with an offline did:peer mediator ────────────

// did:peer:2 carries its service inline, so a DID string alone is enough
// to point a client at any host: no resolver or network is involved.
function didPeerMediator(endpoints) {
  const service = { t: "dm", s: endpoints.map((uri) => ({ uri })) };
  return `did:peer:2.E${x25519Multikey()}.S${Buffer.from(JSON.stringify(service)).toString("base64url")}`;
}

test("connectVtaViaMediator: netPolicy reaches mediator auth and the WebSocket", async () => {
  const internal = await listener();
  const sockets = [];
  class SpyWebSocket {
    constructor(url) {
      sockets.push(url);
      this.readyState = 0;
      setTimeout(() => {
        this.readyState = 1;
        this.onopen?.();
      }, 0);
    }
    send() {}
    close() {
      this.readyState = 3;
    }
  }
  try {
    const vta = generateEphemeralClient();
    const client = generateEphemeralClient();
    const wsUrl = `ws://127.0.0.1:${internal.port}/ws`;
    const args = {
      vtaDid: vta.did,
      mediatorDid: didPeerMediator([internal.origin, wsUrl]),
      clientDid: client.did,
      clientX25519Private: client.privateKey,
      clientX25519Public: client.publicKey,
      WebSocketImpl: SpyWebSocket,
    };

    await assert.rejects(
      () => connectVtaViaMediator({ ...args, netPolicy: { allowInsecure: true } }),
      blocked("private_address"),
    );
    await assert.rejects(() => connectVtaViaMediator(args), /insecure REST endpoint/);
    assert.equal(internal.hits.length, 0);
    assert.equal(sockets.length, 0);

    // Positive control: with private hosts allowed the handshake and the
    // socket both go to the advertised endpoints.
    const vtaClient = await connectVtaViaMediator({ ...args, netPolicy: DEV });
    assert.equal(internal.hits.length, 2);
    assert.deepEqual(sockets, [wsUrl]);
    vtaClient.close();
  } finally {
    await internal.close();
  }
});
