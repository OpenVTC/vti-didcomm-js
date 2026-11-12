// A did:webs DID names the host its `keri.cesr` and `did.json` are fetched
// from, and DIDs reach this library from whoever it talks to: `unpackInbound`
// resolves an inbound frame's `skid` before the frame is authenticated, so a
// sender that can route a frame through the mediator picks a host this client
// would GET. Resolution must produce no request at all to a host the policy
// refuses — through `didWebs.resolve` and through the dispatcher both — and
// what it does fetch is bounded: no redirects, a size cap, a timeout.
//
// The counterpart of `did-webvh-ssrf.test.js`, plus the resolver cache.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

import * as didWebs from "../src/did-webs.js";
import { createResolver, resolve as resolveDid } from "../src/resolver.js";
import { BLOCKED_ENDPOINT } from "../src/net-guard.js";

const FIXTURES = resolvePath(dirname(fileURLToPath(import.meta.url)), "fixtures", "did-webs");
const CESR = new Uint8Array(readFileSync(resolvePath(FIXTURES, "ENro7uf0.keri.cesr")));
const DID_JSON = new Uint8Array(readFileSync(resolvePath(FIXTURES, "ENro7uf0.did.json")));
const AID = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
// The reference identifier's own host: a single-label name, so reaching it
// takes allowPrivate, and not loopback, so it stays https.
const DID = `did:webs:did-webs-service%3a7676:${AID}`;
const DEV = { allowPrivate: true };

function blocked(reason) {
  return (err) => {
    assert.equal(err.code, BLOCKED_ENDPOINT, `expected ${BLOCKED_ENDPOINT}, got: ${err.message}`);
    if (reason) assert.equal(err.reason, reason);
    return true;
  };
}

function refused(kind) {
  return (err) => {
    assert.equal(err.code, didWebs.DID_WEBS_ERROR, err.message);
    assert.equal(err.kind, kind, err.message);
    return true;
  };
}

// A fetch serving the reference artifacts at their URLs, counting calls.
function servingFetch({ cesr = CESR, didJson = DID_JSON, status = 200 } = {}) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    if (status !== 200) return new Response("nope", { status });
    if (String(url).endsWith("/keri.cesr")) return new Response(cesr);
    if (String(url).endsWith("/did.json")) return new Response(didJson);
    return new Response("not found", { status: 404 });
  };
  return { fetch, calls };
}

// Stand-in for an internal-only service, recording every request.
async function listener() {
  const hits = [];
  let connections = 0;
  const server = createServer((req, res) => {
    hits.push({ method: req.method, path: req.url });
    res.end(req.url.endsWith("/keri.cesr") ? CESR : DID_JSON);
  });
  server.on("connection", () => {
    connections += 1;
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    hits,
    port: server.address().port,
    get connections() {
      return connections;
    },
    close: () =>
      new Promise((r) => {
        server.closeAllConnections?.();
        server.close(r);
      }),
  };
}

const vectors = (port) => {
  const p = port === undefined ? "" : `%3A${port}`;
  return [
    [`localhost${p}`, "private_name"],
    [`log.localhost${p}`, "private_name"],
    [`127.0.0.1${p}`, "private_address"],
    [`127.1${p}`, "private_address"],
    [`2130706433${p}`, "private_address"],
    [`%5B%3A%3A1%5D${p}`, "private_address"],
    ["169.254.169.254", "private_address"],
    ["10.0.0.5", "private_address"],
    ["192.168.1.1", "private_address"],
    ["100.100.100.200", "private_address"],
    ["intranet", "private_name"],
    ["log.internal", "private_name"],
    ["printer.local", "private_name"],
  ];
};

test("did:webs: a non-public host is refused before any fetch, through both entry points", async () => {
  let fetched = 0;
  const fetch = async () => {
    fetched += 1;
    throw new Error("must not be called");
  };
  for (const [host, reason] of vectors(8000)) {
    const did = `did:webs:${host}:${AID}`;
    await assert.rejects(didWebs.resolve(did, { fetch }), blocked(reason), did);
    await assert.rejects(resolveDid(did, { fetch }), blocked(reason), did);
  }
  assert.equal(fetched, 0);
});

test("did:webs: a refused loopback host gets no request and no connection", async () => {
  const srv = await listener();
  try {
    for (const host of [`localhost%3A${srv.port}`, `127.0.0.1%3A${srv.port}`, `0x7f000001%3A${srv.port}`]) {
      const did = `did:webs:${host}:${AID}`;
      await assert.rejects(didWebs.resolve(did), (e) => e.code === BLOCKED_ENDPOINT, did);
      await assert.rejects(resolveDid(did), (e) => e.code === BLOCKED_ENDPOINT, did);
    }
    assert.equal(srv.hits.length, 0);
    assert.equal(srv.connections, 0);

    // Positive control: with private hosts admitted, a loopback host is
    // fetched over plain http — both artifacts, in order — and then refused
    // because the stream does not designate a DID at this host.
    await assert.rejects(didWebs.resolve(`did:webs:127.0.0.1%3A${srv.port}:${AID}`, { netPolicy: DEV }), refused("NotDesignated"));
    assert.deepEqual(srv.hits.map((h) => h.path), [`/${AID}/keri.cesr`, `/${AID}/did.json`]);
  } finally {
    await srv.close();
  }
});

test("did:webs: allowHosts narrows, and never re-admits a private address", async () => {
  const { fetch, calls } = servingFetch();
  await assert.rejects(
    didWebs.resolve(`did:webs:example.com:${AID}`, { fetch, netPolicy: { allowHosts: ["other.example"] } }),
    blocked("not_allowlisted"),
  );
  await assert.rejects(
    didWebs.resolve(`did:webs:127.0.0.1:${AID}`, { fetch, netPolicy: { allowHosts: ["127.0.0.1"] } }),
    blocked("private_address"),
  );
  assert.equal(calls.length, 0);
});

test("did:webs: resolves through the vetted fetch, which never follows a redirect", async () => {
  const { fetch, calls } = servingFetch();
  const { didDocument } = await didWebs.resolve(DID, { fetch, netPolicy: DEV });
  assert.equal(didDocument.id, DID);
  assert.deepEqual(calls.map((c) => c.url), [
    `https://did-webs-service:7676/${AID}/keri.cesr`,
    `https://did-webs-service:7676/${AID}/did.json`,
  ]);
  for (const c of calls) {
    assert.equal(c.init.redirect, "manual");
    assert.ok(c.init.signal instanceof AbortSignal, "every request has a timeout");
  }

  const redirecting = async () => new Response(null, { status: 302, headers: { location: "http://169.254.169.254/" } });
  await assert.rejects(didWebs.resolve(DID, { fetch: redirecting, netPolicy: DEV }), blocked("redirect"));
});

test("did:webs: both artifacts are required, and a failed fetch is a Fetch error", async () => {
  await assert.rejects(didWebs.resolve(DID, { fetch: servingFetch({ status: 404 }).fetch, netPolicy: DEV }), (e) => {
    refused("Fetch")(e);
    assert.equal(e.status, 404);
    return true;
  });
  const noDidJson = async (url) => (String(url).endsWith("/keri.cesr") ? new Response(CESR) : new Response("gone", { status: 410 }));
  await assert.rejects(didWebs.resolve(DID, { fetch: noDidJson, netPolicy: DEV }), refused("Fetch"));
  const failing = async () => {
    throw new TypeError("network down");
  };
  await assert.rejects(didWebs.resolve(DID, { fetch: failing, netPolicy: DEV }), refused("Fetch"));
});

test("did:webs: an artifact over 4 MiB is refused, by its declared length or as it is read", async () => {
  const declared = async () =>
    new Response("x", { headers: { "content-length": String(didWebs.MAX_ARTIFACT_BYTES + 1) } });
  await assert.rejects(didWebs.resolve(DID, { fetch: declared, netPolicy: DEV }), (e) => refused("Fetch")(e) && /declares \d+ bytes, over the 4194304-byte cap/.test(e.message));

  let pulled = 0;
  const chunk = new Uint8Array(64 * 1024).fill(0x20);
  const endless = async () =>
    new Response(
      new ReadableStream({
        pull(controller) {
          pulled += chunk.length;
          controller.enqueue(chunk);
        },
      }),
    );
  await assert.rejects(didWebs.resolve(DID, { fetch: endless, netPolicy: DEV }), (e) => refused("Fetch")(e) && /is over the 4194304-byte cap/.test(e.message));
  assert.ok(pulled <= didWebs.MAX_ARTIFACT_BYTES + 2 * chunk.length, `read ${pulled} bytes of an endless body`);
});

test("did:webs: a stalled host times out", async () => {
  // AbortSignal.timeout's timer does not hold the event loop open, so the
  // stalled host holds it until the abort arrives.
  const stalled = (url, init) =>
    new Promise((_, reject) => {
      const open = setTimeout(() => {}, 10_000);
      init.signal.addEventListener("abort", () => {
        clearTimeout(open);
        reject(init.signal.reason);
      });
    });
  await assert.rejects(didWebs.resolve(DID, { fetch: stalled, netPolicy: DEV, timeoutMs: 20 }), refused("Fetch"));
});

// ─── The resolver cache ─────────────────────────────────────────────────

test("resolver cache: a did:webs resolution is cached, and invalidate forces a refetch", async () => {
  const resolver = createResolver();
  const { fetch, calls } = servingFetch();
  const first = await resolver.resolve(DID, { fetch, netPolicy: DEV });
  const again = await resolver.resolve(DID, { fetch, netPolicy: DEV });
  assert.equal(again, first);
  assert.equal(calls.length, 2, "keri.cesr and did.json, once");
  assert.equal(resolver.size(), 1);

  // A versionId DID URL is its own entry.
  await resolver.resolve(`${DID}?versionId=2`, { fetch, netPolicy: DEV });
  assert.equal(calls.length, 4);
  assert.equal(resolver.size(), 2);

  resolver.invalidate(DID);
  await resolver.resolve(DID, { fetch, netPolicy: DEV });
  assert.equal(calls.length, 6);
});

test("resolver cache: a refused did:webs resolution is not memoized", async () => {
  const resolver = createResolver();
  const bad = servingFetch({ didJson: new TextEncoder().encode('{"id":"did:web:attacker.example:x"}') });
  await assert.rejects(resolver.resolve(DID, { fetch: bad.fetch, netPolicy: DEV }), refused("DocumentMismatch"));
  assert.equal(resolver.size(), 0);
  const good = servingFetch();
  await resolver.resolve(DID, { fetch: good.fetch, netPolicy: DEV });
  assert.equal(good.calls.length, 2);
  assert.equal(resolver.size(), 1);
});

test("resolver cache: versionTime is refused for did:webs, and bypasses the cache", async () => {
  const resolver = createResolver();
  const { fetch, calls } = servingFetch();
  await resolver.resolve(DID, { fetch, netPolicy: DEV });
  await assert.rejects(resolver.resolve(DID, { fetch, netPolicy: DEV, versionTime: new Date() }), /versionTime is not supported/);
  assert.equal(calls.length, 2);
});
