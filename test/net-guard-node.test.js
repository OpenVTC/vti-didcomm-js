// guardedLookup: connect-time filtering of DNS answers (Node only).

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, get } from "node:http";

import { guardedLookup } from "../src/net-guard-node.js";
import { BLOCKED_ENDPOINT } from "../src/net-guard.js";

// A dns.lookup stand-in answering from a fixed table.
function stubResolver(table) {
  const calls = [];
  const lookup = (hostname, options, callback) => {
    calls.push({ hostname, options });
    const answer = table[hostname];
    if (answer instanceof Error) return process.nextTick(callback, answer);
    const list = (answer ?? []).map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));
    process.nextTick(callback, null, list);
  };
  return { lookup, calls };
}

function lookupOnce(fn, hostname, options) {
  return new Promise((resolve, reject) => {
    fn(hostname, options, (err, address, family) => (err ? reject(err) : resolve({ address, family })));
  });
}

const TABLE = {
  "a.test": ["93.184.216.34"],
  "b.test": ["127.0.0.1"],
  "c.test": ["93.184.216.34", "10.0.0.1"],
  "d.test": ["::ffff:169.254.169.254"],
  "e.test": ["64:ff9b::7f00:1"],
  "f.test": [],
};

test("guardedLookup dns vectors", async () => {
  const { lookup, calls } = stubResolver(TABLE);
  const guarded = guardedLookup({ lookup });

  assert.deepEqual(await lookupOnce(guarded, "a.test", {}), { address: "93.184.216.34", family: 4 });
  for (const host of ["b.test", "c.test", "d.test", "e.test"]) {
    await assert.rejects(
      () => lookupOnce(guarded, host, {}),
      (e) => e.code === BLOCKED_ENDPOINT && e.reason === "private_address" && e.host === host,
      host,
    );
  }
  await assert.rejects(() => lookupOnce(guarded, "f.test", {}), (e) => e.code === "ENOTFOUND");

  // Every underlying lookup asks for all addresses, so none is left unchecked.
  assert.ok(calls.every((c) => c.options.all === true));
});

test("guardedLookup: honours all:true, numeric family and the two-argument form", async () => {
  const { lookup, calls } = stubResolver({ "multi.test": ["93.184.216.34", "2606:4700:4700::1111"] });
  const guarded = guardedLookup({ lookup });

  const all = await new Promise((resolve, reject) =>
    guarded("multi.test", { all: true }, (err, list) => (err ? reject(err) : resolve(list))),
  );
  assert.equal(all.length, 2);

  await lookupOnce(guarded, "multi.test", 4);
  assert.equal(calls.at(-1).options.family, 4);

  const two = await new Promise((resolve, reject) =>
    guarded("multi.test", (err, address) => (err ? reject(err) : resolve(address))),
  );
  assert.equal(two, "93.184.216.34");
});

test("guardedLookup: allowPrivate skips the check; resolver errors pass through", async () => {
  const boom = Object.assign(new Error("resolver down"), { code: "EAI_AGAIN" });
  const { lookup } = stubResolver({ ...TABLE, "down.test": boom });
  assert.equal((await lookupOnce(guardedLookup({ lookup, allowPrivate: true }), "b.test", {})).address, "127.0.0.1");
  await assert.rejects(() => lookupOnce(guardedLookup({ lookup }), "down.test", {}), (e) => e === boom);
  assert.throws(() => guardedLookup({ lookup: "nope" }), TypeError);
});

test("guardedLookup: an http request to a name resolving to loopback never connects", async () => {
  const hits = [];
  const server = createServer((req, res) => {
    hits.push(req.url);
    res.end("ok");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  const request = (lookup) =>
    new Promise((resolve, reject) => {
      const req = get({ host: "localhost", port, path: "/internal", family: 4, lookup, agent: false }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      });
      req.on("error", reject);
    });

  try {
    await assert.rejects(() => request(guardedLookup()), (e) => e.code === BLOCKED_ENDPOINT);
    assert.equal(hits.length, 0);

    // Positive control: the same request connects when private hosts are allowed.
    assert.equal(await request(guardedLookup({ allowPrivate: true })), 200);
    assert.equal(hits.length, 1);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
});
