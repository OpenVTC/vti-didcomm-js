// Egress guard vectors (SEC-4045 conformance set: ip, url, names, scheme,
// redirect), plus allow-list and error-shape checks.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

import {
  BLOCKED_ENDPOINT,
  BlockedEndpointError,
  assertSafeEndpoint,
  guardedFetch,
  isBlockedIp,
} from "../src/net-guard.js";

// ─── ip ─────────────────────────────────────────────────────────────────

const IP_BLOCK = [
  "127.0.0.1", "127.255.255.254", "0.0.0.0", "0.1.2.3", "10.0.0.1", "172.16.0.1",
  "172.31.255.255", "192.168.0.1", "169.254.169.254", "169.254.170.2", "100.64.0.1",
  "100.100.100.200", "100.127.255.254", "192.0.0.1", "198.18.0.1", "198.19.255.255",
  "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.250",
  "240.0.0.1", "255.255.255.255",
  "::1", "::", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:169.254.169.254",
  "0:0:0:0:0:ffff:7f00:1", "::127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",
  "64:ff9b:1::a00:1", "2002:7f00:1::1", "2001:0:4136:e378::1", "fc00::1", "fd00::1",
  "fd00:ec2::254", "fe80::1", "febf::1", "fec0::1", "ff02::1", "2001:db8::1", "100::1",
];

const IP_ALLOW = [
  "8.8.8.8", "1.1.1.1", "11.0.0.1", "100.63.255.255", "100.128.0.0", "172.15.255.255",
  "172.32.0.1", "169.253.255.255", "192.169.0.1", "198.20.0.1", "2606:4700:4700::1111",
  "2001:4860:4860::8888", "64:ff9b::808:808", "::ffff:8.8.8.8", "2002:808:808::1",
];

test("isBlockedIp: blocks every non-public vector", () => {
  for (const ip of IP_BLOCK) assert.equal(isBlockedIp(ip), true, ip);
});

test("isBlockedIp: allows every public vector", () => {
  for (const ip of IP_ALLOW) assert.equal(isBlockedIp(ip), false, ip);
});

test("isBlockedIp: accepts brackets, fails closed on anything that is not an IP literal", () => {
  assert.equal(isBlockedIp("[::1]"), true);
  assert.equal(isBlockedIp("[2606:4700:4700::1111]"), false);
  for (const s of [
    "example.com", "", "0177.0.0.1", "127.1", "1.2.3.4.5", "256.0.0.1", "fe80::1%en0",
    "::ffff:1.2.3", "1:2:3:4:5:6:7:8:9", "1::2::3", "gggg::1", ":::1",
  ]) {
    assert.equal(isBlockedIp(s), true, JSON.stringify(s));
  }
  assert.throws(() => isBlockedIp(2130706433), TypeError);
});

// ─── url / names / scheme ───────────────────────────────────────────────

function refusal(fn) {
  try {
    fn();
  } catch (err) {
    return err;
  }
  return null;
}

function assertBlocked(url, policy, reason) {
  const err = refusal(() => assertSafeEndpoint(url, policy));
  assert.ok(err instanceof BlockedEndpointError, `${String(url)} should be blocked (got ${err ?? "allowed"})`);
  assert.equal(err.code, BLOCKED_ENDPOINT);
  if (reason) assert.equal(err.reason, reason, `${String(url)}: reason`);
}

function assertAllowed(url, policy) {
  const err = refusal(() => assertSafeEndpoint(url, policy));
  assert.equal(err, null, `${url} should be allowed under ${JSON.stringify(policy)}: ${err?.message}`);
}

test("assertSafeEndpoint url vectors: alternate encodings and embedded IPv4 are canonicalised, then blocked", () => {
  for (const url of [
    "https://2130706433/", "https://0x7f000001/", "https://017700000001/", "https://0177.0.0.1/",
    "https://0x7f.0.0.1/", "https://127.1/", "https://127.0.1/", "https://0/",
    "https://169.254.169.254/", "https://169.254.169.254./", "https://%31%32%37.0.0.1/",
    "https://①②⑦.0.0.1/", "https://127。0。0。1/", "https://[::ffff:127.0.0.1]/",
    "https://[0:0:0:0:0:ffff:7f00:1]/", "https://[::1]:8443/", "wss://0x7f.1/",
    "https://127.0.0.1\\@example.com/", "https://100.100.100.200/", "https://[fd00::1]/",
    "https://[64:ff9b::a9fe:a9fe]/", "https://[fd00:ec2::254]/", "wss://10.0.0.5/ws",
  ]) {
    assertBlocked(url, undefined, "private_address");
  }
});

test("assertSafeEndpoint url vectors: userinfo is refused", () => {
  assertBlocked("https://user:pass@example.com/", undefined, "userinfo");
  assertBlocked("https://u@example.com/", undefined, "userinfo");
  // Userinfo that disguises a private host is still refused.
  assertBlocked("https://example.com@127.0.0.1/", undefined, "userinfo");
});

test("assertSafeEndpoint url vectors: unparseable input is refused as invalid_url", () => {
  for (const url of [
    "https://0x100000000/", "https://1.2.3.4.5/", "https://[fe80::1%25en0]/", "not a url", "",
    "/relative/path", 42, null, undefined, {},
  ]) {
    assertBlocked(url, undefined, "invalid_url");
  }
});

test("assertSafeEndpoint names vectors", () => {
  for (const url of [
    "https://localhost/", "https://LOCALHOST./", "https://localhost../", "https://svc.localhost/",
    "https://printer.local/", "https://kube-dns.kube-system.svc.cluster.local/",
    "https://metadata.google.internal/", "https://router.home.arpa/",
    // Single-label names (no dot) are never public FQDNs — an internal name the
    // platform's search list would resolve. Blocked as of SEC #15 (previously an
    // uncovered gap that the wallet's own guard caught but this library did not).
    "https://metadata/", "https://intranet/", "https://router/",
  ]) {
    assertBlocked(url, undefined, "private_name");
  }
  for (const url of [
    "https://example.com/", "https://example.com./", "https://localhost.example.com/",
    "https://mediator.example/", "https://local.example/", "https://internal.example.com/",
  ]) {
    assertAllowed(url);
  }
});

test("assertSafeEndpoint scheme vectors: https/wss only by default", () => {
  for (const url of [
    "http://example.com/", "ws://example.com/", "ftp://example.com/", "file:///etc/passwd",
    "gopher://example.com/", "data:text/plain,x", "javascript:alert(1)", "blob:https://x/y",
  ]) {
    assertBlocked(url, undefined, "scheme");
  }
  assertAllowed("https://example.com/");
  assertAllowed("wss://example.com/");
});

test("assertSafeEndpoint: allowInsecure is a scheme opt-out only and never admits private hosts", () => {
  const insecure = { allowInsecure: true };
  assertAllowed("http://example.com/", insecure);
  assertAllowed("ws://example.com/", insecure);
  assertBlocked("ftp://example.com/", insecure, "scheme");
  assertBlocked("http://10.0.0.5/", insecure, "private_address");
  assertBlocked("http://169.254.169.254/", insecure, "private_address");
  assertBlocked("http://127.0.0.1:9099/", insecure, "private_address");
  assertBlocked("http://localhost:8000/", insecure, "private_name");
});

test("assertSafeEndpoint: allowInsecure + allowPrivate admits local development endpoints", () => {
  const dev = { allowInsecure: true, allowPrivate: true };
  assertAllowed("http://localhost:8000/", dev);
  assertAllowed("http://127.0.0.1:9099/", dev);
  assertAllowed("http://[::1]:7037/", dev);
  assertAllowed("ws://mediator.local/ws", dev);
  // allowPrivate alone keeps the https/wss requirement.
  assertBlocked("http://localhost:8000/", { allowPrivate: true }, "scheme");
  assertAllowed("https://localhost:8000/", { allowPrivate: true });
});

test("assertSafeEndpoint: schemes narrows the accepted set; allowInsecure adds only the matching plaintext scheme", () => {
  assertBlocked("https://example.com/", { schemes: ["wss:"] }, "scheme");
  assertAllowed("wss://example.com/", { schemes: ["wss"] });
  assertAllowed("http://example.com/", { schemes: ["https:"], allowInsecure: true });
  assertBlocked("ws://example.com/", { schemes: ["https:"], allowInsecure: true }, "scheme");
  for (const schemes of [["ftp:"], [], "https:", [42], ["file"]]) {
    assert.throws(() => assertSafeEndpoint("https://example.com/", { schemes }), TypeError, JSON.stringify(schemes));
  }
});

test("assertSafeEndpoint: allowHosts exact and *. suffix matching", () => {
  const exact = { allowHosts: ["mediator.example"] };
  assertAllowed("https://mediator.example/ws", exact);
  assertAllowed("https://MEDIATOR.example./v1", exact);
  assertAllowed("wss://mediator.example:8443/ws", exact);
  assertBlocked("https://evil.example/", exact, "not_allowlisted");
  assertBlocked("https://sub.mediator.example/", exact, "not_allowlisted");

  const wildcard = { allowHosts: ["*.vta.example"] };
  assertAllowed("https://a.vta.example/", wildcard);
  assertAllowed("https://a.b.vta.example/", wildcard);
  assertBlocked("https://vta.example/", wildcard, "not_allowlisted");
  assertBlocked("https://evilvta.example/", wildcard, "not_allowlisted");

  // Entries are canonicalised like URL hosts (case, trailing dot, IDN).
  assertAllowed("https://xn--bcher-kva.example/", { allowHosts: ["Bücher.Example."] });
  assertAllowed("https://bücher.example/", { allowHosts: ["xn--bcher-kva.example"] });

  // An empty list admits nothing.
  assertBlocked("https://example.com/", { allowHosts: [] }, "not_allowlisted");
});

test("assertSafeEndpoint: allowHosts never re-admits a blocked address", () => {
  assertBlocked("https://127.0.0.1/", { allowHosts: ["127.0.0.1"] }, "private_address");
  assertBlocked("https://localhost/", { allowHosts: ["localhost"] }, "private_name");
  assertAllowed("https://127.0.0.1/", { allowHosts: ["127.0.0.1"], allowPrivate: true });
  assertAllowed("https://[::1]/", { allowHosts: ["::1"], allowPrivate: true });
  assertAllowed("https://[::1]/", { allowHosts: ["[::1]"], allowPrivate: true });
  assertBlocked("https://[::2]/", { allowHosts: ["::1"], allowPrivate: true }, "not_allowlisted");
});

test("assertSafeEndpoint: malformed allowHosts is a TypeError, not a silent pass", () => {
  for (const allowHosts of [
    "mediator.example", [42], ["https://mediator.example"], ["mediator.example:443"],
    ["mediator.example/path"], ["*"], [""], ["user@host"], ["*.*.example"],
  ]) {
    assert.throws(
      () => assertSafeEndpoint("https://mediator.example/", { allowHosts }),
      TypeError,
      JSON.stringify(allowHosts),
    );
  }
});

test("assertSafeEndpoint: returns the parsed URL; errors carry a stable code and no secrets", () => {
  const u = assertSafeEndpoint("https://0x7f.1:8443/x", { allowPrivate: true });
  assert.ok(u instanceof URL);
  assert.equal(u.hostname, "127.0.0.1");

  const err = refusal(() =>
    assertSafeEndpoint("https://user:secret@example.com:8443/p?token=abc#frag", { label: "mediator REST" }),
  );
  assert.ok(err instanceof Error);
  assert.ok(err instanceof BlockedEndpointError);
  assert.equal(err.name, "BlockedEndpointError");
  assert.equal(err.code, "E_BLOCKED_ENDPOINT");
  assert.equal(err.reason, "userinfo");
  assert.equal(err.label, "mediator REST");
  assert.equal(err.url, "https://example.com:8443/p");
  assert.match(err.message, /mediator REST endpoint/);
  assert.doesNotMatch(err.message, /secret|token|abc|frag/);

  const priv = refusal(() => assertSafeEndpoint("https://[::ffff:7f00:1]/"));
  assert.equal(priv.host, "::ffff:7f00:1");
});

// ─── guardedFetch ───────────────────────────────────────────────────────

function spyFetch(respond = () => new Response("{}", { status: 200 })) {
  const calls = [];
  const fn = async (input, init) => {
    calls.push({ input, init });
    return respond(input, init);
  };
  return { fn, calls };
}

test("guardedFetch: a blocked target never reaches the underlying fetch", async () => {
  const spy = spyFetch();
  const f = guardedFetch(spy.fn, { allowInsecure: true });
  for (const target of ["http://127.0.0.1:1/", "https://169.254.169.254/latest/meta-data/", { url: "https://localhost/" }]) {
    await assert.rejects(() => f(target, { method: "POST" }), (e) => e.code === BLOCKED_ENDPOINT);
  }
  assert.equal(spy.calls.length, 0);
});

test("guardedFetch: forces redirect:manual and keeps the rest of init", async () => {
  const spy = spyFetch();
  const f = guardedFetch(spy.fn, { schemes: ["https:"] });
  const resp = await f("https://mediator.example/v1", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
    redirect: "follow",
  });
  assert.equal(resp.status, 200);
  assert.equal(spy.calls.length, 1);
  assert.equal(spy.calls[0].init.redirect, "manual");
  assert.equal(spy.calls[0].init.method, "POST");
  assert.equal(spy.calls[0].init.body, "{}");

  // A Request object is checked by its URL and passed through unchanged.
  const req = new Request("https://mediator.example/v1");
  await f(req);
  assert.equal(spy.calls[1].input, req);
  assert.equal(spy.calls[1].init.redirect, "manual");
});

test("guardedFetch: rejects 3xx and opaqueredirect responses", async () => {
  for (const status of [301, 302, 303, 307, 308]) {
    const spy = spyFetch(() => new Response(null, { status, headers: { location: "https://127.0.0.1/" } }));
    await assert.rejects(
      () => guardedFetch(spy.fn)("https://mediator.example/"),
      (e) => e.code === BLOCKED_ENDPOINT && e.reason === "redirect" && e.status === status,
    );
  }
  // What a browser returns for redirect:"manual".
  const opaque = spyFetch(() => ({ type: "opaqueredirect", status: 0, ok: false, body: null }));
  await assert.rejects(
    () => guardedFetch(opaque.fn)("https://mediator.example/"),
    (e) => e.code === BLOCKED_ENDPOINT && e.reason === "redirect",
  );
});

test("guardedFetch: validates the fetch implementation and the policy when wrapping", () => {
  assert.throws(() => guardedFetch("nope"), TypeError);
  assert.throws(() => guardedFetch(async () => {}, { allowHosts: "mediator.example" }), TypeError);
  assert.throws(() => guardedFetch(async () => {}, { schemes: ["ftp:"] }), TypeError);
  assert.equal(typeof guardedFetch(undefined), "function"); // falls back to globalThis.fetch
});

// ─── redirect (real sockets) ────────────────────────────────────────────

async function listen(handler) {
  const hits = [];
  const server = createServer((req, res) => {
    hits.push({ method: req.method, url: req.url });
    handler(req, res);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    hits,
    port: server.address().port,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(resolve);
      }),
  };
}

test("guardedFetch redirect vectors: the redirect target receives zero requests", async () => {
  const target = await listen((_req, res) => res.end("{}"));
  const redirector = await listen((req, res) => {
    const status = req.method === "POST" ? 307 : 302;
    res.writeHead(status, { location: `http://127.0.0.1:${target.port}/landed` });
    res.end();
  });
  try {
    const f = guardedFetch(globalThis.fetch, { allowInsecure: true, allowPrivate: true });
    await assert.rejects(
      () => f(`http://127.0.0.1:${redirector.port}/`),
      (e) => e.code === BLOCKED_ENDPOINT && e.reason === "redirect" && e.status === 302,
    );
    await assert.rejects(
      () => f(`http://127.0.0.1:${redirector.port}/`, { method: "POST", body: "{}" }),
      (e) => e.code === BLOCKED_ENDPOINT && e.reason === "redirect" && e.status === 307,
    );
    assert.equal(redirector.hits.length, 2);
    assert.equal(target.hits.length, 0);
  } finally {
    await redirector.close();
    await target.close();
  }
});
