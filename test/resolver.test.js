import { test } from "node:test";
import assert from "node:assert/strict";

import {
  createResolver,
  defaultResolver,
  resolve,
  DEFAULT_DID_CACHE_MAX_ENTRIES,
} from "../src/resolver.js";

const DID_KEY = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

test("resolver: dispatches did:key to the built-in handler", async () => {
  const { didDocument } = await defaultResolver.resolve(
    "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
  );
  assert.equal(
    didDocument.id,
    "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
  );
});

test("resolver: module-level resolve() is equivalent to defaultResolver.resolve()", async () => {
  const a = await resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
  const b = await defaultResolver.resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
  assert.deepEqual(a.didDocument, b.didDocument);
});

test("resolver: rejects an unknown method", async () => {
  await assert.rejects(
    () => defaultResolver.resolve("did:totally-fake:abc123"),
    /no handler for method "totally-fake"/,
  );
});

test("resolver: rejects a malformed DID", async () => {
  await assert.rejects(
    () => defaultResolver.resolve("not-a-did"),
    /not a DID/,
  );
  await assert.rejects(
    () => defaultResolver.resolve("did:onlyamethod"),
    /missing method-specific identifier/,
  );
});

test("resolver: custom overrides plug in", async () => {
  const r = createResolver({
    fake: {
      async resolve(did) {
        return {
          didDocument: { id: did, custom: true },
          didResolutionMetadata: {},
          didDocumentMetadata: {},
        };
      },
    },
  });
  const { didDocument } = await r.resolve("did:fake:hello");
  assert.deepEqual(didDocument, { id: "did:fake:hello", custom: true });
});

test("resolver: overrides do not pollute the default", async () => {
  // Sanity check: createResolver makes a NEW handler map; subsequent
  // calls to `resolve(…)` (which uses defaultResolver) must not see
  // the custom handler.
  createResolver({
    fake: { async resolve() {} },
  });
  await assert.rejects(
    () => resolve("did:fake:hello"),
    /no handler for method "fake"/,
  );
});

// Counting handler: records how many times the underlying resolver ran,
// so we can assert the cache actually short-circuits repeat resolutions.
function countingHandler() {
  let calls = 0;
  return {
    get calls() {
      return calls;
    },
    resolver: {
      async resolve(did) {
        calls += 1;
        return {
          didDocument: { id: did, calls },
          didResolutionMetadata: {},
          didDocumentMetadata: {},
        };
      },
    },
  };
}

test("resolver cache: a repeat resolution is served from cache (handler runs once)", async () => {
  const h = countingHandler();
  const r = createResolver({ count: h.resolver });
  const first = await r.resolve("did:count:x");
  const second = await r.resolve("did:count:x");
  assert.equal(h.calls, 1, "second resolve must hit the cache");
  assert.equal(second.didDocument.calls, 1);
  assert.equal(first.didDocument.calls, second.didDocument.calls);
});

test("resolver cache: concurrent resolutions of the same DID share one fetch", async () => {
  const h = countingHandler();
  const r = createResolver({ count: h.resolver });
  const [a, b] = await Promise.all([r.resolve("did:count:y"), r.resolve("did:count:y")]);
  assert.equal(h.calls, 1, "in-flight de-dup: only one underlying fetch");
  assert.equal(a.didDocument.calls, b.didDocument.calls);
});

test("resolver cache: invalidate(did) forces a re-resolution", async () => {
  const h = countingHandler();
  const r = createResolver({ count: h.resolver });
  await r.resolve("did:count:z");
  r.invalidate("did:count:z");
  await r.resolve("did:count:z");
  assert.equal(h.calls, 2);
});

test("resolver cache: setCacheTtl(0) disables caching", async () => {
  const h = countingHandler();
  const r = createResolver({ count: h.resolver });
  r.setCacheTtl(0);
  await r.resolve("did:count:n");
  await r.resolve("did:count:n");
  assert.equal(h.calls, 2);
});

test("resolver cache: a failed resolution is not memoized", async () => {
  let calls = 0;
  const r = createResolver({
    flaky: {
      async resolve(did) {
        calls += 1;
        // First call returns a resolution error; second succeeds.
        if (calls === 1) {
          return {
            didDocument: null,
            didResolutionMetadata: { error: "notFound" },
            didDocumentMetadata: {},
          };
        }
        return {
          didDocument: { id: did },
          didResolutionMetadata: {},
          didDocumentMetadata: {},
        };
      },
    },
  });
  const bad = await r.resolve("did:flaky:1");
  assert.equal(bad.didResolutionMetadata.error, "notFound");
  const good = await r.resolve("did:flaky:1");
  assert.equal(good.didDocument.id, "did:flaky:1");
  assert.equal(calls, 2, "error result must not be cached");
});

// ─── Cache bounds ───────────────────────────────────────────────────────
//
// A client resolves DIDs it did not choose — an inbound frame's `skid`
// names its own sender — so the cache is bounded in two ways: a size cap
// with LRU eviction, and not caching the methods that are free to mint.

function stubHandler() {
  return {
    async resolve(did) {
      return {
        didDocument: { id: did },
        didResolutionMetadata: {},
        didDocumentMetadata: {},
      };
    },
  };
}

test("resolver cache: 1,000 distinct did:webvh resolutions stay inside maxEntries", async () => {
  const r = createResolver({ webvh: stubHandler() }, { maxEntries: 100 });
  for (let i = 0; i < 1000; i++) {
    await r.resolve(`did:webvh:QmStub${i}:example.com`);
  }
  assert.equal(r.size(), 100, "the bound holds, and a full cache stays full");
});

test("resolver cache: the default bound is 500 entries", async () => {
  const r = createResolver({ webvh: stubHandler() });
  for (let i = 0; i < 600; i++) {
    await r.resolve(`did:webvh:QmStub${i}:example.com`);
  }
  assert.equal(r.size(), DEFAULT_DID_CACHE_MAX_ENTRIES);
  assert.equal(DEFAULT_DID_CACHE_MAX_ENTRIES, 500);
});

test("resolver cache: 1,000 did:keys leave the cache empty", async () => {
  const h = countingHandler();
  const r = createResolver({ key: h.resolver, peer: h.resolver });
  for (let i = 0; i < 1000; i++) {
    await r.resolve(`did:key:zStub${i}`);
  }
  assert.equal(r.size(), 0, "did:key resolves offline; caching it only costs memory");

  for (let i = 0; i < 1000; i++) {
    await r.resolve(`did:peer:2.Stub${i}`);
  }
  assert.equal(r.size(), 0);
  assert.equal(h.calls, 2000, "every resolution runs its (offline) handler");
});

test("resolver cache: the real did:key handler is not cached either", async () => {
  const r = createResolver();
  const first = await r.resolve(DID_KEY);
  const second = await r.resolve(DID_KEY);
  assert.equal(first.didDocument.id, DID_KEY);
  assert.deepEqual(first.didDocument, second.didDocument);
  assert.equal(r.size(), 0);
});

test("resolver cache: eviction is least-recently-used", async () => {
  const h = countingHandler();
  const r = createResolver({ count: h.resolver }, { maxEntries: 2 });
  await r.resolve("did:count:a");
  await r.resolve("did:count:b");
  await r.resolve("did:count:a"); // a hit, so `a` becomes the newest entry
  assert.equal(h.calls, 2);

  await r.resolve("did:count:c"); // evicts `b`, the least recently used
  assert.equal(h.calls, 3);
  assert.equal(r.size(), 2);

  await r.resolve("did:count:a");
  assert.equal(h.calls, 3, "`a` survived: it was used more recently than `b`");
  await r.resolve("did:count:b");
  assert.equal(h.calls, 4, "`b` was evicted and had to be resolved again");
});

test("resolver cache: an expired entry is dropped rather than evicting a live one", async () => {
  const h = countingHandler();
  const r = createResolver({ count: h.resolver }, { maxEntries: 2, cacheTtlMs: 1 });
  await r.resolve("did:count:old");
  await new Promise((done) => setTimeout(done, 5));
  r.setCacheTtl(60_000);
  await r.resolve("did:count:fresh");
  await r.resolve("did:count:newer");
  assert.equal(r.size(), 2);
  await r.resolve("did:count:fresh");
  assert.equal(h.calls, 3, "`fresh` is still cached: the expired entry made room");
});

test("resolver cache: maxEntries 0 disables caching, and a bad bound is a TypeError", async () => {
  const h = countingHandler();
  const r = createResolver({ count: h.resolver }, { maxEntries: 0 });
  await r.resolve("did:count:x");
  await r.resolve("did:count:x");
  assert.equal(h.calls, 2);
  assert.equal(r.size(), 0);

  for (const maxEntries of [-1, Number.NaN, Infinity, "500"]) {
    assert.throws(() => createResolver({}, { maxEntries }), TypeError, String(maxEntries));
  }
});

test("resolver cache: size() tracks clearCache and invalidate", async () => {
  const r = createResolver({ webvh: stubHandler() });
  await r.resolve("did:webvh:QmA:example.com");
  await r.resolve("did:webvh:QmB:example.com");
  assert.equal(r.size(), 2);
  r.invalidate("did:webvh:QmA:example.com");
  assert.equal(r.size(), 1);
  r.clearCache();
  assert.equal(r.size(), 0);
  assert.equal(defaultResolver.size(), defaultResolver.size());
});
