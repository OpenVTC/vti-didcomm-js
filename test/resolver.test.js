import { test } from "node:test";
import assert from "node:assert/strict";

import { createResolver, defaultResolver, resolve } from "../src/resolver.js";

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
