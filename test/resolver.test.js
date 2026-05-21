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
