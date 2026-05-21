import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve as pathResolve } from "node:path";

import * as didWebvh from "../src/did-webvh.js";

// Path to the didwebvh-rs Cargo registry fixtures. These belong to
// a published Rust crate, so we don't ship them — we read them from
// the local crates.io cache. If a developer hasn't built the Rust
// side yet the cache won't exist; in that case we skip the
// fixture-based tests rather than fail spuriously.
const RUST_FIXTURES_BASE = pathResolve(
  process.env.HOME ?? "~",
  ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f/didwebvh-rs-0.5.2/tests/test_vectors/test_suite",
);

async function readJsonlFixture(name) {
  const path = `${RUST_FIXTURES_BASE}/${name}/did.jsonl`;
  const text = await readFile(path, "utf-8");
  return text
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
}

const fixturesAvailable = existsSync(RUST_FIXTURES_BASE);
const maybeSkip = fixturesAvailable ? {} : { skip: "Rust fixture cache not present" };

// ─── Cross-implementation resolution ────────────────────────────────────

test("did:webvh: resolves the didwebvh-rs basic-create fixture", maybeSkip, async () => {
  const log = await readJsonlFixture("basic-create");
  const { didDocument, didDocumentMetadata } = await didWebvh.resolveLog(log);

  assert.equal(
    didDocument.id,
    "did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com",
    "resolved DID document id must match the fixture's expected identifier",
  );
  assert.equal(didDocumentMetadata.deactivated, false);
  assert.equal(
    didDocumentMetadata.versionId,
    log[0].versionId,
    "single-entry log → final versionId equals the genesis versionId",
  );
});

test("did:webvh: resolves the multi-entry basic-update fixture", maybeSkip, async () => {
  const log = await readJsonlFixture("basic-update");
  assert.equal(log.length, 2, "fixture should have 2 entries");
  const { didDocument, didDocumentMetadata } = await didWebvh.resolveLog(log);

  // After update, the final document corresponds to the LAST entry.
  assert.equal(didDocument.id, log[1].state.id);
  assert.equal(didDocumentMetadata.versionId, log[1].versionId);
});

test("did:webvh: resolves the key-rotation fixture", maybeSkip, async () => {
  const log = await readJsonlFixture("key-rotation");
  const { didDocument } = await didWebvh.resolveLog(log);
  assert.equal(didDocument.id, log[log.length - 1].state.id);
});

// ─── Tamper detection ───────────────────────────────────────────────────

test("did:webvh: rejects a tampered log entry (hash mismatch)", maybeSkip, async () => {
  const log = await readJsonlFixture("basic-create");
  // Mutate the state in a way that doesn't touch the proof (so the
  // proof would still verify against a hypothetical re-signed
  // document — but the versionId hash won't).
  const tampered = JSON.parse(JSON.stringify(log));
  tampered[0].state.assertionMethod = ["did:example:injected#vm1"];
  await assert.rejects(
    () => didWebvh.resolveLog(tampered),
    "tampered state must produce a verification failure",
  );
});

test("did:webvh: rejects an empty log", async () => {
  await assert.rejects(
    () => didWebvh.resolveLog([]),
    "empty log must not resolve",
  );
});

test("did:webvh: surfaces a resolution error instead of a null document", async () => {
  // A did:webvh whose host is unreachable (or whose log fails
  // verification) makes didwebvh-ts return `{ doc, meta: { error } }`
  // rather than throwing. Our wrapper must turn that into a thrown
  // error with the reason — not pass a null `doc` downstream where it
  // surfaces as "Cannot read properties of null".
  await assert.rejects(
    () => didWebvh.resolve("did:webvh:nonexistent-scid:127.0.0.1:0"),
    (err) => {
      // Either our explicit "resolve failed" wrapper or a propagated
      // network error is acceptable — what matters is it's NOT a
      // "Cannot read properties of null" TypeError.
      assert.ok(
        !/Cannot read properties of null/.test(err.message),
        `should not be a null-deref: ${err.message}`,
      );
      return true;
    },
  );
});

// ─── Identifier shape ───────────────────────────────────────────────────

test("did:webvh resolve: rejects non-string input", async () => {
  await assert.rejects(() => didWebvh.resolve(42), /input must be a string/);
});

test("did:webvh resolve: rejects identifiers without the did:webvh prefix", async () => {
  await assert.rejects(
    () => didWebvh.resolve("did:web:example.com"),
    /must start with "did:webvh:"/,
  );
});
