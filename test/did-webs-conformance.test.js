// did:webs conformance against the Rust reference, `affinidi-did-webs`
// 0.13.1 (KERI 2.0).
//
// The vectors under `test/fixtures/did-webs/rust-vectors/` are what the Rust
// crate answered: every resolution, key state, endpoint set and designation
// read its own test suite performs, recorded as it ran, plus generated
// vectors — lifecycles in both KERI versions, controlled, weighted and ECDSA
// identifiers, hand-built key event logs for the KEL rules, and mutation
// sweeps over accepted streams. Each must get the same answer here: the same
// document and metadata where Rust accepts, and a refusal of the same kind
// where it refuses.
//
// Static vectors rather than a live Rust helper (as `roundtrip-rust.test.js`
// uses), because the Rust side is a resolver, not a codec: what is being
// checked is the verdict on fixed input, and fixing the input lets these run
// everywhere, with nothing to skip. The generated sweeps over the long
// lifecycles are in `did-webs-sweeps.test.js`, so the two run in parallel.

import { test } from "node:test";
import assert from "node:assert/strict";

import { disagreement, loadVectors, tally } from "./support-did-webs-vectors.js";

const SWEEPS = /^tests\/extra_vectors\.rs::(lifecycle_|key_roles_)/;

for (const [file, records] of loadVectors()) {
  const mine = records.filter((r) => !SWEEPS.test(r.source));
  if (!mine.length) continue;
  const { accepted, refused } = tally(mine);
  test(`did:webs agrees with affinidi-did-webs on ${file} (${accepted} accepted, ${refused} refused)`, () => {
    const differences = mine.map(disagreement).filter(Boolean);
    assert.deepEqual(differences, [], `${differences.length} of ${mine.length} vectors disagree:\n${differences.slice(0, 20).join("\n")}`);
  });
}

test("did:webs conformance vectors cover acceptance and every kind of refusal", () => {
  const all = [...loadVectors().values()].flat();
  const kinds = new Set(all.filter((r) => !r.ok).map((r) => r.error.kind));
  for (const kind of ["Kel", "Stream", "DocumentMismatch", "NotDesignated", "Registry", "UnsupportedDesignation"]) {
    assert.ok(kinds.has(kind), `no vector is refused as ${kind}`);
  }
  assert.ok(all.filter((r) => r.ok && r.op === "resolve").length > 100);
});
