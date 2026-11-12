// did:webs conformance against `affinidi-did-webs` 0.13.1: the generated
// lifecycles in both KERI versions, every version of every step, and mutation
// sweeps over them (a dropped, duplicated, swapped or truncated message, or
// one character changed in a body or an attachment). See
// `did-webs-conformance.test.js`, which runs the rest.

import { test } from "node:test";
import assert from "node:assert/strict";

import { disagreement, loadVectors, tally } from "./support-did-webs-vectors.js";

const SWEEPS = /^tests\/extra_vectors\.rs::(lifecycle_|key_roles_)/;
const records = [...loadVectors().values()].flat().filter((r) => SWEEPS.test(r.source));
const groups = new Map();
for (const r of records) {
  const group = r.source.split("::")[1];
  if (!groups.has(group)) groups.set(group, []);
  groups.get(group).push(r);
}

for (const [group, mine] of groups) {
  const { accepted, refused } = tally(mine);
  test(`did:webs agrees with affinidi-did-webs on ${group} (${accepted} accepted, ${refused} refused)`, () => {
    const differences = mine.map(disagreement).filter(Boolean);
    assert.deepEqual(differences, [], `${differences.length} of ${mine.length} vectors disagree:\n${differences.slice(0, 20).join("\n")}`);
  });
}
