# did:webs conformance vectors from `affinidi-did-webs`

Each line of a `.jsonl` file is one call the Rust crate answered, with its
inputs and its answer. `test/did-webs-conformance.test.js` and
`test/did-webs-sweeps.test.js` make the same call here and require the same
answer: the same document and metadata where Rust accepts, a refusal of the
same `DidWebsError` kind where it refuses.

- Crate: `affinidi-did-webs` 0.13.3 (crates.io; affinidi-tdk-rs commit `68e6b032`)
  (`affinidi-keri-core` / `affinidi-keri-crypto` 0.8.1, `affinidi-cesr`
  0.1.4), feature `create`.
- `<name>.jsonl` — every resolution, key state, endpoint set and designation
  read performed by that crate's own `tests/<name>.rs`, recorded as it ran.
- `extra_vectors.jsonl.gz` — generated vectors (see below), gzipped because
  they are many and alike.
- `blobs/` — the `keri.cesr` and `did.json` artifacts the records name, by the
  first 20 hex digits of their SHA-256.

## Records

```
{ "op": "resolve", "did": "<DID or DID URL with versionId>",
  "keri_cesr": "<blob>", "did_json": "<blob>" | null, "mutation": {…}?,
  "ok": true, "document": {…}, "metadata": {…} }          resolve_with_metadata
{ "op": "key_state", "keri_cesr", "prefix", "as_of": [prefix, sn]?, "ok", "state" }
{ "op": "service_endpoints" | "delegator_service" | "designated_aliases" |
  "designated_key_agreement" | "designated_services", "keri_cesr", "aid", "ok", "result" }
```

A refusal carries `"error": {"kind", "message"}`. `document` is
`serde_json::to_value` of the `affinidi_did_common::Document` returned, whose
own serialization writes a service `type` as a list and normalizes a URL
endpoint; the tests compare after applying the same two rules.

A record with `mutation` was resolved over its base `keri_cesr` changed as the
mutation says, so mutated streams need not be stored:

- `{"type": "replace", "at": n, "byte": b}` — byte `n` becomes `b`;
- `{"type": "splice", "start": s, "end": e, "insert": [a, b] | null}` — bytes
  `s..e` are replaced by bytes `a..b` of the base (or by nothing);
- `{"type": "swap", "a": [s1, e1], "b": [s2, e2]}` — two adjacent spans swap.

## How they were made

A throwaway Cargo crate, not committed, whose library is named
`affinidi_did_webs` and re-exports the real crate (a path dependency on the
checkout above) while replacing the entry points its tests call —
`resolve_from_artifacts`, `resolve_with_metadata`, `Kels::parse`,
`Kels::key_state`, `Kels::as_of`, `service_endpoints`, `delegator_service`
and the `designated_*` readers — with wrappers that call the real function and
write the call and its result to `$WEBS_VECTORS_OUT`. The crate's own test
files (`tests/*.rs` and `tests/fixtures/` at that commit, except
`network.rs`, which needs a mock server) were copied in unchanged and run
against it, so every call they make became a record.

`tests/extra_vectors.rs` in that crate adds, through the same wrappers:

- lifecycles in KERI 1.0 and 2.0 (create, interact, rotate to a 2-of-3 key
  set, replace key agreement, designated services and aliases, rotate,
  deactivate), each step resolved at every `versionId`;
- key role identifiers in both versions, with a key revoked for compromise;
- controlled identifiers with weighted and 2-of-3 thresholds, secp256k1 and
  P-256 key state, and P-256 / secp256k1 key agreement designations;
- hand-built key event logs for the KEL rules: simple, hex and weighted
  thresholds; pre-rotation with partial reveal, reordering and big-index
  signatures; out-of-order and wrong-prior events; superseding recovery (P7)
  and a stale rotation; deactivation; establishment-only; basic prefixes;
  witness thresholds with attached and separate (`rct`) receipts; delegation
  (`dip`, `drt`, a missing or misdirected anchor, `DND`);
- mutation sweeps over accepted streams (the reference identifier, the
  keripy-checked lifecycle, the native-body KEL and the generated ones): each
  message dropped, duplicated, swapped with the next, the stream truncated
  after it, and one character changed in its body and attachments; and
  edits of the published `did.json`.

The three `tests/stream_bounds.rs` records whose streams are over 200 KiB
(too many messages, signatures or seals) are left out; `test/did-webs.test.js`
builds equivalent streams instead. To regenerate, run that crate's tests with
`WEBS_VECTORS_OUT=<dir> cargo test`, then write each record directory as one
compact, key-sorted JSONL file and copy the blobs they name.
