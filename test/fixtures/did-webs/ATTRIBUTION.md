# did:webs test fixtures

Everything here except `rust-vectors/` is copied unchanged from the Rust
reference this library's did:webs resolver is ported from,
[`affinidi-did-webs`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/identity/did-methods/did-webs)
(Apache-2.0), `tests/fixtures/` at affinidi-tdk-rs commit `68e6b032`
(did-webs 0.13.3). Its own attribution, as it reads there:

> `ENro7uf0.keri.cesr` and `ENro7uf0.did.json` are the artifacts published for
>
>     did:webs:did-webs-service%3a7676:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe
>
> reproduced verbatim from the Apache-2.0 licensed
> [hyperledger-labs/did-webs-resolver](https://github.com/hyperledger-labs/did-webs-resolver)
> reference implementation, at
> `volume/dkr/examples/ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe/`.
>
> They are used unmodified as conformance vectors. Everything else this crate is
> tested against, it also produced — these are the only bytes in the suite that
> came from keripy, so they are the only ones that can catch us agreeing with
> ourselves rather than with the ecosystem.

- `keripy-native/` — a KEL with native CESR bodies and the key state keripy
  reached (built with keripy 2.1.0-dev1, b70986f); see its README.
- `ours-v2/` — a KERI 2.0 identifier written by `affinidi-did-webs` and checked
  by keripy; see its README. Its `verify_ours.py` stays in the Rust crate.
- `deactivated/` — an identifier rotated at sn 3 and deactivated at sn 4, with
  its keyless `did.json` and the full derivation published before 0.13.3
  (`legacy.did.json`).
- `rust-vectors/` — what `affinidi-did-webs` answered for each of these and for
  generated streams; see its README.
