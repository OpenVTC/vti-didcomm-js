# did:webs parties for the auth and encryption tests

A VTA and a mediator whose DID is a `did:webs`, minted by `affinidi-did-webs`
0.13.3 (feature `create`, crates.io) so that `test/did-webs-auth.test.js` and
`test/roundtrip-rust.test.js` can authenticate and encrypt to them with keys
whose secrets are known.

Each directory holds the published artifacts (`keri.cesr`, `did.json`), the DID
(`did.txt`) and the document the Rust resolver derived from them
(`resolved.json`, `serde_json` of `resolve_from_artifacts`); the tests require
this library to derive the same document.

- `vta/` — `did:webs:vta.example.com:…`, with **key roles** (VTI-KEY-173): the
  `attestation` key (`assertionMethod`) and the `operational` key
  (`authentication`) are different Ed25519 keys, and `messaging`
  (`keyAgreement`) is a P-256 key followed by an X25519 key, so the X25519 key
  is found by relationship and curve, never by being first.
  - X25519 key agreement secret: 32 bytes of `0x31`.
  - P-256 key agreement secret: 32 bytes of `0x34`.
  - Ed25519 attestation / operational public keys: those of 32-byte seeds of
    `0x32` / `0x33` (nothing here signs with them).
- `mediator/` — `did:webs:mediator.example.com:…`, a designated X25519 key
  agreement key (secret: 32 bytes of `0x41`) and a designated
  `DIDCommMessaging` service with `https://mediator.example.com` and
  `wss://mediator.example.com/ws`.

These are test keys: they are derived from constant bytes and must never hold
anything.

## How they were made

A throwaway crate, not committed, run as `cargo run -- <this directory>`. The
public keys are those of the secrets above (computed with `@noble/curves`):

```toml
[package]
name = "webs-gen"
version = "0.0.0"
edition = "2024"
publish = false
[dependencies]
affinidi-did-webs = { version = "=0.13.3", features = ["create"] }
affinidi-keri = "=0.8.1"
serde_json = "1"
hex = "0.4"
[workspace]
```

```rust
use affinidi_did_webs::create::{CreateConfig, create};
use affinidi_did_webs::{DesignatedService, DidWebs, KeyAgreementKey, KeyRoles, VerificationKey, resolve_from_artifacts};
use affinidi_keri::config::InceptionConfig;
use serde_json::json;
use std::fs;

fn h32(s: &str) -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() }

fn main() {
    let out = std::env::args().nth(1).expect("out dir");
    // A VTA: key roles (VTI-KEY-173): attestation (assertionMethod) and
    // operational (authentication) are different Ed25519 keys; messaging
    // (keyAgreement) is a P-256 key first, then an X25519 key.
    let vta = create(
        CreateConfig::builder("vta.example.com")
            .inception(InceptionConfig::builder().salt(vec![0x31; 16]).build())
            .key_roles(
                KeyRoles::new()
                    .with_attestation(VerificationKey::Ed25519(h32("5e212c0980e4b39fc09721134aa02109374edfd260c0d3d03cb501c8d65457a9")))
                    .with_operational(VerificationKey::Ed25519(h32("17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce")))
                    .with_messaging(KeyAgreementKey::P256(hex::decode("031004c4e613c6732516d177d226ed7382d6167f76adfa072436a72b652064ceb5").unwrap()))
                    .with_messaging(KeyAgreementKey::X25519(h32("04f5f29162c31a8defa18e6e742224ee806fc1718a278be859ba5620402b8f3a"))),
            )
            .build(),
    )
    .expect("create vta");
    // A mediator: one designated X25519 key agreement key and a
    // DIDCommMessaging service with REST + WebSocket endpoints.
    let med = create(
        CreateConfig::builder("mediator.example.com")
            .inception(InceptionConfig::builder().salt(vec![0x41; 16]).build())
            .key_agreement(KeyAgreementKey::X25519(h32("7a1a4e709bf085ac494aba0469b9b1eda0ab1f78b16aabb79ffeda90623e8522")))
            .designated_service(DesignatedService::new(
                "#didcomm",
                "DIDCommMessaging",
                json!([
                    { "uri": "https://mediator.example.com", "accept": ["didcomm/v2"], "routingKeys": [] },
                    { "uri": "wss://mediator.example.com/ws", "accept": ["didcomm/v2"], "routingKeys": [] }
                ]),
            ))
            .build(),
    )
    .expect("create mediator");
    for (name, r) in [("vta", &vta), ("mediator", &med)] {
        let a = r.artifacts();
        fs::create_dir_all(format!("{out}/{name}")).unwrap();
        fs::write(format!("{out}/{name}/keri.cesr"), &a.keri_cesr).unwrap();
        fs::write(format!("{out}/{name}/did.json"), &a.did_json).unwrap();
        let doc = resolve_from_artifacts(&DidWebs::parse(r.did()).unwrap(), &a.keri_cesr, Some(&a.did_json)).expect("resolves");
        fs::write(format!("{out}/{name}/did.txt"), r.did()).unwrap();
        fs::write(format!("{out}/{name}/resolved.json"), serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    }
}
```

The salts fix the identifiers, keys and documents, so a rerun gives the same
DIDs and documents (`resolved.json` may list members in another order);
`keri.cesr` differs, because each designation carries its issuance time.
