# dmrtd-rs

A Cargo workspace for the **dmrtd** eMRTD / ICAO 9303 reader stack in pure Rust.

## Crates

| Crate | Path | Description |
|-------|------|-------------|
| [`dmrtd`](crates/dmrtd) | `crates/dmrtd` | eMRTD / ICAO 9303 reader core — BAC, PACE (ECDH-GM P-256 and DH-GM), MRZ, LDS parsing, secure messaging. Transport-agnostic (NFC plugs in via a `Transceiver` trait). |
| [`mrz-parser`](crates/mrz-parser) | `crates/mrz-parser` | ICAO 9303 Machine Readable Zone (TD1 / TD2 / TD3) text parser — fields + check digits, country patterns, OCR-defect fixer. |
| [`aamva`](crates/aamva) | `crates/aamva` | AAMVA DL/ID — PDF417 barcode scan + payload parser (US / Canadian driver's licenses). |
| [`aadhaar-offline-kyc`](crates/aadhaar-offline-kyc) | `crates/aadhaar-offline-kyc` | Aadhaar offline e-KYC (India UIDAI) — Secure QR v2 + Paperless Offline e-KYC (ZIP/XML) with signature verification; Verhoeff number validation. |
| [`incometax-pan-qr`](crates/incometax-pan-qr) | `crates/incometax-pan-qr` | Indian Income-Tax PAN structural validation + entity-type classification. |

## Build

```sh
cargo build            # build all workspace crates
cargo test             # run all tests
cargo build -p dmrtd   # build a single crate
```

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
