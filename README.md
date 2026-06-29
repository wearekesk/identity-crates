# dmrtd-rs

A Cargo workspace for the **dmrtd** eMRTD / ICAO 9303 reader stack in pure Rust.

## Crates

| Crate | Path | Description |
|-------|------|-------------|
| [`dmrtd`](crates/dmrtd) | `crates/dmrtd` | eMRTD / ICAO 9303 reader core — BAC, PACE (ECDH-GM P-256 and DH-GM), MRZ, LDS parsing, secure messaging. Transport-agnostic (NFC plugs in via a `Transceiver` trait). |

## Build

```sh
cargo build            # build all workspace crates
cargo test             # run all tests
cargo build -p dmrtd   # build a single crate
```

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
