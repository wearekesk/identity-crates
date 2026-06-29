# dmrtd

**eMRTD / ePassport reader core in pure Rust** — ICAO 9303 over BAC and PACE, LDS
parsing, secure messaging, and a high-level `Passport` API.

The crate is **synchronous** and has no NFC dependencies — transport plugs in via
the [`com::Transceiver`](src/com/mod.rs) trait, so it drops into Flutter / iOS /
Android (Dart FFI), a desktop reader, or tests alike.

## Status

| Area | Status |
|------|--------|
| Crypto (AES, 3DES, ISO 9797, KDF, DH, AA pubkey) | ✅ |
| LDS (TLV, MRZ, DG1–16, EF.COM, EF.SOD, EF.CardAccess, EF.CardSecurity) | ✅ |
| ASN.1 OIDs + PACE info (via `asn1` crate) | ✅ |
| Keys (`DBAKey`, `CanKey`, `AccessKey` trait) | ✅ |
| SM ciphers (3DES, AES) + `MrtdSM` wrapper | ✅ |
| BAC — pure helpers, session keys, `BacSession` state machine | ✅ |
| PACE — helpers, `PaceSession` state machine (ECDH-GM on NIST P-256) | ✅ |
| DH-PACE (RFC 5114 groups) | ✅ |
| ECDH-PACE (NIST P-256 via `p256`) | ✅ |
| `MrtdApi` (sync ICC orchestrator) + `Transceiver` trait | ✅ |
| `Passport` — high-level BAC/PACE + file-read API | ✅ |
| Additional PACE curves (Brainpool etc.) | ⏳ pending |

Reference vectors verified include ICAO 9303 Appendix A check digits + EF.COM +
EF.DG1 TD1 sample, Appendix D.2 `K_seed`, Appendix D.3 BAC SSC + session keys
end-to-end through `BacSession`, Appendix D.4 MAC vectors, PACE AES-256 nonce
encrypt/decrypt, and a full PACE 4-step loopback through `PaceSession`.

## Quickstart — reading an ePassport

```rust
use dmrtd::com::{Transceiver, TransceiveError};
use dmrtd::passport::Passport;
use dmrtd::proto::dba_key::DBAKey;
use chrono::NaiveDate;

// 1. Implement the transport — for Flutter this forwards to
//    flutter_nfc_kit.transceive over the FFI boundary.
struct MyNfc { /* … */ }
impl Transceiver for MyNfc {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransceiveError> {
        /* send apdu over NFC, return response bytes */
        # unimplemented!()
    }
}

// 2. Build DBAKey from MRZ fields (doc number, DOB, DOE).
// `DBAKey::new` returns `Result` — it validates the MRZ document number.
let key = DBAKey::new(
    "L898902C",
    NaiveDate::from_ymd_opt(1969, 8, 6).unwrap(),
    NaiveDate::from_ymd_opt(1994, 6, 23).unwrap(),
    false, // BAC mode (set true for PACE)
)?;

// 3. Start SM session + read files.
let mut passport = Passport::new(MyNfc { /* … */ });
passport.start_session(key)?;
let dg1 = passport.read_ef_dg1()?;   // MRZ
let dg2 = passport.read_ef_dg2()?;   // Face photo
let sod = passport.read_ef_sod()?;   // Document Security Object
```

For PACE: `passport.start_session_pace(access_key, &ef_card_access)` where
`ef_card_access` is the result of `passport.read_ef_card_access()`.

## Architecture for Flutter / iOS / Android via Dart FFI

Dart FFI is a **synchronous** C ABI. NFC on iOS (CoreNFC) and Android (IsoDep) is
async on the OS side, but plugins like
[`flutter_nfc_kit`](https://pub.dev/packages/flutter_nfc_kit) expose the transceive
loop as a clean Dart `Future`. **The clean split: Dart owns the transceive loop,
Rust owns the crypto and state.**

```text
┌────── Flutter app (Dart) ────────┐
│  flutter_nfc_kit.transceive(apdu)│  ← real NFC I/O
│         ↓              ↑          │
│    flutter_rust_bridge / ffi     │
└──────────────────────────────────┘
          ↓              ↑
┌────── Rust (this crate) ─────────┐
│  Passport + Transceiver trait    │
│  BacSession / PaceSession        │
│  LDS parsers, SM, AA             │
│  (no async, no NFC, no tokio)    │
└──────────────────────────────────┘
```

Two integration styles, which coexist:

1. **High-level `Passport`** — blocking synchronous methods (`passport.read_ef_dg1()?`).
   Simplest if you can afford one FFI callback per APDU.
2. **Low-level session state machines** — `BacSession` / `PaceSession` produce APDU
   bytes and consume responses via `next()` / `feed_response()`, returning a ready
   `MrtdSM` on completion. The Dart side drives the loop natively, never blocking a
   Rust thread:

```rust
let mut session = BacSession::new(key);
loop {
    match session.next()? {
        BacAction::SendApdu(apdu) => {
            let resp = /* await nfc.transceive(apdu) on the Dart side */;
            session.feed_response(&resp)?;
        }
        BacAction::Done(sm) => break /* sm = MrtdSM<DesSmCipher> */,
    }
}
```

[**`flutter_rust_bridge`**](https://pub.dev/packages/flutter_rust_bridge) is the
path of least resistance for bindings (`Vec<u8>` ↔ `Uint8List`, `Result<T,E>` ↔
`Future<T>`, opaque `Passport`/`MrtdSM` handles, XCFramework + JNI packaging).

## Module layout

```text
src/
├── lib.rs                  # crate root (was dmrtd/mod.rs)
├── com/                    # Transceiver trait (sync I/O boundary)
├── passport.rs            # High-level passport API + DF caching
├── crypto/                 # AES, DES, DH, KDF, ISO 9797, AA pubkey
├── extension/              # datetime, int, logging, string, uint8list
├── lds/                    # TLV, MRZ, ASN.1 OIDs, EF.CardAccess/Security
│   ├── df1/                # DG1–DG16, EF.COM, EF.SOD
│   └── substruct/          # PaceInfo, PaceCons
├── proto/                  # Protocol layer
│   ├── access_key.rs       # AccessKey trait (public)
│   ├── bac_session.rs      # BAC state machine (public)
│   ├── can_key.rs          # CAN-based PACE key (public)
│   ├── dba_key.rs          # MRZ-derived BAC/PACE key (public)
│   ├── iso7816/            # APDU types + constants (public)
│   ├── pace_session.rs     # PACE state machine (public)
│   ├── ssc.rs              # Secure-messaging counters (public)
│   ├── mrtd_api.rs         # ICC orchestrator (pub(crate))
│   └── mrtd_sm.rs          # SM protect/unprotect (pub(crate))
├── types/                  # Pair, DMRTDException
└── utils.rs
```

The public API surface is pruned: internal-only helpers (`bac`, `pace`, `mrtd_api`,
`mrtd_sm`, SM ciphers, PACE engines) are `pub(crate)` — callers reach BAC/PACE via
the `*Session` state machines and LDS files via `Passport`.

## Running tests

```bash
cargo test           # unit + doc tests
cargo check --all-targets
```

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
