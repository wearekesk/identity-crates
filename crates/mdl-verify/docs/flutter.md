# Using `mdl-verify` from Flutter

This crate is a plain Rust library. Flutter reaches it the same way it reaches any
Rust code: a thin wrapper crate compiled to a native library, plus generated Dart
bindings. Nothing about verification changes — a reader app on a phone runs exactly
the same code as a server.

What Flutter has to supply is the **decrypted `DeviceResponse`**. This crate does no
transport: no BLE, no NFC, no session establishment. Those bytes come from whatever
does the presentation exchange — an ISO 18013-5 proximity plugin, or your OpenID4VP /
Digital Credentials API layer.

## Shape

```
Flutter app (Dart)
        │  generated bindings (flutter_rust_bridge v2, or dart:ffi over a C ABI)
        ▼
your wrapper crate  ── cdylib (Android) / staticlib (iOS)
        │
        ▼
   mdl-verify
```

Write the wrapper crate yourself: it decides what the Dart side sees, and keeps
FFI concerns out of this crate.

```toml
# rust/Cargo.toml
[package]
name = "mdl_verify_ffi"
edition = "2021"

[lib]
crate-type = ["cdylib", "staticlib"]

[dependencies]
# Default features bundle a reqwest CRL client. See "Which HTTP client" below —
# `default-features = false` is often the better call on mobile.
mdl-verify = { path = "../../identity-crates/crates/mdl-verify" }
flutter_rust_bridge = "2"
```

## Which HTTP client

Only one decision here really matters, and it is about the CRL fetch.

| | Bundled (default) | Yours (`default-features = false`) |
|---|---|---|
| Android build | needs the **NDK** — `ring` compiles C | no NDK, no C toolchain |
| Added to the app | reqwest + rustls + ring + tokio net | nothing |
| `http:` CRL endpoints | just work — native sockets are not subject to ATS or Android cleartext policy | need an ATS exception / network security config entry |
| Platform proxy, VPN, pinning | bypassed | honoured |
| CRL caching | yes | you add it |

The bundled client is the path of least resistance and is fine if you already have an
NDK in your build (you likely do — most Flutter+Rust projects use `cargo-ndk`). Choose
your own client when app size matters, when a security review requires all TLS through
one audited stack, or when the device sits behind a managed proxy.

Both are the same verification. The choice only changes who makes the request.

## What to expose

Keep the FFI surface small and boring: bytes in, a flat struct out. Do not try to
mirror `MdlValue`'s CBOR tree across the boundary — pull out the fields the app
actually shows.

```rust
// rust/src/api/mdl.rs
use std::sync::OnceLock;

use mdl_verify::{
    revocation::{BlockingCrlChecker, ReqwestClient},
    IacaAnchor, MdlError, SessionTranscript, VerifyOptions,
};

/// One checker for the life of the process: it caches CRLs, so building a new one
/// per scan would refetch every time.
///
/// `BlockingCrlChecker` is generic over the HTTP client. This uses the bundled one;
/// with `default-features = false` you name your own type here instead.
fn crl() -> &'static BlockingCrlChecker<ReqwestClient> {
    static CRL: OnceLock<BlockingCrlChecker<ReqwestClient>> = OnceLock::new();
    CRL.get_or_init(|| BlockingCrlChecker::new().expect("build CRL checker"))
}

pub struct ScanResult {
    pub family_name: Option<String>,
    pub given_name: Option<String>,
    pub birth_date: Option<String>,
    pub document_number: Option<String>,
    pub portrait: Option<Vec<u8>>,
    pub age_over_21: Option<bool>,
    /// Issuer-signed, chained to a trusted IACA, inside its validity window.
    pub authentic: bool,
    /// The holder proved possession of the device key. False on the static path.
    pub device_authenticated: bool,
    /// Why trust failed, if it did — surface this in a debug view, not to the user.
    pub trust_errors: Vec<String>,
    /// Present when the CRL could not be checked at all. Your policy decides.
    pub revocation_errors: Vec<String>,
}

/// Verify a decrypted DeviceResponse. `anchors` are DER IACA certificates.
pub fn verify(
    device_response: Vec<u8>,
    anchors: Vec<Vec<u8>>,
    session_transcript: Option<Vec<u8>>,
    e_reader_key: Option<Vec<u8>>,
) -> Result<ScanResult, String> {
    let anchors: Vec<IacaAnchor> = anchors
        .iter()
        .map(|der| IacaAnchor::from_certificate(der))
        .collect::<Result<_, MdlError>>()
        .map_err(|e| e.to_string())?;

    let options = VerifyOptions::default();

    let verification = match session_transcript {
        // Live presentation: check holder possession too.
        Some(transcript) => {
            let transcript =
                SessionTranscript::from_cbor(&transcript).map_err(|e| e.to_string())?;
            let key: Option<[u8; 32]> = e_reader_key
                .map(|k| k.try_into().map_err(|_| "reader key must be 32 bytes".to_string()))
                .transpose()?;

            crl()
                .verify_presentation(&device_response, &anchors, &transcript, key.as_ref(), &options)
                .map_err(|e| e.to_string())?
        }
        // Static: issuer data authentication only.
        None => crl()
            .verify_issuer_auth(&device_response, &anchors, &options)
            .map_err(|e| e.to_string())?,
    };

    let mdl = verification.mdl().ok_or("no mDL in the response")?;

    Ok(ScanResult {
        family_name: mdl.family_name().map(str::to_owned),
        given_name: mdl.given_name().map(str::to_owned),
        birth_date: mdl.birth_date().map(str::to_owned),
        document_number: mdl.document_number().map(str::to_owned),
        portrait: mdl.portrait().map(<[u8]>::to_vec),
        age_over_21: mdl.age_over(21),
        authentic: mdl.is_authentic(),
        device_authenticated: mdl.device_authenticated,
        trust_errors: mdl.trust_errors.clone(),
        revocation_errors: mdl.revocation_errors.clone(),
    })
}
```

Two things worth copying from that:

- **`BlockingCrlChecker`, not the async entry points.** Handing a Rust future across
  an FFI boundary is more trouble than it is worth. The blocking checker owns a small
  runtime; build it once and keep it.
- **Hold it in a `OnceLock`.** The CRL cache is the whole point — a checker rebuilt
  per scan refetches the list every time.

## Threading

`flutter_rust_bridge` runs Rust on a worker thread by default, which is where the
blocking checker belongs. If you are hand-rolling `dart:ffi`, call it from an isolate
or a background thread — a CRL fetch on the UI isolate will jank the frame.

Never call `BlockingCrlChecker` from inside another async runtime: driving a runtime
from within a runtime panics. That is a server concern, not a Flutter one, but it is
the same type.

## Android

With the bundled client you need the **NDK** — not because of this crate, but because
reqwest pulls in `ring`, which compiles C and assembly:

```sh
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  x86_64-linux-android i686-linux-android

export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/28.2.13676358   # any 26+ will do

cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o ../android/app/src/main/jniLibs \
    build --release
```

With `default-features = false` there is no C in the graph at all, and the target
builds with nothing but rustup:

```sh
cargo build --release --target aarch64-linux-android    # no NDK needed
```

You still want `cargo-ndk` for the multi-ABI build and `jniLibs` layout, but the
toolchain requirement goes away — handy for CI, where an NDK is one more thing to
provision and cache.

`android/app/src/main/AndroidManifest.xml` needs internet access for the CRL fetch:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

**Cleartext traffic.** CRL distribution points are usually plain `http:` — RFC 5280
prefers it, because the CRL is signed by the CA and TLS adds a circular dependency.
Android's cleartext restriction (`usesCleartextTraffic`, network security config)
applies to the *platform* HTTP stacks; the bundled Rust client uses native sockets and
is not subject to it. So the default client just works, and a Dart- or OkHttp-backed
client would need an explicit exception for the issuer's CRL host.

## iOS

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim

cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
```

Package the `.a` files into an `.xcframework` and reference it from your plugin's
podspec, or let `flutter_rust_bridge`'s tooling do it. No NDK equivalent is needed —
the Xcode SDK is enough. `cargo check --target aarch64-apple-ios` on this crate passes
as-is.

**App Transport Security.** The same point as Android in reverse: ATS governs
`URLSession`/CFNetwork, not raw sockets, so the bundled client fetches an `http:` CRL
without an `NSAppTransportSecurity` exception. Bridge the fetch to `URLSession` and
you will need one.

## Trust anchors

IACA roots are per-jurisdiction and this crate does not source them — ship them with
the app and pass them in:

```dart
final anchor = await rootBundle.load('assets/iaca/ny-dmv.der');
final result = await verify(
  deviceResponse: response,
  anchors: [anchor.buffer.asUint8List()],
);
```

Verifying with an empty anchor list is allowed and sometimes useful during
development: signatures and element digests are still checked, and the result comes
back with `authentic == false`.

## Dart side

```dart
final result = await verify(
  deviceResponse: deviceResponse,
  anchors: anchors,
  sessionTranscript: transcript,   // null for a static check
  eReaderKey: readerKey,           // required if the holder used DeviceMac
);

// Issuer-signed, chained to a trusted IACA, inside its validity window.
if (!result.authentic) {
  return Denied(reasons: result.trustErrors);
}

// A reader app is doing a live presentation, so require holder possession. Without
// it, a response captured off the wire once replays forever.
if (!result.deviceAuthenticated) {
  return Denied(reasons: ['device authentication not established']);
}

// The CRL could not be checked, so "not revoked" is unproven rather than true.
// Failing closed is the right default for an in-person check; a deployment that
// must work offline can decide otherwise, deliberately and in one place.
if (result.revocationErrors.isNotEmpty) {
  return Denied(reasons: result.revocationErrors);
}

if (result.ageOver21 == true) {
  return Allowed(portrait: result.portrait);
}
return Denied(reasons: ['age not attested']);
```

Note what that does *not* do: it never reaches `Allowed` on an unproven result.
`authentic` covers the issuer's signature and trust chain, `deviceAuthenticated`
covers the holder, and an unchecked CRL is treated as unknown rather than clean. Each
is a separate decision, and each defaults to no.

## Gotchas

| | |
|---|---|
| A `DeviceResponse` verifies but `deviceAuthenticated` is false | You used the static path. Without a session transcript, a captured response replays forever. |
| `EReaderKeyRequired` | The holder used `DeviceMac`; you must pass the reader's ephemeral private key from that session. |
| `NonCanonicalTranscript` | Your transcript does not re-encode byte-for-byte. Fix the encoder rather than working around it — device auth signs those exact bytes. |
| `revocationErrors` populated on every scan | The CRL host is unreachable from the device, or you are on the no-network path. |
| Android build fails in `ring` | NDK not on `PATH` / `ANDROID_NDK_HOME` unset — or build with `default-features = false` and the problem disappears. |
| `CrlChecker::new()` does not exist | You are on `default-features = false`. Use `with_http_client` and supply one. |
