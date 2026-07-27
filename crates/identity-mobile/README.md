# identity-mobile

One identity-verification API over **ePassport chips** (ICAO 9303) and **mobile
driving licences** (ISO/IEC 18013-5), shaped for Android, iOS and Flutter.

Two very different documents come back as the same `VerifiedIdentity`, so an app that
accepts both has one code path and one result to reason about.

```rust
use identity_mobile::{mdl, passport, VerifiedIdentity};

// From a wallet:
let identity: VerifiedIdentity = mdl::verify_mdl(device_response, &[iaca_der], None)?;

// From a passport chip:
let identity: VerifiedIdentity = passport::read_passport(channel, &key, &[csca_der], &opts)?;

if identity.authenticity.is_trustworthy() {
    println!("{}", identity.display_name().unwrap_or_default());
}
```

## What "the same shape" does and does not mean

The two documents prove different things, and `Authenticity` keeps that visible rather
than flattening it into one boolean:

| | Passport chip | mDL |
|---|---|---|
| `data_authentic` | data group hashes match EF.SOD | MSO signature + element digests |
| `issuer_trusted` | Document Signer chains to a CSCA you supplied | chains to an IACA you supplied |
| `holder_bound` | active authentication — the chip is not a clone | device authentication — not a replay |
| `not_expired` | MRZ date of expiry | MSO `validityInfo` |

`holder_bound` is `None` when it was not attempted, which is **not** `Some(false)`.
`is_trustworthy()` deliberately excludes it; use `is_present_and_trustworthy()` when
you are checking a document in person and a copy would not do.

Read the name precisely: it binds the *document*, not the person. Active authentication
proves the chip in front of you holds the private key the issuer signed into DG15, and
device authentication proves the same of an mDL's device key — so neither is a copy.
Neither says anything about whether the person presenting it is the person it was issued
to. That question is answered by comparing the portrait against the face in front of you,
and this crate does not do it.

There is no single "valid" boolean because there is no honest one: a genuine credential
from an unknown issuer and a well-formed forgery are both "invalid" for very different
reasons, and an app should be able to tell them apart.

## Passports: reading versus verifying

Split in two on purpose:

- `passport::read_passport` drives a live chip through your NFC.
- `passport::verify_passport` takes files already read and does the verification and
  mapping. It touches no hardware.

Plenty of apps already have an NFC stack and only want the second half. It also means
the security-relevant code is testable without a chip — which is how the tests here
work.

Passive authentication vouches for the data groups it was given and no others. If you
skip DG2 to make the read faster, the result says so: `verified_data_groups` lists what
was checked, `signed_data_groups` what the chip signs, and a warning names the gap.

### NFC comes from the platform

Implement `ApduChannel` over `IsoDep` on Android or `NFCISO7816Tag` on iOS — one APDU
in, the full response out. A transport failure and a rejected access key are reported
differently (`IdentityError::Nfc` versus `IdentityError::Access`) because they need
opposite responses from the holder: hold still, versus check the document number.

## mDLs

`mdl::verify_mdl` wraps [`mdl-verify`](../mdl-verify) and maps the result. Pass a
`Session` when you have one — without a session transcript there is no proof of
presence, `holder_bound` stays `None`, and a captured response can be replayed for
as long as the credential itself remains valid — the expiry and MSO validity checks
still apply, and they are all that bounds it.

For the parts this crate does not wrap — CRL revocation with your own HTTP client,
VICAL-sourced trust anchors, the `preflight` algorithm check — `mdl_verify` is
re-exported.

## Mobile builds

Nothing here compiles C. `mdl-verify` is depended on with `default-features = false`,
which keeps `ring` out of the graph, so:

```sh
cargo check --target aarch64-apple-ios       # works
cargo check --target aarch64-linux-android   # works, with no NDK installed
```

The trade is that CRL revocation needs an HTTP client from you, through
`mdl_verify::revocation::CrlChecker::with_http_client`. On a phone that is the better
arrangement anyway: the fetch goes through the platform's stack and inherits its proxy,
VPN and pinning policy.

The crate builds as `cdylib` (Android `.so`), `staticlib` (iOS xcframework) and `rlib`.
See [docs/flutter.md](docs/flutter.md) for wiring it to Dart, including the NFC bridge.

## Tests

```sh
cargo test -p identity-mobile
```

Nothing is a canned blob. `tests/fixtures/generate.sh` builds a CSCA, the Document
Signer it certifies, and a real CMS `SignedData` EF.SOD over data groups produced by
`dmrtd`'s own TLV encoder; the mDL tests issue a signed mdoc at test time. The tamper
cases alter a data group and assert the signature no longer covers it.

## Status

`0.0.0`, unpublished. It depends on `mdl-verify`, which cannot be published while its
own dependency is a pinned git revision — see that crate's README.

## License

Licensed under either of [Apache-2.0](../../LICENSE-APACHE) or [MIT](../../LICENSE-MIT)
at your option.
