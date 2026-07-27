# Using `identity-mobile` from Flutter

This crate is the one a Flutter app should bind to: it already combines the passport
and mDL paths behind a single result, and its API is FFI-shaped — plain data in, a flat
struct out, no async, no generics at the boundary.

The mDL-specific mechanics (build tooling, xcframework, which HTTP client to pick) are
covered in [`mdl-verify`'s Flutter guide](../../mdl-verify/docs/flutter.md) and are not
repeated here. What follows is what changes when passports are in scope too.

## The NFC bridge

This is the part with no equivalent on the mDL side. Passport reads need APDU exchange
with the chip, and that hardware belongs to the platform.

`ApduChannel` is one method: bytes in, bytes out. Implement it over a Dart callback
with `flutter_rust_bridge`'s `DartFnFuture`, or — usually simpler and faster — over the
native API directly in Kotlin and Swift, exposed through your plugin.

```rust
// rust/src/api/passport.rs
use identity_mobile::passport::{self, ApduChannel, MrzKey, PassportOptions};

/// Bridges to whatever the host hands us. `transceive` is called many times during a
/// read — dozens of round trips — so keep it cheap and keep the tag alive across all
/// of them.
struct PlatformNfc {
    exchange: Box<dyn Fn(Vec<u8>) -> Result<Vec<u8>, String> + Send>,
}

impl ApduChannel for PlatformNfc {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        (self.exchange)(apdu.to_vec())
    }
}

pub fn read_passport(
    document_number: String,
    date_of_birth: String,
    date_of_expiry: String,
    csca_anchors: Vec<Vec<u8>>,
) -> Result<ScanResult, String> {
    let key = MrzKey::new(document_number, &date_of_birth, &date_of_expiry)
        .map_err(|e| e.to_string())?;

    let channel = PlatformNfc { exchange: platform_exchange() };

    passport::read_passport(Box::new(channel), &key, &csca_anchors, &PassportOptions::default())
        .map(ScanResult::from)
        .map_err(|e| e.to_string())
}
```

### Keeping the tag alive

The single biggest source of failed reads. A passport read is dozens of round trips, and
both platforms will drop the tag if you let them:

- **Android** — do the whole read on a background thread with the `IsoDep` connected for
  its entire duration. Call `setTimeout` generously (5–10 s); the default is short and a
  DG2 read is not fast. Do not reconnect between APDUs.
- **iOS** — hold the `NFCTagReaderSession` open across the read and update
  `alertMessage` as you go, or the OS times out with the sheet still up. `NFCISO7816Tag`
  wants `sendCommand(apdu:)`; wrap the whole loop, not each call.

Tell the user to rest the phone on the document rather than hold it. Most "chip failed"
reports are a moved phone.

### Which error to show

```dart
try {
  final result = await readPassport(...);
} on IdentityError catch (e) {
  // Nfc     → "Hold the phone still on the passport" and retry automatically.
  // Access  → "Check the document number, date of birth and expiry" — the document
  //           is probably fine, the key is wrong. Do not retry the same values.
  // NotAuthentic → stop. This is not a retry, and should not look like one.
}
```

That distinction is why the Rust side separates them: retrying a wrong key forever, or
telling someone their genuine passport is fake because they moved their hand, are both
avoidable.

## What to expose over FFI

One flat struct for both document types, because that is the whole point:

```rust
pub struct ScanResult {
    pub family_name: Option<String>,
    pub given_name: Option<String>,
    pub date_of_birth: Option<String>,   // YYYY-MM-DD
    pub document_number: Option<String>,
    pub nationality: Option<String>,
    pub portrait: Option<Vec<u8>>,
    pub age_over_21: Option<bool>,

    /// Genuine, from an issuer you trust, in date.
    pub trustworthy: bool,
    /// The above *and* proof this is the original document, not a copy.
    pub present_and_trustworthy: bool,
    /// Shown in a debug view, not to the holder.
    pub warnings: Vec<String>,
}

impl From<identity_mobile::VerifiedIdentity> for ScanResult {
    fn from(identity: identity_mobile::VerifiedIdentity) -> Self {
        Self {
            family_name: identity.family_name,
            given_name: identity.given_name,
            date_of_birth: identity.date_of_birth,
            document_number: identity.document_number,
            nationality: identity.nationality,
            portrait: identity.portrait,
            age_over_21: identity.age_over(21),
            trustworthy: identity.authenticity.is_trustworthy(),
            present_and_trustworthy: identity.authenticity.is_present_and_trustworthy(),
            warnings: identity.authenticity.warnings,
        }
    }
}
```

Expose **both** booleans rather than collapsing them. Which one to gate on is a policy
decision your Dart code should make explicitly:

```dart
// In person, with the document in hand — a copy will not do.
if (!result.presentAndTrustworthy) return Denied();

// Server-side, accepting a wallet presentation you already bound to a session.
if (!result.trustworthy) return Denied();
```

## Trust anchors

Both document types need them, and neither is fetched for you:

- **Passports** — CSCA certificates from the ICAO masterlist, DER-encoded.
- **mDLs** — IACA certificates, or a VICAL through `mdl_verify::vical`.

Ship them as Flutter assets and pass them in. Verifying with none is allowed and
sometimes useful in development: the data is still checked against its signature, and
`trustworthy` comes back `false` because nothing attributes it to an issuer.

## Age checks without a date of birth

Worth designing for, because the two documents differ:

- An **mDL** can attest `age_over_21` while disclosing nothing else — no name, no date
  of birth. `age_over(21)` answers directly.
- A **passport** carries the date of birth and nothing else, so the arithmetic — and
  the disclosure — is yours.

If you are building an age check, prefer the mDL path and ask for exactly the
attestation you need. It is the one place where the newer document is meaningfully
better for the holder's privacy.
