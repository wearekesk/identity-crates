# aadhaar-offline-kyc

**Aadhaar offline e-KYC reader in pure Rust** (India / UIDAI) — covers the
**Secure QR v2** printed on Aadhaar cards/PDFs, the **Paperless Offline e-KYC**
share-phrase ZIP/XML, and **Verhoeff** Aadhaar-number syntax validation.

The crate's library name is `aadhaar`.

## Features

- **Secure QR v2** — decode a QR from PNG/JPEG bytes or a luma8 buffer
  ([`decode_qr_from_image_bytes`]) and parse the base-10 digit string into an
  [`AadhaarData`] record ([`parse_secure_qr_text`]); or do both at once with
  [`parse_secure_qr_image_bytes`]. Confirm the record was issued by UIDAI and is
  unmodified with **UIDAI signature verification** — [`AadhaarData::verify`] on a
  parsed record, or [`parse_and_verify_secure_qr_image_bytes`] /
  [`parse_and_verify_secure_qr_text`] to parse and verify in one call (these fail
  closed: a bad signature is an error, not an `Ok` record).
- **Paperless Offline e-KYC** — decrypt the share-phrase ZIP and parse the XML
  into an [`OfflineEkyc`] with **UIDAI digital-signature verification**
  ([`parse_offline_ekyc`]); optionally confirm a claimed contact against the
  embedded hash ([`verify_mobile`] / [`verify_email`]) or verify the XML
  signature alone ([`verify_signature`]).
- **Verhoeff validation** — check that an Aadhaar number is syntactically valid
  (12 digits, leading 2–9, correct check digit) with
  [`verhoeff::validate_aadhaar_syntax`]. This is a syntax check, not proof of
  issuance.

The UIDAI signer public keys are **pinned** in the crate. Older keys are kept on
purpose: UIDAI cards and offline artifacts stay valid for years and may be signed
with rotated-out (now-expired) signer certs, so the older keys must remain trusted
for legacy artifacts to still verify.

## Usage

```rust,no_run
use aadhaar::{parse_and_verify_secure_qr_image_bytes, verhoeff::validate_aadhaar_syntax};

// Scan + parse + verify the UIDAI signature on the Secure QR v2 of a card image.
// Errors if the signature does not verify against a pinned UIDAI signer key.
let bytes: Vec<u8> = std::fs::read("aadhaar_card.png")?;
let data = parse_and_verify_secure_qr_image_bytes(&bytes)?;
assert!(data.signature_verified);
println!("{} (Aadhaar ****{})", data.name, data.last_four_aadhaar);

// Syntactic Aadhaar-number check (Verhoeff). Use a synthetic number here.
let ok = validate_aadhaar_syntax("999999990019");
println!("syntactically valid: {ok}");
# Ok::<(), aadhaar::AadhaarError>(())
```

Paperless Offline e-KYC (decrypt + parse + verify UIDAI signature):

```rust,no_run
use aadhaar::parse_offline_ekyc;

let zip: Vec<u8> = std::fs::read("offlineaadhaar.zip")?;
let ekyc = parse_offline_ekyc(&zip, "SHARE_PHRASE")?;
assert!(ekyc.signature_verified);
# Ok::<(), aadhaar::AadhaarError>(())
```

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
