# incometax-pan-qr

**Indian Income-Tax PAN utilities in pure Rust** — structural validation and
entity-type classification of a Permanent Account Number, plus a decoder for the
Enhanced Secure QR codes printed on PAN / e-PAN cards.

## Features

- **PAN validation** — [`check_pan_details`] structurally validates a PAN
  (`AAAAA9999A`) and classifies the holder by the 4th-character entity code,
  returning a [`PanDetails`] with a [`PanType`] (Individual, Company, HUF, Firm,
  AOP, Trust, BOI, Local Authority, Artificial Juridical Person, Government).
  This is a structural check only; it does not confirm the PAN was issued.
- **Secure-QR decoding** — [`PanQr::from_image_bytes`] detects and reads the QR
  from a card image (PNG/JPEG); [`PanQr::from_scanned_string`] decodes an
  already-scanned QR string. The decoded PAN exposes:
  - `.pii()` — a [`PanPii`] (`Individual { pan, pan_valid, name, father_name,
    dob }` or `Organization { pan, pan_valid, name, date_of_incorporation }`),
  - `.image()` — the embedded photo bytes (individuals only),
  - `.verify()` — P-384 / SHA-384 ECDSA signature verification against the
    embedded public key.

## Usage

Validate and classify a PAN (use a clearly-fake specimen, not a real PAN):

```rust,no_run
use incometax_pan_qr::{check_pan_details, PanType};

let details = check_pan_details("ABCDE1234F");
println!("valid: {}", details.is_valid);
if details.pan_type == PanType::Individual {
    println!("individual PAN");
}
```

Decode a PAN / e-PAN Secure QR from a card image:

```rust,no_run
use incometax_pan_qr::{PanQr, PanPii};

let bytes: Vec<u8> = std::fs::read("epan.png")?;
let qr = PanQr::from_image_bytes(&bytes)?;

match qr.pii() {
    Some(PanPii::Individual { pan, name, dob, .. }) => {
        println!("individual {name} ({pan}), dob {dob}");
    }
    Some(PanPii::Organization { pan, name, date_of_incorporation }) => {
        println!("org {name} ({pan}), incorporated {date_of_incorporation}");
    }
    None => println!("no PII in QR"),
}

if let Some(photo) = qr.image() {
    println!("embedded photo: {} bytes", photo.len());
}

let signature_ok = qr.verify()?; // P-384 / SHA-384 ECDSA
println!("signature valid: {signature_ok}");
# Ok::<(), incometax_pan_qr::PanQrError>(())
```

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
