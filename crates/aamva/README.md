# aamva

**AAMVA driver's-license / ID reader in pure Rust** — scans the PDF417 barcode
on the back of a US or Canadian driver's license and parses the AAMVA payload
into structured fields.

Image decoding is handled by [`rxing`]; the AAMVA payload parser covers Card
Design Standard versions 01–10 (MMDDCCYY dates for US jurisdictions, CCYYMMDD for
Canada, both tolerated).

## Features

- Decode a PDF417 barcode from PNG/JPEG bytes or a raw luma8 buffer
  ([`decode_pdf417_from_image_bytes`], [`decode_pdf417_from_luma8`]).
- Parse an AAMVA text payload into an [`AamvaLicense`] ([`parse`]).
- One-call scan + parse ([`parse_license_from_image_bytes`],
  [`parse_license_from_luma8`]).
- Typed fields: names, address, dates, [`Sex`], [`EyeColor`], [`HairColor`],
  [`Height`], [`Country`], [`Compliance`], [`Truncation`].

## Usage

```rust,no_run
use aamva::parse_license_from_image_bytes;

// `bytes` is a PNG/JPEG of the back of the licence (the PDF417 barcode).
let bytes: Vec<u8> = std::fs::read("license_back.png")?;
let license = parse_license_from_image_bytes(&bytes)?;

println!("{:?} {:?}", license.first_name, license.family_name);
# Ok::<(), aamva::AamvaError>(())
```

If you already have the decoded barcode text, parse it directly:

```rust,no_run
use aamva::parse;

let payload: &[u8] = b"@\n\u{1e}\rANSI ..."; // raw AAMVA payload
let license = parse(payload)?;
# Ok::<(), aamva::AamvaError>(())
```

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
