# mrz-parser

**ICAO 9303 Machine Readable Zone parser in pure Rust** — turns the 1–3 line MRZ
printed on passports and ID cards into structured fields, with check-digit
validation and country-specific document-number handling.

The parser auto-detects the document format (TD1 3-line ID cards, TD2 2-line
travel documents, TD3 2-line passports), polishes raw OCR input (filters empty
lines, upper-cases, validates the MRZ character set), validates the composite and
per-field check digits, and applies country-specific patterns to recover the
document number.

## Features

- TD1 / TD2 / TD3 detection and parsing into an [`MRZResult`].
- Check-digit calculation and validation ([`get_check_digit`]).
- Country-specific document-number recognition / defect fixing.
- Tolerant entry point for noisy OCR output (`Option<Vec<Option<String>>>`).
- Helpers in [`string_extensions`] for cleaning MRZ text.

## Usage

`MRZParser::parse` returns `Result<MRZResult, MRZError>`; `MRZParser::try_parse`
returns `Option<MRZResult>` (`None` on any error). Input is the MRZ lines as an
`Option<Vec<Option<String>>>`, modelling OCR results that may be missing.

```rust,no_run
use mrz_parser::{MRZParser, Sex};

// ICAO 9303 TD3 (passport) specimen — synthetic, not real personal data.
let lines = Some(vec![
    Some("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".to_string()),
    Some("L898902C36UTO7408122F1204159ZE184226B<<<<<10".to_string()),
]);

let result = MRZParser::parse(lines).expect("valid MRZ");
assert_eq!(result.document_type, "P");
assert_eq!(result.country_code, "UTO");
assert_eq!(result.document_number, "L898902C3");
assert_eq!(result.sex, Sex::Female);
println!("{result}");
```

Need just a check digit? Call [`get_check_digit`] directly:

```rust,no_run
use mrz_parser::get_check_digit;

let cd = get_check_digit("L898902C3"); // -> 6
assert_eq!(cd, 6);
```

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
