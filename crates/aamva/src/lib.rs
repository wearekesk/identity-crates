//! AAMVA DL / ID (PDF417) reader.
//!
//! - [`decode_pdf417_from_image_bytes`] / [`decode_pdf417_from_luma8`] — scan
//!   the PDF417 barcode printed on the back of a US / Canadian driver's
//!   licence via the [`rxing`] crate.
//! - [`parse`] — parse the text payload into an [`AamvaLicense`].
//! - [`parse_license_from_image_bytes`] / [`parse_license_from_luma8`] —
//!   convenience: scan + parse in one call.
//!
//! Covers AAMVA Card Design Standard versions 01–10 (MMDDCCYY dates for USA
//! jurisdictions, CCYYMMDD for Canada, both tolerated).

pub mod data;
pub mod error;
pub mod parser;
pub mod pdf417;

pub use data::{
    AamvaHeader, AamvaLicense, Compliance, Country, EyeColor, HairColor, Height, Sex,
    SubfileDesignator, Truncation,
};
pub use error::AamvaError;
pub use parser::parse;
pub use pdf417::{decode_pdf417_from_image_bytes, decode_pdf417_from_luma8};

/// Scan the PDF417 on PNG/JPEG image bytes and parse the AAMVA payload.
pub fn parse_license_from_image_bytes(image_bytes: &[u8]) -> Result<AamvaLicense, AamvaError> {
    let text = decode_pdf417_from_image_bytes(image_bytes)?;
    parse(text.as_bytes())
}

/// Scan the PDF417 on a luma8 buffer and parse the AAMVA payload.
pub fn parse_license_from_luma8(
    width: u32,
    height: u32,
    luma: Vec<u8>,
) -> Result<AamvaLicense, AamvaError> {
    let text = decode_pdf417_from_luma8(width, height, luma)?;
    parse(text.as_bytes())
}
