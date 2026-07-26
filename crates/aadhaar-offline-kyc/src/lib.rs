//! Aadhaar offline e-KYC (India UIDAI).
//!
//! **Secure QR v2** (the printed/digital QR):
//! - [`decode_qr_from_image_bytes`] / [`decode_qr_from_luma8`] — scan a QR via [`rxing`].
//! - [`parse_secure_qr_text`] — parse the base-10 digit string into [`AadhaarData`].
//! - [`parse_secure_qr_image_bytes`] — scan + parse in one call.
//! - [`AadhaarData::verify`] — check the UIDAI signature on a parsed record;
//!   [`parse_and_verify_secure_qr_text`] / [`parse_and_verify_secure_qr_image_bytes`]
//!   parse and verify in one call, failing closed on a bad signature.
//!
//! **Paperless Offline e-KYC** (the share-phrase ZIP/XML) — [`offline_ekyc`]:
//! - [`parse_offline_ekyc`] — decrypt the ZIP, parse the XML, verify the UIDAI signature.
//! - [`verify_mobile`] / [`verify_email`] — check a claimed contact against the e-KYC hash.

pub mod data;
pub mod error;
pub mod offline_ekyc;
pub mod parser;
pub mod qr;
pub mod signature;
pub mod verhoeff;

pub use data::{AadhaarData, Gender};
pub use error::AadhaarError;
pub use offline_ekyc::{
    decrypt_offline_zip, parse_offline_ekyc, parse_offline_xml, verify_email, verify_mobile,
    verify_signature, OfflineEkyc,
};
pub use parser::{
    parse_and_verify_decompressed, parse_and_verify_secure_qr_bytes,
    parse_and_verify_secure_qr_text, parse_decompressed, parse_secure_qr_bytes,
    parse_secure_qr_text,
};
pub use qr::{decode_qr_from_image_bytes, decode_qr_from_luma8};
pub use signature::{verify_secure_qr_payload, verify_uidai_rsa_sha256};

/// Convenience: decode a QR code from PNG/JPEG bytes and parse the Aadhaar
/// payload in one call.
pub fn parse_secure_qr_image_bytes(image_bytes: &[u8]) -> Result<AadhaarData, AadhaarError> {
    let text = decode_qr_from_image_bytes(image_bytes)?;
    parse_secure_qr_text(&text)
}

/// Convenience: decode a QR code from a luma8 buffer and parse the Aadhaar
/// payload in one call.
pub fn parse_secure_qr_luma8(
    width: u32,
    height: u32,
    luma: Vec<u8>,
) -> Result<AadhaarData, AadhaarError> {
    let text = decode_qr_from_luma8(width, height, luma)?;
    parse_secure_qr_text(&text)
}

/// Convenience: decode a QR code from PNG/JPEG bytes, parse it, and verify the
/// UIDAI signature — failing closed if it does not verify.
pub fn parse_and_verify_secure_qr_image_bytes(
    image_bytes: &[u8],
) -> Result<AadhaarData, AadhaarError> {
    let text = decode_qr_from_image_bytes(image_bytes)?;
    parse_and_verify_secure_qr_text(&text)
}

/// Convenience: decode a QR code from a luma8 buffer, parse it, and verify the
/// UIDAI signature — failing closed if it does not verify.
pub fn parse_and_verify_secure_qr_luma8(
    width: u32,
    height: u32,
    luma: Vec<u8>,
) -> Result<AadhaarData, AadhaarError> {
    let text = decode_qr_from_luma8(width, height, luma)?;
    parse_and_verify_secure_qr_text(&text)
}
