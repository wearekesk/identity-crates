//! Error types for the Aadhaar QR parser.

use thiserror::Error;

/// Error returned by the Aadhaar parser and QR decoder.
#[derive(Debug, Error)]
pub enum AadhaarError {
    #[error("QR code not found in image")]
    QrNotFound,

    #[error("QR decode failed: {0}")]
    QrDecode(String),

    #[error("image decode failed: {0}")]
    ImageDecode(String),

    #[error("QR text is not a base-10 digit string")]
    NotDecimal,

    #[error("gzip decompress failed: {0}")]
    Gunzip(String),

    #[error("payload is too short ({len} bytes)")]
    PayloadTooShort { len: usize },

    #[error("expected {expected} delimited text fields, got {got}")]
    InsufficientFields { expected: usize, got: usize },

    #[error("invalid UTF-8 in Aadhaar field `{field}`")]
    InvalidUtf8 { field: &'static str },

    #[error("invalid date in Aadhaar DOB field `{raw}`")]
    InvalidDate { raw: String },

    #[error("invalid email/mobile indicator `{raw}`")]
    InvalidIndicator { raw: String },

    // --- Paperless Offline e-KYC (ZIP / XML) ---
    #[error("offline e-KYC zip error: {0}")]
    Zip(String),

    #[error("offline e-KYC xml error: {0}")]
    Xml(String),

    #[error("offline e-KYC signature did not verify against any UIDAI certificate")]
    SignatureInvalid,

    #[error("offline e-KYC signature error: {0}")]
    Signature(String),
}
