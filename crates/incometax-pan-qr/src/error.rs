//! Error type for the PAN Secure-QR decoder.

use thiserror::Error;

/// Errors produced while decoding / verifying a PAN Secure QR.
#[derive(Debug, Error)]
pub enum PanQrError {
    /// A 4-character chunk of the scanned string was not a decimal integer.
    #[error("invalid scanned-string chunk: {0:?}")]
    InvalidChunk(String),

    /// `bit_unpack` was called with a bit count outside `1..=32`.
    #[error("bit count {0} is not between 1 and 32")]
    InvalidBitCount(i64),

    /// The byte stream ended before a field could be fully read.
    #[error("unexpected end of input while parsing {0}")]
    UnexpectedEof(&'static str),

    /// A `Const` field did not contain the expected magic bytes.
    #[error("bad magic for {field}: expected {expected:02x?}, found {found:02x?}")]
    BadMagic {
        /// The struct field that carried the constant.
        field: &'static str,
        /// The bytes that were expected.
        expected: Vec<u8>,
        /// The bytes that were actually found.
        found: Vec<u8>,
    },

    /// The QR failed structural validation (bad version / reserved fields).
    #[error("PAN QR failed validation")]
    ValidationFailed,

    /// zlib inflation of a PII blob failed.
    #[error("zlib inflate failed: {0}")]
    Inflate(String),

    /// The PII blob did not contain the four expected elements.
    #[error("PII blob did not yield the expected PAN/Name/FName/DOB elements")]
    MissingPii,

    /// No public key corresponds to the QR's version.
    #[error("no public key found for this QR version")]
    MissingPublicKey,

    /// The base64 ECC key could not be decoded.
    #[error("ECC key base64 decode failed: {0}")]
    KeyDecode(String),

    /// The ECC key bytes could not be loaded as a P-384 verifying key.
    #[error("ECC key could not be loaded as a P-384 public key")]
    InvalidKey,

    /// The signature bytes were malformed.
    #[error("signature could not be parsed")]
    InvalidSignature,
}
