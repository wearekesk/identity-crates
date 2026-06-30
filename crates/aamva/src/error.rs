//! Error types for the AAMVA DL / ID parser.

use thiserror::Error;

/// Error returned by the AAMVA parser and PDF417 decoder.
#[derive(Debug, Error)]
pub enum AamvaError {
    #[error("PDF417 barcode not found in image")]
    BarcodeNotFound,

    #[error("PDF417 decode failed: {0}")]
    PdfDecode(String),

    #[error("image decode failed: {0}")]
    ImageDecode(String),

    #[error("payload is too short ({len} bytes, need at least {min})")]
    PayloadTooShort { len: usize, min: usize },

    #[error("missing AAMVA compliance indicator (expected `@`)")]
    MissingComplianceIndicator,

    #[error("missing AAMVA header token `ANSI `")]
    MissingAnsiHeader,

    #[error("malformed AAMVA header: {0}")]
    MalformedHeader(String),

    #[error("malformed subfile designator at index {index}")]
    MalformedSubfileDesignator { index: usize },

    #[error("subfile {subfile:?} out of bounds (offset={offset}, length={length}, payload={payload_len})")]
    SubfileOutOfBounds {
        subfile: String,
        offset: usize,
        length: usize,
        payload_len: usize,
    },

    #[error("subfile {expected:?} does not start with its type tag")]
    SubfileTypeMismatch { expected: String },

    #[error("invalid date `{raw}` for element `{element}`")]
    InvalidDate { element: &'static str, raw: String },
}
