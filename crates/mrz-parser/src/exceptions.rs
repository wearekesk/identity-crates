//! MRZ parser errors. `MRZError` is an enum of the concrete error cases; each
//! variant implements `Display` and `std::error::Error`.

use std::error::Error;
use std::fmt;

/// Error types produced by the MRZ parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MRZError {
    /// Invalid MRZ parser input
    InvalidMRZInput,

    /// Document number hash mismatch
    InvalidDocumentNumber,

    /// Birth date hash mismatch
    InvalidBirthDate,

    /// Expiry date hash mismatch
    InvalidExpiryDate,

    /// Optional data hash mismatch
    InvalidOptionalData,

    /// Final hash mismatch
    InvalidMRZValue,

    /// A generic/custom error with a message.
    Custom(String),
}

impl MRZError {
    /// Convenience constructors for each variant.
    pub fn invalid_mrz_input() -> Self {
        MRZError::InvalidMRZInput
    }

    pub fn invalid_document_number() -> Self {
        MRZError::InvalidDocumentNumber
    }

    pub fn invalid_birth_date() -> Self {
        MRZError::InvalidBirthDate
    }

    pub fn invalid_expiry_date() -> Self {
        MRZError::InvalidExpiryDate
    }

    pub fn invalid_optional_data() -> Self {
        MRZError::InvalidOptionalData
    }

    pub fn invalid_mrz_value() -> Self {
        MRZError::InvalidMRZValue
    }

    /// Create a custom error with a provided message.
    pub fn custom<M: Into<String>>(msg: M) -> Self {
        MRZError::Custom(msg.into())
    }

    /// Human-friendly message for each error variant (without the GitHub hint).
    fn short_message(&self) -> &str {
        match self {
            MRZError::InvalidMRZInput => "Invalid MRZ parser input",
            MRZError::InvalidDocumentNumber => "Document number hash mismatch",
            MRZError::InvalidBirthDate => "Birth date hash mismatch",
            MRZError::InvalidExpiryDate => "Expiry date hash mismatch",
            MRZError::InvalidOptionalData => "Optional data hash mismatch",
            MRZError::InvalidMRZValue => "Final hash mismatch",
            MRZError::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for MRZError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}. If you think this is a mistake, please file an issue at {}/issues",
            self.short_message(),
            env!("CARGO_PKG_REPOSITORY")
        )
    }
}

impl Error for MRZError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_contains_message_and_link() {
        let e = MRZError::invalid_mrz_input();
        let s = format!("{}", e);
        assert!(s.contains("Invalid MRZ parser input"));
        assert!(s.contains(concat!(env!("CARGO_PKG_REPOSITORY"), "/issues")));
    }

    #[test]
    fn custom_error_message() {
        let e = MRZError::custom("something went wrong");
        let s = format!("{}", e);
        assert!(s.contains("something went wrong"));
        assert!(s.contains(concat!(env!("CARGO_PKG_REPOSITORY"), "/issues")));
    }

    #[test]
    fn variants_have_expected_short_messages() {
        assert_eq!(
            MRZError::InvalidDocumentNumber.short_message(),
            "Document number hash mismatch"
        );
        assert_eq!(
            MRZError::InvalidBirthDate.short_message(),
            "Birth date hash mismatch"
        );
        assert_eq!(
            MRZError::InvalidExpiryDate.short_message(),
            "Expiry date hash mismatch"
        );
        assert_eq!(
            MRZError::InvalidOptionalData.short_message(),
            "Optional data hash mismatch"
        );
        assert_eq!(
            MRZError::InvalidMRZValue.short_message(),
            "Final hash mismatch"
        );
    }
}
