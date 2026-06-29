//! Elementary File base type.
//!
//! [`ElementaryFile`] is the common trait implemented by every EF type
//! (`EF.CardAccess`, `EF.COM`, `EF.DGx`, `EF.SOD`, …). Each concrete EF
//! provides:
//! - file-id and short-file-id associated constants ([`ElementaryFile::FID`],
//!   [`ElementaryFile::SFI`]),
//! - a [`to_bytes`] accessor for the original encoded payload,
//! - a type-specific `from_bytes` constructor that parses that payload
//!   (returning [`EfParseError`] on failure).
//!
//! [`to_bytes`]: ElementaryFile::to_bytes

use thiserror::Error;

/// Error returned by EF parsers when the underlying bytes do not match the
/// expected structure.
#[derive(Debug, Error)]
#[error("EfParseError: {0}")]
pub struct EfParseError(pub String);

impl EfParseError {
    /// Creates a new [`EfParseError`] with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl From<asn1::ParseError> for EfParseError {
    fn from(e: asn1::ParseError) -> Self {
        Self(format!("ASN.1 parse error: {e}"))
    }
}

/// Marker trait for elementary files. Concrete EF types supply their
/// file-id and short-file-id as associated constants and expose their
/// original encoded payload via [`ElementaryFile::to_bytes`].
pub trait ElementaryFile {
    /// File ID.
    const FID: u16;
    /// Short File ID.
    const SFI: u8;

    /// Returns the original encoded bytes this EF was parsed from.
    fn to_bytes(&self) -> &[u8];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct DummyEf {
        encoded: Vec<u8>,
    }

    impl DummyEf {
        fn from_bytes(data: Vec<u8>) -> Result<Self, EfParseError> {
            if data.is_empty() {
                return Err(EfParseError::new("empty"));
            }
            Ok(Self { encoded: data })
        }
    }

    impl ElementaryFile for DummyEf {
        const FID: u16 = 0x011C;
        const SFI: u8 = 0x1C;

        fn to_bytes(&self) -> &[u8] {
            &self.encoded
        }
    }

    #[test]
    fn trait_exposes_associated_constants() {
        assert_eq!(DummyEf::FID, 0x011C);
        assert_eq!(DummyEf::SFI, 0x1C);
    }

    #[test]
    fn to_bytes_returns_payload() {
        let ef = DummyEf::from_bytes(vec![1, 2, 3]).unwrap();
        assert_eq!(ef.to_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn empty_payload_is_error() {
        let err = DummyEf::from_bytes(vec![]).unwrap_err();
        assert_eq!(err.0, "empty");
    }
}
