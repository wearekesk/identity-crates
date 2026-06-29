//! Data-group base type.
//!
//! Defines:
//! - [`DgTag`] — newtype wrapping the BER-TLV tag assigned to a data group.
//! - [`parse_dg_content`] — helper that strips the outer TLV wrapper of a DG
//!   blob and returns the value bytes, validating the tag against the
//!   expected one. Concrete DG structs typically call this from their
//!   constructor before delegating to a type-specific parser.

use crate::lds::ef::EfParseError;
use crate::lds::tlv::Tlv;

/// BER-TLV tag attached to a data group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DgTag(pub u32);

impl DgTag {
    /// Returns the numeric tag value.
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for DgTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:X}", self.0)
    }
}

/// Parses the outer BER-TLV wrapper around a data-group blob and returns the
/// value bytes. Concrete DG implementations call this and then pass the
/// returned bytes to a type-specific content parser.
///
/// # Errors
/// Returns [`EfParseError`] if the wrapper is malformed or its tag does not
/// equal `expected_tag`.
pub fn parse_dg_content(content: &[u8], expected_tag: u32) -> Result<Vec<u8>, EfParseError> {
    let tlv = Tlv::decode(content)
        .map_err(|e| EfParseError::new(format!("Invalid DG wrapper: {e}")))?;
    if tlv.tag.value != expected_tag {
        return Err(EfParseError::new(format!(
            "Invalid tag={:X}, expected tag={:X}",
            tlv.tag.value, expected_tag
        )));
    }
    // An elementary file is exactly one BER-TLV; reject any trailing bytes.
    if tlv.encoded_len != content.len() {
        return Err(EfParseError::new(format!(
            "Trailing bytes after DG TLV: {} extra byte(s)",
            content.len() - tlv.encoded_len
        )));
    }
    Ok(tlv.value)
}

// ---------------------------------------------------------------------------
// Stub data-group helper
// ---------------------------------------------------------------------------

/// Generates a minimal data-group struct that stores its raw bytes and
/// validates only the outer TLV tag. Used by the content-free DG types
/// (DG3-10, DG13, DG14, DG16) whose ports are stubs.
#[macro_export]
macro_rules! dg_stub {
    ($(#[$m:meta])* $name:ident, $fid:expr, $sfi:expr, $tag:expr) => {
        $(#[$m])*
        #[derive(Debug, Clone)]
        pub struct $name {
            encoded: Vec<u8>,
        }

        impl $name {
            /// File ID.
            pub const FID: u16 = $fid;
            /// Short File ID.
            pub const SFI: u8 = $sfi;
            /// Data-group TLV tag.
            pub const TAG: $crate::lds::df1::dg::DgTag =
                $crate::lds::df1::dg::DgTag($tag);

            /// Parses the data group, validating only the outer TLV tag.
            pub fn from_bytes(
                data: impl Into<Vec<u8>>,
            ) -> Result<Self, $crate::lds::ef::EfParseError> {
                let encoded = data.into();
                let _ = $crate::lds::df1::dg::parse_dg_content(&encoded, $tag)?;
                Ok(Self { encoded })
            }
        }

        impl $crate::lds::ef::ElementaryFile for $name {
            const FID: u16 = $fid;
            const SFI: u8 = $sfi;

            fn to_bytes(&self) -> &[u8] {
                &self.encoded
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dg_tag_equality() {
        assert_eq!(DgTag(0x61), DgTag(0x61));
        assert_ne!(DgTag(0x61), DgTag(0x62));
    }

    #[test]
    fn parse_strips_wrapper() {
        // Build TLV: tag=0x6A, value=[0xAA, 0xBB]
        let wrapped = Tlv::encode(0x6A, &[0xAA, 0xBB]);
        let content = parse_dg_content(&wrapped, 0x6A).unwrap();
        assert_eq!(content, vec![0xAA, 0xBB]);
    }

    #[test]
    fn parse_rejects_wrong_tag() {
        let wrapped = Tlv::encode(0x61, &[0xAA]);
        let err = parse_dg_content(&wrapped, 0x6A).unwrap_err();
        assert!(err.0.contains("expected tag=6A"));
    }

    #[test]
    fn parse_rejects_malformed_input() {
        let err = parse_dg_content(&[], 0x61).unwrap_err();
        assert!(err.0.contains("Invalid DG wrapper"));
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let mut wrapped = Tlv::encode(0x6A, &[0xAA, 0xBB]);
        wrapped.push(0xFF); // extra byte after the TLV
        let err = parse_dg_content(&wrapped, 0x6A).unwrap_err();
        assert!(err.0.contains("Trailing bytes"));
    }
}
