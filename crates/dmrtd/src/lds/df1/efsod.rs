//! EF.SOD (Document Security Object) — stores the raw SignedData bytes.
//!
//! The reference stores the payload verbatim; full validation requires a
//! CMS / `SignedData` decoder that is out of scope for this library.

use crate::lds::ef::{ElementaryFile, EfParseError};

/// EF.SOD file ID.
pub const EF_SOD_FID: u16 = 0x011D;
/// EF.SOD short file ID.
pub const EF_SOD_SFI: u8 = 0x1D;
/// EF.SOD tag byte.
pub const EF_SOD_TAG: u8 = 0x77;

#[derive(Debug, Clone)]
pub struct EfSOD {
    encoded: Vec<u8>,
}

impl EfSOD {
    /// Stores the raw EF.SOD bytes without structural validation.
    pub fn from_bytes(encoded: impl Into<Vec<u8>>) -> Result<Self, EfParseError> {
        Ok(Self {
            encoded: encoded.into(),
        })
    }
}

impl ElementaryFile for EfSOD {
    const FID: u16 = EF_SOD_FID;
    const SFI: u8 = EF_SOD_SFI;

    fn to_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_raw_bytes() {
        let ef = EfSOD::from_bytes(vec![0x77, 0x03, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(ef.to_bytes(), &[0x77, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn constants() {
        assert_eq!(EfSOD::FID, 0x011D);
        assert_eq!(EfSOD::SFI, 0x1D);
    }
}
