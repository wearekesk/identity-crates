//! EF.CardSecurity elementary file.
//!
//! The reference implementation intentionally stores the raw bytes
//! without parsing them further (parsing would require PKCS#7 / `SignedData`
//! handling which is out of scope for the DMRTD library). This port matches
//! that behaviour.

use crate::lds::ef::{EfParseError, ElementaryFile};

/// EF.CardSecurity file ID.
pub const EF_CARD_SECURITY_FID: u16 = 0x011D;
/// EF.CardSecurity short file ID.
pub const EF_CARD_SECURITY_SFI: u8 = 0x1D;
/// EF.CardSecurity tag byte.
pub const EF_CARD_SECURITY_TAG: u8 = 0x6D;

/// EF.CardSecurity container.
#[derive(Debug, Clone)]
pub struct EfCardSecurity {
    encoded: Vec<u8>,
}

impl EfCardSecurity {
    /// Stores the raw bytes as EF.CardSecurity. Never fails — the payload
    /// is held verbatim without structural validation.
    pub fn from_bytes(encoded: impl Into<Vec<u8>>) -> Result<Self, EfParseError> {
        Ok(Self {
            encoded: encoded.into(),
        })
    }
}

impl ElementaryFile for EfCardSecurity {
    const FID: u16 = EF_CARD_SECURITY_FID;
    const SFI: u8 = EF_CARD_SECURITY_SFI;

    fn to_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_raw_bytes() {
        let payload = vec![0x30, 0x03, 0x02, 0x01, 0x2A];
        let ef = EfCardSecurity::from_bytes(payload.clone()).unwrap();
        assert_eq!(ef.to_bytes(), payload.as_slice());
    }

    #[test]
    fn accepts_empty_input() {
        let ef = EfCardSecurity::from_bytes(Vec::<u8>::new()).unwrap();
        assert_eq!(ef.to_bytes(), b"");
    }

    #[test]
    fn associated_constants() {
        assert_eq!(EfCardSecurity::FID, 0x011D);
        assert_eq!(EfCardSecurity::SFI, 0x1D);
    }
}
