//! Card Access Number (CAN) access key.
//!
//! A [`CanKey`] wraps the 6-digit Card Access Number printed on a travel
//! document (see ICAO TAG MRTD WP020 §3.1.6). The CAN bytes feed the PACE
//! key-derivation function directly — no SHA-1 seed step as with BAC.

use thiserror::Error;

use crate::crypto::kdf::DeriveKey;
use crate::lds::asn1_object_identifiers::{CipherAlgorithm, KeyLength};
use crate::proto::access_key::{AccessKey, PACE_REF_KEY_TAG_CAN};

/// Error returned when constructing a [`CanKey`].
#[derive(Debug, Error, PartialEq, Eq)]
#[error("CanKeysError: {0}")]
pub struct CanKeysError(pub String);

const CAN_LEN: usize = 6;

/// Card Access Number key.
#[derive(Debug, Clone)]
pub struct CanKey {
    can: [u8; CAN_LEN],
}

impl CanKey {
    /// Constructs a [`CanKey`] from a 6-digit CAN string.
    ///
    /// # Errors
    /// Returns [`CanKeysError`] if `can_number` is not exactly 6 digits.
    pub fn new(can_number: &str) -> Result<Self, CanKeysError> {
        if can_number.len() != CAN_LEN || !can_number.chars().all(|c| c.is_ascii_digit()) {
            return Err(CanKeysError(
                "AccessKey.CanKeys; Code must be exactly 6 digits and only contain numbers".into(),
            ));
        }
        let bytes = can_number.as_bytes();
        let mut can = [0u8; CAN_LEN];
        can.copy_from_slice(bytes);
        Ok(Self { can })
    }

    /// Returns the raw CAN bytes (ASCII digit codes).
    pub fn can(&self) -> &[u8; CAN_LEN] {
        &self.can
    }
}

impl AccessKey for CanKey {
    fn pace_ref_key_tag(&self) -> u8 {
        PACE_REF_KEY_TAG_CAN
    }

    fn kpi(
        &self,
        cipher_algorithm: CipherAlgorithm,
        key_length: KeyLength,
    ) -> Result<Vec<u8>, String> {
        match (cipher_algorithm, key_length) {
            (CipherAlgorithm::DeSede, _) => Ok(DeriveKey::des_ede(&self.can, true)),
            (CipherAlgorithm::Aes, KeyLength::S128) => Ok(DeriveKey::aes128(&self.can, true)),
            (CipherAlgorithm::Aes, KeyLength::S192) => Ok(DeriveKey::aes192(&self.can, true)),
            (CipherAlgorithm::Aes, KeyLength::S256) => Ok(DeriveKey::aes256(&self.can, true)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_6_digit_can() {
        let key = CanKey::new("123456").unwrap();
        assert_eq!(key.can(), b"123456");
        assert_eq!(key.pace_ref_key_tag(), PACE_REF_KEY_TAG_CAN);
    }

    #[test]
    fn rejects_too_short() {
        let err = CanKey::new("12345").unwrap_err();
        assert!(err.0.contains("6 digits"));
    }

    #[test]
    fn rejects_too_long() {
        let err = CanKey::new("1234567").unwrap_err();
        assert!(err.0.contains("6 digits"));
    }

    #[test]
    fn rejects_non_digit() {
        let err = CanKey::new("12345A").unwrap_err();
        assert!(err.0.contains("digits"));
    }

    #[test]
    fn kpi_aes128_is_16_bytes() {
        let key = CanKey::new("123456").unwrap();
        let kpi = key.kpi(CipherAlgorithm::Aes, KeyLength::S128).unwrap();
        assert_eq!(kpi.len(), 16);
    }

    /// Reference vector: CAN `123456` derives `K_π` for AES-128 equal to
    /// `591468cda83d65219cccb8560233600f`.
    #[test]
    fn kpi_aes128_value_matches_reference_vector() {
        let key = CanKey::new("123456").unwrap();
        let kpi = key.kpi(CipherAlgorithm::Aes, KeyLength::S128).unwrap();
        assert_eq!(
            hex::encode(kpi),
            "591468cda83d65219cccb8560233600f"
        );
    }

    #[test]
    fn kpi_aes256_is_32_bytes() {
        let key = CanKey::new("123456").unwrap();
        let kpi = key.kpi(CipherAlgorithm::Aes, KeyLength::S256).unwrap();
        assert_eq!(kpi.len(), 32);
    }

    #[test]
    fn kpi_desede_is_16_bytes() {
        let key = CanKey::new("123456").unwrap();
        let kpi = key.kpi(CipherAlgorithm::DeSede, KeyLength::S128).unwrap();
        assert_eq!(kpi.len(), 16);
    }
}
