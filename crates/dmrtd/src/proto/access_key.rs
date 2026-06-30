//! Abstract access-key trait.
//!
//! An [`AccessKey`] is the chip-facing identifier used by BAC or PACE: either
//! a [`DBAKey`](crate::proto::dba_key::DBAKey) derived from the
//! MRZ or a [`CanKey`](crate::proto::can_key::CanKey) derived from
//! the 6-digit CAN printed on the document.

use crate::lds::asn1_object_identifiers::{CipherAlgorithm, KeyLength};

/// ISO 9303 p11 §4.4.4.1 `MSE:Set AT` reference tag — MRZ (DBA) key.
pub const PACE_REF_KEY_TAG_MRZ: u8 = 0x01;
/// ISO 9303 p11 §4.4.4.1 `MSE:Set AT` reference tag — CAN key.
pub const PACE_REF_KEY_TAG_CAN: u8 = 0x02;

/// Access key used by BAC / PACE.
pub trait AccessKey {
    /// Returns the reference-key tag transmitted in `MSE:Set AT`
    /// (`0x01` = MRZ, `0x02` = CAN).
    fn pace_ref_key_tag(&self) -> u8;

    /// Derives the PACE `K_π` key for the given cipher algorithm and key
    /// length.
    ///
    /// # Errors
    /// Returns `Err(String)` when the combination of `cipher_algorithm` and
    /// `key_length` is not supported.
    fn kpi(
        &self,
        cipher_algorithm: CipherAlgorithm,
        key_length: KeyLength,
    ) -> Result<Vec<u8>, String>;
}
