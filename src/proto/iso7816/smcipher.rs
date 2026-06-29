//! Secure Messaging cipher trait.
//!
//! Concrete implementations (`DesSmCipher`, `AesSmCipher`, …) wrap the block
//! cipher and MAC primitives used to protect/unprotect APDUs under secure
//! messaging. Each cipher carries a [`CipherAlgorithm`] tag and exposes
//! encrypt / decrypt / mac primitives.

use crate::lds::asn1_object_identifiers::CipherAlgorithm;
use crate::proto::ssc::Ssc;

/// Abstract SM cipher — mirrors the `SMCipher` class.
pub trait SmCipher {
    /// Returns the algorithm family of this cipher.
    fn cipher_algorithm(&self) -> CipherAlgorithm;

    /// Encrypts `data` for a Secure Messaging payload.
    ///
    /// `data` must already be padded as required by the concrete cipher.
    /// `ssc` is consumed as the IV where applicable.
    fn encrypt(&self, data: &[u8], ssc: Option<&Ssc>) -> Vec<u8>;

    /// Decrypts `edata` from a Secure Messaging payload.
    ///
    /// The caller is responsible for any post-decryption unpadding. `ssc` is
    /// consumed as the IV where applicable.
    fn decrypt(&self, edata: &[u8], ssc: Option<&Ssc>) -> Vec<u8>;

    /// Computes the MAC of `data` using this cipher's MAC primitive.
    ///
    /// `data` must already be padded as required.
    fn mac(&self, data: &[u8]) -> Vec<u8>;
}
