//! AES Secure Messaging cipher.
//!
//! Used by PACE. The IV for each encrypt / decrypt is derived by
//! ECB-encrypting the SSC with `K_enc`. MAC is AES-CMAC truncated to 8 bytes
//! ([`crypto::aes::AesCipher::calculate_cmac`]).

use crate::crypto::aes::{AesCipher, BlockCipherMode, KeyLength};
use crate::lds::asn1_object_identifiers::CipherAlgorithm;
use crate::proto::iso7816::sm::SmError;
use crate::proto::iso7816::smcipher::SmCipher;
use crate::proto::ssc::Ssc;

/// AES-based secure messaging cipher.
#[derive(Clone)]
pub struct AesSmCipher {
    pub ks_enc: Vec<u8>,
    pub ks_mac: Vec<u8>,
    cipher: AesCipher,
}

impl AesSmCipher {
    /// Creates a new AES SM cipher for the given key size.
    pub fn new(
        ks_enc: impl Into<Vec<u8>>,
        ks_mac: impl Into<Vec<u8>>,
        size: KeyLength,
    ) -> Self {
        Self {
            ks_enc: ks_enc.into(),
            ks_mac: ks_mac.into(),
            cipher: AesCipher::new(size),
        }
    }

    fn iv_from_ssc(&self, ssc: &Ssc) -> Result<Vec<u8>, SmError> {
        // IV = E(K_enc, SSC)  using ECB (one block).
        self.cipher
            .encrypt(&ssc.to_bytes(), &self.ks_enc, None, BlockCipherMode::Ecb, false)
            .map_err(|e| SmError(format!("AES ECB of SSC for IV: {e}")))
    }
}

impl SmCipher for AesSmCipher {
    fn cipher_algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Aes
    }

    fn encrypt(&self, data: &[u8], ssc: Option<&Ssc>) -> Result<Vec<u8>, SmError> {
        let ssc = ssc.ok_or_else(|| SmError("AES SM encrypt requires SSC".into()))?;
        let iv = self.iv_from_ssc(ssc)?;
        self.cipher
            .encrypt(data, &self.ks_enc, Some(&iv), BlockCipherMode::Cbc, false)
            .map_err(|e| SmError(format!("AES CBC encrypt: {e}")))
    }

    fn decrypt(&self, edata: &[u8], ssc: Option<&Ssc>) -> Result<Vec<u8>, SmError> {
        let ssc = ssc.ok_or_else(|| SmError("AES SM decrypt requires SSC".into()))?;
        let iv = self.iv_from_ssc(ssc)?;
        self.cipher
            .decrypt(edata, &self.ks_enc, Some(&iv), BlockCipherMode::Cbc)
            .map_err(|e| SmError(format!("AES CBC decrypt: {e}")))
    }

    fn mac(&self, data: &[u8]) -> Result<Vec<u8>, SmError> {
        self.cipher
            .calculate_cmac(data, &self.ks_mac)
            .map_err(|e| SmError(format!("AES CMAC: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build() -> AesSmCipher {
        AesSmCipher::new([0x11u8; 16], [0x22u8; 16], KeyLength::S128)
    }

    fn ssc() -> Ssc {
        Ssc::new(&[0x01], 128).unwrap()
    }

    #[test]
    fn algorithm_is_aes() {
        assert_eq!(build().cipher_algorithm(), CipherAlgorithm::Aes);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let c = build();
        let s = ssc();
        let pt = vec![0x55u8; 32];
        let ct = c.encrypt(&pt, Some(&s)).unwrap();
        let pt2 = c.decrypt(&ct, Some(&s)).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn different_ssc_yields_different_ciphertext() {
        let c = build();
        let s1 = Ssc::new(&[0x01], 128).unwrap();
        let s2 = Ssc::new(&[0x02], 128).unwrap();
        let pt = vec![0x55u8; 16];
        assert_ne!(
            c.encrypt(&pt, Some(&s1)).unwrap(),
            c.encrypt(&pt, Some(&s2)).unwrap()
        );
    }

    #[test]
    fn mac_is_8_bytes() {
        let c = build();
        let mac = c.mac(&[0u8; 16]).unwrap();
        assert_eq!(mac.len(), 8);
    }

    #[test]
    fn encrypt_without_ssc_errors() {
        let c = build();
        let err = c.encrypt(&[0u8; 16], None).unwrap_err();
        assert!(err.0.contains("requires SSC"));
    }
}
