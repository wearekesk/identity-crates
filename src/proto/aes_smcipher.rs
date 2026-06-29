//! AES Secure Messaging cipher.
//!
//! Used by PACE. The IV for each encrypt / decrypt is derived by
//! ECB-encrypting the SSC with `K_enc`. MAC is AES-CMAC truncated to 8 bytes
//! ([`crypto::aes::AesCipher::calculate_cmac`]).

use crate::crypto::aes::{AesCipher, BlockCipherMode, KeyLength};
use crate::lds::asn1_object_identifiers::CipherAlgorithm;
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

    fn iv_from_ssc(&self, ssc: &Ssc) -> Vec<u8> {
        // IV = E(K_enc, SSC)  using ECB (one block).
        self.cipher
            .encrypt(&ssc.to_bytes(), &self.ks_enc, None, BlockCipherMode::Ecb, false)
            .expect("AES ECB of SSC for IV")
    }
}

impl SmCipher for AesSmCipher {
    fn cipher_algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Aes
    }

    fn encrypt(&self, data: &[u8], ssc: Option<&Ssc>) -> Vec<u8> {
        let ssc = ssc.expect("AES SM encrypt requires SSC");
        let iv = self.iv_from_ssc(ssc);
        self.cipher
            .encrypt(data, &self.ks_enc, Some(&iv), BlockCipherMode::Cbc, false)
            .expect("AES CBC encrypt")
    }

    fn decrypt(&self, edata: &[u8], ssc: Option<&Ssc>) -> Vec<u8> {
        let ssc = ssc.expect("AES SM decrypt requires SSC");
        let iv = self.iv_from_ssc(ssc);
        self.cipher
            .decrypt(edata, &self.ks_enc, Some(&iv), BlockCipherMode::Cbc)
            .expect("AES CBC decrypt")
    }

    fn mac(&self, data: &[u8]) -> Vec<u8> {
        self.cipher
            .calculate_cmac(data, &self.ks_mac)
            .expect("AES CMAC")
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
        let ct = c.encrypt(&pt, Some(&s));
        let pt2 = c.decrypt(&ct, Some(&s));
        assert_eq!(pt2, pt);
    }

    #[test]
    fn different_ssc_yields_different_ciphertext() {
        let c = build();
        let s1 = Ssc::new(&[0x01], 128).unwrap();
        let s2 = Ssc::new(&[0x02], 128).unwrap();
        let pt = vec![0x55u8; 16];
        assert_ne!(c.encrypt(&pt, Some(&s1)), c.encrypt(&pt, Some(&s2)));
    }

    #[test]
    fn mac_is_8_bytes() {
        let c = build();
        let mac = c.mac(&[0u8; 16]);
        assert_eq!(mac.len(), 8);
    }

    #[test]
    #[should_panic(expected = "requires SSC")]
    fn encrypt_without_ssc_panics() {
        let c = build();
        let _ = c.encrypt(&[0u8; 16], None);
    }
}
