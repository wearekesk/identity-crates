//! 3DES Secure Messaging cipher.
//!
//! Used by BAC. 3DES SM uses a fixed all-zero IV for each encrypt / decrypt
//! (the SSC is folded into the MAC, not the cipher). MAC is ISO 9797-1
//! algorithm 3.

use crate::crypto::des::DesedeCipher;
use crate::crypto::iso9797;
use crate::lds::asn1_object_identifiers::CipherAlgorithm;
use crate::proto::iso7816::smcipher::SmCipher;
use crate::proto::ssc::Ssc;

/// 3DES-based secure messaging cipher.
#[derive(Clone)]
pub struct DesSmCipher {
    pub enc_key: Vec<u8>,
    pub mac_key: Vec<u8>,
}

impl DesSmCipher {
    /// Creates a new [`DesSmCipher`] with the given `K_enc` and `K_mac`.
    pub fn new(enc_key: impl Into<Vec<u8>>, mac_key: impl Into<Vec<u8>>) -> Self {
        Self {
            enc_key: enc_key.into(),
            mac_key: mac_key.into(),
        }
    }
}

impl SmCipher for DesSmCipher {
    fn cipher_algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::DeSede
    }

    fn encrypt(&self, data: &[u8], _ssc: Option<&Ssc>) -> Vec<u8> {
        let iv = [0u8; DesedeCipher::BLOCK_SIZE];
        let cipher = DesedeCipher::new(&self.enc_key, &iv).expect("valid DES key");
        cipher
            .encrypt(data, false)
            .expect("DES encrypt: block-aligned data")
    }

    fn decrypt(&self, edata: &[u8], _ssc: Option<&Ssc>) -> Vec<u8> {
        let iv = [0u8; DesedeCipher::BLOCK_SIZE];
        let cipher = DesedeCipher::new(&self.enc_key, &iv).expect("valid DES key");
        cipher
            .decrypt(edata, false)
            .expect("DES decrypt: block-aligned data")
    }

    fn mac(&self, data: &[u8]) -> Vec<u8> {
        iso9797::mac_alg3(&self.mac_key, data, false).expect("ISO 9797-1 MAC alg 3")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> DesSmCipher {
        DesSmCipher::new(
            hex::decode("AB94FDECF2674FDFB9B391F85D7F76F2").unwrap(),
            hex::decode("7862D9ECE03D1ACD4C76089DCE131543").unwrap(),
        )
    }

    #[test]
    fn algorithm_is_desede() {
        assert_eq!(k().cipher_algorithm(), CipherAlgorithm::DeSede);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let c = k();
        let pt = vec![0xAAu8; 16];
        let ct = c.encrypt(&pt, None);
        let pt2 = c.decrypt(&ct, None);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn mac_is_8_bytes() {
        let c = k();
        let mac = c.mac(&[0u8; 8]);
        assert_eq!(mac.len(), 8);
    }
}
