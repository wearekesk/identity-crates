//! 3DES Secure Messaging cipher.
//!
//! Used by BAC. 3DES SM uses a fixed all-zero IV for each encrypt / decrypt
//! (the SSC is folded into the MAC, not the cipher). MAC is ISO 9797-1
//! algorithm 3.

use crate::crypto::des::{DesError, DesedeCipher};
use crate::crypto::iso9797;
use crate::lds::asn1_object_identifiers::CipherAlgorithm;
use crate::proto::iso7816::sm::SmError;
use crate::proto::iso7816::smcipher::SmCipher;
use crate::proto::ssc::Ssc;

/// 3DES-based secure messaging cipher.
#[derive(Clone)]
pub struct DesSmCipher {
    pub mac_key: Vec<u8>,
    /// Encryption cipher built once at construction (3DES SM always uses a
    /// fixed all-zero IV), so the 3DES key is not re-validated/expanded on
    /// every transceive.
    enc_cipher: DesedeCipher,
}

impl DesSmCipher {
    /// Creates a new [`DesSmCipher`] with the given `K_enc` and `K_mac`.
    ///
    /// # Errors
    /// Returns [`DesError`] if `enc_key` or `mac_key` is not a valid 3DES /
    /// ISO 9797-1 MAC algorithm 3 key length (16 or 24 bytes).
    pub fn new(enc_key: impl AsRef<[u8]>, mac_key: impl Into<Vec<u8>>) -> Result<Self, DesError> {
        let iv = [0u8; DesedeCipher::BLOCK_SIZE];
        let mac_key = mac_key.into();
        // The MAC key feeds ISO 9797-1 MAC algorithm 3, which (like 3DES) only
        // accepts 16- or 24-byte keys. Validate it up front so an invalid SM
        // session fails fast at construction rather than on the first MAC.
        if mac_key.len() != iso9797::MAC_ALG3_KEY1_LEN
            && mac_key.len() != iso9797::MAC_ALG3_KEY2_LEN
        {
            return Err(DesError::InvalidDesedeKeyLength(mac_key.len()));
        }
        Ok(Self {
            mac_key,
            enc_cipher: DesedeCipher::new(enc_key.as_ref(), &iv)?,
        })
    }
}

impl SmCipher for DesSmCipher {
    fn cipher_algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::DeSede
    }

    fn encrypt(&self, data: &[u8], _ssc: Option<&Ssc>) -> Result<Vec<u8>, SmError> {
        self.enc_cipher
            .encrypt(data, false)
            .map_err(|e| SmError(format!("DES encrypt: {e}")))
    }

    fn decrypt(&self, edata: &[u8], _ssc: Option<&Ssc>) -> Result<Vec<u8>, SmError> {
        self.enc_cipher
            .decrypt(edata, false)
            .map_err(|e| SmError(format!("DES decrypt: {e}")))
    }

    fn mac(&self, data: &[u8]) -> Result<Vec<u8>, SmError> {
        iso9797::mac_alg3(&self.mac_key, data, false)
            .map_err(|e| SmError(format!("ISO 9797-1 MAC alg 3: {e}")))
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
            hex::decode("7962D9ECE03D1ACD4C76089DCE131543").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn algorithm_is_desede() {
        assert_eq!(k().cipher_algorithm(), CipherAlgorithm::DeSede);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let c = k();
        let pt = vec![0xAAu8; 16];
        let ct = c.encrypt(&pt, None).unwrap();
        let pt2 = c.decrypt(&ct, None).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn mac_is_8_bytes() {
        let c = k();
        let mac = c.mac(&[0u8; 8]).unwrap();
        assert_eq!(mac.len(), 8);
    }

    #[test]
    fn new_rejects_wrong_mac_key_length() {
        // Valid 16-byte enc key but an invalid 8-byte MAC key must be rejected.
        let enc = hex::decode("AB94FDECF2674FDFB9B391F85D7F76F2").unwrap();
        let bad_mac = vec![0u8; 8];
        assert!(matches!(
            DesSmCipher::new(enc, bad_mac),
            Err(DesError::InvalidDesedeKeyLength(8))
        ));
    }
}
