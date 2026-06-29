//! Triple-DES (DESede) cipher implementation.
//!
//! Implements 3DES encryption/decryption in CBC block cipher mode, used
//! internally by BAC and the DES secure-messaging cipher. This is a
//! crate-internal primitive (`pub(crate)`), not part of the public API.
//!
//! Uses RustCrypto crates:
//! - [`des`] for the block cipher primitives
//! - [`cbc`] for CBC mode
//!
//! # Key sizes
//! [`DesedeCipher`] accepts a 16- or 24-byte key.
//!
//! # IV
//! The cipher uses an 8-byte IV (one DES block).

use crate::crypto::iso9797::{pad, unpad, DES_BLOCK_SIZE};
use cbc::cipher::block_padding::NoPadding;
use cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use des::TdesEde3;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error type for DES/3DES cipher operations.
#[derive(Debug, Error)]
pub enum DesError {
    #[error("DES key length must be {DES_BLOCK_SIZE} bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("DESede key length must be 16 or 24 bytes, got {0}")]
    InvalidDesedeKeyLength(usize),

    #[error("DES IV length must be {DES_BLOCK_SIZE} bytes, got {0}")]
    InvalidIvLength(usize),

    #[error("DES data length must be a multiple of {DES_BLOCK_SIZE} bytes, got {0}")]
    InvalidDataLength(usize),

    #[error("DES block length must be exactly {DES_BLOCK_SIZE} bytes, got {0}")]
    InvalidBlockLength(usize),

    #[error(transparent)]
    Iso9797(#[from] crate::crypto::iso9797::Iso9797Error),
}

// ---------------------------------------------------------------------------
// DESedeCipher  (Triple-DES, CBC mode)
// ---------------------------------------------------------------------------

/// The expanded 24-byte 3DES key (three independent 8-byte sub-keys).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct TripleDesKey([u8; 24]);

impl TripleDesKey {
    /// Expands a 16- or 24-byte key into the internal 24-byte representation.
    ///
    /// | Input length | Keying option | Expansion rule          |
    /// |-------------|---------------|-------------------------|
    /// | 16 bytes    | Option 2      | `Ka || Kb || Ka`         |
    /// | 24 bytes    | Option 1      | `Ka || Kb || Kc` (as-is) |
    ///
    /// 8-byte keys are intentionally rejected: silently expanding `Ka || Ka ||
    /// Ka` would downgrade 3DES to single DES.
    fn from_slice(key: &[u8]) -> Result<Self, DesError> {
        let mut expanded = [0u8; 24];
        match key.len() {
            16 => {
                expanded[0..8].copy_from_slice(&key[0..8]);
                expanded[8..16].copy_from_slice(&key[8..16]);
                expanded[16..24].copy_from_slice(&key[0..8]); // Ka repeated
            }
            24 => {
                expanded.copy_from_slice(key);
            }
            n => return Err(DesError::InvalidDesedeKeyLength(n)),
        }
        Ok(Self(expanded))
    }
}

/// Implements Triple-DES (DESede) encryption and decryption in CBC block cipher mode.
///
/// # Key sizes
/// - 16 bytes → keying option 2 (Ka, Kb, Ka)
/// - 24 bytes → keying option 1 (Ka, Kb, Kc)
///
/// # IV
/// Must be exactly 8 bytes.
///
/// # Padding
/// By default, data is padded / unpadded using ISO/IEC 9797-1 Method 2.
///
/// # Usage
/// Construct with [`DesedeCipher::new`] (16- or 24-byte key, 8-byte IV), then
/// call [`encrypt`](DesedeCipher::encrypt) / [`decrypt`](DesedeCipher::decrypt)
/// for CBC mode. This is a crate-internal primitive; see the unit tests for
/// worked round-trips.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct DesedeCipher {
    triple_key: TripleDesKey,
    iv: [u8; DES_BLOCK_SIZE],
}

impl DesedeCipher {
    /// Block size (same as DES – 8 bytes).
    pub const BLOCK_SIZE: usize = DES_BLOCK_SIZE;

    /// Creates a new [`DesedeCipher`] with the given `key` and `iv`.
    ///
    /// # Errors
    /// Returns [`DesError::InvalidDesedeKeyLength`] if key length is not 16 or 24.
    /// Returns [`DesError::InvalidIvLength`] if `iv.len() != 8`.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, DesError> {
        if iv.len() != DES_BLOCK_SIZE {
            return Err(DesError::InvalidIvLength(iv.len()));
        }
        let triple_key = TripleDesKey::from_slice(key)?;
        let mut v = [0u8; DES_BLOCK_SIZE];
        v.copy_from_slice(iv);
        Ok(Self { triple_key, iv: v })
    }

    /// Encrypts `data` using 3DES in CBC mode.
    ///
    /// If `pad_data` is `true`, `data` is padded with ISO/IEC 9797-1 Method 2.
    ///
    /// # Errors
    /// Returns [`DesError::InvalidDataLength`] if `pad_data` is `false` and
    /// `data.len()` is not a multiple of 8.
    pub fn encrypt(&self, data: &[u8], pad_data: bool) -> Result<Vec<u8>, DesError> {
        let owned;
        let input: &[u8] = if pad_data {
            owned = pad(data, DES_BLOCK_SIZE)?;
            &owned
        } else {
            data
        };
        if input.len() % DES_BLOCK_SIZE != 0 {
            return Err(DesError::InvalidDataLength(input.len()));
        }
        Ok(cbc_encrypt_3des(&self.triple_key.0, &self.iv, input))
    }

    /// Decrypts `edata` using 3DES in CBC mode.
    ///
    /// If `padded_data` is `true`, ISO/IEC 9797-1 Method 2 padding is stripped.
    ///
    /// # Errors
    /// Returns [`DesError::InvalidDataLength`] if `edata.len()` is not a multiple of 8.
    /// When `padded_data` is `true`, also returns [`DesError::Iso9797`] if the
    /// decrypted plaintext is not valid ISO/IEC 9797-1 Method 2 padding.
    pub fn decrypt(&self, edata: &[u8], padded_data: bool) -> Result<Vec<u8>, DesError> {
        if edata.len() % DES_BLOCK_SIZE != 0 {
            return Err(DesError::InvalidDataLength(edata.len()));
        }
        let plain = cbc_decrypt_3des(&self.triple_key.0, &self.iv, edata);
        if padded_data {
            Ok(unpad(&plain, DES_BLOCK_SIZE)?.to_vec())
        } else {
            Ok(plain)
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level block cipher helpers
// ---------------------------------------------------------------------------

/// 3DES CBC encrypt (EDE order: Ka-enc, Kb-dec, Kc-enc).  `data` must be block-aligned.
///
/// The 24-byte `key` is laid out as `[Ka(8) | Kb(8) | Kc(8)]`.
fn cbc_encrypt_3des(key: &[u8; 24], iv: &[u8], data: &[u8]) -> Vec<u8> {
    cbc::Encryptor::<TdesEde3>::new_from_slices(key, iv)
        .expect("valid 3DES key/iv")
        .encrypt_padded_vec::<NoPadding>(data)
}

/// 3DES CBC decrypt.  `data` must be block-aligned.
fn cbc_decrypt_3des(key: &[u8; 24], iv: &[u8], data: &[u8]) -> Vec<u8> {
    cbc::Decryptor::<TdesEde3>::new_from_slices(key, iv)
        .expect("valid 3DES key/iv")
        .decrypt_padded_vec::<NoPadding>(data)
        .expect("CBC NoPadding decrypt of block-aligned data is infallible")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // DesedeCipher – key expansion
    // -----------------------------------------------------------------------

    #[test]
    fn desede_rejects_8_byte_key() {
        // An 8-byte key is rejected: silently expanding K||K||K would downgrade
        // 3DES to single DES.
        let k8 = [0xAAu8; 8];
        assert!(matches!(
            TripleDesKey::from_slice(&k8),
            Err(DesError::InvalidDesedeKeyLength(8))
        ));
    }

    #[test]
    fn desede_expands_16_byte_key_correctly() {
        let mut k16 = [0u8; 16];
        k16[0..8].copy_from_slice(&[0xAAu8; 8]);
        k16[8..16].copy_from_slice(&[0xBBu8; 8]);
        let t = TripleDesKey::from_slice(&k16).unwrap();
        assert_eq!(&t.0[0..8], &[0xAAu8; 8]);
        assert_eq!(&t.0[8..16], &[0xBBu8; 8]);
        assert_eq!(&t.0[16..24], &[0xAAu8; 8]); // Ka repeated
    }

    #[test]
    fn desede_invalid_key_length() {
        assert!(matches!(
            DesedeCipher::new(&[0u8; 10], &[0u8; 8]),
            Err(DesError::InvalidDesedeKeyLength(10))
        ));
    }

    // -----------------------------------------------------------------------
    // DesedeCipher – encrypt / decrypt
    // -----------------------------------------------------------------------

    #[test]
    fn desede_roundtrip_16_byte_key_no_padding() {
        let key = [0x01u8; 16];
        let iv = [0x00u8; 8];
        let cipher = DesedeCipher::new(&key, &iv).unwrap();

        let plaintext = b"Hello!!!";
        let ct = cipher.encrypt(plaintext, false).unwrap();
        assert_eq!(ct.len(), 8);

        let pt = cipher.decrypt(&ct, false).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_ref());
    }

    #[test]
    fn desede_roundtrip_24_byte_key_no_padding() {
        let key = [0x02u8; 24];
        let iv = [0x01u8; 8];
        let cipher = DesedeCipher::new(&key, &iv).unwrap();

        let plaintext = [0xABu8; 16]; // two blocks
        let ct = cipher.encrypt(&plaintext, false).unwrap();
        assert_eq!(ct.len(), 16);

        let pt = cipher.decrypt(&ct, false).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn desede_roundtrip_with_padding() {
        let key = [0x03u8; 16];
        let iv = [0x00u8; 8];
        let cipher = DesedeCipher::new(&key, &iv).unwrap();

        let plaintext = b"Hi";
        let ct = cipher.encrypt(plaintext, true).unwrap();
        assert_eq!(ct.len(), 8);

        let pt = cipher.decrypt(&ct, true).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_ref());
    }

    // -----------------------------------------------------------------------
    // ICAO 9303 Part 11 – Appendix D.1 BAC test vector
    // -----------------------------------------------------------------------

    /// Verify the 3DES-CBC encryption step from ICAO 9303 p11 Appendix D.1.
    ///
    /// Given:
    ///   Kenc  = AB94FDECF2674FDFB9B391F85D7F76F2
    ///   S     = 781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B
    ///   IV    = 00000000 00000000
    ///   Eifd  = 72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2
    #[test]
    fn desede_icao_d1_encrypt_vector() {
        let kenc = hex::decode("AB94FDECF2674FDFB9B391F85D7F76F2").unwrap();
        let s = hex::decode("781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B")
            .unwrap();
        let expected_eifd =
            hex::decode("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2")
                .unwrap();

        let eifd = DesedeCipher::new(&kenc, &[0u8; 8])
            .unwrap()
            .encrypt(&s, false)
            .unwrap();
        assert_eq!(eifd, expected_eifd);
    }

    /// Verify the 3DES-CBC decryption step from ICAO 9303 p11 Appendix D.3.
    ///
    /// Given:
    ///   Kenc  = AB94FDECF2674FDFB9B391F85D7F76F2
    ///   Eicc  = 46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F
    ///   R     = 4608F91988702212781723860C06C2260B4F80323EB3191CB04970CB4052790B
    #[test]
    fn desede_icao_d3_decrypt_vector() {
        let kenc = hex::decode("AB94FDECF2674FDFB9B391F85D7F76F2").unwrap();
        let eicc = hex::decode("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F")
            .unwrap();
        let expected_r =
            hex::decode("4608F91988702212781723860C06C2260B4F80323EB3191CB04970CB4052790B")
                .unwrap();

        let r = DesedeCipher::new(&kenc, &[0u8; 8])
            .unwrap()
            .decrypt(&eicc, false)
            .unwrap();
        assert_eq!(r, expected_r);
    }

    // -----------------------------------------------------------------------
    // Zeroize-on-drop
    // -----------------------------------------------------------------------

    /// Compile-level proof that the cipher key material is wiped on drop:
    /// [`DesedeCipher`] implements [`ZeroizeOnDrop`] and can be constructed and
    /// dropped without disturbing the cbc/cipher usage.
    #[test]
    fn cipher_zeroize_on_drop() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<DesedeCipher>();

        let dede = DesedeCipher::new(&[0xCDu8; 16], &[0x00u8; 8]).unwrap();
        drop(dede);
    }

    // -----------------------------------------------------------------------
    // Former doc example, preserved as a unit test after [`DesedeCipher`] was
    // narrowed to `pub(crate)` (its `use dmrtd::crypto::des::...` import can no
    // longer compile as a doctest).
    // -----------------------------------------------------------------------

    #[test]
    fn desedecipher_doc_example_roundtrip() {
        let key = [0x01u8; 16]; // 16-byte key
        let iv = [0x00u8; 8];
        let cipher = DesedeCipher::new(&key, &iv).unwrap();

        let plaintext = b"Hello!!!"; // 8 bytes – exactly one block
        let encrypted = cipher.encrypt(plaintext, false).unwrap();
        assert_eq!(encrypted.len(), 8);

        let decrypted = cipher.decrypt(&encrypted, false).unwrap();
        assert_eq!(&decrypted, plaintext);
    }
}
