//! DES and Triple-DES (DESede) cipher implementations.
//!
//! Implements DES and 3DES encryption/decryption in CBC block cipher mode,
//! and standalone ECB block operations, mirroring the `DESCipher` and
//! `DESedeCipher` classes.
//!
//! Uses RustCrypto crates:
//! - [`des`] for the block cipher primitives
//! - [`cbc`] for CBC mode
//!
//! # Key sizes
//! | Type          | Key length(s)         |
//! |---------------|-----------------------|
//! | `DESCipher`   | 8 bytes               |
//! | `DESedeCipher`| 16 or 24 bytes        |
//!
//! # IV
//! Both ciphers use an 8-byte IV (one DES block).

use crate::crypto::iso9797::{DES_BLOCK_SIZE, pad, unpad};
use cbc::cipher::block_padding::NoPadding;
use cipher::{
    Array, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyInit,
    KeyIvInit,
};
use des::{Des, TdesEde3};
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
// DESCipher  (single DES, CBC mode)
// ---------------------------------------------------------------------------

/// Implements single-DES encryption and decryption in CBC block cipher mode.
///
/// # Key / IV size
/// Both key and IV must be exactly 8 bytes (`DES_BLOCK_SIZE`).
///
/// # Padding
/// By default, data is padded / unpadded using ISO/IEC 9797-1 Method 2
/// (append `0x80` then zero bytes).  Pass `pad_data: false` / `padded_data:
/// false` to skip padding.
///
/// # Examples
/// ```
/// use dmrtd::crypto::des::DesCipher;
///
/// let key = [0x01u8; 8];
/// let iv  = [0x00u8; 8];
/// let cipher = DesCipher::new(&key, &iv).unwrap();
///
/// let plaintext = b"Hello!!!"; // 8 bytes – exactly one block
/// let encrypted = cipher.encrypt(plaintext, false).unwrap();
/// assert_eq!(encrypted.len(), 8);
///
/// let decrypted = cipher.decrypt(&encrypted, false).unwrap();
/// assert_eq!(&decrypted, plaintext);
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DesCipher {
    key: [u8; DES_BLOCK_SIZE],
    iv: [u8; DES_BLOCK_SIZE],
}

impl DesCipher {
    /// Block size for DES (8 bytes / 64 bits).
    pub const BLOCK_SIZE: usize = DES_BLOCK_SIZE;

    /// Creates a new [`DesCipher`] with the given `key` and initial vector `iv`.
    ///
    /// # Errors
    /// Returns [`DesError::InvalidKeyLength`] if `key.len() != 8`.
    /// Returns [`DesError::InvalidIvLength`]  if `iv.len()  != 8`.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, DesError> {
        if key.len() != DES_BLOCK_SIZE {
            return Err(DesError::InvalidKeyLength(key.len()));
        }
        if iv.len() != DES_BLOCK_SIZE {
            return Err(DesError::InvalidIvLength(iv.len()));
        }
        let mut k = [0u8; DES_BLOCK_SIZE];
        let mut v = [0u8; DES_BLOCK_SIZE];
        k.copy_from_slice(key);
        v.copy_from_slice(iv);
        Ok(Self { key: k, iv: v })
    }

    /// Returns the current key.
    pub fn key(&self) -> &[u8; DES_BLOCK_SIZE] {
        &self.key
    }

    /// Sets a new 8-byte key.
    ///
    /// # Errors
    /// Returns [`DesError::InvalidKeyLength`] if `key.len() != 8`.
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), DesError> {
        if key.len() != DES_BLOCK_SIZE {
            return Err(DesError::InvalidKeyLength(key.len()));
        }
        self.key.copy_from_slice(key);
        Ok(())
    }

    /// Returns the current IV.
    pub fn iv(&self) -> &[u8; DES_BLOCK_SIZE] {
        &self.iv
    }

    /// Sets a new 8-byte IV.
    ///
    /// # Errors
    /// Returns [`DesError::InvalidIvLength`] if `iv.len() != 8`.
    pub fn set_iv(&mut self, iv: &[u8]) -> Result<(), DesError> {
        if iv.len() != DES_BLOCK_SIZE {
            return Err(DesError::InvalidIvLength(iv.len()));
        }
        self.iv.copy_from_slice(iv);
        Ok(())
    }

    /// Encrypts `data` using single DES in CBC mode.
    ///
    /// If `pad_data` is `true`, `data` is padded with ISO/IEC 9797-1 Method 2
    /// before encryption.  Otherwise `data` must already be a multiple of 8 bytes.
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
        Ok(cbc_encrypt_single_des(&self.key, &self.iv, input))
    }

    /// Decrypts `edata` using single DES in CBC mode.
    ///
    /// If `padded_data` is `true`, the padding inserted during encryption is
    /// removed from the decrypted plaintext.
    ///
    /// # Errors
    /// Returns [`DesError::InvalidDataLength`] if `edata.len()` is not a
    /// multiple of 8. When `padded_data` is `true`, also returns
    /// [`DesError::Iso9797`] if the decrypted plaintext is not valid ISO/IEC
    /// 9797-1 Method 2 padding.
    pub fn decrypt(&self, edata: &[u8], padded_data: bool) -> Result<Vec<u8>, DesError> {
        if edata.len() % DES_BLOCK_SIZE != 0 {
            return Err(DesError::InvalidDataLength(edata.len()));
        }
        let plain = cbc_decrypt_single_des(&self.key, &self.iv, edata);
        if padded_data {
            Ok(unpad(&plain, DES_BLOCK_SIZE)?.to_vec())
        } else {
            Ok(plain)
        }
    }

    /// Encrypts a single block of exactly 8 bytes using ECB mode (no IV, no padding).
    ///
    /// # Errors
    /// Returns [`DesError::InvalidBlockLength`] if `block.len() != 8`.
    pub fn encrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, DesError> {
        if block.len() != DES_BLOCK_SIZE {
            return Err(DesError::InvalidBlockLength(block.len()));
        }
        let cipher = Des::new_from_slice(&self.key).expect("valid DES key");
        let mut b = Array::try_from(block).expect("DES block");
        cipher.encrypt_block(&mut b);
        Ok(b.to_vec())
    }

    /// Decrypts a single block of exactly 8 bytes using ECB mode (no IV, no padding).
    ///
    /// # Errors
    /// Returns [`DesError::InvalidBlockLength`] if `eblock.len() != 8`.
    pub fn decrypt_block(&self, eblock: &[u8]) -> Result<Vec<u8>, DesError> {
        if eblock.len() != DES_BLOCK_SIZE {
            return Err(DesError::InvalidBlockLength(eblock.len()));
        }
        let cipher = Des::new_from_slice(&self.key).expect("valid DES key");
        let mut b = Array::try_from(eblock).expect("DES block");
        cipher.decrypt_block(&mut b);
        Ok(b.to_vec())
    }
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
/// # Examples
/// ```
/// use dmrtd::crypto::des::DesedeCipher;
///
/// let key = [0x01u8; 16]; // 16-byte key
/// let iv  = [0x00u8; 8];
/// let cipher = DesedeCipher::new(&key, &iv).unwrap();
///
/// let plaintext = b"Hello!!!"; // 8 bytes – exactly one block
/// let encrypted = cipher.encrypt(plaintext, false).unwrap();
/// assert_eq!(encrypted.len(), 8);
///
/// let decrypted = cipher.decrypt(&encrypted, false).unwrap();
/// assert_eq!(&decrypted, plaintext);
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DesedeCipher {
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

    /// Sets a new key (16 or 24 bytes).
    ///
    /// # Errors
    /// Returns [`DesError::InvalidDesedeKeyLength`] if key length is not 16 or 24.
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), DesError> {
        self.triple_key = TripleDesKey::from_slice(key)?;
        Ok(())
    }

    /// Sets a new 8-byte IV.
    ///
    /// # Errors
    /// Returns [`DesError::InvalidIvLength`] if `iv.len() != 8`.
    pub fn set_iv(&mut self, iv: &[u8]) -> Result<(), DesError> {
        if iv.len() != DES_BLOCK_SIZE {
            return Err(DesError::InvalidIvLength(iv.len()));
        }
        self.iv.copy_from_slice(iv);
        Ok(())
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

    /// Encrypts a single 8-byte block using 3DES in ECB mode.
    ///
    /// # Errors
    /// Returns [`DesError::InvalidBlockLength`] if `block.len() != 8`.
    pub fn encrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, DesError> {
        if block.len() != DES_BLOCK_SIZE {
            return Err(DesError::InvalidBlockLength(block.len()));
        }
        Ok(ecb_encrypt_3des(&self.triple_key.0, block))
    }

    /// Decrypts a single 8-byte block using 3DES in ECB mode.
    ///
    /// # Errors
    /// Returns [`DesError::InvalidBlockLength`] if `eblock.len() != 8`.
    pub fn decrypt_block(&self, eblock: &[u8]) -> Result<Vec<u8>, DesError> {
        if eblock.len() != DES_BLOCK_SIZE {
            return Err(DesError::InvalidBlockLength(eblock.len()));
        }
        Ok(ecb_decrypt_3des(&self.triple_key.0, eblock))
    }
}

// ---------------------------------------------------------------------------
// Free-function API  (mirrors top-level functions DESedeEncrypt / DESedeDecrypt)
// ---------------------------------------------------------------------------

/// Encrypts `data` using Triple-DES in CBC mode.
///
/// # Arguments
/// - `key`      – 16 or 24-byte key.
/// - `iv`       – 8-byte initialisation vector.
/// - `data`     – Plaintext to encrypt.
/// - `pad_data` – When `true`, `data` is padded with ISO/IEC 9797-1 Method 2.
///
/// # Errors
/// See [`DesedeCipher::encrypt`].
///
/// # Examples
/// ```
/// use dmrtd::crypto::des::desede_encrypt;
///
/// let key = [0x01u8; 16];
/// let iv  = [0x00u8; 8];
/// let ct  = desede_encrypt(&key, &iv, b"Hello!!!", false).unwrap();
/// assert_eq!(ct.len(), 8);
/// ```
pub fn desede_encrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    pad_data: bool,
) -> Result<Vec<u8>, DesError> {
    DesedeCipher::new(key, iv)?.encrypt(data, pad_data)
}

/// Decrypts `edata` using Triple-DES in CBC mode.
///
/// # Arguments
/// - `key`         – 16 or 24-byte key.
/// - `iv`          – 8-byte initialisation vector.
/// - `edata`       – Ciphertext to decrypt.
/// - `padded_data` – When `true`, ISO/IEC 9797-1 Method 2 padding is stripped.
///
/// # Errors
/// See [`DesedeCipher::decrypt`].
///
/// # Examples
/// ```
/// use dmrtd::crypto::des::{desede_encrypt, desede_decrypt};
///
/// let key = [0x01u8; 16];
/// let iv  = [0x00u8; 8];
/// let ct = desede_encrypt(&key, &iv, b"Hello!!!", false).unwrap();
/// let pt = desede_decrypt(&key, &iv, &ct, false).unwrap();
/// assert_eq!(&pt, b"Hello!!!");
/// ```
pub fn desede_decrypt(
    key: &[u8],
    iv: &[u8],
    edata: &[u8],
    padded_data: bool,
) -> Result<Vec<u8>, DesError> {
    DesedeCipher::new(key, iv)?.decrypt(edata, padded_data)
}

// ---------------------------------------------------------------------------
// Low-level block cipher helpers
// ---------------------------------------------------------------------------

/// Single-DES CBC encrypt.  `data` must be block-aligned.
fn cbc_encrypt_single_des(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    // `data` is block-aligned by the caller, so `NoPadding` is a no-op and the
    // CBC chaining is delegated to the vetted `cbc` crate.
    cbc::Encryptor::<Des>::new_from_slices(key, iv)
        .expect("valid DES key/iv")
        .encrypt_padded_vec::<NoPadding>(data)
}

/// Single-DES CBC decrypt.  `data` must be block-aligned.
fn cbc_decrypt_single_des(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    cbc::Decryptor::<Des>::new_from_slices(key, iv)
        .expect("valid DES key/iv")
        .decrypt_padded_vec::<NoPadding>(data)
        .expect("CBC NoPadding decrypt of block-aligned data is infallible")
}

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

/// 3DES ECB encrypt – single block.
fn ecb_encrypt_3des(key: &[u8; 24], block: &[u8]) -> Vec<u8> {
    let cipher = TdesEde3::new_from_slice(key).expect("valid 3DES key");
    let mut ga = Array::try_from(block).expect("3DES block");
    cipher.encrypt_block(&mut ga);
    ga.to_vec()
}

/// 3DES ECB decrypt – single block.
fn ecb_decrypt_3des(key: &[u8; 24], block: &[u8]) -> Vec<u8> {
    let cipher = TdesEde3::new_from_slice(key).expect("valid 3DES key");
    let mut ga = Array::try_from(block).expect("3DES block");
    cipher.decrypt_block(&mut ga);
    ga.to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // DesCipher
    // -----------------------------------------------------------------------

    #[test]
    fn des_roundtrip_no_padding() {
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let iv = [0x00u8; 8];
        let cipher = DesCipher::new(&key, &iv).unwrap();

        let plaintext = b"TESTDATA"; // exactly 8 bytes
        let ct = cipher.encrypt(plaintext, false).unwrap();
        assert_eq!(ct.len(), 8);

        let pt = cipher.decrypt(&ct, false).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn des_roundtrip_with_padding() {
        let key = [0x01u8; 8];
        let iv = [0x00u8; 8];
        let cipher = DesCipher::new(&key, &iv).unwrap();

        let plaintext = b"HELLO";
        let ct = cipher.encrypt(plaintext, true).unwrap();
        assert_eq!(ct.len(), 8); // padded to 8 bytes

        let pt = cipher.decrypt(&ct, true).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn des_encrypt_block_roundtrip() {
        let key = [0x01u8; 8];
        let iv = [0x00u8; 8];
        let cipher = DesCipher::new(&key, &iv).unwrap();

        let block = [0xAA; 8];
        let enc = cipher.encrypt_block(&block).unwrap();
        let dec = cipher.decrypt_block(&enc).unwrap();
        assert_eq!(dec, block);
    }

    #[test]
    fn des_invalid_key_length() {
        assert!(matches!(
            DesCipher::new(&[0u8; 7], &[0u8; 8]),
            Err(DesError::InvalidKeyLength(7))
        ));
    }

    #[test]
    fn des_invalid_iv_length() {
        assert!(matches!(
            DesCipher::new(&[0u8; 8], &[0u8; 7]),
            Err(DesError::InvalidIvLength(7))
        ));
    }

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

    #[test]
    fn desede_encrypt_block_roundtrip() {
        let key = [0x04u8; 16];
        let iv = [0x00u8; 8];
        let cipher = DesedeCipher::new(&key, &iv).unwrap();

        let block = [0xCCu8; 8];
        let enc = cipher.encrypt_block(&block).unwrap();
        let dec = cipher.decrypt_block(&enc).unwrap();
        assert_eq!(dec, block);
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

        let eifd = desede_encrypt(&kenc, &[0u8; 8], &s, false).unwrap();
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

        let r = desede_decrypt(&kenc, &[0u8; 8], &eicc, false).unwrap();
        assert_eq!(r, expected_r);
    }

    // -----------------------------------------------------------------------
    // free functions
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Zeroize-on-drop
    // -----------------------------------------------------------------------

    /// Compile-level proof that the cipher key material is wiped on drop:
    /// both ciphers implement [`ZeroizeOnDrop`] and can be constructed and
    /// dropped without disturbing the cbc/cipher usage.
    #[test]
    fn ciphers_zeroize_on_drop() {
        use zeroize::Zeroize;
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<DesCipher>();
        assert_zod::<DesedeCipher>();

        // Construct and drop; also verify explicit zeroize clears the key.
        let mut des = DesCipher::new(&[0xABu8; 8], &[0x00u8; 8]).unwrap();
        des.zeroize();
        assert_eq!(des.key(), &[0u8; 8]);
        drop(des);

        let dede = DesedeCipher::new(&[0xCDu8; 16], &[0x00u8; 8]).unwrap();
        drop(dede);
    }

    #[test]
    fn free_functions_roundtrip() {
        let key = [0xAAu8; 16];
        let iv = [0x00u8; 8];
        let plain = [0x01u8; 8];
        let ct = desede_encrypt(&key, &iv, &plain, false).unwrap();
        let pt = desede_decrypt(&key, &iv, &ct, false).unwrap();
        assert_eq!(pt, plain);
    }
}
