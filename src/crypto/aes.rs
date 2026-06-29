//! AES cipher implementation.
//!
//! Implements AES encryption/decryption in CBC and ECB block cipher modes,
//! and AES-based CMAC calculation (64-bit / 8-byte truncated output).
//!
//! Uses RustCrypto crates:
//! - [`aes`] for the block cipher primitives (Aes128, Aes192, Aes256)
//! - [`cmac`] for CMAC MAC calculation
//!
//! # Key sizes
//! | [`KeyLength`] | Byte size |
//! |---------------|-----------|
//! | `S128`        | 16 bytes  |
//! | `S192`        | 24 bytes  |
//! | `S256`        | 32 bytes  |
//!
//! # IV
//! AES IV must be exactly 16 bytes (one AES block). If not provided for CBC
//! mode, an all-zero IV is used automatically.
//!
//! # CMAC output
//! [`AesCipher::calculate_cmac`] returns 8 bytes (64 bits), truncated from the
//! standard 16-byte AES-CMAC output, matching the reference.

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::NoPadding;
use cipher::{
    Array, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyInit,
    KeyIvInit,
};
use cmac::Cmac;
use digest::Mac;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES block size in bytes (128 bits).
pub const AES_BLOCK_SIZE: usize = 16;

/// CMAC output length returned by [`AesCipher::calculate_cmac`] (64 bits).
pub const AES_CMAC_OUTPUT_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// AES key length selector.
///
/// Also used by `DeriveKey` in the KDF module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLength {
    /// 128-bit key (16 bytes).
    S128,
    /// 192-bit key (24 bytes).
    S192,
    /// 256-bit key (32 bytes).
    S256,
}

impl KeyLength {
    /// Returns the key size in bytes.
    pub fn byte_size(&self) -> usize {
        match self {
            KeyLength::S128 => 16,
            KeyLength::S192 => 24,
            KeyLength::S256 => 32,
        }
    }
}

/// Cipher algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    /// Triple-DES (DESede).
    DeSede,
    /// AES.
    Aes,
}

/// AES block cipher mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockCipherMode {
    /// Cipher Block Chaining mode (default).
    #[default]
    Cbc,
    /// Electronic Codebook mode.
    Ecb,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error type for AES cipher operations.
#[derive(Debug, Error)]
pub enum AesCipherError {
    #[error("AES{bits} key length must be {bytes} bytes, got {got}", bits = size * 8, bytes = size)]
    InvalidKeyLength { size: usize, got: usize },

    #[error("AES IV length must be {AES_BLOCK_SIZE} bytes, got {0}")]
    InvalidIvLength(usize),

    #[error("AES data length must be a multiple of {AES_BLOCK_SIZE} bytes, got {0}")]
    InvalidDataLength(usize),

    #[error("CMAC key is invalid: {0}")]
    CmacKeyError(String),

    #[error("AES block size must be greater than zero")]
    InvalidBlockSize,
}

// ---------------------------------------------------------------------------
// AesCipher
// ---------------------------------------------------------------------------

/// AES cipher supporting CBC and ECB modes, and CMAC calculation.
///
/// # Examples
/// ```
/// use dmrtd::crypto::aes::{AesCipher, KeyLength, BlockCipherMode};
///
/// let cipher = AesCipher::new(KeyLength::S128);
/// let key = [0x01u8; 16];
/// let iv  = [0x00u8; 16];
/// let plaintext = [0xABu8; 16]; // one block, no padding needed
///
/// let ct = cipher.encrypt(&plaintext, &key, Some(&iv), BlockCipherMode::Cbc, false).unwrap();
/// let pt = cipher.decrypt(&ct, &key, Some(&iv), BlockCipherMode::Cbc).unwrap();
/// assert_eq!(pt, plaintext);
/// ```
#[derive(Clone)]
pub struct AesCipher {
    key_size: usize,
}

impl AesCipher {
    /// Creates a new [`AesCipher`] for the given key length.
    pub fn new(key_length: KeyLength) -> Self {
        Self {
            key_size: key_length.byte_size(),
        }
    }

    /// Returns the expected key size in bytes.
    pub fn key_size(&self) -> usize {
        self.key_size
    }

    /// Encrypts `data` using AES in the given `mode`.
    ///
    /// # Arguments
    /// - `data`    – Plaintext bytes.
    /// - `key`     – Must be exactly [`key_size()`] bytes.
    /// - `iv`      – 16-byte IV. If `None` and mode is CBC, an all-zero IV is used.
    ///               Ignored for ECB mode.
    /// - `mode`    – [`BlockCipherMode::Cbc`] (default) or [`BlockCipherMode::Ecb`].
    /// - `padding` – If `true`, `data` is zero-padded to the next 16-byte boundary
    ///               before encryption. If `false`, `data` must already be a multiple
    ///               of 16 bytes.
    ///
    /// # Errors
    /// - [`AesCipherError::InvalidKeyLength`] if `key.len() != key_size`.
    /// - [`AesCipherError::InvalidIvLength`] if `iv` is `Some` and `iv.len() != 16`.
    /// - [`AesCipherError::InvalidDataLength`] if `padding` is `false` and
    ///   `data.len()` is not a multiple of 16.
    pub fn encrypt(
        &self,
        data: &[u8],
        key: &[u8],
        iv: Option<&[u8]>,
        mode: BlockCipherMode,
        padding: bool,
    ) -> Result<Vec<u8>, AesCipherError> {
        self.validate_key(key)?;

        let input = if padding {
            self.zero_pad(data, AES_BLOCK_SIZE)?
        } else {
            data.to_vec()
        };

        if input.len() % AES_BLOCK_SIZE != 0 {
            return Err(AesCipherError::InvalidDataLength(input.len()));
        }

        match mode {
            // The IV is only meaningful — and only validated — for CBC; ECB
            // ignores it entirely.
            BlockCipherMode::Cbc => {
                let iv_bytes = self.resolve_iv(iv)?;
                Ok(aes_cbc_encrypt(key, &iv_bytes, &input))
            }
            BlockCipherMode::Ecb => Ok(aes_ecb_encrypt(key, &input)),
        }
    }

    /// Decrypts `data` using AES in the given `mode`.
    ///
    /// # Arguments
    /// - `data` – Ciphertext bytes; must be a multiple of 16 bytes.
    /// - `key`  – Must be exactly [`key_size()`] bytes.
    /// - `iv`   – 16-byte IV. If `None` and mode is CBC, an all-zero IV is used.
    /// - `mode` – [`BlockCipherMode::Cbc`] or [`BlockCipherMode::Ecb`].
    ///
    /// # Errors
    /// See [`encrypt`].
    pub fn decrypt(
        &self,
        data: &[u8],
        key: &[u8],
        iv: Option<&[u8]>,
        mode: BlockCipherMode,
    ) -> Result<Vec<u8>, AesCipherError> {
        self.validate_key(key)?;

        if data.len() % AES_BLOCK_SIZE != 0 {
            return Err(AesCipherError::InvalidDataLength(data.len()));
        }

        match mode {
            // The IV is only meaningful — and only validated — for CBC; ECB
            // ignores it entirely.
            BlockCipherMode::Cbc => {
                let iv_bytes = self.resolve_iv(iv)?;
                Ok(aes_cbc_decrypt(key, &iv_bytes, data))
            }
            BlockCipherMode::Ecb => Ok(aes_ecb_decrypt(key, data)),
        }
    }

    /// Calculates the AES-CMAC of `data` using `key`, returning exactly 8 bytes
    /// (the first 8 bytes of the standard 16-byte AES-CMAC output — matches
    /// `CMac(BlockCipher('AES'), 64)`).
    ///
    /// # Errors
    /// - [`AesCipherError::InvalidKeyLength`] if `key.len() != key_size`.
    /// - [`AesCipherError::CmacKeyError`] if the CMAC initialisation fails.
    pub fn calculate_cmac(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, AesCipherError> {
        self.validate_key(key)?;
        compute_cmac_truncated(key, data).map_err(|e| AesCipherError::CmacKeyError(e.to_string()))
    }

    /// Zero-pads `data` to the next multiple of `block_size` bytes by appending
    /// `0x00` bytes (not ISO 9797-1 method 2).
    ///
    /// # Errors
    /// Returns [`AesCipherError::InvalidBlockSize`] if `block_size == 0`
    /// (instead of panicking, so misuse from the public API is recoverable).
    ///
    /// # Examples
    /// ```
    /// use dmrtd::crypto::aes::{AesCipher, KeyLength, AES_BLOCK_SIZE};
    ///
    /// let cipher = AesCipher::new(KeyLength::S128);
    /// let padded = cipher.zero_pad(&[0x01, 0x02, 0x03], AES_BLOCK_SIZE).unwrap();
    /// assert_eq!(padded.len(), AES_BLOCK_SIZE);
    /// assert_eq!(&padded[..3], &[0x01, 0x02, 0x03]);
    /// assert!(padded[3..].iter().all(|&b| b == 0));
    /// ```
    pub fn zero_pad(&self, data: &[u8], block_size: usize) -> Result<Vec<u8>, AesCipherError> {
        if block_size == 0 {
            return Err(AesCipherError::InvalidBlockSize);
        }
        let remainder = data.len() % block_size;
        if remainder == 0 {
            return Ok(data.to_vec());
        }
        let pad_len = block_size - remainder;
        let mut padded = data.to_vec();
        padded.resize(padded.len() + pad_len, 0);
        Ok(padded)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn validate_key(&self, key: &[u8]) -> Result<(), AesCipherError> {
        if key.len() != self.key_size {
            return Err(AesCipherError::InvalidKeyLength {
                size: self.key_size,
                got: key.len(),
            });
        }
        Ok(())
    }

    fn resolve_iv(&self, iv: Option<&[u8]>) -> Result<[u8; AES_BLOCK_SIZE], AesCipherError> {
        match iv {
            Some(v) => {
                if v.len() != AES_BLOCK_SIZE {
                    return Err(AesCipherError::InvalidIvLength(v.len()));
                }
                let mut arr = [0u8; AES_BLOCK_SIZE];
                arr.copy_from_slice(v);
                Ok(arr)
            }
            None => Ok([0u8; AES_BLOCK_SIZE]), // default zero IV (CBC or ignored for ECB)
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor (mirrors AESChiperSelector.getChiper)
// ---------------------------------------------------------------------------

/// Returns an [`AesCipher`] for the given key length.
///
/// # Examples
/// ```
/// use dmrtd::crypto::aes::{get_cipher, KeyLength, BlockCipherMode};
///
/// let cipher = get_cipher(KeyLength::S256);
/// assert_eq!(cipher.key_size(), 32);
/// ```
pub fn get_cipher(key_length: KeyLength) -> AesCipher {
    AesCipher::new(key_length)
}

// ---------------------------------------------------------------------------
// Low-level AES block operations (dispatch on key length)
// ---------------------------------------------------------------------------

/// Encrypts `data` using AES in CBC mode with the given `key` and `iv`.
///
/// `data` must be block-aligned. Dispatches to Aes128/Aes192/Aes256 based on
/// `key.len()`.
///
/// # Panics
/// Panics if `key.len()` is not 16, 24, or 32.
fn aes_cbc_encrypt(key: &[u8], iv: &[u8; AES_BLOCK_SIZE], data: &[u8]) -> Vec<u8> {
    // `data` is guaranteed block-aligned by the caller, so `NoPadding` adds
    // nothing — we delegate the CBC chaining to the vetted `cbc` crate.
    match key.len() {
        16 => cbc::Encryptor::<Aes128>::new_from_slices(key, iv)
            .expect("valid AES-128 key/iv")
            .encrypt_padded_vec::<NoPadding>(data),
        24 => cbc::Encryptor::<Aes192>::new_from_slices(key, iv)
            .expect("valid AES-192 key/iv")
            .encrypt_padded_vec::<NoPadding>(data),
        32 => cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
            .expect("valid AES-256 key/iv")
            .encrypt_padded_vec::<NoPadding>(data),
        n => panic!("Invalid AES key length: {n}"),
    }
}

/// Decrypts `data` using AES in CBC mode.
fn aes_cbc_decrypt(key: &[u8], iv: &[u8; AES_BLOCK_SIZE], data: &[u8]) -> Vec<u8> {
    // `NoPadding` decrypt cannot fail for block-aligned input (which the caller
    // validates), so the unpad result is infallible here.
    match key.len() {
        16 => cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
            .expect("valid AES-128 key/iv")
            .decrypt_padded_vec::<NoPadding>(data),
        24 => cbc::Decryptor::<Aes192>::new_from_slices(key, iv)
            .expect("valid AES-192 key/iv")
            .decrypt_padded_vec::<NoPadding>(data),
        32 => cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
            .expect("valid AES-256 key/iv")
            .decrypt_padded_vec::<NoPadding>(data),
        n => panic!("Invalid AES key length: {n}"),
    }
    .expect("CBC NoPadding decrypt of block-aligned data is infallible")
}

/// Encrypts `data` using AES in ECB mode (no IV).
fn aes_ecb_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let schedule = AesKeySchedule::new(key);
    let mut output = data.to_vec();
    for block in output.chunks_exact_mut(AES_BLOCK_SIZE) {
        let mut arr: [u8; AES_BLOCK_SIZE] = block.try_into().unwrap();
        schedule.encrypt_block_inplace(&mut arr);
        block.copy_from_slice(&arr);
    }
    output
}

/// Decrypts `data` using AES in ECB mode.
fn aes_ecb_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let schedule = AesKeySchedule::new(key);
    let mut output = data.to_vec();
    for block in output.chunks_exact_mut(AES_BLOCK_SIZE) {
        let mut arr: [u8; AES_BLOCK_SIZE] = block.try_into().unwrap();
        schedule.decrypt_block_inplace(&mut arr);
        block.copy_from_slice(&arr);
    }
    output
}

/// A key-scheduled AES cipher, dispatching on key length. Built once per
/// message so the (relatively expensive) key expansion is not repeated for
/// every 16-byte block in the CBC/ECB loops.
enum AesKeySchedule {
    A128(Aes128),
    A192(Aes192),
    A256(Aes256),
}

impl AesKeySchedule {
    /// Expands `key` into a reusable schedule.
    ///
    /// # Panics
    /// Panics if `key.len()` is not 16, 24, or 32.
    fn new(key: &[u8]) -> Self {
        match key.len() {
            16 => Self::A128(Aes128::new_from_slice(key).expect("valid AES-128 key")),
            24 => Self::A192(Aes192::new_from_slice(key).expect("valid AES-192 key")),
            32 => Self::A256(Aes256::new_from_slice(key).expect("valid AES-256 key")),
            n => panic!("Invalid AES key length: {n}"),
        }
    }

    /// Encrypts a single 16-byte block in-place.
    fn encrypt_block_inplace(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let ga: &mut Array<u8, _> = block.into();
        match self {
            Self::A128(c) => c.encrypt_block(ga),
            Self::A192(c) => c.encrypt_block(ga),
            Self::A256(c) => c.encrypt_block(ga),
        }
    }

    /// Decrypts a single 16-byte block in-place.
    fn decrypt_block_inplace(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let ga: &mut Array<u8, _> = block.into();
        match self {
            Self::A128(c) => c.decrypt_block(ga),
            Self::A192(c) => c.decrypt_block(ga),
            Self::A256(c) => c.decrypt_block(ga),
        }
    }
}

/// Computes the AES-CMAC of `data` with `key`, returning the first 8 bytes.
///
/// Dispatches to `Cmac<Aes128>`, `Cmac<Aes192>`, or `Cmac<Aes256>` based on
/// `key.len()`.
fn compute_cmac_truncated(key: &[u8], data: &[u8]) -> Result<Vec<u8>, digest::InvalidLength> {
    let full: Vec<u8> = match key.len() {
        16 => {
            let mut mac = <Cmac<Aes128> as digest::KeyInit>::new_from_slice(key)?;
            Mac::update(&mut mac, data);
            mac.finalize().into_bytes().to_vec()
        }
        24 => {
            let mut mac = <Cmac<Aes192> as digest::KeyInit>::new_from_slice(key)?;
            Mac::update(&mut mac, data);
            mac.finalize().into_bytes().to_vec()
        }
        32 => {
            let mut mac = <Cmac<Aes256> as digest::KeyInit>::new_from_slice(key)?;
            Mac::update(&mut mac, data);
            mac.finalize().into_bytes().to_vec()
        }
        n => panic!("Invalid AES key length for CMAC: {n}"),
    };
    // Truncate to 8 bytes (64 bits) — mirrors the CMac(BlockCipher('AES'), 64)
    Ok(full[..AES_CMAC_OUTPUT_LEN].to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // KeyLength
    // -----------------------------------------------------------------------

    #[test]
    fn key_length_byte_sizes() {
        assert_eq!(KeyLength::S128.byte_size(), 16);
        assert_eq!(KeyLength::S192.byte_size(), 24);
        assert_eq!(KeyLength::S256.byte_size(), 32);
    }

    // -----------------------------------------------------------------------
    // AES-128 CBC roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn aes128_cbc_roundtrip() {
        let cipher = AesCipher::new(KeyLength::S128);
        let key = [0x01u8; 16];
        let iv = [0x00u8; 16];
        let pt = [0xABu8; 32]; // two blocks

        let ct = cipher
            .encrypt(&pt, &key, Some(&iv), BlockCipherMode::Cbc, false)
            .unwrap();
        assert_eq!(ct.len(), 32);
        let dec = cipher
            .decrypt(&ct, &key, Some(&iv), BlockCipherMode::Cbc)
            .unwrap();
        assert_eq!(dec, pt);
    }

    // -----------------------------------------------------------------------
    // AES-192 CBC roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn aes192_cbc_roundtrip() {
        let cipher = AesCipher::new(KeyLength::S192);
        let key = [0x02u8; 24];
        let iv = [0x01u8; 16];
        let pt = [0xCDu8; 16];

        let ct = cipher
            .encrypt(&pt, &key, Some(&iv), BlockCipherMode::Cbc, false)
            .unwrap();
        let dec = cipher
            .decrypt(&ct, &key, Some(&iv), BlockCipherMode::Cbc)
            .unwrap();
        assert_eq!(dec, pt);
    }

    // -----------------------------------------------------------------------
    // AES-256 CBC roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn aes256_cbc_roundtrip() {
        let cipher = AesCipher::new(KeyLength::S256);
        let key = [0x03u8; 32];
        let iv = [0x00u8; 16];
        let pt = [0xEFu8; 48]; // three blocks

        let ct = cipher
            .encrypt(&pt, &key, Some(&iv), BlockCipherMode::Cbc, false)
            .unwrap();
        let dec = cipher
            .decrypt(&ct, &key, Some(&iv), BlockCipherMode::Cbc)
            .unwrap();
        assert_eq!(dec, pt);
    }

    // -----------------------------------------------------------------------
    // ECB mode roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn aes128_ecb_roundtrip() {
        let cipher = AesCipher::new(KeyLength::S128);
        let key = [0xAAu8; 16];
        let pt = [0x55u8; 16];

        let ct = cipher
            .encrypt(&pt, &key, None, BlockCipherMode::Ecb, false)
            .unwrap();
        let dec = cipher
            .decrypt(&ct, &key, None, BlockCipherMode::Ecb)
            .unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn ecb_ignores_iv_even_if_wrong_length() {
        // ECB does not use the IV, so a wrong-length IV must not cause an error.
        let cipher = AesCipher::new(KeyLength::S128);
        let key = [0xAAu8; 16];
        let pt = [0x55u8; 16];
        let bad_iv = [0u8; 3]; // wrong length — ignored by ECB

        let ct = cipher
            .encrypt(&pt, &key, Some(&bad_iv), BlockCipherMode::Ecb, false)
            .unwrap();
        let dec = cipher
            .decrypt(&ct, &key, Some(&bad_iv), BlockCipherMode::Ecb)
            .unwrap();
        assert_eq!(dec, pt);

        // The result must match the None-IV path (ECB truly ignores the IV).
        let ct_none = cipher
            .encrypt(&pt, &key, None, BlockCipherMode::Ecb, false)
            .unwrap();
        assert_eq!(ct, ct_none);
    }

    #[test]
    fn aes256_ecb_roundtrip() {
        let cipher = AesCipher::new(KeyLength::S256);
        let key = [0xBBu8; 32];
        let pt = [0x11u8; 32];

        let ct = cipher
            .encrypt(&pt, &key, None, BlockCipherMode::Ecb, false)
            .unwrap();
        let dec = cipher
            .decrypt(&ct, &key, None, BlockCipherMode::Ecb)
            .unwrap();
        assert_eq!(dec, pt);
    }

    // -----------------------------------------------------------------------
    // Zero-padding
    // -----------------------------------------------------------------------

    #[test]
    fn zero_pad_three_bytes() {
        let cipher = AesCipher::new(KeyLength::S128);
        let padded = cipher.zero_pad(&[0x01, 0x02, 0x03], AES_BLOCK_SIZE).unwrap();
        assert_eq!(padded.len(), AES_BLOCK_SIZE);
        assert_eq!(&padded[..3], &[0x01u8, 0x02, 0x03]);
        assert!(padded[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn zero_pad_exact_block_is_unchanged() {
        let cipher = AesCipher::new(KeyLength::S128);
        let data = [0xAAu8; AES_BLOCK_SIZE];
        let padded = cipher.zero_pad(&data, AES_BLOCK_SIZE).unwrap();
        assert_eq!(padded, data);
    }

    #[test]
    fn zero_pad_zero_block_size_errors() {
        let cipher = AesCipher::new(KeyLength::S128);
        assert!(matches!(
            cipher.zero_pad(&[0x01], 0),
            Err(AesCipherError::InvalidBlockSize)
        ));
    }

    #[test]
    fn encrypt_with_padding_roundtrip() {
        let cipher = AesCipher::new(KeyLength::S128);
        let key = [0x01u8; 16];
        let pt = b"Hello".as_ref(); // 5 bytes

        let ct = cipher
            .encrypt(pt, &key, None, BlockCipherMode::Cbc, true)
            .unwrap();
        assert_eq!(ct.len(), AES_BLOCK_SIZE); // padded to one block

        // Decrypt gives zero-padded plaintext; strip trailing zeros to compare
        let dec = cipher
            .decrypt(&ct, &key, None, BlockCipherMode::Cbc)
            .unwrap();
        assert_eq!(&dec[..5], pt);
        assert!(dec[5..].iter().all(|&b| b == 0));
    }

    // -----------------------------------------------------------------------
    // Null IV defaults to zero IV
    // -----------------------------------------------------------------------

    #[test]
    fn null_iv_same_as_zero_iv() {
        let cipher = AesCipher::new(KeyLength::S128);
        let key = [0x01u8; 16];
        let pt = [0xFFu8; 16];
        let zero_iv = [0u8; 16];

        let ct_null = cipher
            .encrypt(&pt, &key, None, BlockCipherMode::Cbc, false)
            .unwrap();
        let ct_zero = cipher
            .encrypt(&pt, &key, Some(&zero_iv), BlockCipherMode::Cbc, false)
            .unwrap();
        assert_eq!(ct_null, ct_zero);
    }

    // -----------------------------------------------------------------------
    // CMAC
    // -----------------------------------------------------------------------

    #[test]
    fn cmac128_returns_8_bytes() {
        let cipher = AesCipher::new(KeyLength::S128);
        let key = [0x01u8; 16];
        let data = [0x00u8; 16];
        let mac = cipher.calculate_cmac(&data, &key).unwrap();
        assert_eq!(mac.len(), AES_CMAC_OUTPUT_LEN);
    }

    #[test]
    fn cmac256_returns_8_bytes() {
        let cipher = AesCipher::new(KeyLength::S256);
        let key = [0x01u8; 32];
        let data = [0xFFu8; 32];
        let mac = cipher.calculate_cmac(&data, &key).unwrap();
        assert_eq!(mac.len(), AES_CMAC_OUTPUT_LEN);
    }

    #[test]
    fn cmac_empty_data() {
        let cipher = AesCipher::new(KeyLength::S128);
        let key = [0x02u8; 16];
        let mac = cipher.calculate_cmac(&[], &key).unwrap();
        assert_eq!(mac.len(), AES_CMAC_OUTPUT_LEN);
    }

    #[test]
    fn cmac_different_data_gives_different_mac() {
        let cipher = AesCipher::new(KeyLength::S128);
        let key = [0x01u8; 16];
        let mac1 = cipher.calculate_cmac(&[0x00u8; 16], &key).unwrap();
        let mac2 = cipher.calculate_cmac(&[0xFFu8; 16], &key).unwrap();
        assert_ne!(mac1, mac2);
    }

    // -----------------------------------------------------------------------
    // PACE AES-256 test vector (from pace_aes_256_test.dart)
    //
    // kpi   = 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
    // nonce = A1A2A3A4A5A6A7A8A9AAABACADAEAFB0
    // Encrypt nonce with kpi (AES-256, CBC, zero IV, no padding)
    // Then decrypt and verify we recover the original nonce.
    // -----------------------------------------------------------------------

    #[test]
    fn pace_aes256_encrypt_decrypt_nonce() {
        let kpi = hex::decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
            .unwrap();
        let nonce = hex::decode("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0").unwrap();

        let cipher = AesCipher::new(KeyLength::S256);
        let encrypted = cipher
            .encrypt(&nonce, &kpi, None, BlockCipherMode::Cbc, false)
            .unwrap();
        assert_eq!(encrypted.len(), AES_BLOCK_SIZE);

        let decrypted = cipher
            .decrypt(&encrypted, &kpi, None, BlockCipherMode::Cbc)
            .unwrap();
        assert_eq!(decrypted, nonce);
    }

    // -----------------------------------------------------------------------
    // Error cases
    // -----------------------------------------------------------------------

    #[test]
    fn wrong_key_length_returns_error() {
        let cipher = AesCipher::new(KeyLength::S128);
        let bad_key = [0u8; 24]; // 24 bytes instead of 16
        assert!(
            cipher
                .encrypt(&[0u8; 16], &bad_key, None, BlockCipherMode::Cbc, false)
                .is_err()
        );
    }

    #[test]
    fn bad_iv_length_returns_error() {
        let cipher = AesCipher::new(KeyLength::S128);
        let key = [0u8; 16];
        let bad_iv = [0u8; 8]; // 8 bytes instead of 16
        assert!(
            cipher
                .encrypt(&[0u8; 16], &key, Some(&bad_iv), BlockCipherMode::Cbc, false)
                .is_err()
        );
    }

    #[test]
    fn non_block_aligned_data_without_padding_returns_error() {
        let cipher = AesCipher::new(KeyLength::S128);
        let key = [0u8; 16];
        assert!(
            cipher
                .encrypt(&[0u8; 5], &key, None, BlockCipherMode::Cbc, false)
                .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // get_cipher convenience constructor
    // -----------------------------------------------------------------------

    #[test]
    fn get_cipher_s256_returns_correct_size() {
        let c = get_cipher(KeyLength::S256);
        assert_eq!(c.key_size(), 32);
    }
}
