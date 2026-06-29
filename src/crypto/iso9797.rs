//! ISO/IEC 9797-1 MAC Algorithm 3 and Padding Method 2.
//!
//! This module implements:
//! - **Padding Method 2** (ISO/IEC 9797-1 §6.3.2): append 0x80 then zero bytes
//!   to the next block boundary.
//! - **MAC Algorithm 3** (ISO/IEC 9797-1 §9.3): a retail-MAC variant using
//!   Triple DES (3DES / DESede):
//!   1. Encrypt `msg` (padded) with `Ka` using single DES in CBC mode → last block = `H`.
//!   2. Decrypt `H` with `Kb` using single DES in ECB mode → `H'`.
//!   3. Encrypt `H'` with `Kc` using single DES in ECB mode → MAC.
//!
//! Key lengths:
//! - 16 bytes: `Ka = key[0..8]`, `Kb = key[8..16]`, `Kc = Ka`  (keying option 2)
//! - 24 bytes: `Ka = key[0..8]`, `Kb = key[8..16]`, `Kc = key[16..24]`
//!
//! # References
//! - ISO/IEC 9797-1:2011
//! - ICAO Doc 9303 Part 11, Section 9.8.6

use cbc::cipher::block_padding::NoPadding;
use cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use des::Des;
use thiserror::Error;

/// Block size for DES (8 bytes / 64 bits).
pub const DES_BLOCK_SIZE: usize = 8;

/// Acceptable 16-byte key length for [`mac_alg3`].
pub const MAC_ALG3_KEY1_LEN: usize = 16;
/// Acceptable 24-byte key length for [`mac_alg3`].
pub const MAC_ALG3_KEY2_LEN: usize = 24;
/// Output length of [`mac_alg3`] (one DES block = 8 bytes).
pub const MAC_ALG3_DIGEST_LEN: usize = DES_BLOCK_SIZE;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error type for ISO 9797-1 operations.
#[derive(Debug, Error)]
pub enum Iso9797Error {
    #[error("ISO9797 key length must be 16 or 24 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("ISO9797 data length must be a multiple of {DES_BLOCK_SIZE} bytes, got {0}")]
    InvalidDataLength(usize),

    #[error("ISO9797 block size must be greater than zero")]
    InvalidBlockSize,

    #[error("ISO9797 unpad failed: malformed Padding Method 2 (no 0x80 marker)")]
    UnpadFailed,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns the ISO/IEC 9797-1, Padding Method 2 padded form of `data`.
///
/// A `0x80` byte is appended, followed by enough `0x00` bytes so that the
/// total length is the next multiple of `block_size`.
///
/// If `data.len()` is already a multiple of `block_size`, an entire new block
/// of padding is added (i.e. `0x80 00 00 00 00 00 00 00` for 8-byte blocks).
///
/// # Errors
/// Returns [`Iso9797Error::InvalidBlockSize`] if `block_size == 0` (instead of
/// panicking, so misuse from the public API is recoverable).
///
/// # Examples
/// ```
/// use dmrtd::crypto::iso9797::{pad, DES_BLOCK_SIZE};
///
/// let padded = pad(&[0x01, 0x02, 0x03], DES_BLOCK_SIZE).unwrap();
/// assert_eq!(padded, vec![0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00]);
/// assert_eq!(padded.len() % DES_BLOCK_SIZE, 0);
/// ```
pub fn pad(data: &[u8], block_size: usize) -> Result<Vec<u8>, Iso9797Error> {
    if block_size == 0 {
        return Err(Iso9797Error::InvalidBlockSize);
    }
    // Number of padding bytes needed: 1 (the 0x80) + zero or more 0x00 bytes.
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    padded.push(0x80);
    padded.extend(std::iter::repeat(0x00).take(pad_len - 1));
    Ok(padded)
}

/// Removes ISO/IEC 9797-1, Padding Method 2 padding from `data`.
///
/// Scans backwards for the last `0x80` byte (skipping trailing `0x00` bytes)
/// and returns the slice up to (but not including) that byte.
///
/// # Errors
/// Returns [`Iso9797Error::UnpadFailed`] if the input is not valid ISO/IEC
/// 9797-1 Method 2 padding — i.e. there is no `0x80` marker preceding the
/// trailing run of `0x00` bytes (this includes empty input and all-zero input).
///
/// # Examples
/// ```
/// use dmrtd::crypto::iso9797::unpad;
///
/// let data = vec![0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00];
/// assert_eq!(unpad(&data).unwrap(), &[0x01, 0x02, 0x03]);
/// ```
pub fn unpad(data: &[u8]) -> Result<&[u8], Iso9797Error> {
    let mut i = data.len();
    // Skip trailing zero bytes
    while i > 0 && data[i - 1] == 0x00 {
        i -= 1;
    }
    // The byte preceding the trailing zeros must be the 0x80 marker; anything
    // else (including no marker at all) is malformed padding.
    if i > 0 && data[i - 1] == 0x80 {
        Ok(&data[..i - 1])
    } else {
        Err(Iso9797Error::UnpadFailed)
    }
}

/// Returns the ISO/IEC 9797-1 MAC Algorithm 3 result for `msg` using `key`.
///
/// # Key layout
/// | Key length | Ka        | Kb         | Kc         |
/// |------------|-----------|------------|------------|
/// | 16 bytes   | `[0..8]`  | `[8..16]`  | `[0..8]`   |
/// | 24 bytes   | `[0..8]`  | `[8..16]`  | `[16..24]` |
///
/// # Arguments
/// - `key`    – 16 or 24-byte key.
/// - `msg`    – Message to authenticate.
/// - `pad_msg`– When `true` the message is padded with Method 2 before MAC
///              computation; when `false` the caller is responsible for padding.
///
/// # Errors
/// Returns [`Iso9797Error::InvalidKeyLength`] if the key length is not 16 or 24.
///
/// # Examples
/// ```
/// use dmrtd::crypto::iso9797::mac_alg3;
///
/// // Test vector from the BouncyCastle ISO 9797-1 test suite
/// let key = hex::decode("7CA110454A1A6E570131D9619DC1376E").unwrap();
/// let msg = b"Hello World !!!!".to_vec();
/// let mac = mac_alg3(&key, &msg, false).unwrap();
/// assert_eq!(mac, hex::decode("F09B856213BAB83B").unwrap());
/// ```
pub fn mac_alg3(key: &[u8], msg: &[u8], pad_msg: bool) -> Result<Vec<u8>, Iso9797Error> {
    if key.len() != MAC_ALG3_KEY1_LEN && key.len() != MAC_ALG3_KEY2_LEN {
        return Err(Iso9797Error::InvalidKeyLength(key.len()));
    }

    let ka = &key[0..8];
    let kb = &key[8..16];
    let kc = if key.len() == MAC_ALG3_KEY1_LEN {
        ka
    } else {
        &key[16..24]
    };

    // Step 1 – Encrypt `msg` with Ka in single-DES CBC mode; keep last block.
    let data = if pad_msg {
        pad(msg, DES_BLOCK_SIZE)?
    } else {
        msg.to_vec()
    };

    if data.len() % DES_BLOCK_SIZE != 0 {
        return Err(Iso9797Error::InvalidDataLength(data.len()));
    }

    // An empty (unpadded) message has no final CBC block to extract; reject it
    // instead of panicking when slicing the last block below. With `pad_msg`,
    // padding always yields at least one block, so this only triggers for
    // `pad_msg == false` and an empty `msg`.
    if data.is_empty() {
        return Err(Iso9797Error::InvalidDataLength(0));
    }

    let mut mac = cbc_encrypt_des(ka, &[0u8; DES_BLOCK_SIZE], &data);
    // Keep only the last block
    mac = mac[mac.len() - DES_BLOCK_SIZE..].to_vec();

    // Step 2 – Decrypt the last block with Kb (single DES, ECB).
    mac = ecb_decrypt_des(kb, &mac);

    // Step 3 – Encrypt the result with Kc (single DES, ECB).
    mac = ecb_encrypt_des(kc, &mac);

    Ok(mac)
}

// ---------------------------------------------------------------------------
// Internal DES helpers (single DES, CBC and ECB)
// ---------------------------------------------------------------------------

/// Encrypts `data` using single DES in CBC mode with the given `key` and `iv`.
///
/// `data` must already be a multiple of 8 bytes.
fn cbc_encrypt_des(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    // `data` is block-aligned by the caller, so `NoPadding` is a no-op; the CBC
    // chaining is delegated to the vetted `cbc` crate.
    cbc::Encryptor::<Des>::new_from_slices(key, iv)
        .expect("valid DES key/iv")
        .encrypt_padded_vec::<NoPadding>(data)
}

/// Encrypts a single 8-byte block using single DES in ECB mode.
fn ecb_encrypt_des(key: &[u8], block: &[u8]) -> Vec<u8> {
    let cipher = Des::new_from_slice(key).expect("valid DES key");
    let mut b = Array::try_from(block).expect("DES block");
    cipher.encrypt_block(&mut b);
    b.to_vec()
}

/// Decrypts a single 8-byte block using single DES in ECB mode.
fn ecb_decrypt_des(key: &[u8], block: &[u8]) -> Vec<u8> {
    let cipher = Des::new_from_slice(key).expect("valid DES key");
    let mut b = Array::try_from(block).expect("DES block");
    cipher.decrypt_block(&mut b);
    b.to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // pad
    // -----------------------------------------------------------------------

    #[test]
    fn pad_empty_data() {
        // Empty input: one full block of padding (0x80 followed by 7 zeros)
        let padded = pad(&[], DES_BLOCK_SIZE).unwrap();
        assert_eq!(padded, vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn pad_three_bytes() {
        let padded = pad(&[0x01, 0x02, 0x03], DES_BLOCK_SIZE).unwrap();
        assert_eq!(padded, vec![0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(padded.len(), DES_BLOCK_SIZE);
    }

    #[test]
    fn pad_full_block_adds_new_block() {
        // Input is already 8 bytes → padding adds another 8-byte block
        let input = vec![0xAA; DES_BLOCK_SIZE];
        let padded = pad(&input, DES_BLOCK_SIZE).unwrap();
        assert_eq!(padded.len(), 2 * DES_BLOCK_SIZE);
        assert_eq!(padded[DES_BLOCK_SIZE], 0x80);
        assert!(padded[DES_BLOCK_SIZE + 1..].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn pad_seven_bytes_adds_one_padding_byte() {
        let input: Vec<u8> = (1u8..=7).collect();
        let padded = pad(&input, DES_BLOCK_SIZE).unwrap();
        assert_eq!(padded.len(), DES_BLOCK_SIZE);
        assert_eq!(padded[7], 0x80);
    }

    #[test]
    fn pad_result_multiple_of_block_size() {
        for len in 0..=24 {
            let input = vec![0xBBu8; len];
            let padded = pad(&input, DES_BLOCK_SIZE).unwrap();
            assert_eq!(
                padded.len() % DES_BLOCK_SIZE,
                0,
                "pad({len}) is not a multiple of block size"
            );
        }
    }

    #[test]
    fn pad_zero_block_size_errors() {
        assert!(matches!(pad(&[0x01], 0), Err(Iso9797Error::InvalidBlockSize)));
    }

    // -----------------------------------------------------------------------
    // unpad
    // -----------------------------------------------------------------------

    #[test]
    fn unpad_three_bytes() {
        let data = vec![0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(unpad(&data).unwrap(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn unpad_roundtrip() {
        for len in 0..=24usize {
            let original: Vec<u8> = (0..len as u8).collect();
            let padded = pad(&original, DES_BLOCK_SIZE).unwrap();
            let unpadded = unpad(&padded).unwrap();
            assert_eq!(
                unpadded,
                original.as_slice(),
                "roundtrip failed for len={len}"
            );
        }
    }

    #[test]
    fn unpad_empty_padding_block() {
        // pad of empty = [0x80, 0x00 x7]; unpad should return []
        let data = vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(unpad(&data).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn unpad_no_marker_errors() {
        // No 0x80 marker anywhere — malformed Method 2 padding.
        let data = vec![0x01, 0x02, 0x03];
        assert!(matches!(unpad(&data), Err(Iso9797Error::UnpadFailed)));
    }

    #[test]
    fn unpad_all_zeros_errors() {
        // Trailing zeros with no preceding 0x80 marker is malformed.
        let data = vec![0x00; 8];
        assert!(matches!(unpad(&data), Err(Iso9797Error::UnpadFailed)));
    }

    #[test]
    fn unpad_empty_errors() {
        let data: Vec<u8> = Vec::new();
        assert!(matches!(unpad(&data), Err(Iso9797Error::UnpadFailed)));
    }

    // -----------------------------------------------------------------------
    // mac_alg3
    // -----------------------------------------------------------------------

    /// Test vector from BouncyCastle test suite (used iso9797_test.dart).
    #[test]
    fn mac_alg3_bouncy_castle_vector() {
        let key = hex::decode("7CA110454A1A6E570131D9619DC1376E").unwrap();
        let msg = b"Hello World !!!!".to_vec(); // 16 bytes, no padding needed
        let expected = hex::decode("F09B856213BAB83B").unwrap();

        let mac = mac_alg3(&key, &msg, false).unwrap();
        assert_eq!(mac, expected);
    }

    /// ICAO 9303 Part 11, Appendix D.3 – BAC Eifd MAC test vector.
    #[test]
    fn mac_alg3_icao_d3_eifd_vector() {
        // Kmac from ICAO 9303 p11 Appendix D.3
        let key = hex::decode("7962D9ECE03D1ACD4C76089DCE131543").unwrap();
        // Eifd (32 bytes); function pads it before computing MAC
        let msg = hex::decode("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2")
            .unwrap();
        let expected = hex::decode("5F1448EEA8AD90A7").unwrap();

        let mac = mac_alg3(&key, &msg, true).unwrap();
        assert_eq!(mac, expected);
    }

    #[test]
    fn mac_alg3_invalid_key_length_errors() {
        let key = vec![0u8; 8]; // 8 bytes – invalid
        assert!(matches!(
            mac_alg3(&key, &[], true),
            Err(Iso9797Error::InvalidKeyLength(8))
        ));
    }

    #[test]
    fn mac_alg3_unpadded_non_block_aligned_errors() {
        let key = vec![0u8; 16];
        let msg = vec![0u8; 5]; // 5 bytes – not block-aligned, pad_msg=false
        assert!(matches!(
            mac_alg3(&key, &msg, false),
            Err(Iso9797Error::InvalidDataLength(5))
        ));
    }

    #[test]
    fn mac_alg3_empty_unpadded_errors() {
        // Empty message without padding has no final CBC block — must error
        // instead of panicking.
        let key = vec![0u8; 16];
        assert!(matches!(
            mac_alg3(&key, &[], false),
            Err(Iso9797Error::InvalidDataLength(0))
        ));
    }

    #[test]
    fn mac_alg3_produces_eight_bytes() {
        let key = vec![0u8; 16];
        let mac = mac_alg3(&key, &[0u8; 8], false).unwrap();
        assert_eq!(mac.len(), MAC_ALG3_DIGEST_LEN);
    }

    #[test]
    fn mac_alg3_with_padding_produces_eight_bytes() {
        let key = vec![0u8; 16];
        let mac = mac_alg3(&key, &[0u8; 3], true).unwrap();
        assert_eq!(mac.len(), MAC_ALG3_DIGEST_LEN);
    }

    #[test]
    fn mac_alg3_24_byte_key_produces_eight_bytes() {
        let key = vec![0u8; 24];
        let mac = mac_alg3(&key, &[0u8; 8], false).unwrap();
        assert_eq!(mac.len(), MAC_ALG3_DIGEST_LEN);
    }

    // ICAO 9303 p11 Appendix D.4 worked-example MAC vectors — each produced
    // from K_mac `F1CB1F1FB5ADF208806B89DC579DC1F8` (the BAC KS_mac from
    // Appendix D.3).
    fn ks_mac_d3() -> Vec<u8> {
        hex::decode("F1CB1F1FB5ADF208806B89DC579DC1F8").unwrap()
    }

    #[test]
    fn icao_d41_n_vector_matches() {
        let n = hex::decode(
            "887022120C06C2270CA4020C800000008709016375432908C044F6",
        )
        .unwrap();
        let mac = mac_alg3(&ks_mac_d3(), &n, true).unwrap();
        assert_eq!(hex::encode_upper(&mac), "BF8B92D635FF24F8");
    }

    #[test]
    fn icao_d41_k_vector_matches() {
        let k = hex::decode("887022120C06C22899029000").unwrap();
        let mac = mac_alg3(&ks_mac_d3(), &k, true).unwrap();
        assert_eq!(hex::encode_upper(&mac), "FA855A5D4C50A8ED");
    }

    #[test]
    fn icao_d42_n_vector_matches() {
        let n = hex::decode("887022120C06C2290CB0000080000000970104").unwrap();
        let mac = mac_alg3(&ks_mac_d3(), &n, true).unwrap();
        assert_eq!(hex::encode_upper(&mac), "ED6705417E96BA55");
    }

    #[test]
    fn icao_d42_k_vector_matches() {
        let k = hex::decode(
            "887022120C06C22A8709019FF0EC34F992265199029000",
        )
        .unwrap();
        let mac = mac_alg3(&ks_mac_d3(), &k, true).unwrap();
        assert_eq!(hex::encode_upper(&mac), "AD55CC17140B2DED");
    }

    #[test]
    fn icao_d43_n_vector_matches() {
        let n = hex::decode("887022120C06C22B0CB0000480000000970112").unwrap();
        let mac = mac_alg3(&ks_mac_d3(), &n, true).unwrap();
        assert_eq!(hex::encode_upper(&mac), "2EA28A70F3C7B535");
    }

    #[test]
    fn icao_d43_k_vector_matches() {
        let k = hex::decode(
            "887022120C06C22C871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A99029000",
        )
        .unwrap();
        let mac = mac_alg3(&ks_mac_d3(), &k, true).unwrap();
        assert_eq!(hex::encode_upper(&mac), "C8B2787EAEA07D74");
    }
}
