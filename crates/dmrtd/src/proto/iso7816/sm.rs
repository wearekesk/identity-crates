//! ISO/IEC 7816-4 Secure Messaging base.
//!
//! Provides:
//! - The [`SecureMessaging`] trait (`protect` / `unprotect`).
//! - Free functions for building the SM data objects `DO'85'`, `DO'87'`,
//!   `DO'8E'`, `DO'97'`, and `DO'99'`.
//! - [`SmError`] used by concrete implementations when the SM state is
//!   inconsistent (MAC mismatch, missing DO, …).

use thiserror::Error;

use crate::lds::tlv::Tlv;
use crate::proto::iso7816::command_apdu::CommandApdu;
use crate::proto::iso7816::response_apdu::ResponseApdu;
use crate::utils::int_to_bin;

/// Secure Messaging error.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("SMError: {0}")]
pub struct SmError(pub String);

/// SM data-object tags (see ISO/IEC 7816-4 §5.6).
pub const TAG_DO85: u32 = 0x85;
pub const TAG_DO87: u32 = 0x87;
pub const TAG_DO8E: u32 = 0x8E;
pub const TAG_DO97: u32 = 0x97;
pub const TAG_DO99: u32 = 0x99;

// ---------------------------------------------------------------------------
// SecureMessaging trait
// ---------------------------------------------------------------------------

/// ISO/IEC 7816-4 Secure Messaging interface.
pub trait SecureMessaging {
    /// Wraps `cmd` in a secure messaging envelope.
    fn protect(&mut self, cmd: &CommandApdu) -> Result<CommandApdu, SmError>;

    /// Unwraps a protected response APDU.
    fn unprotect(&mut self, rapdu: &ResponseApdu) -> Result<ResponseApdu, SmError>;
}

// ---------------------------------------------------------------------------
// Data object builders
// ---------------------------------------------------------------------------

/// Builds `DO'85'` = `85 <len> <data>`.
pub fn do85(data: &[u8]) -> Vec<u8> {
    build_do(TAG_DO85, data)
}

/// Builds `DO'87'` = `87 <len> <padding_info> <data>` where the padding-info
/// byte is `0x01` when the plaintext was ISO 9797-1 padded before encryption,
/// or `0x02` when it was not.
pub fn do87(data: &[u8], data_is_padded: bool) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut body = Vec::with_capacity(data.len() + 1);
    body.push(if data_is_padded { 0x01 } else { 0x02 });
    body.extend_from_slice(data);
    build_do(TAG_DO87, &body)
}

/// Builds `DO'8E'` = `8E <len> <mac>`.
pub fn do8e(mac: &[u8]) -> Vec<u8> {
    build_do(TAG_DO8E, mac)
}

/// Builds `DO'97'`. `Ne` values of `256` or `65536` use a zero-byte placeholder
/// (1 or 2 zero bytes respectively); smaller values are emitted as a minimal
/// big-endian integer.
pub fn do97(ne: u32) -> Vec<u8> {
    if ne == 256 || ne == 65536 {
        let placeholder = vec![0u8; if ne == 256 { 1 } else { 2 }];
        return build_do(TAG_DO97, &placeholder);
    }
    build_do(TAG_DO97, &int_to_bin(ne as u64, 0))
}

/// Builds `DO'99'` = `99 02 <SW1 SW2>`.
///
/// The status word is always exactly 2 bytes. A minimal-integer encoding would
/// drop leading zero bytes (e.g. a status with `SW1 == 0x00`), emitting a
/// 1-byte or empty DO'99'; the SW must be carried verbatim as two bytes.
pub fn do99(sw: u16) -> Vec<u8> {
    // `sw` is a u16, so the status word always encodes as exactly two bytes —
    // out-of-range statuses are rejected at the type level.
    build_do(TAG_DO99, &int_to_bin(sw as u64, 2))
}

fn build_do(tag: u32, data: &[u8]) -> Vec<u8> {
    assert!(tag < 256, "DO tag must fit in a single byte");
    if data.is_empty() {
        return Vec::new();
    }
    Tlv::encode(tag, data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn do85_wraps_bytes() {
        let d = do85(&[0xAA, 0xBB]);
        assert_eq!(d, vec![0x85, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn do87_padded_flag_is_0x01() {
        let d = do87(&[0xFF; 8], true);
        assert_eq!(d[0], TAG_DO87 as u8);
        // length = 1 (flag) + 8 (data) = 9
        assert_eq!(d[1], 9);
        assert_eq!(d[2], 0x01);
    }

    #[test]
    fn do87_unpadded_flag_is_0x02() {
        let d = do87(&[0xFF; 8], false);
        assert_eq!(d[2], 0x02);
    }

    #[test]
    fn do87_empty_returns_empty() {
        assert!(do87(&[], true).is_empty());
    }

    #[test]
    fn do8e_wraps_mac() {
        let d = do8e(&[0x11; 8]);
        assert_eq!(d[0], TAG_DO8E as u8);
        assert_eq!(d[1], 8);
    }

    #[test]
    fn do97_small_ne() {
        let d = do97(0x20);
        assert_eq!(d, vec![0x97, 0x01, 0x20]);
    }

    #[test]
    fn do97_ne_256_is_zero_placeholder() {
        let d = do97(256);
        assert_eq!(d, vec![0x97, 0x01, 0x00]);
    }

    #[test]
    fn do97_ne_65536_is_two_zero_placeholder() {
        let d = do97(65536);
        assert_eq!(d, vec![0x97, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn do99_minimal() {
        let d = do99(0x9000);
        assert_eq!(d, vec![0x99, 0x02, 0x90, 0x00]);
    }

    #[test]
    fn do99_leading_zero_status_is_two_bytes() {
        // A status word whose SW1 byte is 0x00 must still encode as 2 bytes,
        // not be shortened by minimal-integer encoding.
        let d = do99(0x0090);
        assert_eq!(d, vec![0x99, 0x02, 0x00, 0x90]);
    }
}
