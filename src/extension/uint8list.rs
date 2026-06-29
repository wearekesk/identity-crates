//! Byte-slice extension utilities.
//!
//! Provides a [`BytesExt`] trait on `[u8]` that mirrors the extensions
//! `Uint8ListEncodeApis` and `Uint8ListDecodeApis`:
//!
//! ```dart
//! extension Uint8ListEncodeApis on Uint8List {
//!   String base64() { ... }
//!   String hex()    { ... }
//! }
//!
//! extension Uint8ListDecodeApis on Uint8List {
//!   DateTime toDate() { ... } // BCD-encoded CCYYMMDD -> NaiveDate
//! }
//! ```

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::NaiveDate;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error returned when byte-slice conversion fails.
#[derive(Debug, thiserror::Error)]
pub enum BytesExtError {
    #[error("Invalid length for date conversion: expected exactly 4 bytes, got {0}")]
    InvalidDateLength(usize),

    #[error("Invalid BCD date value: {0}")]
    InvalidDate(String),
}

// ---------------------------------------------------------------------------
// BytesExt trait
// ---------------------------------------------------------------------------

/// Extension trait that adds encoding and date-decoding helpers to `[u8]`.
///
/// # Examples
/// ```
/// use dmrtd::extension::uint8list::BytesExt;
///
/// let bytes = b"\xDE\xAD\xBE\xEF";
/// assert_eq!(bytes.hex(), "deadbeef");
///
/// let b64 = bytes.base64();
/// assert!(!b64.is_empty());
///
/// // BCD date: 0x20 0x23 0x12 0x31 -> 2023-12-31
/// let date_bytes: &[u8] = &[0x20, 0x23, 0x12, 0x31];
/// let date = date_bytes.to_date().unwrap();
/// assert_eq!(date.to_string(), "2023-12-31");
/// ```
pub trait BytesExt {
    /// Encodes the byte slice as a lowercase hexadecimal string.
    fn hex(&self) -> String;

    /// Encodes the byte slice as a standard (padded) base64 string.
    fn base64(&self) -> String;

    /// Decodes a BCD-encoded 4-byte `CCYYMMDD` date into a [`NaiveDate`].
    ///
    /// Each byte holds two BCD digits: the high nibble is the tens digit and
    /// the low nibble is the units digit.  The four bytes represent:
    ///
    /// | Byte index | Meaning        | Example (`0x20 0x23 0x12 0x31`) |
    /// |------------|----------------|---------------------------------|
    /// | `[0]`      | Century (`CC`) | `0x20` → 20                     |
    /// | `[1]`      | Year (`YY`)    | `0x23` → 23  → year = 2023      |
    /// | `[2]`      | Month (`MM`)   | `0x12` → 12                     |
    /// | `[3]`      | Day (`DD`)     | `0x31` → 31                     |
    ///
    /// # Errors
    /// Returns [`BytesExtError::InvalidDateLength`] if `self.len() != 4` (the
    /// `CCYYMMDD` field is fixed-width).
    /// Returns [`BytesExtError::InvalidDate`] if the BCD values produce an
    /// invalid calendar date.
    fn to_date(&self) -> Result<NaiveDate, BytesExtError>;
}

impl BytesExt for [u8] {
    fn hex(&self) -> String {
        hex::encode(self)
    }

    fn base64(&self) -> String {
        BASE64.encode(self)
    }

    fn to_date(&self) -> Result<NaiveDate, BytesExtError> {
        if self.len() != 4 {
            return Err(BytesExtError::InvalidDateLength(self.len()));
        }

        // Convert a single BCD byte (0x00–0x99) to an integer (0–99). Each
        // nibble must be a valid decimal digit (0–9); otherwise the byte is not
        // valid BCD and would produce a bogus decimal value.
        let bcd_to_int = |byte: u8| -> Result<u32, BytesExtError> {
            let hi = (byte >> 4) as u32;
            let lo = (byte & 0x0F) as u32;
            if hi > 9 || lo > 9 {
                return Err(BytesExtError::InvalidDate(format!(
                    "invalid BCD byte: {byte:02X}"
                )));
            }
            Ok(hi * 10 + lo)
        };

        // Bytes 0 and 1 encode century and year-within-century.
        let year = bcd_to_int(self[0])? * 100 + bcd_to_int(self[1])?;
        let month = bcd_to_int(self[2])?;
        let day = bcd_to_int(self[3])?;

        NaiveDate::from_ymd_opt(year as i32, month, day).ok_or_else(|| {
            BytesExtError::InvalidDate(format!(
                "{:04}-{:02}-{:02} (raw BCD: {:02X} {:02X} {:02X} {:02X})",
                year, month, day, self[0], self[1], self[2], self[3]
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- hex ---

    #[test]
    fn hex_encoding_lowercase() {
        let bytes: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(bytes.hex(), "deadbeef");
    }

    #[test]
    fn hex_encoding_empty() {
        let bytes: &[u8] = &[];
        assert_eq!(bytes.hex(), "");
    }

    #[test]
    fn hex_encoding_single_byte_low() {
        let bytes: &[u8] = &[0x0A];
        assert_eq!(bytes.hex(), "0a");
    }

    #[test]
    fn hex_encoding_all_zeros() {
        let bytes: &[u8] = &[0x00, 0x00, 0x00];
        assert_eq!(bytes.hex(), "000000");
    }

    // --- base64 ---

    #[test]
    fn base64_encoding_hello() {
        let bytes: &[u8] = b"hello";
        assert_eq!(bytes.base64(), "aGVsbG8=");
    }

    #[test]
    fn base64_encoding_empty() {
        let bytes: &[u8] = &[];
        assert_eq!(bytes.base64(), "");
    }

    #[test]
    fn base64_roundtrip() {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        let original: &[u8] = &[1, 2, 3, 4, 5, 255, 0];
        let encoded = original.base64();
        let decoded = B64.decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    // --- to_date ---

    #[test]
    fn to_date_valid() {
        // 0x20 0x23 0x12 0x31 -> 2023-12-31
        let bytes: &[u8] = &[0x20, 0x23, 0x12, 0x31];
        let date = bytes.to_date().unwrap();
        assert_eq!(date.to_string(), "2023-12-31");
    }

    #[test]
    fn to_date_century_boundary() {
        // 0x19 0x99 0x01 0x01 -> 1999-01-01
        let bytes: &[u8] = &[0x19, 0x99, 0x01, 0x01];
        let date = bytes.to_date().unwrap();
        assert_eq!(date.to_string(), "1999-01-01");
    }

    #[test]
    fn to_date_year_2000() {
        // 0x20 0x00 0x06 0x15 -> 2000-06-15
        let bytes: &[u8] = &[0x20, 0x00, 0x06, 0x15];
        let date = bytes.to_date().unwrap();
        assert_eq!(date.to_string(), "2000-06-15");
    }

    #[test]
    fn to_date_too_short_returns_error() {
        let bytes: &[u8] = &[0x20, 0x23, 0x12];
        assert!(matches!(
            bytes.to_date(),
            Err(BytesExtError::InvalidDateLength(3))
        ));
    }

    #[test]
    fn to_date_invalid_month_returns_error() {
        // Month 13 is invalid
        let bytes: &[u8] = &[0x20, 0x23, 0x13, 0x01];
        assert!(matches!(
            bytes.to_date(),
            Err(BytesExtError::InvalidDate(_))
        ));
    }

    #[test]
    fn to_date_invalid_day_returns_error() {
        // February 30 is invalid
        let bytes: &[u8] = &[0x20, 0x23, 0x02, 0x30];
        assert!(matches!(
            bytes.to_date(),
            Err(BytesExtError::InvalidDate(_))
        ));
    }

    #[test]
    fn to_date_invalid_bcd_nibble_returns_error() {
        // 0x1A has a low nibble of 0xA (10), which is not a valid BCD digit.
        let bytes: &[u8] = &[0x20, 0x1A, 0x01, 0x01];
        assert!(matches!(
            bytes.to_date(),
            Err(BytesExtError::InvalidDate(_))
        ));
    }

    #[test]
    fn to_date_extra_bytes_returns_error() {
        // The CCYYMMDD field is fixed-width: more than 4 bytes is rejected.
        let bytes: &[u8] = &[0x20, 0x23, 0x06, 0x01, 0xFF, 0xFF];
        assert!(matches!(
            bytes.to_date(),
            Err(BytesExtError::InvalidDateLength(6))
        ));
    }
}
