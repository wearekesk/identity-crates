//! Integer extension utilities.
//!
//! Provides a `IntHexExt` trait that adds a `.hex()` method to integer types,
//! mirroring the `IntApis` extension:
//!
//! ```dart
//! extension IntApis on int {
//!   String hex() {
//!     final str = toRadixString(16);
//!     final paddedLen = (str.length.isOdd ? 1 : 0) + str.length;
//!     return str.padLeft(paddedLen, '0').toUpperCase();
//!   }
//! }
//! ```
//!
//! The rule is: format as uppercase hex, then zero-pad to an **even** number
//! of nibbles (i.e. always a whole number of bytes).

/// Extension trait that adds a `.hex()` method producing an even-length,
/// uppercase hexadecimal string.
///
/// # Examples
/// ```
/// use dmrtd::extension::int::IntHexExt;
///
/// assert_eq!(0x0u8.hex(),   "00");
/// assert_eq!(0x1u8.hex(),   "01");
/// assert_eq!(0xABu8.hex(),  "AB");
/// assert_eq!(0x1u16.hex(),  "01");
/// assert_eq!(0x100u16.hex(),"0100");
/// assert_eq!(255u8.hex(),   "FF");
/// assert_eq!(256u16.hex(),  "0100");
/// ```
pub trait IntHexExt {
    /// Returns the value as an uppercase hex string with an even number of digits
    /// (i.e. zero-padded to the next whole byte if needed).
    fn hex(&self) -> String;
}

// ---------------------------------------------------------------------------
// Macro to implement the trait for all primitive integer types
// ---------------------------------------------------------------------------

macro_rules! impl_int_hex_ext {
    ($($t:ty),+) => {
        $(
            impl IntHexExt for $t {
                fn hex(&self) -> String {
                    // Format without prefix, uppercase
                    let s = format!("{:X}", self);
                    // Pad to even length (whole bytes)
                    if s.len() % 2 == 0 {
                        s
                    } else {
                        format!("0{}", s)
                    }
                }
            }
        )+
    };
}

impl_int_hex_ext!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_two_digits() {
        assert_eq!(0u8.hex(), "00");
        assert_eq!(0u32.hex(), "00");
    }

    #[test]
    fn single_nibble_is_padded() {
        assert_eq!(0x1u8.hex(), "01");
        assert_eq!(0xFu8.hex(), "0F");
    }

    #[test]
    fn two_nibbles_unchanged() {
        assert_eq!(0xABu8.hex(), "AB");
        assert_eq!(0xFFu8.hex(), "FF");
    }

    #[test]
    fn three_nibbles_padded_to_four() {
        // 0x100 = 256  -> "100" (3 nibbles) -> padded -> "0100"
        assert_eq!(0x100u16.hex(), "0100");
        assert_eq!(0xABCu16.hex(), "0ABC");
    }

    #[test]
    fn four_nibbles_unchanged() {
        assert_eq!(0xABCDu16.hex(), "ABCD");
    }

    #[test]
    fn larger_values() {
        assert_eq!(0xDEADBEEFu32.hex(), "DEADBEEF");
        assert_eq!(0x0102_0304_0506_0708u64.hex(), "0102030405060708");
    }

    #[test]
    fn signed_positive_values() {
        assert_eq!(1i32.hex(), "01");
        assert_eq!(255i32.hex(), "FF");
        assert_eq!(256i32.hex(), "0100");
    }

    #[test]
    fn usize_value() {
        assert_eq!(0usize.hex(), "00");
        assert_eq!(16usize.hex(), "10");
    }
}
