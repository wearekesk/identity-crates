//! General utility functions.
//!
//! Provides bit/byte counting, integer serialisation, and BigUint
//! conversion helpers used throughout the DMRTD library.

use num_bigint::BigUint;

// ---------------------------------------------------------------------------
// Bit / byte counting
// ---------------------------------------------------------------------------

/// Returns the number of bits required to represent `n`.
///
/// Returns 0 for `n = 0`, otherwise `floor(log2(n)) + 1`.
///
/// # Examples
/// ```
/// use dmrtd::utils::bit_count;
/// assert_eq!(bit_count(0),    0);
/// assert_eq!(bit_count(1),    1);
/// assert_eq!(bit_count(2),    2);
/// assert_eq!(bit_count(3),    2);
/// assert_eq!(bit_count(255),  8);
/// assert_eq!(bit_count(256),  9);
/// ```
pub fn bit_count(n: u64) -> usize {
    if n == 0 {
        return 0;
    }
    (u64::BITS - n.leading_zeros()) as usize
}

/// Returns the number of bytes required to represent `n`.
///
/// # Examples
/// ```
/// use dmrtd::utils::byte_count;
/// assert_eq!(byte_count(0),      0);
/// assert_eq!(byte_count(1),      1);
/// assert_eq!(byte_count(0xFF),   1);
/// assert_eq!(byte_count(0x100),  2);
/// assert_eq!(byte_count(0xFFFF), 2);
/// assert_eq!(byte_count(0x10000),3);
/// ```
pub fn byte_count(n: u64) -> usize {
    (bit_count(n) + 7) / 8
}

// ---------------------------------------------------------------------------
// Integer serialisation
// ---------------------------------------------------------------------------

/// Serialises `n` as a big-endian byte slice, stripping leading zero bytes,
/// but guaranteeing the result has at least `min_len` bytes (left-padded with
/// `0x00` if needed).
///
/// Special case: if `min_len == 0` and `n == 0`, returns an empty `Vec`.
///
/// # Behaviour
/// The function first serialises `n` as 8 big-endian bytes, then finds the
/// index of the first non-zero byte (`i`).  The number of significant bytes is
/// `8 - i`.  If that is already ≥ `min_len` the slice from `i` onwards is
/// returned; otherwise the slice from `8 - min_len` onwards is returned (which
/// gives exactly `min_len` bytes, zero-padded on the left).
///
/// # Examples
/// ```
/// use dmrtd::utils::int_to_bin;
/// assert_eq!(int_to_bin(0,     1), vec![0x00]);
/// assert_eq!(int_to_bin(0,     0), vec![]);
/// assert_eq!(int_to_bin(1,     1), vec![0x01]);
/// assert_eq!(int_to_bin(0x100, 1), vec![0x01, 0x00]);
/// assert_eq!(int_to_bin(4,     0), vec![0x04]);
/// assert_eq!(int_to_bin(0x12,  0), vec![0x12]);
/// assert_eq!(int_to_bin(0xFF,  2), vec![0x00, 0xFF]);
/// ```
pub fn int_to_bin(n: u64, min_len: usize) -> Vec<u8> {
    let raw = n.to_be_bytes(); // [u8; 8], big-endian

    // Find the index of the first non-zero byte.
    let first_set = raw.iter().position(|&b| b != 0).unwrap_or(8);

    // Significant byte count
    let sig_bytes = 8 - first_set;

    if sig_bytes >= min_len {
        // Return from the first non-zero byte (natural significant bytes).
        raw[first_set..].to_vec()
    } else {
        // Left-pad to min_len bytes by starting from `8 - min_len`.
        if min_len > 8 {
            // Extremely unlikely, but handle gracefully.
            let mut v = vec![0u8; min_len - 8];
            v.extend_from_slice(&raw);
            v
        } else {
            raw[8 - min_len..].to_vec()
        }
    }
}

// ---------------------------------------------------------------------------
// BigUint helpers
// ---------------------------------------------------------------------------

/// Converts a [`BigUint`] to a big-endian byte vector.
///
/// Returns an empty `Vec` for zero.
///
/// # Examples
/// ```
/// use num_bigint::BigUint;
/// use dmrtd::utils::big_uint_to_bytes;
/// assert_eq!(big_uint_to_bytes(&BigUint::from(0u8)),    vec![]);
/// assert_eq!(big_uint_to_bytes(&BigUint::from(1u8)),    vec![0x01]);
/// assert_eq!(big_uint_to_bytes(&BigUint::from(256u16)), vec![0x01, 0x00]);
/// ```
pub fn big_uint_to_bytes(n: &BigUint) -> Vec<u8> {
    use num_traits::Zero;
    if n.is_zero() {
        return vec![];
    }
    n.to_bytes_be()
}

/// Converts a big-endian byte slice to a [`BigUint`].
///
/// # Examples
/// ```
/// use num_bigint::BigUint;
/// use dmrtd::utils::bytes_to_big_uint;
/// assert_eq!(bytes_to_big_uint(&[]),           BigUint::from(0u8));
/// assert_eq!(bytes_to_big_uint(&[0x01]),       BigUint::from(1u8));
/// assert_eq!(bytes_to_big_uint(&[0x01, 0x00]), BigUint::from(256u16));
/// ```
pub fn bytes_to_big_uint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// Converts a little-endian byte slice to a [`BigUint`].
pub fn bytes_to_big_uint_le(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // bit_count
    // -----------------------------------------------------------------------

    #[test]
    fn bit_count_zero() {
        assert_eq!(bit_count(0), 0);
    }

    #[test]
    fn bit_count_one() {
        assert_eq!(bit_count(1), 1);
    }

    #[test]
    fn bit_count_two() {
        assert_eq!(bit_count(2), 2);
    }

    #[test]
    fn bit_count_three() {
        assert_eq!(bit_count(3), 2);
    }

    #[test]
    fn bit_count_255() {
        assert_eq!(bit_count(255), 8);
    }

    #[test]
    fn bit_count_256() {
        assert_eq!(bit_count(256), 9);
    }

    #[test]
    fn bit_count_max_u64() {
        assert_eq!(bit_count(u64::MAX), 64);
    }

    // -----------------------------------------------------------------------
    // byte_count
    // -----------------------------------------------------------------------

    #[test]
    fn byte_count_zero() {
        assert_eq!(byte_count(0), 0);
    }

    #[test]
    fn byte_count_one() {
        assert_eq!(byte_count(1), 1);
    }

    #[test]
    fn byte_count_ff() {
        assert_eq!(byte_count(0xFF), 1);
    }

    #[test]
    fn byte_count_100() {
        assert_eq!(byte_count(0x100), 2);
    }

    #[test]
    fn byte_count_ffff() {
        assert_eq!(byte_count(0xFFFF), 2);
    }

    #[test]
    fn byte_count_10000() {
        assert_eq!(byte_count(0x10000), 3);
    }

    #[test]
    fn byte_count_ffffff() {
        assert_eq!(byte_count(0xFFFFFF), 3);
    }

    // -----------------------------------------------------------------------
    // int_to_bin
    // -----------------------------------------------------------------------

    #[test]
    fn int_to_bin_zero_min1() {
        assert_eq!(int_to_bin(0, 1), vec![0x00]);
    }

    #[test]
    fn int_to_bin_zero_min0() {
        assert_eq!(int_to_bin(0, 0), vec![]);
    }

    #[test]
    fn int_to_bin_one_min1() {
        assert_eq!(int_to_bin(1, 1), vec![0x01]);
    }

    #[test]
    fn int_to_bin_one_min0() {
        assert_eq!(int_to_bin(1, 0), vec![0x01]);
    }

    #[test]
    fn int_to_bin_0x100_min1() {
        assert_eq!(int_to_bin(0x100, 1), vec![0x01, 0x00]);
    }

    #[test]
    fn int_to_bin_four_min0() {
        assert_eq!(int_to_bin(4, 0), vec![0x04]);
    }

    #[test]
    fn int_to_bin_0x12_min0() {
        assert_eq!(int_to_bin(0x12, 0), vec![0x12]);
    }

    #[test]
    fn int_to_bin_0xff_min2() {
        // Only 1 significant byte, but min_len=2 → left-pad with 0x00
        assert_eq!(int_to_bin(0xFF, 2), vec![0x00, 0xFF]);
    }

    #[test]
    fn int_to_bin_0x0001_min1() {
        assert_eq!(int_to_bin(0x0001, 1), vec![0x01]);
    }

    #[test]
    fn int_to_bin_0xffff_min1() {
        assert_eq!(int_to_bin(0xFFFF, 1), vec![0xFF, 0xFF]);
    }

    #[test]
    fn int_to_bin_large_value() {
        // 0x01_0000_0000 → 5 bytes big-endian
        assert_eq!(
            int_to_bin(0x01_0000_0000, 1),
            vec![0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn int_to_bin_min_len_forces_padding() {
        // n=1 (1 byte), min_len=4 → [0x00, 0x00, 0x00, 0x01]
        assert_eq!(int_to_bin(1, 4), vec![0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn int_to_bin_default_min1_nonzero() {
        assert_eq!(int_to_bin(255, 1), vec![0xFF]);
    }

    // -----------------------------------------------------------------------
    // big_uint_to_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn big_uint_to_bytes_zero() {
        // Matches the bigIntToUint8List(BigInt.zero) which returns an empty list
        // (bitLength = 0 → ByteData(0) → empty Uint8List).
        // Note: num-bigint's to_bytes_be() would return [0], but we special-case zero.
        assert_eq!(big_uint_to_bytes(&BigUint::from(0u8)), vec![]);
    }

    #[test]
    fn big_uint_to_bytes_one() {
        assert_eq!(big_uint_to_bytes(&BigUint::from(1u8)), vec![0x01]);
    }

    #[test]
    fn big_uint_to_bytes_256() {
        assert_eq!(big_uint_to_bytes(&BigUint::from(256u16)), vec![0x01, 0x00]);
    }

    #[test]
    fn big_uint_to_bytes_large() {
        let n = BigUint::from(0xDEADBEEFu64);
        assert_eq!(big_uint_to_bytes(&n), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // -----------------------------------------------------------------------
    // bytes_to_big_uint
    // -----------------------------------------------------------------------

    #[test]
    fn bytes_to_big_uint_empty() {
        assert_eq!(bytes_to_big_uint(&[]), BigUint::from(0u8));
    }

    #[test]
    fn bytes_to_big_uint_one() {
        assert_eq!(bytes_to_big_uint(&[0x01]), BigUint::from(1u8));
    }

    #[test]
    fn bytes_to_big_uint_256() {
        assert_eq!(bytes_to_big_uint(&[0x01, 0x00]), BigUint::from(256u16));
    }

    #[test]
    fn bytes_to_big_uint_roundtrip() {
        let original = BigUint::from(0xDEADBEEF_CAFEBABEu64);
        let bytes = big_uint_to_bytes(&original);
        let recovered = bytes_to_big_uint(&bytes);
        assert_eq!(recovered, original);
    }

    // -----------------------------------------------------------------------
    // bytes_to_big_uint_le
    // -----------------------------------------------------------------------

    #[test]
    fn bytes_to_big_uint_le_basic() {
        // [0x01, 0x00] in little-endian = 1
        assert_eq!(bytes_to_big_uint_le(&[0x01, 0x00]), BigUint::from(1u8));
    }

    #[test]
    fn bytes_to_big_uint_le_empty() {
        assert_eq!(bytes_to_big_uint_le(&[]), BigUint::from(0u8));
    }
}
