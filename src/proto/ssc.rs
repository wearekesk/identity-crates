//! Send Sequence Counter (SSC) implementation.
//!
//! The SSC is an unsigned big integer whose bit size equals the block size of
//! the chosen block cipher (64 bits for 3DES, 128 bits for AES).
//!
//! On every protected APDU exchange (protect or unprotect) the counter is
//! incremented by one.  When the counter overflows its bit size it wraps to
//! zero, mirroring the reference.
//!
//! # ICAO reference
//! ICAO Doc 9303 Part 11, Section 9.8.2
//!
//! # Concrete sub-types
//! - [`DESedeSSC`]     – 64-bit SSC for 3DES Secure Messaging (BAC)
//! - [`DESedePaceSSC`] – 64-bit SSC for 3DES PACE (starts at zero)
//! - [`AesSSC`]        – 128-bit SSC for AES Secure Messaging (PACE)

use thiserror::Error;

// ---------------------------------------------------------------------------
// Block sizes (in bits, matching the reference constants)
// ---------------------------------------------------------------------------

/// Block size of DES/3DES in bits (64 bits = 8 bytes).
pub const DESEDE_BLOCK_BITS: usize = 64;

/// Block size of AES in bits (128 bits = 16 bytes).
pub const AES_BLOCK_BITS: usize = 128;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error returned when constructing an [`Ssc`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SscError {
    /// `bit_size` must be a multiple of 8.
    #[error("bit_size ({0}) must be a multiple of 8")]
    BitSizeNotMultipleOf8(usize),

    /// `bit_size` exceeds the 128-bit counter width supported by the backing
    /// `u128` representation.
    #[error("bit_size ({0}) exceeds the maximum supported width of 128 bits")]
    BitSizeTooLarge(usize),

    /// The provided initial value exceeds the declared `bit_size`.
    #[error(
        "initial SSC value ({value_bits} bits) exceeds the declared bit_size ({bit_size} bits)"
    )]
    ValueTooLarge { value_bits: usize, bit_size: usize },
}

// ---------------------------------------------------------------------------
// Ssc
// ---------------------------------------------------------------------------

/// Send Sequence Counter.
///
/// An unsigned integer whose bit width is fixed to `bit_size`.  Incrementing
/// past the maximum value wraps around to zero.
///
/// # Examples
/// ```
/// use dmrtd::proto::ssc::Ssc;
///
/// let mut ssc = Ssc::new(&[0x00], 8).unwrap();
/// assert_eq!(ssc.to_bytes(), vec![0x00]);
/// ssc.increment();
/// assert_eq!(ssc.to_bytes(), vec![0x01]);
/// ```
#[derive(Debug, Clone)]
pub struct Ssc {
    /// Current counter value. The SSC is at most 128 bits wide (AES block
    /// size), so a stack-allocated `u128` holds it without any heap allocation
    /// — important because the counter is incremented on every APDU exchange.
    value: u128,
    /// Maximum allowed bit width of the counter.
    pub bit_size: usize,
}

impl Ssc {
    /// Creates a new [`Ssc`] initialised to the value encoded by `ssc` bytes
    /// (big-endian).
    ///
    /// # Arguments
    /// - `ssc`      – Initial value as a big-endian byte slice.  Leading zero
    ///                bytes are permitted (they are stripped when interpreting
    ///                the value, but the result must still fit in `bit_size` bits).
    /// - `bit_size` – Counter width in bits.  Must be a multiple of 8.
    ///
    /// # Errors
    /// - [`SscError::BitSizeNotMultipleOf8`] if `bit_size % 8 != 0`.
    /// - [`SscError::ValueTooLarge`] if the decoded value requires more than
    ///   `bit_size` bits.
    ///
    /// # Examples
    /// ```
    /// use dmrtd::proto::ssc::{Ssc, SscError};
    ///
    /// // Valid: 8-bit counter initialised to 0
    /// assert!(Ssc::new(&[0x00], 8).is_ok());
    ///
    /// // Error: bit_size not a multiple of 8
    /// assert!(matches!(Ssc::new(&[0x00], 7), Err(SscError::BitSizeNotMultipleOf8(7))));
    ///
    /// // Error: value too large for bit_size
    /// assert!(Ssc::new(&[0x01, 0x00], 8).is_err()); // 0x100 > 8-bit max
    /// ```
    pub fn new(ssc: &[u8], bit_size: usize) -> Result<Self, SscError> {
        if bit_size % 8 != 0 {
            return Err(SscError::BitSizeNotMultipleOf8(bit_size));
        }
        if bit_size > 128 {
            return Err(SscError::BitSizeTooLarge(bit_size));
        }

        // Fold the big-endian bytes into a u128. Leading zero bytes are
        // permitted; any value whose magnitude exceeds 128 bits cannot be held.
        let mut value: u128 = 0;
        for &b in ssc {
            if value > (u128::MAX >> 8) {
                return Err(SscError::ValueTooLarge {
                    value_bits: 129,
                    bit_size,
                });
            }
            value = (value << 8) | b as u128;
        }

        // Check that the value fits in `bit_size` bits (0 always fits).
        let value_bits = (128 - value.leading_zeros()) as usize;
        if value_bits > bit_size {
            return Err(SscError::ValueTooLarge {
                value_bits,
                bit_size,
            });
        }

        Ok(Self { value, bit_size })
    }

    /// Creates a zero-valued [`Ssc`] with the given `bit_size`.
    ///
    /// # Panics
    /// Panics if `bit_size % 8 != 0`.
    pub fn zeroed(bit_size: usize) -> Self {
        Self::new(&vec![0u8; bit_size / 8], bit_size)
            .expect("zeroed SSC: bit_size must be a multiple of 8")
    }

    /// Increments the counter by one, wrapping to zero on overflow.
    ///
    /// Overflow occurs when the counter reaches `2^bit_size`, at which point
    /// it is reset to zero.
    ///
    /// # Examples
    /// ```
    /// use dmrtd::proto::ssc::Ssc;
    ///
    /// // Overflow wrap-around
    /// let mut ssc = Ssc::new(&[0xFF], 8).unwrap();
    /// ssc.increment();
    /// assert_eq!(ssc.to_bytes(), vec![0x00]);
    ///
    /// // Normal increment
    /// let mut ssc = Ssc::new(&[0xFE], 8).unwrap();
    /// ssc.increment();
    /// assert_eq!(ssc.to_bytes(), vec![0xFF]);
    /// ```
    pub fn increment(&mut self) {
        // Wrapping add handles the full 128-bit case; for narrower counters we
        // mask back down to `bit_size` bits so the counter wraps at 2^bit_size.
        self.value = self.value.wrapping_add(1);
        if self.bit_size < 128 {
            let mask = (1u128 << self.bit_size) - 1;
            self.value &= mask;
        }
    }

    /// Returns the current counter value as a big-endian byte slice of exactly
    /// `bit_size / 8` bytes, zero-padded on the left.
    ///
    /// # Examples
    /// ```
    /// use dmrtd::proto::ssc::Ssc;
    ///
    /// let ssc = Ssc::new(&[0x01], 16).unwrap();
    /// // 16-bit counter → always 2 bytes
    /// assert_eq!(ssc.to_bytes(), vec![0x00, 0x01]);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let byte_len = self.bit_size / 8;
        // The value never exceeds `bit_size` bits, so the most-significant
        // `16 - byte_len` bytes of the big-endian encoding are always zero.
        self.value.to_be_bytes()[16 - byte_len..].to_vec()
    }
}

// ---------------------------------------------------------------------------
// Specialised SSC types (mirrors sub-classes)
// ---------------------------------------------------------------------------

/// 64-bit SSC for 3DES Secure Messaging (used in BAC).
///
/// # Examples
/// ```
/// use dmrtd::proto::ssc::DesedeSSC;
///
/// let mut ssc = DesedeSSC::new(&[0x88, 0x70, 0x22, 0x12, 0x0C, 0x06, 0xC2, 0x26]).unwrap();
/// assert_eq!(ssc.to_bytes(), vec![0x88, 0x70, 0x22, 0x12, 0x0C, 0x06, 0xC2, 0x26]);
/// ssc.increment();
/// assert_eq!(ssc.to_bytes(), vec![0x88, 0x70, 0x22, 0x12, 0x0C, 0x06, 0xC2, 0x27]);
/// ```
#[derive(Debug, Clone)]
pub struct DesedeSSC(pub Ssc);

impl DesedeSSC {
    /// Creates a [`DesedeSSC`] from an 8-byte initial value.
    ///
    /// # Errors
    /// Returns [`SscError::ValueTooLarge`] if `ssc` decodes to a value that
    /// requires more than 64 bits.
    pub fn new(ssc: &[u8]) -> Result<Self, SscError> {
        Ok(Self(Ssc::new(ssc, DESEDE_BLOCK_BITS)?))
    }

    /// Increments the counter.
    pub fn increment(&mut self) {
        self.0.increment();
    }

    /// Returns the counter value as 8 bytes (big-endian, zero-padded).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Returns the underlying bit size.
    pub fn bit_size(&self) -> usize {
        self.0.bit_size
    }
}

/// 64-bit SSC for 3DES PACE, initialised to all-zero bytes.
///
/// # Examples
/// ```
/// use dmrtd::proto::ssc::DesedePaceSSC;
///
/// let mut ssc = DesedePaceSSC::new();
/// assert_eq!(ssc.to_bytes(), vec![0x00; 8]);
/// ssc.increment();
/// assert_eq!(ssc.to_bytes(), vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
/// ```
#[derive(Debug, Clone)]
pub struct DesedePaceSSC(pub Ssc);

impl DesedePaceSSC {
    /// Creates a zero-valued 64-bit PACE SSC.
    pub fn new() -> Self {
        Self(Ssc::zeroed(DESEDE_BLOCK_BITS))
    }

    /// Increments the counter.
    pub fn increment(&mut self) {
        self.0.increment();
    }

    /// Returns the counter value as 8 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl Default for DesedePaceSSC {
    fn default() -> Self {
        Self::new()
    }
}

/// 128-bit SSC for AES Secure Messaging (PACE), initialised to zero.
///
/// As specified in ICAO 9303 Part 11 Section 9.8.7.3.
///
/// # Examples
/// ```
/// use dmrtd::proto::ssc::AesSSC;
///
/// let mut ssc = AesSSC::new();
/// assert_eq!(ssc.to_bytes(), vec![0x00; 16]);
/// ssc.increment();
/// let mut expected = vec![0x00; 15];
/// expected.push(0x01);
/// assert_eq!(ssc.to_bytes(), expected);
/// ```
#[derive(Debug, Clone)]
pub struct AesSSC(pub Ssc);

impl AesSSC {
    /// Creates a zero-valued 128-bit AES SSC.
    pub fn new() -> Self {
        Self(Ssc::zeroed(AES_BLOCK_BITS))
    }

    /// Increments the counter.
    pub fn increment(&mut self) {
        self.0.increment();
    }

    /// Returns the counter value as 16 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl Default for AesSSC {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Construction errors
    // -----------------------------------------------------------------------

    #[test]
    fn error_bit_size_not_multiple_of_8() {
        assert!(matches!(
            Ssc::new(&[0x00], 7),
            Err(SscError::BitSizeNotMultipleOf8(7))
        ));
    }

    #[test]
    fn error_value_too_large() {
        // 0x0100 needs 9 bits, but bit_size = 8
        let result = Ssc::new(&[0x01, 0x00], 8);
        assert!(matches!(result, Err(SscError::ValueTooLarge { .. })));
    }

    #[test]
    fn valid_value_just_fitting() {
        // 0xFF needs exactly 8 bits
        assert!(Ssc::new(&[0xFF], 8).is_ok());
    }

    // -----------------------------------------------------------------------
    // ICAO test case 1 – 8-bit zero
    // -----------------------------------------------------------------------

    #[test]
    fn tc1_8bit_zero() {
        let ssc = Ssc::new(&[0x00], 8).unwrap();
        assert_eq!(ssc.to_bytes(), vec![0x00]);
    }

    // -----------------------------------------------------------------------
    // ICAO test case 2 – 16-bit, value 1
    // -----------------------------------------------------------------------

    #[test]
    fn tc2_16bit_one() {
        let ssc = Ssc::new(&[0x01], 16).unwrap();
        assert_eq!(ssc.to_bytes(), vec![0x00, 0x01]);
    }

    // -----------------------------------------------------------------------
    // ICAO test case 3 – 16-bit, value 0xFF, increment to 0x100
    // -----------------------------------------------------------------------

    #[test]
    fn tc3_16bit_ff_then_100() {
        let mut ssc = Ssc::new(&[0xFF], 16).unwrap();
        assert_eq!(ssc.to_bytes(), vec![0x00, 0xFF]);

        ssc.increment();
        assert_eq!(ssc.to_bytes(), vec![0x01, 0x00]);
    }

    // -----------------------------------------------------------------------
    // ICAO test case 4 – 16-bit overflow: 0xFFFF + 1 → 0x0000
    // -----------------------------------------------------------------------

    #[test]
    fn tc4_16bit_overflow() {
        let mut ssc = Ssc::new(&[0xFF, 0xFF], 16).unwrap();
        ssc.increment();
        assert_eq!(ssc.to_bytes(), vec![0x00, 0x00]);
    }

    // -----------------------------------------------------------------------
    // ICAO test case 5 – 64-bit counter, increment
    // -----------------------------------------------------------------------

    #[test]
    fn tc5_64bit_increment() {
        let bytes = hex::decode("02FFFFFFFFFFFF01").unwrap();
        let mut ssc = Ssc::new(&bytes, 64).unwrap();
        assert_eq!(ssc.to_bytes(), bytes);

        ssc.increment();
        let expected = hex::decode("02FFFFFFFFFFFF02").unwrap();
        assert_eq!(ssc.to_bytes(), expected);
    }

    // -----------------------------------------------------------------------
    // ICAO test case 6 – 64-bit, two increments cause overflow
    // -----------------------------------------------------------------------

    #[test]
    fn tc6_64bit_overflow() {
        let bytes = hex::decode("FFFFFFFFFFFFFFFE").unwrap();
        let mut ssc = Ssc::new(&bytes, 64).unwrap();
        ssc.increment(); // → 0xFFFFFFFFFFFFFFFF
        ssc.increment(); // → overflow → 0x0000000000000000
        assert_eq!(ssc.to_bytes(), vec![0x00; 8]);
    }

    // -----------------------------------------------------------------------
    // ICAO test case 7 – 128-bit counter, two increments
    // -----------------------------------------------------------------------

    #[test]
    fn tc7_128bit_two_increments() {
        let init = hex::decode("0102030405060708090A0B0C0D0E0FFE").unwrap();
        let mut ssc = Ssc::new(&init, 128).unwrap();
        assert_eq!(ssc.to_bytes(), init);

        ssc.increment();
        let expected = hex::decode("0102030405060708090A0B0C0D0E0FFF").unwrap();
        assert_eq!(ssc.to_bytes(), expected);

        ssc.increment();
        let expected2 = hex::decode("0102030405060708090A0B0C0D0E1000").unwrap();
        assert_eq!(ssc.to_bytes(), expected2);
    }

    // -----------------------------------------------------------------------
    // ICAO test case 8 – 128-bit, carry propagation
    // -----------------------------------------------------------------------

    #[test]
    fn tc8_128bit_carry() {
        let init = hex::decode("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        let mut ssc = Ssc::new(&init, 128).unwrap();
        assert_eq!(ssc.to_bytes(), init);

        ssc.increment();
        let expected = hex::decode("02000000000000000000000000000000").unwrap();
        assert_eq!(ssc.to_bytes(), expected);
    }

    // -----------------------------------------------------------------------
    // ICAO test case 9 – 128-bit overflow
    // -----------------------------------------------------------------------

    #[test]
    fn tc9_128bit_overflow() {
        let init = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        let mut ssc = Ssc::new(&init, 128).unwrap();
        assert_eq!(ssc.to_bytes(), init);

        ssc.increment();
        assert_eq!(ssc.to_bytes(), vec![0x00; 16]);
    }

    // -----------------------------------------------------------------------
    // ICAO test case 10 – leading zero bytes in initial value are fine
    // -----------------------------------------------------------------------

    #[test]
    fn tc10_leading_zeros_accepted() {
        // 0x0000000000000000000000000001 for an 8-bit SSC
        // In the reference: SSC('0000000000000000000000000001'.parseHex(), 8)
        // The actual value is 1, which fits in 8 bits.
        let bytes = hex::decode("0000000000000000000000000001").unwrap();
        let ssc = Ssc::new(&bytes, 8).unwrap();
        assert_eq!(ssc.to_bytes(), vec![0x01]);
    }

    // -----------------------------------------------------------------------
    // ICAO test case 11 – DESedeSSC ICAO D.4 vectors
    // -----------------------------------------------------------------------

    #[test]
    fn tc11_desede_ssc_icao_d4() {
        let init = hex::decode("887022120C06C226").unwrap();
        let mut ssc = DesedeSSC::new(&init).unwrap();
        assert_eq!(ssc.to_bytes(), init);

        ssc.increment();
        assert_eq!(ssc.to_bytes(), hex::decode("887022120C06C227").unwrap());

        ssc.increment();
        assert_eq!(ssc.to_bytes(), hex::decode("887022120C06C228").unwrap());

        ssc.increment();
        assert_eq!(ssc.to_bytes(), hex::decode("887022120C06C229").unwrap());

        ssc.increment();
        assert_eq!(ssc.to_bytes(), hex::decode("887022120C06C22A").unwrap());

        ssc.increment();
        assert_eq!(ssc.to_bytes(), hex::decode("887022120C06C22B").unwrap());

        ssc.increment();
        assert_eq!(ssc.to_bytes(), hex::decode("887022120C06C22C").unwrap());
    }

    // -----------------------------------------------------------------------
    // DESedeSSC – basic properties
    // -----------------------------------------------------------------------

    #[test]
    fn desede_ssc_is_64_bits() {
        let ssc = DesedeSSC::new(&[0x00; 8]).unwrap();
        assert_eq!(ssc.bit_size(), 64);
        assert_eq!(ssc.to_bytes().len(), 8);
    }

    // -----------------------------------------------------------------------
    // DESedePaceSSC – initialised to zero
    // -----------------------------------------------------------------------

    #[test]
    fn desede_pace_ssc_starts_at_zero() {
        let ssc = DesedePaceSSC::new();
        assert_eq!(ssc.to_bytes(), vec![0x00; 8]);
    }

    #[test]
    fn desede_pace_ssc_increment() {
        let mut ssc = DesedePaceSSC::new();
        ssc.increment();
        let mut expected = vec![0x00; 7];
        expected.push(0x01);
        assert_eq!(ssc.to_bytes(), expected);
    }

    // -----------------------------------------------------------------------
    // AesSSC – initialised to zero, 128 bits
    // -----------------------------------------------------------------------

    #[test]
    fn aes_ssc_starts_at_zero() {
        let ssc = AesSSC::new();
        assert_eq!(ssc.to_bytes(), vec![0x00; 16]);
    }

    #[test]
    fn aes_ssc_increment() {
        let mut ssc = AesSSC::new();
        ssc.increment();
        let mut expected = vec![0x00; 15];
        expected.push(0x01);
        assert_eq!(ssc.to_bytes(), expected);
    }

    #[test]
    fn aes_ssc_overflow() {
        // Set to max 128-bit value and increment
        let max = vec![0xFFu8; 16];
        let inner = Ssc::new(&max, 128).unwrap();
        let mut ssc = AesSSC(inner);
        ssc.increment();
        assert_eq!(ssc.to_bytes(), vec![0x00; 16]);
    }

    // -----------------------------------------------------------------------
    // Zeroed helper
    // -----------------------------------------------------------------------

    #[test]
    fn zeroed_produces_all_zero_bytes() {
        let ssc = Ssc::zeroed(64);
        assert_eq!(ssc.to_bytes(), vec![0x00; 8]);
    }

    // -----------------------------------------------------------------------
    // to_bytes always produces fixed-width output
    // -----------------------------------------------------------------------

    #[test]
    fn to_bytes_always_fixed_width() {
        // Even for value 1 in a 128-bit SSC, must produce 16 bytes
        let ssc = Ssc::new(&[0x01], 128).unwrap();
        assert_eq!(ssc.to_bytes().len(), 16);
        assert_eq!(&ssc.to_bytes()[..15], &[0x00; 15]);
        assert_eq!(ssc.to_bytes()[15], 0x01);
    }
}
