//! Cryptographic utilities.
//!
//! Provides a [`random_bytes`] function that generates cryptographically secure
//! random bytes using the `rand` crate, mirroring the reference:
//!
//! ```dart
//! Uint8List randomBytes(int length) {
//!   final random = Random.secure();
//!   var intBytes = List<int>.generate(length, (i) => random.nextInt(256));
//!   return Uint8List.fromList(intBytes);
//! }
//! ```

use rand::RngCore;

/// Generates `length` cryptographically secure random bytes.
///
/// Uses [`rand::rngs::OsRng`] as the underlying source, which delegates to the
/// OS entropy source (e.g. `getrandom` / `/dev/urandom` on Linux, `BCryptGenRandom`
/// on Windows).
///
/// # Panics
/// Panics if the OS random source is unavailable (extremely rare / OS fault).
///
/// # Examples
/// ```
/// use dmrtd::crypto::crypto_utils::random_bytes;
///
/// let bytes = random_bytes(16);
/// assert_eq!(bytes.len(), 16);
///
/// // Two successive calls should (with overwhelming probability) differ
/// let a = random_bytes(8);
/// let b = random_bytes(8);
/// // Not asserting inequality because the probability of collision is 1/2^64
/// // and we don't want a flaky test, but in practice they will always differ.
/// let _ = (a, b);
/// ```
pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_correct_length() {
        for len in [0, 1, 8, 16, 32, 64, 255] {
            let bytes = random_bytes(len);
            assert_eq!(bytes.len(), len, "Expected {len} bytes");
        }
    }

    #[test]
    fn zero_length_returns_empty() {
        let bytes = random_bytes(0);
        assert!(bytes.is_empty());
    }

    #[test]
    fn not_all_zeros_for_reasonable_length() {
        // The probability of 32 random bytes all being zero is 1/2^256 ≈ 0.
        let bytes = random_bytes(32);
        assert!(
            bytes.iter().any(|&b| b != 0),
            "32 random bytes were all zero – RNG may be broken"
        );
    }

    #[test]
    fn consecutive_calls_differ() {
        // The probability of two independent 16-byte draws being equal is 1/2^128 ≈ 0.
        let a = random_bytes(16);
        let b = random_bytes(16);
        assert_ne!(
            a, b,
            "Two consecutive 16-byte draws were identical – RNG may be broken"
        );
    }

    #[test]
    fn large_buffer() {
        let bytes = random_bytes(4096);
        assert_eq!(bytes.len(), 4096);
    }
}
