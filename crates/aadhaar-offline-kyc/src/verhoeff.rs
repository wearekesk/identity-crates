//! Aadhaar number syntax validation via the Verhoeff checksum.
//!
//! UIDAI Aadhaar numbers are 12 digits whose final digit is a Verhoeff check
//! digit (and the leading digit is 2–9, never 0 or 1). This validates the
//! *syntax* of a number string — it does NOT prove the number was issued.

/// Verhoeff dihedral-group multiplication (`d`) table.
const D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

/// Verhoeff permutation (`p`) table, indexed by `position % 8`.
const P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Validates a 12-digit Aadhaar number string using the Verhoeff algorithm.
///
/// Returns `true` only when `aadhaar` is exactly 12 ASCII digits, the leading
/// digit is in `2..=9` (UIDAI never issues numbers starting with 0 or 1), and
/// the Verhoeff checksum over the whole number is 0.
///
/// This is a syntactic check, not proof of issuance.
pub fn validate_aadhaar_syntax(aadhaar: &str) -> bool {
    let bytes = aadhaar.as_bytes();
    // Exactly 12 digits, leading digit 2–9, the rest 0–9.
    if bytes.len() != 12 || !(b'2'..=b'9').contains(&bytes[0]) {
        return false;
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return false;
    }

    let mut c = 0usize;
    // Process digits from least- to most-significant.
    for (i, &b) in bytes.iter().rev().enumerate() {
        let digit = (b - b'0') as usize;
        c = D[c][P[i % 8][digit] as usize] as usize;
    }
    c == 0
}

#[cfg(test)]
mod tests {
    use super::validate_aadhaar_syntax;

    #[test]
    fn accepts_valid_verhoeff_numbers() {
        // Known Verhoeff-valid 12-digit Aadhaar specimens (checksum == 0).
        assert!(validate_aadhaar_syntax("234123412346"));
        assert!(validate_aadhaar_syntax("999941057058"));
    }

    #[test]
    fn rejects_wrong_checksum() {
        // Last digit altered -> checksum no longer 0.
        assert!(!validate_aadhaar_syntax("234123412347"));
        assert!(!validate_aadhaar_syntax("999941057059"));
    }

    #[test]
    fn rejects_bad_format() {
        assert!(!validate_aadhaar_syntax("")); // empty
        assert!(!validate_aadhaar_syntax("23412341234")); // 11 digits
        assert!(!validate_aadhaar_syntax("2341234123466")); // 13 digits
        assert!(!validate_aadhaar_syntax("034123412346")); // leading 0
        assert!(!validate_aadhaar_syntax("134123412346")); // leading 1
        assert!(!validate_aadhaar_syntax("23412341234A")); // non-digit
        assert!(!validate_aadhaar_syntax("2341 23412346")); // space / wrong len
    }
}
