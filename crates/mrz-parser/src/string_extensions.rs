/// Utilities for MRZ-specific string operations: validation, trimming a
/// specific character, and OCR-friendly character replacements commonly used
/// when processing MRZ zones.
///
/// These functions are intentionally simple and avoid heap allocations where
/// possible, but return owned `String` when a transformed string is required.

/// Return `true` if `s` contains only valid MRZ characters:
/// uppercase A-Z, digits 0-9, or the filler '<'.
pub fn is_valid_mrz_input(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '<')
}

/// Trim leading and trailing occurrences of the single character `ch` from
/// `input`. Returns an owned `String`.
///
/// Example:
/// - `trim_char("<<ABC<<", '<') -> "ABC"`
pub fn trim_char(input: &str, ch: char) -> String {
    input.trim_matches(ch).to_string()
}

/// Replace digits that commonly get misrecognized as letters by OCR:
/// - '0' -> 'O'
/// - '1' -> 'I'
/// - '2' -> 'Z'
/// - '8' -> 'B'
pub fn replace_similar_digits_with_letters(input: &str) -> String {
    // Small transformation — build a new String
    input
        .chars()
        .map(|c| match c {
            '0' => 'O',
            '1' => 'I',
            '2' => 'Z',
            '8' => 'B',
            other => other,
        })
        .collect()
}

/// Replace letters that commonly get misrecognized as digits by OCR:
/// - 'O','o','Q','q','U','u','D','d' -> '0'
/// - 'I','i' -> '1'
/// - 'Z','z' -> '2'
/// - 'B','b' -> '8'
pub fn replace_similar_letters_with_digits(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'O' | 'o' | 'Q' | 'q' | 'U' | 'u' | 'D' | 'd' => '0',
            'I' | 'i' => '1',
            'Z' | 'z' => '2',
            'B' | 'b' => '8',
            other => other,
        })
        .collect()
}

/// Replace MRZ angle brackets '<' with spaces.
pub fn replace_angle_brackets_with_spaces(input: &str) -> String {
    // Use simple replace; MRZ fields are small.
    if input.contains('<') {
        input.replace('<', " ")
    } else {
        input.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_mrz_inputs() {
        assert!(is_valid_mrz_input("ABCDE<12345"));
        assert!(is_valid_mrz_input("<<<<<<<<"));
        assert!(!is_valid_mrz_input("lowercase"));
        assert!(!is_valid_mrz_input("HAS SPACE"));
        assert!(!is_valid_mrz_input("!@#"));
    }

    #[test]
    fn trim_char_basic() {
        assert_eq!(trim_char("<<ABC<<", '<'), "ABC");
        assert_eq!(trim_char("ABC", '<'), "ABC");
        assert_eq!(trim_char("<<<<", '<'), "");
        assert_eq!(trim_char("", '<'), "");
    }

    #[test]
    fn replace_digits_with_letters() {
        assert_eq!(
            replace_similar_digits_with_letters("0 1 2 8 ABC"),
            "O I Z B ABC"
        );
        assert_eq!(
            replace_similar_digits_with_letters("123"),
            "IZ3".replace('3', "3")
        );
    }

    #[test]
    fn replace_letters_with_digits() {
        // O→0, Q→0, U→0, I→1, D→0, Z→2, B→8 (both cases)
        assert_eq!(
            replace_similar_letters_with_digits("OQUIDZB oquidzb"),
            "0001028 0001028"
        );
        // 'B' maps to '8', so "ABC123" => "A8C123"
        assert_eq!(replace_similar_letters_with_digits("ABC123"), "A8C123");
    }

    #[test]
    fn replace_angle_brackets() {
        assert_eq!(replace_angle_brackets_with_spaces("A<B<C"), "A B C");
        assert_eq!(replace_angle_brackets_with_spaces("NOANGLE"), "NOANGLE");
    }
}
