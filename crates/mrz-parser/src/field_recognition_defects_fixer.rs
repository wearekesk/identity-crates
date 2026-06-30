/// Utilities to fix common OCR/recognition defects in MRZ fields.
///
/// Each function accepts an MRZ-like input string and returns a corrected String.
///
/// Replacements are intentionally conservative and target characters commonly
/// misrecognized by OCR engines when reading MRZ zones (ASCII uppercase and digits).
///
/// The actual character-substitution helpers live in [`crate::string_extensions`];
/// this type is a thin, field-oriented facade over them.
use crate::string_extensions::{
    replace_similar_digits_with_letters, replace_similar_letters_with_digits,
};

pub struct MRZFieldRecognitionDefectsFixer;

impl MRZFieldRecognitionDefectsFixer {
    /// Replace digits that are commonly misrecognized for letters.
    ///
    /// Mapping (applied left-to-right, character-by-character):
    /// - '0' -> 'O'
    /// - '1' -> 'I'
    /// - '2' -> 'Z'
    /// - '8' -> 'B'
    pub fn fix_document_type(input: &str) -> String {
        replace_similar_digits_with_letters(input)
    }

    /// Replace letters that are commonly misrecognized for digits.
    ///
    /// Mapping (case-insensitive for letters):
    /// - 'O','o' -> '0'
    /// - 'Q','q' -> '0'
    /// - 'U','u' -> '0'
    /// - 'D','d' -> '0'
    /// - 'I','i' -> '1'
    /// - 'Z','z' -> '2'
    /// - 'B','b' -> '8'
    pub fn fix_check_digit(input: &str) -> String {
        replace_similar_letters_with_digits(input)
    }

    /// Fix dates by converting misrecognized letters into digits (same as check digit fixer).
    pub fn fix_date(input: &str) -> String {
        replace_similar_letters_with_digits(input)
    }

    /// Fix sex field misrecognition: convert 'P' (and lowercase 'p') to 'F'.
    ///
    /// Both cases map to the uppercase `F` the sex parser expects, so a
    /// lowercase OCR result is still accepted.
    pub fn fix_sex(input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                'P' | 'p' => 'F',
                other => other,
            })
            .collect()
    }

    /// Fix country code by replacing digits misrecognized as letters (same as document type fixer).
    pub fn fix_country_code(input: &str) -> String {
        replace_similar_digits_with_letters(input)
    }

    /// Fix names by replacing digits misrecognized as letters.
    pub fn fix_names(input: &str) -> String {
        replace_similar_digits_with_letters(input)
    }

    /// Fix nationality by replacing digits misrecognized as letters.
    pub fn fix_nationality(input: &str) -> String {
        replace_similar_digits_with_letters(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_similar_digits_with_letters() {
        assert_eq!(
            replace_similar_digits_with_letters("0 1 2 8 ABC"),
            "O I Z B ABC"
        );
        // unchanged characters stay the same
        assert_eq!(
            replace_similar_digits_with_letters("MRZ<123"),
            "MRZ<IZ3".replace('3', "3")
        );
    }

    #[test]
    fn test_replace_similar_letters_with_digits() {
        assert_eq!(
            replace_similar_letters_with_digits("OQUIDZB oquidzb"),
            "0001028 0001028"
        );
        // 'B' maps to '8'; other characters unchanged
        assert_eq!(replace_similar_letters_with_digits("ABC123"), "A8C123");
    }

    #[test]
    fn test_fix_sex() {
        assert_eq!(MRZFieldRecognitionDefectsFixer::fix_sex("P"), "F");
        assert_eq!(MRZFieldRecognitionDefectsFixer::fix_sex("p"), "F");
        assert_eq!(MRZFieldRecognitionDefectsFixer::fix_sex("M"), "M");
    }

    #[test]
    fn roundtrip_example_document_type() {
        let input = "1P0"; // OCR produced digits where letters are expected
        let fixed = MRZFieldRecognitionDefectsFixer::fix_document_type(input);
        assert_eq!(fixed, "IPO");
    }

    #[test]
    fn fix_check_date_example() {
        let input = "OIZB"; // letters misread where digits expected
        let fixed = MRZFieldRecognitionDefectsFixer::fix_check_digit(input);
        assert_eq!(fixed, "0128");
    }
}
