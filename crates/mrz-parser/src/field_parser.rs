use crate::exceptions::MRZError;
use crate::string_extensions::replace_angle_brackets_with_spaces;
use crate::Sex;
use chrono::{Datelike, Local, NaiveDate};

/// Utilities for parsing MRZ fields. Methods accept MRZ-style inputs (which
/// frequently include `<` as a filler) and return Rust-native types.
///
/// Date-parsing functions return `Result<NaiveDate, MRZError>` to reflect that
/// malformed input may occur; callers should handle errors as needed.
pub struct MRZFieldParser;

impl MRZFieldParser {
    pub fn parse_document_number(input: &str) -> String {
        trim(input)
    }

    pub fn parse_document_type(input: &str) -> String {
        trim(input)
    }

    pub fn parse_country_code(input: &str) -> String {
        trim(input)
    }

    pub fn parse_nationality(input: &str) -> String {
        trim(input)
    }

    pub fn parse_optional_data(input: &str) -> String {
        trim(input)
    }

    /// Parse the names field: returns a Vec with two entries:
    /// [surnames, given_names] (either may be empty strings).
    ///
    /// MRZ name field uses `<<` to separate surname and given names, and `<` as
    /// filler between name parts. We:
    /// - strip only the *trailing* filler padding (`<`), preserving any leading
    ///   `<<` so an empty surname (`<<GIVEN...`) is not mistaken for the surname
    /// - split on the first `<<` into [surname, given names]
    /// - `trim` each part (replace remaining `<` with ` ` and trim whitespace)
    pub fn parse_names(input: &str) -> Vec<String> {
        let trimmed = input.trim_end_matches('<');
        let mut parts = trimmed.splitn(2, "<<");
        let surname = trim(parts.next().unwrap_or(""));
        let given_names = trim(parts.next().unwrap_or(""));
        vec![surname, given_names]
    }

    /// Parse birth date from MRZ two-digit year format YYMMDD.
    ///
    /// The century is decided using a milestone calculated as
    /// `current_year - 2000`: if the two-digit year is greater than the
    /// milestone the year is in the 1900s, otherwise the 2000s.
    pub fn parse_birth_date(input: &str) -> Result<NaiveDate, MRZError> {
        let formatted = _format_date(input);
        let milestone = (Local::now().year() - 2000).max(0); // keep non-negative
        _parse_date(&formatted, milestone)
    }

    /// Parse expiry date from MRZ two-digit year format YYMMDD.
    ///
    /// Uses a fixed milestone of `70` for expiry dates: if `YY > 70` the
    /// century is `19xx`, otherwise `20xx`.
    pub fn parse_expiry_date(input: &str) -> Result<NaiveDate, MRZError> {
        let formatted = _format_date(input);
        _parse_date(&formatted, 70)
    }

    /// Parse sex field. 'M' => male, 'F' => female, otherwise unspecified.
    pub fn parse_sex(input: &str) -> Sex {
        match input.trim() {
            "M" => Sex::Male,
            "F" => Sex::Female,
            _ => Sex::Unspecified,
        }
    }
}

/// Replace angle-brackets with spaces and trim surrounding whitespace.
///
/// Uses the shared [`replace_angle_brackets_with_spaces`] helper from
/// [`crate::string_extensions`] so there is a single source of truth.
fn trim(input: &str) -> String {
    replace_angle_brackets_with_spaces(input).trim().to_string()
}

/// Internal helper to format the date input (currently just trimming filler).
fn _format_date(input: &str) -> String {
    trim(input)
}

/// Parse date expecting input in format YYMMDD but passed as a string with
/// only those digits (after formatting). `milestone_year` is the threshold
/// described in the comments above: if the two-digit year > milestone_year
/// then the century is 1900, otherwise 2000. Returns an MRZError on failure.
fn _parse_date(input: &str, milestone_year: i32) -> Result<NaiveDate, MRZError> {
    let s = input.trim();
    if s.len() < 6 {
        return Err(MRZError::invalid_mrz_input());
    }

    // Expecting first two characters to be the year in two-digit form.
    // Use char-safe slicing: byte indexing would panic if the (malformed)
    // input contained a multi-byte character straddling index 2.
    let yy_str = s.get(0..2).ok_or_else(MRZError::invalid_mrz_input)?;
    let rest = s.get(2..).ok_or_else(MRZError::invalid_mrz_input)?; // MMDD

    let parsed_year = yy_str
        .parse::<i32>()
        .map_err(|_| MRZError::invalid_mrz_input())?;
    let century = if parsed_year > milestone_year {
        1900
    } else {
        2000
    };
    let full_year = century + parsed_year;

    let full_date_str = format!("{:04}{}", full_year, rest); // YYYYMMDD

    NaiveDate::parse_from_str(&full_date_str, "%Y%m%d").map_err(|_| MRZError::invalid_mrz_input())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn test_trim_and_replace() {
        use crate::string_extensions::trim_char;
        assert_eq!(trim("ABC<<DEF"), "ABC  DEF");
        assert_eq!(trim("<<HELLO<<"), "HELLO");
        assert_eq!(trim_char("<<ABC<<", '<'), "ABC");
        assert_eq!(trim_char("ABC", '<'), "ABC");
    }

    #[test]
    fn test_parse_names() {
        let v = MRZFieldParser::parse_names("DOE<<JOHN<PAUL");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], "DOE"); // surname
        assert_eq!(v[1], "JOHN PAUL"); // given names with internal '<' replaced by spaces
    }

    #[test]
    fn test_parse_names_empty_surname_preserved() {
        // A leading `<<` denotes an empty surname; the given name must not be
        // mis-assigned to the surname slot.
        let v = MRZFieldParser::parse_names("<<JOHN<PAUL<<<<<<");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], ""); // surname stays empty
        assert_eq!(v[1], "JOHN PAUL");
    }

    #[test]
    fn test_parse_date_rejects_non_char_boundary() {
        // A 3-byte character straddling the YY/MM boundary must error, not panic.
        assert!(_parse_date("€0101", 70).is_err());
    }

    #[test]
    fn test_parse_sex() {
        assert_eq!(MRZFieldParser::parse_sex("M"), Sex::Male);
        assert_eq!(MRZFieldParser::parse_sex("F"), Sex::Female);
        assert_eq!(MRZFieldParser::parse_sex("<"), Sex::Unspecified);
        assert_eq!(MRZFieldParser::parse_sex("X"), Sex::Unspecified);
    }

    #[test]
    fn test_parse_dates_birth_and_expiry() {
        // Birth date logic depends on current year; construct values to test both branches.
        // For a deterministic test, test parsing a known date directly via _parse_date.

        // Example: 900101 => 1990-01-01 when milestone < 90
        let d = _parse_date("900101", 26).expect("should parse as 1990");
        assert_eq!(d, NaiveDate::from_ymd_opt(1990, 1, 1).unwrap());

        // Example: 050505 => 2005-05-05 when milestone >= 5
        let d2 = _parse_date("050505", 26).expect("should parse as 2005");
        assert_eq!(d2, NaiveDate::from_ymd_opt(2005, 5, 5).unwrap());

        // expiry with milestone 70: 71 -> 1971, 69 -> 2069
        let e1 = _parse_date("710101", 70).expect("1971");
        assert_eq!(e1, NaiveDate::from_ymd_opt(1971, 1, 1).unwrap());

        let e2 = _parse_date("690101", 70).expect("2069");
        assert_eq!(e2, NaiveDate::from_ymd_opt(2069, 1, 1).unwrap());
    }

    #[test]
    fn test_parse_document_fields() {
        assert_eq!(MRZFieldParser::parse_document_number("ABC<123"), "ABC 123");
        assert_eq!(MRZFieldParser::parse_document_type("P<"), "P");
        assert_eq!(MRZFieldParser::parse_country_code("UTO"), "UTO");
    }
}
