use crate::exceptions::MRZError;
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
    /// MRZ name field uses `<<` to separate surname and given names, and
    /// `<` as filler between name parts:
    /// - trim leading/trailing `<` characters
    /// - split on `<<`
    /// - `_trim` each resulting part (replace `<` with ` ` and trim whitespace)
    pub fn parse_names(input: &str) -> Vec<String> {
        let trimmed = trim_char(input, '<');
        let parts: Vec<&str> = trimmed.split("<<").collect();

        let surname = if !parts.is_empty() {
            trim(parts[0])
        } else {
            String::new()
        };

        let given_names = if parts.len() > 1 {
            trim(parts[1])
        } else {
            String::new()
        };

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
fn trim(input: &str) -> String {
    replace_angle_brackets_with_spaces(input).trim().to_string()
}

/// Remove leading and trailing occurrences of `ch` from the input.
fn trim_char(input: &str, ch: char) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut start = 0usize;
    let mut end = input.len();

    // Work with char indices to be safe for multi-byte (though MRZ is ASCII).
    let mut chars = input.char_indices();

    // find start index
    while let Some((idx, c)) = chars.next() {
        if c == ch {
            start = idx + c.len_utf8();
            continue;
        } else {
            // adjust start back to this index and stop
            start = idx;
            break;
        }
    }

    // find end index (char_indices from the end)
    if start >= input.len() {
        return String::new();
    }

    let mut rev_chars = input.char_indices().rev();
    while let Some((idx, c)) = rev_chars.next() {
        if c == ch {
            // keep skipping; end remains idx
            end = idx;
            continue;
        } else {
            // end should be after this character
            end = idx + c.len_utf8();
            break;
        }
    }

    if start >= end || start >= input.len() {
        String::new()
    } else {
        input[start..end].to_string()
    }
}

/// Replace MRZ filler '<' with space character.
fn replace_angle_brackets_with_spaces(input: &str) -> String {
    input.replace('<', " ")
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
    let yy_str = &s[0..2];
    let rest = &s[2..]; // MMDD

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
