//! This module provides the `MRZParser` convenience API which chooses the
//! correct format-specific parser (TD1 / TD2 / TD3) based on the polished input.
//!
//! Note: this module lives as a nested `mrz_parser::mrz_parser` module. It
//! expects sibling modules to provide the following functions / types:
//! - `super::exceptions::MRZError`
//! - `super::result::MRZResult`
//! - `super::string_extensions::is_valid_mrz_input`
//! - `super::td1_format_mrz_parser::{is_valid_input, parse}` (and similarly for td2/td3)
//!
//! Those format-specific parsers should implement `is_valid_input(&[String]) -> bool`
//! and `parse(&[String]) -> Result<MRZResult, MRZError>` to interoperate cleanly
//! with this module.

use super::exceptions::MRZError;
use super::result::MRZResult;

/// Top-level MRZ parser.
///
/// - `try_parse` returns `Option<MRZResult>` (`None` on error).
/// - `parse` returns `Result<MRZResult, MRZError>` (error when input is
///   invalid or parsing fails).
pub struct MRZParser;

impl MRZParser {
    /// Attempt to parse the given MRZ lines, returning `Some(MRZResult)` on
    /// success or `None` if parsing fails for any reason.
    ///
    /// Input accepts an optional outer vector whose elements may themselves
    /// be optional strings (to model upstream OCR results that may be null).
    pub fn try_parse(input: Option<Vec<Option<String>>>) -> Option<MRZResult> {
        match Self::parse(input) {
            Ok(r) => Some(r),
            Err(_) => None,
        }
    }

    /// Parse MRZ input and return a `MRZResult` or a `MRZError`.
    ///
    /// High-level flow:
    /// 1. Polish input (filter nulls, uppercase, validate allowed MRZ chars).
    /// 2. Attempt to parse with the TD1 parser if it recognises the format.
    /// 3. Otherwise attempt TD2, then TD3.
    /// 4. If none match, return `InvalidMRZInput`.
    pub fn parse(input: Option<Vec<Option<String>>>) -> Result<MRZResult, MRZError> {
        let polished = polish_input(input).ok_or_else(|| MRZError::invalid_mrz_input())?;

        // Try format-specific parsers (order: TD1, TD2, TD3).
        // Each format module is expected to provide:
        // - `is_valid_input(&[String]) -> bool`
        // - `parse(&[String]) -> Result<MRZResult, MRZError>`
        //
        // We call them via the sibling modules. If those modules are not yet
        // implemented, these calls will fail to compile; they will be added as
        // we continue converting files one-by-one.
        if super::td1_format_mrz_parser::is_valid_input(&polished) {
            return super::td1_format_mrz_parser::parse(&polished);
        }

        if super::td2_format_mrz_parser::is_valid_input(&polished) {
            return super::td2_format_mrz_parser::parse(&polished);
        }

        if super::td3_format_mrz_parser::is_valid_input(&polished) {
            return super::td3_format_mrz_parser::parse(&polished);
        }

        Err(MRZError::invalid_mrz_input())
    }
}

/// Transform the raw input (Option<Vec<Option<String>>>) into a cleaned
/// Vec<String> suitable for validation and parsing.
///
/// Steps:
/// - If input is None -> return None
/// - Remove null lines
/// - Convert each line to ASCII uppercase
/// - Validate each line contains only valid MRZ characters using sibling helper
fn polish_input(input: Option<Vec<Option<String>>>) -> Option<Vec<String>> {
    let lines = input?;
    // Filter out None values and convert to uppercase String
    let polished: Vec<String> = lines
        .into_iter()
        .filter_map(|opt| opt.map(|s| s.to_ascii_uppercase()))
        .collect();

    if polished.is_empty() {
        return None;
    }

    // Validate every line using the sibling `mrz_string_extensions` helper.
    // That module should provide `is_valid_mrz_input(&str) -> bool`.
    if polished
        .iter()
        .any(|line| !super::string_extensions::is_valid_mrz_input(line))
    {
        return None;
    }

    Some(polished)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests are intentionally high-level and will require the TD
    // format parsers to be available to fully exercise the end-to-end flow.
    // They still validate the polishing behavior and the try_parse wrapper.

    #[test]
    fn polish_input_filters_and_upcases() {
        let input = Some(vec![
            Some("p<uto123".to_string()),
            None,
            Some("abcdef".to_string()),
        ]);
        // `abcdef` contains lowercase letters but is valid MRZ characters,
        // it will be uppercased by polishing.
        let polished = polish_input(input).expect("should polish");
        assert_eq!(polished.len(), 2);
        assert_eq!(polished[0], "P<UTO123");
        assert_eq!(polished[1], "ABCDEF");
    }

    #[test]
    fn polish_input_rejects_invalid_chars() {
        let input = Some(vec![
            Some("valid<MRZ".to_string()),
            Some("has space".to_string()),
        ]);
        assert!(polish_input(input).is_none());
    }

    #[test]
    fn try_parse_returns_none_on_invalid_input() {
        // completely invalid (None) input
        assert!(MRZParser::try_parse(None).is_none());

        // invalid because polishing fails (spaces not allowed)
        let input = Some(vec![Some("HAS SPACE".to_string())]);
        assert!(MRZParser::try_parse(input).is_none());
    }

    // NOTE:
    // Full parsing tests (TD1/TD2/TD3) will be added when format parsers are
    // implemented. Here, we add a light sanity test to ensure the parse function
    // returns the expected error variant on empty/invalid input.
    #[test]
    fn parse_returns_invalid_error_on_bad_input() {
        let err = MRZParser::parse(None).unwrap_err();
        assert_eq!(
            format!("{}", err).contains("Invalid MRZ parser input"),
            true
        );
    }
}
