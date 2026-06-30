use chrono::NaiveDate;

use super::country_patterns::get_country_pattern;
use super::exceptions::MRZError;
use super::field_parser::MRZFieldParser;
use super::field_recognition_defects_fixer::MRZFieldRecognitionDefectsFixer;
use super::result::MRZResult;
use crate::get_check_digit;

/// TD1 MRZ format parser (3 lines, 30 characters each).
///
/// Provides:
/// - `is_valid_input(lines: &[String]) -> bool`
/// - `parse(lines: &[String]) -> Result<MRZResult, MRZError>`
pub struct TD1FormatMRZParser;

impl TD1FormatMRZParser {
    const LINES_LENGTH: usize = 30;
    const LINES_COUNT: usize = 3;

    /// Validate whether the provided lines match TD1 basic shape.
    pub fn is_valid_input(input: &[String]) -> bool {
        input.len() == Self::LINES_COUNT && input.iter().all(|s| s.len() == Self::LINES_LENGTH)
    }

    /// Parse TD1 MRZ lines into an MRZResult.
    pub fn parse(input: &[String]) -> Result<MRZResult, MRZError> {
        if !Self::is_valid_input(input) {
            return Err(MRZError::invalid_mrz_input());
        }

        let first_line = &input[0];
        let second_line = &input[1];
        let third_line = &input[2];

        // Extract raw segments by fixed positions (MRZ is ASCII; byte indices are safe).
        let document_type_raw = &first_line[0..2];
        let country_code_raw = &first_line[2..5];

        // Variables to be filled below
        let document_number_raw: String;
        let document_number_check_digit_raw: String;
        let optional_data_raw: String;
        let is_long_document_number: bool;

        // Try to use country-specific pattern when available
        if let Some(country_pattern) = get_country_pattern(first_line) {
            // slice the substring where the country-specific document number may start
            let start_idx = country_pattern.document_number_start_index;
            // safe because we validated length earlier and start_idx < length
            let substring = &first_line[start_idx..];
            if let Some(caps) = country_pattern.document_number_pattern.captures(substring) {
                // group 1 is the document number
                if let Some(m1) = caps.get(1) {
                    document_number_raw = m1.as_str().to_string();
                    // end index in the full first_line (byte index)
                    let end_index = start_idx + caps.get(0).unwrap().end();
                    // single character at end_index is the check digit for document number
                    document_number_check_digit_raw =
                        first_line[end_index..end_index + 1].to_string();
                    optional_data_raw = first_line[end_index + 1..Self::LINES_LENGTH].to_string();
                    is_long_document_number = document_number_raw.len() > 9;
                } else {
                    return Err(MRZError::invalid_document_number());
                }
            } else {
                return Err(MRZError::invalid_document_number());
            }
        } else {
            // Default handling for unknown country patterns
            // If position 14 is '<' then document number is long and split across different indexes
            if &first_line[14..15] == "<" {
                // tmpString from substring(15,28) with trailing '<' removed
                let tmp_string = first_line[15..28].trim_end_matches('<').to_string();
                // last char of tmp_string is the check digit
                if tmp_string.is_empty() {
                    return Err(MRZError::invalid_document_number());
                }
                document_number_check_digit_raw = tmp_string[tmp_string.len() - 1..].to_string();
                // document number is substring(5,14) + tmp_string.substring(0, len-1)
                let part1 = &first_line[5..14];
                let part2 = &tmp_string[0..tmp_string.len() - 1];
                document_number_raw = format!("{}{}", part1, part2);
                optional_data_raw = first_line[15 + tmp_string.len()..30].to_string();
                is_long_document_number = true;
            } else {
                document_number_raw = first_line[5..14].to_string();
                document_number_check_digit_raw = first_line[14..15].to_string();
                optional_data_raw = first_line[15..30].to_string();
                is_long_document_number = false;
            }
        }

        // second line fields
        let birth_date_raw = &second_line[0..6];
        let birth_date_check_digit_raw = &second_line[6..7];
        let sex_raw = &second_line[7..8];
        let expiry_date_raw = &second_line[8..14];
        let expiry_date_check_digit_raw = &second_line[14..15];
        let nationality_raw = &second_line[15..18];
        let optional_data2_raw = &second_line[18..29];
        let final_check_digit_raw = &second_line[29..30];

        // Fix recognition defects
        let document_type_fixed =
            MRZFieldRecognitionDefectsFixer::fix_document_type(document_type_raw);
        let country_code_fixed =
            MRZFieldRecognitionDefectsFixer::fix_country_code(country_code_raw);
        let document_number_fixed = document_number_raw.clone();
        let document_number_check_digit_fixed =
            MRZFieldRecognitionDefectsFixer::fix_check_digit(&document_number_check_digit_raw);
        let optional_data_fixed = optional_data_raw.clone();
        let birth_date_fixed = MRZFieldRecognitionDefectsFixer::fix_date(birth_date_raw);
        let birth_date_check_digit_fixed =
            MRZFieldRecognitionDefectsFixer::fix_check_digit(birth_date_check_digit_raw);
        let sex_fixed = MRZFieldRecognitionDefectsFixer::fix_sex(sex_raw);
        let expiry_date_fixed = MRZFieldRecognitionDefectsFixer::fix_date(expiry_date_raw);
        let expiry_date_check_digit_fixed =
            MRZFieldRecognitionDefectsFixer::fix_check_digit(expiry_date_check_digit_raw);
        let nationality_fixed = MRZFieldRecognitionDefectsFixer::fix_nationality(nationality_raw);
        let optional_data2_fixed = optional_data2_raw.to_string();
        let final_check_digit_fixed =
            MRZFieldRecognitionDefectsFixer::fix_check_digit(final_check_digit_raw);

        // Validate document number check digit
        let doc_check_digit_parsed = document_number_check_digit_fixed.parse::<u8>().ok();
        let doc_calc = get_check_digit(&document_number_fixed) as u8;
        if doc_check_digit_parsed != Some(doc_calc) {
            return Err(MRZError::invalid_document_number());
        }

        // Validate birth date check digit
        let birth_check_digit_parsed = birth_date_check_digit_fixed.parse::<u8>().ok();
        let birth_calc = get_check_digit(&birth_date_fixed) as u8;
        if birth_check_digit_parsed != Some(birth_calc) {
            return Err(MRZError::invalid_birth_date());
        }

        // Validate expiry date check digit
        let expiry_check_digit_parsed = expiry_date_check_digit_fixed.parse::<u8>().ok();
        let expiry_calc = get_check_digit(&expiry_date_fixed) as u8;
        if expiry_check_digit_parsed != Some(expiry_calc) {
            return Err(MRZError::invalid_expiry_date());
        }

        // Build the documentNumberFixedForCheckString (insert '<' after 9 chars if long)
        let document_number_fixed_for_check_string = if is_long_document_number {
            let first9 = &document_number_fixed[0..9];
            let rest = &document_number_fixed[9..];
            format!("{}<{}", first9, rest)
        } else {
            document_number_fixed.clone()
        };

        // final check string
        let final_check_string_fixed = format!(
            "{}{}{}{}{}{}{}",
            document_number_fixed_for_check_string,
            document_number_check_digit_fixed,
            optional_data_fixed,
            birth_date_fixed,
            birth_date_check_digit_fixed,
            expiry_date_fixed,
            expiry_date_check_digit_fixed
        );

        let final_check_digit_parsed = final_check_digit_fixed.parse::<u8>().ok();
        let final_calc = get_check_digit(&final_check_string_fixed) as u8;
        if final_check_digit_parsed != Some(final_calc) {
            return Err(MRZError::invalid_mrz_value());
        }

        // Parse to typed fields
        let document_type = MRZFieldParser::parse_document_type(&document_type_fixed);
        let country_code = MRZFieldParser::parse_country_code(&country_code_fixed);
        let document_number = MRZFieldParser::parse_document_number(&document_number_fixed);
        let optional_data = MRZFieldParser::parse_optional_data(&optional_data_fixed);

        // MRZFieldParser::parse_birth_date returns Result<NaiveDate, MRZError>
        let birth_date: NaiveDate = MRZFieldParser::parse_birth_date(&birth_date_fixed)?;
        let sex = MRZFieldParser::parse_sex(&sex_fixed);
        let expiry_date: NaiveDate = MRZFieldParser::parse_expiry_date(&expiry_date_fixed)?;
        let nationality = MRZFieldParser::parse_nationality(&nationality_fixed);
        let optional_data2 = MRZFieldParser::parse_optional_data(&optional_data2_fixed);
        let names = MRZFieldParser::parse_names(&third_line[0..30]);

        // names returns Vec<String> with surname and given names as earlier implemented
        let surnames = names.get(0).cloned().unwrap_or_default();
        let given_names = names.get(1).cloned().unwrap_or_default();

        Ok(MRZResult::new(
            document_type,
            country_code,
            surnames,
            given_names,
            document_number,
            nationality,
            birth_date,
            sex,
            expiry_date,
            optional_data,
            Some(optional_data2),
        ))
    }
}

/// Module-level free functions so `mrz_parser.rs` can call them uniformly
/// alongside the td2/td3 modules which expose free functions directly.
pub fn is_valid_input(input: &[String]) -> bool {
    TD1FormatMRZParser::is_valid_input(input)
}

pub fn parse(input: &[String]) -> Result<MRZResult, MRZError> {
    TD1FormatMRZParser::parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn validate_is_valid_input() {
        // ICAO 9303 TD1 specimen — all lines exactly 30 chars with valid check digits
        let lines = vec![
            "I<UTOD231458907<<<<<<<<<<<<<<<".to_string(),
            "7408122F1204159UTO<<<<<<<<<<<6".to_string(),
            "ERIKSSON<<ANNA<MARIA<<<<<<<<<<".to_string(),
        ];
        assert!(TD1FormatMRZParser::is_valid_input(&lines));
    }

    #[test]
    fn parse_sample_td1() {
        // ICAO 9303 TD1 specimen — 30 chars per line, all check digits valid
        // Line 1: doc type I<, country UTO, doc number D23145890, check 7, optional <<<...
        // Line 2: birth 740812, check 2, sex F, expiry 120415, check 9, nat UTO, opt2 <<<..., final 6
        // Line 3: names ERIKSSON<<ANNA<MARIA<<...
        let lines = vec![
            "I<UTOD231458907<<<<<<<<<<<<<<<".to_string(),
            "7408122F1204159UTO<<<<<<<<<<<6".to_string(),
            "ERIKSSON<<ANNA<MARIA<<<<<<<<<<".to_string(),
        ];

        let res = TD1FormatMRZParser::parse(&lines).expect("should parse");
        assert_eq!(res.document_type, "I");
        assert_eq!(res.country_code, "UTO");
        assert_eq!(res.surnames, "ERIKSSON");
        assert!(res.given_names.contains("ANNA"));
        // birth date: 740812 with milestone (current_year - 2000) => 74 > ~25 => 1974
        assert_eq!(res.birth_date.year(), 1974);
        assert_eq!(res.birth_date.month(), 8);
        assert_eq!(res.birth_date.day(), 12);
    }
}
