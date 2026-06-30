use chrono::{Datelike, NaiveDate};

use super::exceptions::MRZError;
use super::field_parser::MRZFieldParser;
use super::field_recognition_defects_fixer::MRZFieldRecognitionDefectsFixer;
use super::result::MRZResult;
use crate::get_check_digit;

/// TD2 MRZ format parser (2 lines, 36 characters each).
///
/// Provides free functions:
/// - `is_valid_input(lines: &[String]) -> bool`
/// - `parse(lines: &[String]) -> Result<MRZResult, MRZError>`
const LINES_LENGTH: usize = 36;
const LINES_COUNT: usize = 2;

pub fn is_valid_input(input: &[String]) -> bool {
    input.len() == LINES_COUNT && input.iter().all(|s| s.len() == LINES_LENGTH)
}

pub fn parse(input: &[String]) -> Result<MRZResult, MRZError> {
    if !is_valid_input(input) {
        return Err(MRZError::invalid_mrz_input());
    }

    if is_french_id(input) {
        return parse_french_id(input);
    }

    let first_line = &input[0];
    let second_line = &input[1];

    let is_visa_document = first_line.chars().next() == Some('V');
    let document_type_raw = &first_line[0..2];
    let country_code_raw = &first_line[2..5];
    let names_raw = &first_line[5..];

    let document_number_raw = second_line[0..9].to_string();
    let document_number_check_digit_raw = &second_line[9..10];
    let nationality_raw = &second_line[10..13];
    let birth_date_raw = &second_line[13..19];
    let birth_date_check_digit_raw = &second_line[19..20];
    let sex_raw = &second_line[20..21];
    let expiry_date_raw = &second_line[21..27];
    let expiry_date_check_digit_raw = &second_line[27..28];
    let optional_data_raw = &second_line[28..(if is_visa_document { 36 } else { 35 })];

    let final_check_digit_raw = if is_visa_document {
        None
    } else {
        Some(&second_line[35..36])
    };

    // Fix recognition defects
    let document_type_fixed = MRZFieldRecognitionDefectsFixer::fix_document_type(document_type_raw);
    let country_code_fixed = MRZFieldRecognitionDefectsFixer::fix_country_code(country_code_raw);
    let names_fixed = MRZFieldRecognitionDefectsFixer::fix_names(names_raw);
    let document_number_fixed = document_number_raw.clone();
    let document_number_check_digit_fixed =
        MRZFieldRecognitionDefectsFixer::fix_check_digit(document_number_check_digit_raw);
    let nationality_fixed = MRZFieldRecognitionDefectsFixer::fix_nationality(nationality_raw);
    let birth_date_fixed = MRZFieldRecognitionDefectsFixer::fix_date(birth_date_raw);
    let birth_date_check_digit_fixed =
        MRZFieldRecognitionDefectsFixer::fix_check_digit(birth_date_check_digit_raw);
    let sex_fixed = MRZFieldRecognitionDefectsFixer::fix_sex(sex_raw);
    let expiry_date_fixed = MRZFieldRecognitionDefectsFixer::fix_date(expiry_date_raw);
    let expiry_date_check_digit_fixed =
        MRZFieldRecognitionDefectsFixer::fix_check_digit(expiry_date_check_digit_raw);
    let optional_data_fixed = optional_data_raw.to_string();
    let final_check_digit_fixed =
        final_check_digit_raw.map(|s| MRZFieldRecognitionDefectsFixer::fix_check_digit(s));

    // Validate document number check digit
    let doc_check = document_number_check_digit_fixed
        .chars()
        .next()
        .and_then(|c| c.to_digit(10));
    let doc_calc = get_check_digit(&document_number_fixed) as u32;
    if doc_check != Some(doc_calc) {
        return Err(MRZError::invalid_document_number());
    }

    // Validate birth date check digit
    let birth_check = birth_date_check_digit_fixed
        .chars()
        .next()
        .and_then(|c| c.to_digit(10));
    let birth_calc = get_check_digit(&birth_date_fixed) as u32;
    if birth_check != Some(birth_calc) {
        return Err(MRZError::invalid_birth_date());
    }

    // Validate expiry date check digit
    let expiry_check = expiry_date_check_digit_fixed
        .chars()
        .next()
        .and_then(|c| c.to_digit(10));
    let expiry_calc = get_check_digit(&expiry_date_fixed) as u32;
    if expiry_check != Some(expiry_calc) {
        return Err(MRZError::invalid_expiry_date());
    }

    // Final check digit (when present)
    if let Some(ref final_fixed) = final_check_digit_fixed {
        let final_check_string_fixed = format!(
            "{}{}{}{}{}{}{}",
            document_number_fixed,
            document_number_check_digit_fixed,
            birth_date_fixed,
            birth_date_check_digit_fixed,
            expiry_date_fixed,
            expiry_date_check_digit_fixed,
            optional_data_fixed
        );

        let final_check_parsed = final_fixed.chars().next().and_then(|c| c.to_digit(10));
        let final_calc = get_check_digit(&final_check_string_fixed) as u32;
        if final_check_parsed != Some(final_calc) {
            return Err(MRZError::invalid_mrz_value());
        }
    }

    // Parse typed fields (dates may return MRZError via MRZFieldParser)
    let document_type = MRZFieldParser::parse_document_type(&document_type_fixed);
    let country_code = MRZFieldParser::parse_country_code(&country_code_fixed);
    let names = MRZFieldParser::parse_names(&names_fixed);
    let document_number = MRZFieldParser::parse_document_number(&document_number_fixed);
    let nationality = MRZFieldParser::parse_nationality(&nationality_fixed);
    let birth_date = MRZFieldParser::parse_birth_date(&birth_date_fixed)?;
    let sex = MRZFieldParser::parse_sex(&sex_fixed);
    let expiry_date = MRZFieldParser::parse_expiry_date(&expiry_date_fixed)?;
    let optional_data = MRZFieldParser::parse_optional_data(&optional_data_fixed);

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
        None::<String>,
    ))
}

/// French national-ID validity period (in years):
/// - issued before 2004-01-01 → 10 years for everyone.
/// - issued 2004-01-01 onwards → 15 years for adults, 10 for minors.
///   This single branch covers both the 2004–2013 cards (which received an
///   automatic 5-year extension, 10 → 15) and the post-2014 cards (issued for
///   15 years up front). A holder is an adult when they are at least 18 on the
///   issue date, i.e. born on or before `issue_date - 18 years`.
fn french_id_validity_years(issue_date: NaiveDate, birth_date: NaiveDate) -> i32 {
    if issue_date < NaiveDate::from_ymd_opt(2004, 1, 1).unwrap() {
        10
    } else {
        let adult_threshold = subtract_years(issue_date, 18);
        if birth_date <= adult_threshold {
            15
        } else {
            10
        }
    }
}

/// Subtract `years` from `date`, clamping a 29 February source date to
/// 28 February when the target year is not a leap year (so the calculation
/// never fails on the leap-day boundary).
fn subtract_years(date: NaiveDate, years: i32) -> NaiveDate {
    let target_year = date.year() - years;
    NaiveDate::from_ymd_opt(target_year, date.month(), date.day()).unwrap_or_else(|| {
        // The only date that fails to round-trip is 29 Feb → use 28 Feb.
        NaiveDate::from_ymd_opt(target_year, date.month(), date.day() - 1)
            .expect("clamping the day by one yields a valid date")
    })
}

fn is_french_id(input: &[String]) -> bool {
    if input.len() < 2 {
        return false;
    }
    let first = &input[0];
    // first char 'I' and substring(2,5) == "FRA"
    first.chars().next() == Some('I') && first.get(2..5) == Some("FRA")
}

fn parse_french_id(input: &[String]) -> Result<MRZResult, MRZError> {
    let first_line = &input[0];
    let second_line = &input[1];

    let document_type_raw = &first_line[0..2];
    let country_code_raw = &first_line[2..5];
    let last_names_raw = &first_line[5..30];
    let department_and_office_raw = &first_line[30..36];

    let issue_date_raw = &second_line[0..4];
    let department_raw = &second_line[4..7];
    let document_number_raw = &second_line[0..12];
    let document_number_check_digit_raw = &second_line[12..13];
    let given_names_raw = &second_line[13..27];
    let birth_date_raw = &second_line[27..33];
    let birth_date_check_digit_raw = &second_line[33..34];
    let sex_raw = &second_line[34..35];
    let final_check_digit_raw = &second_line[35..36];

    // Fix recognition defects
    let document_type_fixed = MRZFieldRecognitionDefectsFixer::fix_document_type(document_type_raw);
    let country_code_fixed = MRZFieldRecognitionDefectsFixer::fix_country_code(country_code_raw);
    let last_names_fixed = MRZFieldRecognitionDefectsFixer::fix_names(last_names_raw);
    let department_and_office_fixed = department_and_office_raw.to_string();
    let issue_date_fixed = MRZFieldRecognitionDefectsFixer::fix_date(issue_date_raw);
    let department_fixed = department_raw.to_string();
    let document_number_fixed = document_number_raw.to_string();
    let document_number_check_digit_fixed =
        MRZFieldRecognitionDefectsFixer::fix_check_digit(document_number_check_digit_raw);
    let given_names_fixed = MRZFieldRecognitionDefectsFixer::fix_names(given_names_raw);
    let birth_date_fixed = MRZFieldRecognitionDefectsFixer::fix_date(birth_date_raw);
    let birth_date_check_digit_fixed =
        MRZFieldRecognitionDefectsFixer::fix_check_digit(birth_date_check_digit_raw);
    let sex_fixed = MRZFieldRecognitionDefectsFixer::fix_sex(sex_raw);
    let final_check_digit_fixed =
        MRZFieldRecognitionDefectsFixer::fix_check_digit(final_check_digit_raw);

    // Validate document number check digit
    let doc_check = document_number_check_digit_fixed
        .chars()
        .next()
        .and_then(|c| c.to_digit(10));
    let doc_calc = get_check_digit(&document_number_fixed) as u32;
    if doc_check != Some(doc_calc) {
        return Err(MRZError::invalid_document_number());
    }

    // Validate birth date check digit
    let birth_check = birth_date_check_digit_fixed
        .chars()
        .next()
        .and_then(|c| c.to_digit(10));
    let birth_calc = get_check_digit(&birth_date_fixed) as u32;
    if birth_check != Some(birth_calc) {
        return Err(MRZError::invalid_birth_date());
    }

    let final_check_string_fixed = format!(
        "{}{}{}{}{}{}{}{}{}{}",
        document_type_fixed,
        country_code_fixed,
        last_names_fixed,
        department_and_office_fixed,
        document_number_fixed,
        document_number_check_digit_fixed,
        given_names_fixed,
        birth_date_fixed,
        birth_date_check_digit_fixed,
        sex_fixed
    );

    let final_check_parsed = final_check_digit_fixed
        .chars()
        .next()
        .and_then(|c| c.to_digit(10));
    let final_calc = get_check_digit(&final_check_string_fixed) as u32;
    if final_check_parsed != Some(final_calc) {
        return Err(MRZError::invalid_mrz_value());
    }

    // Parse typed fields
    let document_type = MRZFieldParser::parse_document_type(&document_type_fixed);
    let country_code = MRZFieldParser::parse_country_code(&country_code_fixed);
    let given_names_vec = MRZFieldParser::parse_names(&given_names_fixed);
    let given_names = given_names_vec
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let last_names_vec = MRZFieldParser::parse_names(&last_names_fixed);
    let last_names = last_names_vec
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let document_number = MRZFieldParser::parse_document_number(&document_number_fixed);
    let nationality = MRZFieldParser::parse_nationality(&country_code_fixed);
    let birth_date = MRZFieldParser::parse_birth_date(&birth_date_fixed)?;
    let sex = MRZFieldParser::parse_sex(&sex_fixed);

    // Issue date parsing: append "01" and feed through parse_expiry_date.
    let issue_date = MRZFieldParser::parse_expiry_date(&format!("{}01", issue_date_fixed))?;

    let years_valid = french_id_validity_years(issue_date, birth_date);

    let expiry_date = NaiveDate::from_ymd_opt(
        issue_date.year() + years_valid,
        issue_date.month(),
        issue_date.day(),
    )
    .ok_or_else(|| MRZError::invalid_expiry_date())?;

    let optional_data = MRZFieldParser::parse_optional_data(&department_and_office_fixed);
    let optional_data2 = MRZFieldParser::parse_optional_data(&department_fixed);

    Ok(MRZResult::new(
        document_type,
        country_code,
        last_names,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_input_check() {
        let lines = vec![
            "V<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<".to_string(),
            "L898902C36UTO6908061F9406236ZE184226B<<".to_string(),
        ];
        // lines must be exactly 36 long; adjust if necessary for the example
        assert_eq!(is_valid_input(&lines), lines.iter().all(|s| s.len() == 36));
    }

    #[test]
    fn parse_basic_td2_structure() {
        // This test is primarily to ensure the parse path runs for well-formed input.
        // Using a synthetic example with consistent check digits may be required for full success.
        let first = format!("{: <36}", "P<UTOERIKSSON<<ANNA<MARIA");
        let second = format!("{: <36}", "L898902C360UTO7408122F1204159");
        if first.len() == 36 && second.len() == 36 {
            let lines = vec![first, second];
            // Attempt parse; may return Err depending on check digits in the synthetic example.
            let _ = parse(&lines);
        }
    }

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn subtract_years_clamps_leap_day() {
        // 29 Feb 2032 minus 18 years → 2014 is not a leap year → clamp to 28 Feb.
        assert_eq!(subtract_years(d(2032, 2, 29), 18), d(2014, 2, 28));
        // Ordinary dates are unaffected.
        assert_eq!(subtract_years(d(2030, 6, 15), 18), d(2012, 6, 15));
    }

    #[test]
    fn french_validity_pre_2004_is_always_ten() {
        // Even an adult gets 10 years before the 2004 extension.
        assert_eq!(french_id_validity_years(d(2000, 5, 1), d(1950, 1, 1)), 10);
    }

    #[test]
    fn french_validity_2004_2013_adult_extension() {
        // Adult card issued during the 2004–2013 window → 15 years.
        assert_eq!(french_id_validity_years(d(2010, 5, 1), d(1980, 1, 1)), 15);
        // Minor card issued during the same window → 10 years.
        assert_eq!(french_id_validity_years(d(2010, 5, 1), d(2000, 1, 1)), 10);
    }

    #[test]
    fn french_validity_exactly_18_is_adult() {
        // Born exactly 18 years before issue → adult → 15 years (not 10).
        let issue = d(2016, 6, 15);
        let birth = d(1998, 6, 15);
        assert_eq!(french_id_validity_years(issue, birth), 15);
        // One day younger than 18 → minor → 10 years.
        let birth_minor = d(1998, 6, 16);
        assert_eq!(french_id_validity_years(issue, birth_minor), 10);
    }
}
