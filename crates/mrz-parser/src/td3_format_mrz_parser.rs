use super::exceptions::MRZError;
use super::field_parser::MRZFieldParser;
use super::field_recognition_defects_fixer::MRZFieldRecognitionDefectsFixer;
use super::result::MRZResult;
use crate::get_check_digit;

/// TD3 MRZ parser (2 lines, 44 characters each).
const LINES_LENGTH: usize = 44;
const LINES_COUNT: usize = 2;

pub fn is_valid_input(input: &[String]) -> bool {
    input.len() == LINES_COUNT && input.iter().all(|s| s.len() == LINES_LENGTH)
}

pub fn parse(input: &[String]) -> Result<MRZResult, MRZError> {
    if !is_valid_input(input) {
        return Err(MRZError::invalid_mrz_input());
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
    let optional_data_raw = &second_line[28..(if is_visa_document { 44 } else { 42 })];

    let optional_data_check_digit_raw = if is_visa_document {
        None
    } else {
        Some(&second_line[42..43])
    };

    let final_check_digit_raw = if is_visa_document {
        None
    } else {
        Some(&second_line[43..44])
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
    let optional_data_check_digit_fixed =
        optional_data_check_digit_raw.map(|s| MRZFieldRecognitionDefectsFixer::fix_check_digit(s));
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

    // Optional data check digit (when present)
    if let Some(ref opt_cd_fixed) = optional_data_check_digit_fixed {
        let valid_by_digit = opt_cd_fixed
            .chars()
            .next()
            .and_then(|c| c.to_digit(10))
            .map(|d| d as u32 == get_check_digit(&optional_data_fixed) as u32)
            .unwrap_or(false);

        let valid_by_empty = opt_cd_fixed == "<"
            && MRZFieldParser::parse_optional_data(&optional_data_fixed).is_empty();

        if !(valid_by_digit || valid_by_empty) {
            return Err(MRZError::invalid_optional_data());
        }
    }

    // Final check digit (when present)
    if let Some(ref final_cd_fixed) = final_check_digit_fixed {
        let final_check_string_fixed = format!(
            "{}{}{}{}{}{}{}{}",
            document_number_fixed,
            document_number_check_digit_fixed,
            birth_date_fixed,
            birth_date_check_digit_fixed,
            expiry_date_fixed,
            expiry_date_check_digit_fixed,
            optional_data_fixed,
            optional_data_check_digit_fixed.clone().unwrap_or_default()
        );

        let final_check_parsed = final_cd_fixed.chars().next().and_then(|c| c.to_digit(10));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_input_check() {
        let first = format!("{: <44}", "P<UTOERIKSSON<<ANNA<MARIA");
        let second = format!("{: <44}", "L898902C360UTO7408122F1204159<<<<<<<<");
        assert_eq!(
            is_valid_input(&vec![first.clone(), second.clone()]),
            first.len() == 44 && second.len() == 44
        );
    }

    // Note: full round-trip tests require correct check digits; these unit tests only exercise shape validation.
}
