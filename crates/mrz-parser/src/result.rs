use chrono::NaiveDate;
use std::fmt;

use crate::Sex;

/// Parsed contents of an MRZ (Machine Readable Zone) — the values typically
/// extracted from passport / ID MRZ lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MRZResult {
    pub document_type: String,
    pub country_code: String,
    pub surnames: String,
    pub given_names: String,
    pub document_number: String,
    pub nationality_country_code: String,
    pub birth_date: NaiveDate,
    pub sex: Sex,
    pub expiry_date: NaiveDate,
    pub personal_number: String,
    pub personal_number2: Option<String>,
}

impl MRZResult {
    /// Create a new `MRZResult`.
    ///
    /// `birth_date` and `expiry_date` are `NaiveDate` — date-only values are
    /// all MRZ carries for these fields.
    pub fn new(
        document_type: impl Into<String>,
        country_code: impl Into<String>,
        surnames: impl Into<String>,
        given_names: impl Into<String>,
        document_number: impl Into<String>,
        nationality_country_code: impl Into<String>,
        birth_date: NaiveDate,
        sex: Sex,
        expiry_date: NaiveDate,
        personal_number: impl Into<String>,
        personal_number2: Option<impl Into<String>>,
    ) -> Self {
        MRZResult {
            document_type: document_type.into(),
            country_code: country_code.into(),
            surnames: surnames.into(),
            given_names: given_names.into(),
            document_number: document_number.into(),
            nationality_country_code: nationality_country_code.into(),
            birth_date,
            sex,
            expiry_date,
            personal_number: personal_number.into(),
            personal_number2: personal_number2.map(|s| s.into()),
        }
    }
}

impl fmt::Display for MRZResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MRZResult {{ document_type: {}, country_code: {}, surnames: {}, given_names: {}, document_number: {}, nationality: {}, birth_date: {}, sex: {:?}, expiry_date: {}, personal_number: {}, personal_number2: {:?} }}",
            self.document_type,
            self.country_code,
            self.surnames,
            self.given_names,
            self.document_number,
            self.nationality_country_code,
            self.birth_date,
            self.sex,
            self.expiry_date,
            self.personal_number,
            self.personal_number2,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sex;
    use chrono::NaiveDate;

    #[test]
    fn create_and_compare_results() {
        let birth = NaiveDate::from_ymd_opt(1990, 5, 20).expect("valid date");
        let expiry = NaiveDate::from_ymd_opt(2030, 5, 20).expect("valid date");

        let r1 = MRZResult::new(
            "P",
            "UTO",
            "DOE",
            "JOHN",
            "123456789",
            "UTO",
            birth,
            Sex::Male,
            expiry,
            "ABC123<<<",
            Some("SECOND".to_string()),
        );

        let r2 = MRZResult {
            document_type: "P".into(),
            country_code: "UTO".into(),
            surnames: "DOE".into(),
            given_names: "JOHN".into(),
            document_number: "123456789".into(),
            nationality_country_code: "UTO".into(),
            birth_date: birth,
            sex: Sex::Male,
            expiry_date: expiry,
            personal_number: "ABC123<<<".into(),
            personal_number2: Some("SECOND".into()),
        };

        assert_eq!(r1, r2);
        assert!(r1.personal_number2.is_some());
    }

    #[test]
    fn display_contains_key_fields() {
        let birth = NaiveDate::from_ymd_opt(1985, 1, 1).unwrap();
        let expiry = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();

        let r = MRZResult::new(
            "ID",
            "GBR",
            "SMITH",
            "JANE",
            "X9876543",
            "GBR",
            birth,
            Sex::Female,
            expiry,
            "ZZZ000<<<",
            None::<String>,
        );

        let s = format!("{}", r);
        assert!(s.contains("SMITH"));
        assert!(s.contains("JANE"));
        assert!(s.contains("GBR"));
    }
}
