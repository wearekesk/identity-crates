//! String extension utilities.
//!
//! Provides two extension traits on `str`:
//!
//! - [`StringDecodeExt`] – hex and base64 decoding (`parse_hex`, `parse_base64`)
//! - [`StringDateExt`]   – date parsing (`parse_date_yymmdd`, `parse_date`)
//!
//! These mirror the reference extensions `StringDecodeApis` and `StringYYMMDDateApi`.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{Datelike, Local, NaiveDate};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error returned when string decoding or date parsing fails.
#[derive(Debug, thiserror::Error)]
pub enum StringExtError {
    #[error("Invalid hex string: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Invalid base64 string: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Invalid date string: {0}")]
    DateParse(String),
}

// ---------------------------------------------------------------------------
// StringDecodeExt
// ---------------------------------------------------------------------------

/// Extension trait that adds hex and base64 decoding to `str`.
///
/// # Examples
/// ```
/// use dmrtd::extension::string::StringDecodeExt;
///
/// let bytes = "deadbeef".parse_hex().unwrap();
/// assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
///
/// let b64 = "aGVsbG8=".parse_base64().unwrap();
/// assert_eq!(b64, b"hello");
/// ```
pub trait StringDecodeExt {
    /// Decodes a hexadecimal string into bytes.
    ///
    /// Accepts both lowercase and uppercase hex digits.
    /// Returns an error if the string contains non-hex characters or has an
    /// odd number of characters.
    fn parse_hex(&self) -> Result<Vec<u8>, StringExtError>;

    /// Decodes a standard (padded) base64 string into bytes.
    fn parse_base64(&self) -> Result<Vec<u8>, StringExtError>;
}

impl StringDecodeExt for str {
    fn parse_hex(&self) -> Result<Vec<u8>, StringExtError> {
        Ok(hex::decode(self)?)
    }

    fn parse_base64(&self) -> Result<Vec<u8>, StringExtError> {
        Ok(BASE64.decode(self)?)
    }
}

// ---------------------------------------------------------------------------
// StringDateExt
// ---------------------------------------------------------------------------

/// Extension trait that adds `YYMMDD` and flexible date parsing to `str`.
pub trait StringDateExt {
    /// Parses a 6-digit `YYMMDD` compact date string into a [`NaiveDate`].
    ///
    /// The two-digit year is disambiguated against the reference date using a
    /// full `(year, month, day)` threshold (not just the year):
    /// - If `future_date` is **false** (birth date): if the resulting
    ///   `(year, month, day)` would be after the threshold, subtract 100 (i.e.
    ///   it's in the 1900s) — so a same-year/same-month date *after* the
    ///   reference day still rolls back a century.
    /// - If `future_date` is **true** (expiry date): add a ~20-year/5-month
    ///   look-ahead window before applying the same rule.
    ///
    /// Non-digit characters are stripped before parsing, so `"23-05-09"` is
    /// treated the same as `"230509"`.
    ///
    /// # Errors
    /// Returns [`StringExtError::DateParse`] if the string does not contain
    /// exactly 6 digits, or if the resulting month/day values are out of range.
    ///
    /// # Examples
    /// ```
    /// use dmrtd::extension::string::StringDateExt;
    /// use chrono::Datelike;
    ///
    /// // A past birth date
    /// let d = "850423".parse_date_yymmdd(false).unwrap();
    /// assert_eq!(d.year(), 1985);
    /// assert_eq!(d.month(), 4);
    /// assert_eq!(d.day(), 23);
    /// ```
    fn parse_date_yymmdd(&self, future_date: bool) -> Result<NaiveDate, StringExtError>;

    /// Parses a date string in `YYMMDD` (6 digits) or `YYYYMMDD` (8 digits)
    /// format, stripping any non-digit characters first.
    ///
    /// Falls back to `YYMMDD` disambiguation when the stripped string is 6
    /// digits long, and to direct `YYYYMMDD` parsing when it is 8 digits.
    ///
    /// # Errors
    /// Returns [`StringExtError::DateParse`] if the string is empty, has
    /// an unsupported digit count, or contains an invalid date.
    ///
    /// # Examples
    /// ```
    /// use dmrtd::extension::string::StringDateExt;
    /// use chrono::Datelike;
    ///
    /// let d = "20231231".parse_date(false).unwrap();
    /// assert_eq!(d.year(), 2023);
    ///
    /// let d2 = "850423".parse_date(false).unwrap();
    /// assert_eq!(d2.year(), 1985);
    /// ```
    fn parse_date(&self, future_date: bool) -> Result<NaiveDate, StringExtError>;

    /// Like [`parse_date_yymmdd`](StringDateExt::parse_date_yymmdd) but uses the
    /// caller-supplied `reference` date for two-digit-year disambiguation
    /// instead of the system clock.
    ///
    /// This is the deterministic core; prefer it whenever you need reproducible
    /// behaviour (e.g. in tests) or want to avoid depending on `Local::now()`.
    fn parse_date_yymmdd_with_ref(
        &self,
        future_date: bool,
        reference: NaiveDate,
    ) -> Result<NaiveDate, StringExtError>;

    /// Like [`parse_date`](StringDateExt::parse_date) but uses the
    /// caller-supplied `reference` date for two-digit-year disambiguation
    /// instead of the system clock.
    fn parse_date_with_ref(
        &self,
        future_date: bool,
        reference: NaiveDate,
    ) -> Result<NaiveDate, StringExtError>;
}

impl StringDateExt for str {
    fn parse_date_yymmdd(&self, future_date: bool) -> Result<NaiveDate, StringExtError> {
        self.parse_date_yymmdd_with_ref(future_date, Local::now().naive_local().date())
    }

    fn parse_date(&self, future_date: bool) -> Result<NaiveDate, StringExtError> {
        self.parse_date_with_ref(future_date, Local::now().naive_local().date())
    }

    fn parse_date_yymmdd_with_ref(
        &self,
        future_date: bool,
        reference: NaiveDate,
    ) -> Result<NaiveDate, StringExtError> {
        // Strip non-digit characters before parsing.
        let compact: String = self.chars().filter(|c| c.is_ascii_digit()).collect();

        if compact.len() != 6 {
            return Err(StringExtError::DateParse(format!(
                "Invalid length of compact date string: expected exactly 6 digits, got {}",
                compact.len()
            )));
        }

        let yy: i32 = compact[0..2]
            .parse()
            .map_err(|_| StringExtError::DateParse("Invalid year digits".to_string()))?;
        let m: u32 = compact[2..4]
            .parse()
            .map_err(|_| StringExtError::DateParse("Invalid month digits".to_string()))?;
        let d: u32 = compact[4..6]
            .parse()
            .map_err(|_| StringExtError::DateParse("Invalid day digits".to_string()))?;

        // Determine the disambiguation threshold (max_year / max_month / max_day)
        let now = reference;
        let (max_year, max_month, max_day) = if future_date {
            // Look ~20 years and 5 months into the future (mirrors logic)
            let future_months = now.month0() as i32 + 5;
            let extra_years = future_months / 12;
            let future_month = (future_months % 12) as u32 + 1;
            (now.year() + 20 + extra_years, future_month, now.day())
        } else {
            (now.year(), now.month(), now.day())
        };

        // Map two-digit year to four-digit year. The threshold includes the day
        // so a same-year/same-month date that falls after the reference day is
        // still rolled back a century instead of parsing 100 years off.
        let mut year = yy + 2000;
        if (year, m, d) > (max_year, max_month, max_day) {
            year -= 100;
        }

        NaiveDate::from_ymd_opt(year, m, d).ok_or_else(|| {
            StringExtError::DateParse(format!("Invalid date: {year:04}-{m:02}-{d:02}"))
        })
    }

    fn parse_date_with_ref(
        &self,
        future_date: bool,
        reference: NaiveDate,
    ) -> Result<NaiveDate, StringExtError> {
        let raw = self.trim();
        if raw.is_empty() {
            return Err(StringExtError::DateParse("Empty date string".to_string()));
        }

        let cleaned: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();

        match cleaned.len() {
            6 => cleaned.parse_date_yymmdd_with_ref(future_date, reference),
            8 => {
                let year: i32 = cleaned[0..4]
                    .parse()
                    .map_err(|_| StringExtError::DateParse("Invalid year".to_string()))?;
                let month: u32 = cleaned[4..6]
                    .parse()
                    .map_err(|_| StringExtError::DateParse("Invalid month".to_string()))?;
                let day: u32 = cleaned[6..8]
                    .parse()
                    .map_err(|_| StringExtError::DateParse("Invalid day".to_string()))?;
                NaiveDate::from_ymd_opt(year, month, day).ok_or_else(|| {
                    StringExtError::DateParse(format!(
                        "Invalid date: {year:04}-{month:02}-{day:02}"
                    ))
                })
            }
            _ => Err(StringExtError::DateParse(format!(
                "Unsupported date string length: {} (from '{}')",
                cleaned.len(),
                raw
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- hex / base64 ---

    #[test]
    fn parse_hex_lowercase() {
        let bytes = "deadbeef".parse_hex().unwrap();
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_hex_uppercase() {
        let bytes = "DEADBEEF".parse_hex().unwrap();
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_hex_empty() {
        let bytes = "".parse_hex().unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn parse_hex_invalid_returns_error() {
        assert!("ZZZZ".parse_hex().is_err());
    }

    #[test]
    fn parse_base64_hello() {
        let bytes = "aGVsbG8=".parse_base64().unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn parse_base64_empty() {
        let bytes = "".parse_base64().unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn parse_base64_invalid_returns_error() {
        assert!("!!!".parse_base64().is_err());
    }

    // --- parse_date_yymmdd ---

    #[test]
    fn with_ref_is_deterministic_around_threshold() {
        // Pin the reference date so the two-digit-year disambiguation does not
        // depend on the system clock.
        let reference = NaiveDate::from_ymd_opt(2030, 6, 15).unwrap();

        // "29" as a birth date with a 2030 reference is in the past → 2029.
        let d = "290101"
            .parse_date_yymmdd_with_ref(false, reference)
            .unwrap();
        assert_eq!(d.year(), 2029);

        // "31" exceeds the reference year → rolls back a century → 1931.
        let d = "310101"
            .parse_date_yymmdd_with_ref(false, reference)
            .unwrap();
        assert_eq!(d.year(), 1931);

        // parse_date_with_ref routes 6-digit input through the same logic.
        let d = "31-01-01".parse_date_with_ref(false, reference).unwrap();
        assert_eq!(d.year(), 1931);

        // Same year and month as the reference, but a day AFTER the reference
        // day, is in the future for a past date → rolls back a century.
        let d = "300616"
            .parse_date_yymmdd_with_ref(false, reference)
            .unwrap();
        assert_eq!(d.year(), 1930);

        // Same year/month, the exact reference day, stays in the current century.
        let d = "300615"
            .parse_date_yymmdd_with_ref(false, reference)
            .unwrap();
        assert_eq!(d.year(), 2030);

        // Same year/month, a day BEFORE the reference day, stays current century.
        let d = "300614"
            .parse_date_yymmdd_with_ref(false, reference)
            .unwrap();
        assert_eq!(d.year(), 2030);
    }

    #[test]
    fn past_birth_date_1900s() {
        // 85 -> 1985 (past)
        let d = "850423".parse_date_yymmdd(false).unwrap();
        assert_eq!(d.year(), 1985);
        assert_eq!(d.month(), 4);
        assert_eq!(d.day(), 23);
    }

    #[test]
    fn recent_birth_date_2000s() {
        // 05 -> 2005 (recent past, should be 2005 not 1905)
        let d = "050101".parse_date_yymmdd(false).unwrap();
        assert_eq!(d.year(), 2005);
    }

    #[test]
    fn strips_non_digit_characters() {
        // Dashes stripped before parsing
        let d = "85-04-23".parse_date_yymmdd(false).unwrap();
        assert_eq!(d.year(), 1985);
    }

    #[test]
    fn too_short_returns_error() {
        assert!("850".parse_date_yymmdd(false).is_err());
    }

    #[test]
    fn invalid_month_returns_error() {
        assert!("851323".parse_date_yymmdd(false).is_err());
    }

    // --- parse_date ---

    #[test]
    fn parse_date_yyyymmdd() {
        let d = "20231231".parse_date(false).unwrap();
        assert_eq!(d.year(), 2023);
        assert_eq!(d.month(), 12);
        assert_eq!(d.day(), 31);
    }

    #[test]
    fn parse_date_yymmdd_six_digits() {
        let d = "850423".parse_date(false).unwrap();
        assert_eq!(d.year(), 1985);
    }

    #[test]
    fn parse_date_empty_returns_error() {
        assert!("".parse_date(false).is_err());
    }

    #[test]
    fn parse_date_unsupported_length_returns_error() {
        // 7 digits – unsupported
        assert!("2023123".parse_date(false).is_err());
    }
}
