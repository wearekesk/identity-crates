//! DateTime extension utilities.
//!
//! Provides a `DateTimeFormatExt` trait that adds a `.format_yymmdd()` method
//! to `chrono::NaiveDate`, mirroring the `DateTimeYYMMDDFormatApi` extension:
//!
//! ```dart
//! extension DateTimeYYMMDDFormatApi on DateTime {
//!   String formatYYMMDD() {
//!     var y = year.toString().substring(2, 4).padLeft(2, '0');
//!     var m = month.toString().padLeft(2, '0');
//!     var d = day.toString().padLeft(2, '0');
//!     return y + m + d;
//!   }
//! }
//! ```
//!
//! The output is always exactly 6 characters: `YYMMDD`.

use chrono::Datelike;
use chrono::NaiveDate;

/// Extension trait that adds a `.format_yymmdd()` method to date types,
/// producing a compact 6-character `YYMMDD` string.
///
/// # Examples
/// ```
/// use dmrtd::extension::datetime::DateTimeFormatExt;
/// use chrono::NaiveDate;
///
/// let date = NaiveDate::from_ymd_opt(2023, 5, 9).unwrap();
/// assert_eq!(date.format_yymmdd(), "230509");
///
/// let date2 = NaiveDate::from_ymd_opt(2000, 1, 1).unwrap();
/// assert_eq!(date2.format_yymmdd(), "000101");
///
/// let date3 = NaiveDate::from_ymd_opt(1999, 12, 31).unwrap();
/// assert_eq!(date3.format_yymmdd(), "991231");
/// ```
pub trait DateTimeFormatExt {
    /// Returns the date formatted as a 6-character `YYMMDD` string.
    ///
    /// Only the last two digits of the year are used, zero-padded to 2 digits.
    /// Month and day are also zero-padded to 2 digits each.
    fn format_yymmdd(&self) -> String;
}

impl DateTimeFormatExt for NaiveDate {
    fn format_yymmdd(&self) -> String {
        // Take last two digits of the year
        let yy = self.year().rem_euclid(100);
        let mm = self.month();
        let dd = self.day();
        format!("{:02}{:02}{:02}", yy, mm, dd)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_year_2023() {
        let d = NaiveDate::from_ymd_opt(2023, 5, 9).unwrap();
        assert_eq!(d.format_yymmdd(), "230509");
    }

    #[test]
    fn format_year_2000() {
        let d = NaiveDate::from_ymd_opt(2000, 1, 1).unwrap();
        assert_eq!(d.format_yymmdd(), "000101");
    }

    #[test]
    fn format_year_1999() {
        let d = NaiveDate::from_ymd_opt(1999, 12, 31).unwrap();
        assert_eq!(d.format_yymmdd(), "991231");
    }

    #[test]
    fn format_pads_single_digit_month_and_day() {
        let d = NaiveDate::from_ymd_opt(2005, 3, 7).unwrap();
        assert_eq!(d.format_yymmdd(), "050307");
    }

    #[test]
    fn format_century_boundary() {
        // Year 2100 -> yy = 00
        let d = NaiveDate::from_ymd_opt(2100, 6, 15).unwrap();
        assert_eq!(d.format_yymmdd(), "000615");
    }

    #[test]
    fn format_length_is_always_six() {
        let dates = [
            NaiveDate::from_ymd_opt(2000, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(1985, 11, 22).unwrap(),
            NaiveDate::from_ymd_opt(2030, 9, 5).unwrap(),
        ];
        for d in &dates {
            assert_eq!(d.format_yymmdd().len(), 6, "Expected 6 chars for {:?}", d);
        }
    }
}
