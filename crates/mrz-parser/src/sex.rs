use std::str::FromStr;
use strum::{Display, EnumString};

/// Sex as represented in MRZ parsing domain, with helpers for
/// MRZ-character mapping and a sensible default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
#[strum(ascii_case_insensitive)]
pub enum Sex {
    #[strum(to_string = "M", serialize = "male")]
    Male,
    #[strum(to_string = "F", serialize = "female")]
    Female,
    /// Unspecified / unknown — MRZ fillers `<`, `X`, or textual `U`/`unknown`.
    #[strum(
        to_string = "U",
        serialize = "unspecified",
        serialize = "unknown",
        serialize = "X",
        serialize = "<"
    )]
    Unspecified,
}

impl Default for Sex {
    fn default() -> Self {
        Sex::Unspecified
    }
}

impl Sex {
    /// Parse the typical MRZ character into a `Sex`. Anything that isn't
    /// `M`/`F` / `<`/`X` falls back to `Unspecified`.
    pub fn from_mrz_char(c: char) -> Self {
        let mut buf = [0u8; 4];
        let s = c.encode_utf8(&mut buf);
        Self::from_str(s).unwrap_or(Sex::Unspecified)
    }

    /// Convert this `Sex` into its MRZ character representation. `<` is used
    /// for unspecified (common MRZ filler).
    pub fn to_mrz_char(self) -> char {
        match self {
            Sex::Male => 'M',
            Sex::Female => 'F',
            Sex::Unspecified => '<',
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mrz_char_roundtrip() {
        assert_eq!(Sex::from_mrz_char('M'), Sex::Male);
        assert_eq!(Sex::from_mrz_char('F'), Sex::Female);
        assert_eq!(Sex::from_mrz_char('<'), Sex::Unspecified);

        assert_eq!(Sex::Male.to_mrz_char(), 'M');
        assert_eq!(Sex::Female.to_mrz_char(), 'F');
        assert_eq!(Sex::Unspecified.to_mrz_char(), '<');
    }

    #[test]
    fn display_and_parse() {
        // Display emits the primary serialize tag (first declared).
        assert_eq!(Sex::Male.to_string(), "M");
        assert_eq!(Sex::Female.to_string(), "F");
        assert_eq!(Sex::Unspecified.to_string(), "U");

        assert!("M".parse::<Sex>().is_ok());
        assert_eq!("male".parse::<Sex>().unwrap(), Sex::Male);
        assert_eq!("f".parse::<Sex>().unwrap(), Sex::Female);
        assert_eq!("<".parse::<Sex>().unwrap(), Sex::Unspecified);
        assert_eq!("X".parse::<Sex>().unwrap(), Sex::Unspecified);
        assert_eq!("unknown".parse::<Sex>().unwrap(), Sex::Unspecified);
    }

    #[test]
    fn unknown_chars_fall_back_to_unspecified_via_from_mrz_char() {
        assert_eq!(Sex::from_mrz_char('?'), Sex::Unspecified);
        assert_eq!(Sex::from_mrz_char('Z'), Sex::Unspecified);
    }
}
