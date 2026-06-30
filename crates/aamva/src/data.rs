//! Parsed AAMVA DL / ID data model.

use chrono::NaiveDate;
use std::collections::BTreeMap;
use strum::{Display, EnumString};

/// Sex / gender as encoded in element `DBC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
pub enum Sex {
    #[strum(serialize = "1")]
    Male,
    #[strum(serialize = "2")]
    Female,
    /// `9` — not specified / other.
    #[strum(serialize = "9")]
    NotSpecified,
}

/// Eye colour codes — AAMVA §D.12.6. Unknown codes fall into `Other`.
#[derive(Debug, Clone, PartialEq, Eq, EnumString, Display)]
#[strum(ascii_case_insensitive)]
pub enum EyeColor {
    #[strum(serialize = "BLK")]
    Black,
    #[strum(serialize = "BLU")]
    Blue,
    #[strum(serialize = "BRO", serialize = "BRN")]
    Brown,
    #[strum(serialize = "GRY")]
    Gray,
    #[strum(serialize = "GRN")]
    Green,
    #[strum(serialize = "HAZ")]
    Hazel,
    #[strum(serialize = "MAR")]
    Maroon,
    #[strum(serialize = "PNK")]
    Pink,
    #[strum(serialize = "DIC")]
    Dichromatic,
    #[strum(serialize = "UNK")]
    Unknown,
    #[strum(default)]
    Other(String),
}

/// Hair colour codes — AAMVA §D.12.5. Unknown codes fall into `Other`.
#[derive(Debug, Clone, PartialEq, Eq, EnumString, Display)]
#[strum(ascii_case_insensitive)]
pub enum HairColor {
    #[strum(serialize = "BAL")]
    Bald,
    #[strum(serialize = "BLK")]
    Black,
    #[strum(serialize = "BLN")]
    Blond,
    #[strum(serialize = "BRO", serialize = "BRN")]
    Brown,
    #[strum(serialize = "GRY")]
    Gray,
    #[strum(serialize = "RED")]
    Red,
    #[strum(serialize = "SDY")]
    Sandy,
    #[strum(serialize = "WHI")]
    White,
    #[strum(serialize = "UNK")]
    Unknown,
    #[strum(default)]
    Other(String),
}

/// Country identifier from element `DCG`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
pub enum Country {
    #[strum(serialize = "USA")]
    Usa,
    #[strum(serialize = "CAN")]
    Canada,
}

/// DHS / REAL ID compliance indicator from element `DDA`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
pub enum Compliance {
    /// `F` — fully compliant (REAL ID).
    #[strum(serialize = "F")]
    Compliant,
    /// `N` — non-compliant.
    #[strum(serialize = "N")]
    NonCompliant,
}

/// Height as it appears in element `DAU`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Height {
    /// Value in inches (USA).
    Inches(u16),
    /// Value in centimetres (Canada).
    Centimetres(u16),
}

impl Height {
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        // AAMVA format: "nnn in" or "nnn cm" (commonly 3-digit value).
        let trimmed = raw.trim();
        let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return None;
        }
        let value: u16 = digits.parse().ok()?;
        let unit = trimmed[digits.len()..].trim().to_ascii_lowercase();
        match unit.as_str() {
            // USA jurisdictions frequently omit the unit; treat bare values as inches.
            "" | "in" => Some(Height::Inches(value)),
            "cm" => Some(Height::Centimetres(value)),
            // Anything else is an unrecognised unit — reject rather than guess.
            _ => None,
        }
    }
}

/// Truncation flag (`T` / `N` / `U`) applied to name fields `DDE` / `DDF` /
/// `DDG` — indicates whether the preceding name has been truncated to fit
/// AAMVA limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
pub enum Truncation {
    /// `T` — truncated.
    #[strum(serialize = "T")]
    Truncated,
    /// `N` — not truncated.
    #[strum(serialize = "N")]
    NotTruncated,
    /// `U` — unknown / not supported by jurisdiction.
    #[strum(serialize = "U")]
    Unknown,
}

/// Parsed AAMVA header — everything before the first subfile.
#[derive(Debug, Clone)]
pub struct AamvaHeader {
    pub iin: String,
    pub aamva_version: u8,
    pub jurisdiction_version: u8,
    pub entry_count: u8,
    pub subfiles: Vec<SubfileDesignator>,
}

/// Locates one subfile in the payload.
#[derive(Debug, Clone)]
pub struct SubfileDesignator {
    /// 2-char subfile type (`DL` for driver licence, `ID` for identification,
    /// `JA`–`JZ` for jurisdiction-specific extensions).
    pub subfile_type: String,
    /// Offset from the start of the payload to the subfile's type tag.
    pub offset: usize,
    /// Length in bytes of the subfile including the leading type tag and
    /// trailing segment terminator.
    pub length: usize,
}

/// Full parsed AAMVA license.
#[derive(Debug, Clone, Default)]
pub struct AamvaLicense {
    pub header: Option<AamvaHeader>,

    /// Raw 3-letter → value map, exactly as encoded in every subfile.
    pub elements: BTreeMap<String, String>,

    // -------- Identity --------
    pub family_name: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub name_suffix: Option<String>,
    pub family_name_truncation: Option<Truncation>,
    pub first_name_truncation: Option<Truncation>,
    pub middle_name_truncation: Option<Truncation>,

    // -------- Identifiers --------
    pub document_number: Option<String>,
    pub document_discriminator: Option<String>,
    pub country: Option<Country>,
    pub jurisdiction: Option<String>,

    // -------- Dates --------
    pub date_of_birth: Option<NaiveDate>,
    pub issue_date: Option<NaiveDate>,
    pub expiry_date: Option<NaiveDate>,
    pub card_revision_date: Option<NaiveDate>,
    pub under_18_until: Option<NaiveDate>,
    pub under_19_until: Option<NaiveDate>,
    pub under_21_until: Option<NaiveDate>,

    // -------- Physical --------
    pub sex: Option<Sex>,
    pub eye_color: Option<EyeColor>,
    pub hair_color: Option<HairColor>,
    pub height: Option<Height>,
    pub weight_lb: Option<u32>,
    pub weight_kg: Option<u32>,
    pub weight_range: Option<u8>,

    // -------- Address --------
    pub address_street_1: Option<String>,
    pub address_street_2: Option<String>,
    pub city: Option<String>,
    pub postal_code: Option<String>,

    // -------- Licence classification --------
    pub vehicle_class: Option<String>,
    pub restrictions: Option<String>,
    pub endorsements: Option<String>,

    // -------- Flags --------
    pub organ_donor: Option<bool>,
    pub veteran: Option<bool>,
    pub compliance: Option<Compliance>,
}
