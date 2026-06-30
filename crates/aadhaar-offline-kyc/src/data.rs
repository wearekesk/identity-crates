//! Parsed Aadhaar data model.

use chrono::NaiveDate;
use std::str::FromStr;
use strum::{Display, EnumString};

/// Gender as encoded in the Aadhaar Secure QR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
#[strum(ascii_case_insensitive)]
pub enum Gender {
    #[strum(serialize = "M")]
    Male,
    #[strum(serialize = "F")]
    Female,
    /// Third gender / transgender (UIDAI uses `T`).
    #[strum(serialize = "T")]
    Transgender,
}

impl Gender {
    /// Parses a single ASCII byte of gender (`M` / `F` / `T`).
    ///
    /// The input must be exactly one ASCII byte; empty, multi-byte, or
    /// trailing-garbage inputs are rejected rather than silently reading only
    /// the first byte.
    pub(crate) fn parse_byte(raw: &[u8]) -> Option<Self> {
        let [byte] = raw else { return None };
        if !byte.is_ascii() {
            return None;
        }
        Self::from_str((*byte as char).encode_utf8(&mut [0u8; 4])).ok()
    }
}

/// Parsed Aadhaar Secure QR record.
///
/// Field order matches the UIDAI Secure QR v2 spec (email-mobile indicator,
/// reference ID, name, DOB, gender, then address components, then photo,
/// optional hashes, and the 256-byte RSA signature).
#[derive(Debug, Clone, Default)]
pub struct AadhaarData {
    /// Email/mobile indicator digit (bit 0 = mobile present, bit 1 = email
    /// present).
    pub email_mobile_indicator: u8,

    /// Reference ID as encoded in the QR: last 4 digits of the Aadhaar
    /// number concatenated with a `YYYYMMDDHHMMSSnnn` timestamp.
    pub reference_id: String,

    /// Last four digits of the Aadhaar number, parsed from the first four
    /// characters of `reference_id`.
    pub last_four_aadhaar: String,

    pub name: String,
    pub dob: Option<NaiveDate>,
    pub gender: Option<Gender>,

    pub care_of: Option<String>,
    pub district: Option<String>,
    pub landmark: Option<String>,
    pub house: Option<String>,
    pub location: Option<String>,
    pub pincode: Option<String>,
    pub post_office: Option<String>,
    pub state: Option<String>,
    pub street: Option<String>,
    pub sub_district: Option<String>,
    pub village_town_city: Option<String>,

    /// JPEG bytes of the resident's face photo.
    pub photo_jpeg: Option<Vec<u8>>,
    /// 32-byte SHA-256 hash of the mobile number (when indicator bit 0 is set).
    pub mobile_hash: Option<Vec<u8>>,
    /// 32-byte SHA-256 hash of the email address (when indicator bit 1 is set).
    pub email_hash: Option<Vec<u8>>,

    /// 256-byte RSA-SHA256 signature over the preceding payload; verify with
    /// the UIDAI public certificate (out of scope here).
    pub signature: Vec<u8>,
}

impl AadhaarData {
    /// Returns `true` when the indicator declares a mobile-number hash.
    pub fn mobile_declared(&self) -> bool {
        self.email_mobile_indicator & 0b01 != 0
    }
    /// Returns `true` when the indicator declares an email-address hash.
    pub fn email_declared(&self) -> bool {
        self.email_mobile_indicator & 0b10 != 0
    }
}
