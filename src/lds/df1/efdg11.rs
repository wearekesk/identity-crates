//! EF.DG11 — Additional Personal Details.
//!
//! DG11 carries an optional tag list (TL `0x5C`) followed by a sequence of
//! BER-TLV fields. Each field may appear zero or more times; the parser
//! accumulates repeatable fields (other names, places of birth, permanent
//! address lines, other valid TD numbers) into vectors and stores scalars
//! (name, personal number, telephone, etc.) directly.

use chrono::NaiveDate;

use crate::extension::string::StringDateExt;
use crate::extension::uint8list::BytesExt;
use crate::lds::df1::dg::{parse_dg_content, DgTag};
use crate::lds::ef::{ElementaryFile, EfParseError};
use crate::lds::tlv::Tlv;

/// EF.DG11 file ID.
pub const EF_DG11_FID: u16 = 0x010B;
/// EF.DG11 short file ID.
pub const EF_DG11_SFI: u8 = 0x0B;
/// EF.DG11 outer tag.
pub const EF_DG11_TAG: DgTag = DgTag(0x6B);

// Field tags (ICAO 9303 p10 §3.11).
const TAG_TAG_LIST: u32 = 0x5C;
const TAG_FULL_NAME: u32 = 0x5F0E;
const TAG_OTHER_NAME: u32 = 0x5F0F;
const TAG_PERSONAL_NUMBER: u32 = 0x5F10;
const TAG_FULL_DATE_OF_BIRTH: u32 = 0x5F2B;
const TAG_PLACE_OF_BIRTH: u32 = 0x5F11;
const TAG_PERMANENT_ADDRESS: u32 = 0x5F42;
const TAG_TELEPHONE: u32 = 0x5F12;
const TAG_PROFESSION: u32 = 0x5F13;
const TAG_TITLE: u32 = 0x5F14;
const TAG_PERSONAL_SUMMARY: u32 = 0x5F15;
const TAG_PROOF_OF_CITIZENSHIP: u32 = 0x5F16;
const TAG_OTHER_VALID_TD_NUMBERS: u32 = 0x5F17;
const TAG_CUSTODY_INFORMATION: u32 = 0x5F18;

/// EF.DG11 — Additional Personal Details.
#[derive(Debug, Clone, Default)]
pub struct EfDG11 {
    encoded: Vec<u8>,
    pub name_of_holder: Option<String>,
    pub other_names: Vec<String>,
    pub personal_number: Option<String>,
    pub full_date_of_birth: Option<NaiveDate>,
    pub place_of_birth: Vec<String>,
    pub permanent_address: Vec<String>,
    pub telephone: Option<String>,
    pub profession: Option<String>,
    pub title: Option<String>,
    pub personal_summary: Option<String>,
    pub proof_of_citizenship: Option<Vec<u8>>,
    pub other_valid_td_numbers: Vec<String>,
    pub custody_information: Option<String>,
}

impl EfDG11 {
    /// Parses EF.DG11 bytes.
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> Result<Self, EfParseError> {
        let encoded = data.into();
        let body = parse_dg_content(&encoded, EF_DG11_TAG.value())?;

        // First inner TLV must be the tag list (0x5C).
        let tag_list_tlv = Tlv::decode(&body)
            .map_err(|e| EfParseError::new(format!("Invalid DG11 tag-list TLV: {e}")))?;
        if tag_list_tlv.tag.value != TAG_TAG_LIST {
            return Err(EfParseError::new(format!(
                "Invalid tag-list tag={:X}, expected tag={:X}",
                tag_list_tlv.tag.value, TAG_TAG_LIST
            )));
        }

        let mut out = Self {
            encoded,
            ..Self::default()
        };
        let mut offset = tag_list_tlv.encoded_len;
        while offset < body.len() {
            let tlv = Tlv::decode(&body[offset..])
                .map_err(|e| EfParseError::new(format!("Invalid DG11 field TLV: {e}")))?;
            offset += tlv.encoded_len;
            out.absorb_field(tlv.tag.value, &tlv.value)?;
        }
        Ok(out)
    }

    fn absorb_field(&mut self, tag: u32, value: &[u8]) -> Result<(), EfParseError> {
        match tag {
            TAG_FULL_NAME => self.name_of_holder = Some(utf8(value)?),
            TAG_OTHER_NAME => self.other_names.push(utf8(value)?),
            TAG_PERSONAL_NUMBER => self.personal_number = Some(utf8(value)?),
            TAG_FULL_DATE_OF_BIRTH => {
                self.full_date_of_birth = Some(parse_full_dob(value)?);
            }
            TAG_PLACE_OF_BIRTH => self.place_of_birth.push(utf8(value)?),
            TAG_PERMANENT_ADDRESS => self.permanent_address.push(utf8(value)?),
            TAG_TELEPHONE => self.telephone = Some(utf8(value)?),
            TAG_PROFESSION => self.profession = Some(utf8(value)?),
            TAG_TITLE => self.title = Some(utf8(value)?),
            TAG_PERSONAL_SUMMARY => self.personal_summary = Some(utf8(value)?),
            TAG_PROOF_OF_CITIZENSHIP => self.proof_of_citizenship = Some(value.to_vec()),
            TAG_OTHER_VALID_TD_NUMBERS => self.other_valid_td_numbers.push(utf8(value)?),
            TAG_CUSTODY_INFORMATION => self.custody_information = Some(utf8(value)?),
            _ => {} // Ignore unrecognised tags.
        }
        Ok(())
    }
}

impl ElementaryFile for EfDG11 {
    const FID: u16 = EF_DG11_FID;
    const SFI: u8 = EF_DG11_SFI;

    fn to_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

/// Parses the "full date of birth" field, which may be either 4 packed-BCD
/// bytes (`CCYYMMDD` → 4 bytes when read as 8 BCD nibbles) or 8 ASCII digits.
fn parse_full_dob(value: &[u8]) -> Result<NaiveDate, EfParseError> {
    if value.len() == 4 {
        value
            .to_date()
            .map_err(|e| EfParseError::new(format!("Invalid DG11 packed date: {e}")))
    } else {
        // The ASCII form is exactly 8 digits (CCYYMMDD); `parse_date` alone is
        // too permissive (it would also accept e.g. a 6-digit YYMMDD).
        if value.len() != 8 || !value.iter().all(|b| b.is_ascii_digit()) {
            return Err(EfParseError::new(
                "Invalid DG11 date string: expected 8 ASCII digits (CCYYMMDD)",
            ));
        }
        let s: String = value.iter().map(|&b| b as char).collect();
        s.parse_date(false)
            .map_err(|e| EfParseError::new(format!("Invalid DG11 date string: {e}")))
    }
}

fn utf8(value: &[u8]) -> Result<String, EfParseError> {
    std::str::from_utf8(value)
        .map(|s| s.to_string())
        .map_err(|e| EfParseError::new(format!("Invalid UTF-8 in DG11 field: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn field(tag: u32, value: &[u8]) -> Vec<u8> {
        Tlv::encode(tag, value)
    }

    fn build_dg11(tag_list: &[u8], fields: Vec<Vec<u8>>) -> Vec<u8> {
        let mut body = Tlv::encode(TAG_TAG_LIST, tag_list);
        for f in fields {
            body.extend_from_slice(&f);
        }
        Tlv::encode(EF_DG11_TAG.value(), &body)
    }

    #[test]
    fn parses_full_name_and_personal_number() {
        let fields = vec![
            field(TAG_FULL_NAME, "ERIKSSON<<ANNA<MARIA".as_bytes()),
            field(TAG_PERSONAL_NUMBER, "Z1234567".as_bytes()),
        ];
        let bytes = build_dg11(&[0x0E, 0x10], fields);
        let dg = EfDG11::from_bytes(bytes).unwrap();
        assert_eq!(dg.name_of_holder.as_deref(), Some("ERIKSSON<<ANNA<MARIA"));
        assert_eq!(dg.personal_number.as_deref(), Some("Z1234567"));
    }

    #[test]
    fn accumulates_repeatable_fields() {
        let fields = vec![
            field(TAG_OTHER_NAME, b"ALIAS ONE"),
            field(TAG_OTHER_NAME, b"ALIAS TWO"),
            field(TAG_PLACE_OF_BIRTH, b"CITY"),
            field(TAG_PLACE_OF_BIRTH, b"COUNTRY"),
            field(TAG_PERMANENT_ADDRESS, b"LINE 1"),
            field(TAG_OTHER_VALID_TD_NUMBERS, b"TD-A"),
            field(TAG_OTHER_VALID_TD_NUMBERS, b"TD-B"),
        ];
        let dg = EfDG11::from_bytes(build_dg11(&[0x0F, 0x11, 0x42, 0x17], fields)).unwrap();
        assert_eq!(dg.other_names, vec!["ALIAS ONE", "ALIAS TWO"]);
        assert_eq!(dg.place_of_birth, vec!["CITY", "COUNTRY"]);
        assert_eq!(dg.permanent_address, vec!["LINE 1"]);
        assert_eq!(dg.other_valid_td_numbers, vec!["TD-A", "TD-B"]);
    }

    #[test]
    fn parses_date_of_birth_as_ascii() {
        // 8-byte ASCII CCYYMMDD.
        let fields = vec![field(TAG_FULL_DATE_OF_BIRTH, b"19740812")];
        let dg = EfDG11::from_bytes(build_dg11(&[0x2B], fields)).unwrap();
        assert_eq!(
            dg.full_date_of_birth,
            Some(NaiveDate::from_ymd_opt(1974, 8, 12).unwrap())
        );
    }

    #[test]
    fn rejects_non_8_digit_ascii_dob() {
        // 6-digit YYMMDD must be rejected for the full DOB string form.
        let fields = vec![field(TAG_FULL_DATE_OF_BIRTH, b"740812")];
        let err = EfDG11::from_bytes(build_dg11(&[0x2B], fields)).unwrap_err();
        assert!(err.0.contains("8 ASCII digits"));

        // Non-digit characters are rejected even at the valid length of 8 bytes.
        let fields = vec![field(TAG_FULL_DATE_OF_BIRTH, b"1974AB12")];
        let err = EfDG11::from_bytes(build_dg11(&[0x2B], fields)).unwrap_err();
        assert!(err.0.contains("8 ASCII digits"));
    }

    #[test]
    fn parses_date_of_birth_as_packed_bcd() {
        // Packed BCD 4 bytes: 19 74 08 12 → 1974-08-12.
        let fields = vec![field(TAG_FULL_DATE_OF_BIRTH, &[0x19, 0x74, 0x08, 0x12])];
        let dg = EfDG11::from_bytes(build_dg11(&[0x2B], fields)).unwrap();
        assert_eq!(
            dg.full_date_of_birth,
            Some(NaiveDate::from_ymd_opt(1974, 8, 12).unwrap())
        );
    }

    #[test]
    fn stores_proof_of_citizenship_bytes_verbatim() {
        let blob = vec![0xFFu8, 0xD8, 0xFF, 0xE0]; // JPEG SOI + APP0 marker, abbreviated
        let fields = vec![field(TAG_PROOF_OF_CITIZENSHIP, &blob)];
        let dg = EfDG11::from_bytes(build_dg11(&[0x16], fields)).unwrap();
        assert_eq!(dg.proof_of_citizenship, Some(blob));
    }

    #[test]
    fn unknown_tags_are_ignored() {
        // 0x5F22 is a valid 2-byte BER-TLV tag not recognised by DG11.
        let fields = vec![
            field(TAG_FULL_NAME, b"NAME"),
            field(0x5F22, b"UNKNOWN"),
        ];
        let dg = EfDG11::from_bytes(build_dg11(&[0x0E, 0x22], fields)).unwrap();
        assert_eq!(dg.name_of_holder.as_deref(), Some("NAME"));
    }

    #[test]
    fn rejects_missing_tag_list() {
        // Body without the leading 0x5C TLV.
        let bad = Tlv::encode(EF_DG11_TAG.value(), &Tlv::encode(TAG_FULL_NAME, b"X"));
        let err = EfDG11::from_bytes(bad).unwrap_err();
        assert!(err.0.contains("expected tag=5C"));
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        let inner = Tlv::encode(TAG_TAG_LIST, &[0x0E]);
        let bad = Tlv::encode(0x6A, &inner);
        assert!(EfDG11::from_bytes(bad).is_err());
    }

    #[test]
    fn constants() {
        assert_eq!(EfDG11::FID, 0x010B);
        assert_eq!(EfDG11::SFI, 0x0B);
        assert_eq!(EF_DG11_TAG.value(), 0x6B);
    }
}
