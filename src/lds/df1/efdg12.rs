//! EF.DG12 — Additional Document Details.
//!
//! The reference parses only the issuing authority (`0x5F19`) and date
//! of issue (`0x5F26`) — other declared tags (name of other person,
//! endorsements, tax, images, personalisation timestamps) are accepted but
//! stored verbatim. This port preserves that behaviour.

use chrono::NaiveDate;

use crate::extension::string::StringDateExt;
use crate::lds::df1::dg::{parse_dg_content, DgTag};
use crate::lds::ef::{ElementaryFile, EfParseError};
use crate::lds::tlv::Tlv;

/// EF.DG12 file ID.
pub const EF_DG12_FID: u16 = 0x010C;
/// EF.DG12 short file ID.
pub const EF_DG12_SFI: u8 = 0x0C;
/// EF.DG12 outer tag.
pub const EF_DG12_TAG: DgTag = DgTag(0x6C);

const TAG_TAG_LIST: u32 = 0x5C;
const TAG_ISSUING_AUTHORITY: u32 = 0x5F19;
const TAG_DATE_OF_ISSUE: u32 = 0x5F26;

/// EF.DG12 — Additional Document Details.
#[derive(Debug, Clone, Default)]
pub struct EfDG12 {
    encoded: Vec<u8>,
    pub issuing_authority: Option<String>,
    pub date_of_issue: Option<NaiveDate>,
}

impl EfDG12 {
    /// Parses EF.DG12 bytes.
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> Result<Self, EfParseError> {
        let encoded = data.into();
        let body = parse_dg_content(&encoded, EF_DG12_TAG.value())?;

        let tag_list_tlv = Tlv::decode(&body)
            .map_err(|e| EfParseError::new(format!("Invalid DG12 tag-list TLV: {e}")))?;
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
                .map_err(|e| EfParseError::new(format!("Invalid DG12 field TLV: {e}")))?;
            offset += tlv.encoded_len;
            match tlv.tag.value {
                TAG_ISSUING_AUTHORITY => {
                    out.issuing_authority = Some(
                        std::str::from_utf8(&tlv.value)
                            .map_err(|e| {
                                EfParseError::new(format!(
                                    "Invalid UTF-8 in issuing authority: {e}"
                                ))
                            })?
                            .to_string(),
                    );
                }
                TAG_DATE_OF_ISSUE => {
                    let s: String = tlv.value.iter().map(|&b| b as char).collect();
                    out.date_of_issue = Some(s.parse_date(false).map_err(|e| {
                        EfParseError::new(format!("Invalid DG12 date of issue: {e}"))
                    })?);
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

impl ElementaryFile for EfDG12 {
    const FID: u16 = EF_DG12_FID;
    const SFI: u8 = EF_DG12_SFI;

    fn to_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dg12(tag_list: &[u8], fields: Vec<Vec<u8>>) -> Vec<u8> {
        let mut body = Tlv::encode(TAG_TAG_LIST, tag_list);
        for f in fields {
            body.extend_from_slice(&f);
        }
        Tlv::encode(EF_DG12_TAG.value(), &body)
    }

    #[test]
    fn parses_issuing_authority_and_date() {
        let fields = vec![
            Tlv::encode(TAG_ISSUING_AUTHORITY, "UTOPIA MFA".as_bytes()),
            Tlv::encode(TAG_DATE_OF_ISSUE, "20120408".as_bytes()),
        ];
        let dg = EfDG12::from_bytes(build_dg12(&[0x19, 0x26], fields)).unwrap();
        assert_eq!(dg.issuing_authority.as_deref(), Some("UTOPIA MFA"));
        assert_eq!(
            dg.date_of_issue,
            Some(NaiveDate::from_ymd_opt(2012, 4, 8).unwrap())
        );
    }

    #[test]
    fn unknown_tags_are_ignored() {
        let fields = vec![
            Tlv::encode(TAG_ISSUING_AUTHORITY, b"X"),
            Tlv::encode(0x5F55, b"20230101120000"),
        ];
        let dg = EfDG12::from_bytes(build_dg12(&[0x19, 0x55], fields)).unwrap();
        assert_eq!(dg.issuing_authority.as_deref(), Some("X"));
        assert!(dg.date_of_issue.is_none());
    }

    #[test]
    fn rejects_missing_tag_list() {
        let bad = Tlv::encode(
            EF_DG12_TAG.value(),
            &Tlv::encode(TAG_ISSUING_AUTHORITY, b"X"),
        );
        let err = EfDG12::from_bytes(bad).unwrap_err();
        assert!(err.0.contains("expected tag=5C"));
    }

    #[test]
    fn constants() {
        assert_eq!(EfDG12::FID, 0x010C);
        assert_eq!(EfDG12::SFI, 0x0C);
        assert_eq!(EF_DG12_TAG.value(), 0x6C);
    }
}
