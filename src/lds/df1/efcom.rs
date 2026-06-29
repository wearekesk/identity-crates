//! EF.COM — Common data element file.
//!
//! EF.COM holds three TLV-encoded children under tag `0x60`:
//! - version string         (tag `0x5F01`)
//! - unicode version string (tag `0x5F36`)
//! - data-group tag list    (tag `0x5C`)
//!
//! Each byte of the tag-list is interpreted as one [`DgTag`] value.

use std::collections::BTreeSet;

use crate::lds::df1::dg::DgTag;
use crate::lds::ef::{ElementaryFile, EfParseError};
use crate::lds::tlv::Tlv;

/// EF.COM file ID.
pub const EF_COM_FID: u16 = 0x011E;
/// EF.COM short file ID.
pub const EF_COM_SFI: u8 = 0x1E;
/// EF.COM outer tag.
pub const EF_COM_TAG: u32 = 0x60;

const TAG_VERSION: u32 = 0x5F01;
const TAG_UNICODE_VERSION: u32 = 0x5F36;
const TAG_TAG_LIST: u32 = 0x5C;

/// Parsed EF.COM contents.
#[derive(Debug, Clone)]
pub struct EfCOM {
    encoded: Vec<u8>,
    version: String,
    unicode_version: String,
    dg_tags: BTreeSet<DgTag>,
}

impl EfCOM {
    /// Parses EF.COM from raw bytes.
    ///
    /// # Errors
    /// Returns [`EfParseError`] for any structural mismatch.
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> Result<Self, EfParseError> {
        let encoded = data.into();
        let tlv = Tlv::decode(&encoded)
            .map_err(|e| EfParseError::new(format!("Invalid EF.COM wrapper: {e}")))?;
        if tlv.tag.value != EF_COM_TAG {
            return Err(EfParseError::new(format!(
                "Invalid EF.COM tag={:X}, expected tag={:X}",
                tlv.tag.value, EF_COM_TAG
            )));
        }
        // EF.COM is exactly one BER-TLV; reject any trailing bytes.
        if tlv.encoded_len != encoded.len() {
            return Err(EfParseError::new(format!(
                "Trailing bytes after EF.COM TLV: {} extra byte(s)",
                encoded.len() - tlv.encoded_len
            )));
        }

        let data = tlv.value.as_slice();
        let vtv = Tlv::decode(data)
            .map_err(|e| EfParseError::new(format!("Invalid version TLV: {e}")))?;
        if vtv.tag.value != TAG_VERSION {
            return Err(EfParseError::new(format!(
                "Invalid version object tag={:X}, expected version object with tag=5F01",
                vtv.tag.value
            )));
        }
        let version = bytes_to_string(&vtv.value);

        let uvtv = Tlv::decode(&data[vtv.encoded_len..])
            .map_err(|e| EfParseError::new(format!("Invalid unicode version TLV: {e}")))?;
        if uvtv.tag.value != TAG_UNICODE_VERSION {
            return Err(EfParseError::new(format!(
                "Invalid unicode version object tag={:X}, expected unicode version object with tag=5F36",
                uvtv.tag.value
            )));
        }
        let unicode_version = bytes_to_string(&uvtv.value);

        let tag_list_tlv = Tlv::decode(&data[vtv.encoded_len + uvtv.encoded_len..])
            .map_err(|e| EfParseError::new(format!("Invalid tag-list TLV: {e}")))?;
        if tag_list_tlv.tag.value != TAG_TAG_LIST {
            return Err(EfParseError::new(format!(
                "Invalid tag list object tag={:X}, expected tag list object with tag=5C",
                tag_list_tlv.tag.value
            )));
        }

        let dg_tags: BTreeSet<DgTag> = tag_list_tlv
            .value
            .iter()
            .map(|&b| DgTag(b as u32))
            .collect();

        Ok(Self {
            encoded,
            version,
            unicode_version,
            dg_tags,
        })
    }

    /// Version string (LDS version).
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Unicode version string.
    pub fn unicode_version(&self) -> &str {
        &self.unicode_version
    }

    /// Data-group tag list.
    pub fn dg_tags(&self) -> &BTreeSet<DgTag> {
        &self.dg_tags
    }
}

impl ElementaryFile for EfCOM {
    const FID: u16 = EF_COM_FID;
    const SFI: u8 = EF_COM_SFI;

    fn to_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

fn bytes_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ef_com(version: &[u8], uver: &[u8], dg_tags: &[u8]) -> Vec<u8> {
        let v_tlv = Tlv::encode(TAG_VERSION, version);
        let uv_tlv = Tlv::encode(TAG_UNICODE_VERSION, uver);
        let tl_tlv = Tlv::encode(TAG_TAG_LIST, dg_tags);
        let mut body = Vec::new();
        body.extend_from_slice(&v_tlv);
        body.extend_from_slice(&uv_tlv);
        body.extend_from_slice(&tl_tlv);
        Tlv::encode(EF_COM_TAG, &body)
    }

    #[test]
    fn parses_valid_ef_com() {
        let bytes = build_ef_com(b"0107", b"040000", &[0x61, 0x75, 0x77]);
        let ef = EfCOM::from_bytes(bytes.clone()).unwrap();
        assert_eq!(ef.version(), "0107");
        assert_eq!(ef.unicode_version(), "040000");
        let expected: BTreeSet<DgTag> = [DgTag(0x61), DgTag(0x75), DgTag(0x77)]
            .into_iter()
            .collect();
        assert_eq!(ef.dg_tags(), &expected);
        assert_eq!(ef.to_bytes(), bytes.as_slice());
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        // Build the inner body correctly but wrap it with tag 0x61.
        let v_tlv = Tlv::encode(TAG_VERSION, b"0107");
        let uv_tlv = Tlv::encode(TAG_UNICODE_VERSION, b"040000");
        let tl_tlv = Tlv::encode(TAG_TAG_LIST, &[0x61]);
        let mut body = Vec::new();
        body.extend_from_slice(&v_tlv);
        body.extend_from_slice(&uv_tlv);
        body.extend_from_slice(&tl_tlv);
        let bytes = Tlv::encode(0x61, &body);
        let err = EfCOM::from_bytes(bytes).unwrap_err();
        assert!(err.0.contains("Invalid EF.COM tag"));
    }

    #[test]
    fn rejects_wrong_version_inner_tag() {
        let wrong_v = Tlv::encode(0x5F02, b"0107");
        let uv_tlv = Tlv::encode(TAG_UNICODE_VERSION, b"040000");
        let tl_tlv = Tlv::encode(TAG_TAG_LIST, &[0x61]);
        let mut body = Vec::new();
        body.extend_from_slice(&wrong_v);
        body.extend_from_slice(&uv_tlv);
        body.extend_from_slice(&tl_tlv);
        let bytes = Tlv::encode(EF_COM_TAG, &body);
        let err = EfCOM::from_bytes(bytes).unwrap_err();
        assert!(err.0.contains("expected version object with tag=5F01"));
    }

    #[test]
    fn rejects_trailing_bytes_after_outer_tlv() {
        let mut bytes = build_ef_com(b"0107", b"040000", &[0x61]);
        bytes.push(0x00); // trailing byte after the EF.COM TLV
        let err = EfCOM::from_bytes(bytes).unwrap_err();
        assert!(err.0.contains("Trailing bytes"));
    }

    #[test]
    fn empty_tag_list_is_allowed() {
        let bytes = build_ef_com(b"0107", b"040000", &[]);
        let ef = EfCOM::from_bytes(bytes).unwrap();
        assert!(ef.dg_tags().is_empty());
    }

    /// ICAO 9303 p10 Appendix A.1 test case 1.
    #[test]
    fn icao_a1_case1_parses() {
        let bytes =
            hex::decode("60165F0104303130375F36063034303030305C046175766C").unwrap();
        let ef = EfCOM::from_bytes(bytes.clone()).unwrap();
        assert_eq!(ef.to_bytes(), bytes.as_slice());
        assert_eq!(ef.version(), "0107");
        assert_eq!(ef.unicode_version(), "040000");
        let tags = ef.dg_tags();
        assert_eq!(tags.len(), 4);
        assert!(tags.contains(&DgTag(0x61)));
        assert!(tags.contains(&DgTag(0x75)));
        assert!(tags.contains(&DgTag(0x76)));
        assert!(tags.contains(&DgTag(0x6C)));
    }

    /// ICAO 9303 p10 Appendix A.1 test case 2.
    #[test]
    fn icao_a1_case2_parses() {
        let bytes =
            hex::decode("60165F0104313539395F36063034303030305C046175766C").unwrap();
        let ef = EfCOM::from_bytes(bytes.clone()).unwrap();
        assert_eq!(ef.version(), "1599");
        assert_eq!(ef.unicode_version(), "040000");
        assert_eq!(ef.dg_tags().len(), 4);
    }
}
