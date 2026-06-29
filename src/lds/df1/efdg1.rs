//! EF.DG1 — MRZ data group.
//!
//! The DG1 payload is a BER-TLV wrapper (tag `0x61`) containing exactly one
//! inner TLV (tag `0x5F1F`) whose value is the raw MRZ byte string. This
//! parser strips both wrappers, parses the MRZ, and exposes it alongside the
//! original bytes.

use crate::lds::df1::dg::{parse_dg_content, DgTag};
use crate::lds::ef::{ElementaryFile, EfParseError};
use crate::lds::mrz::Mrz;
use crate::lds::tlv::Tlv;

/// EF.DG1 file ID.
pub const EF_DG1_FID: u16 = 0x0101;
/// EF.DG1 short file ID.
pub const EF_DG1_SFI: u8 = 0x01;
/// EF.DG1 outer tag.
pub const EF_DG1_TAG: DgTag = DgTag(0x61);
/// Inner TLV tag holding the raw MRZ bytes.
pub const MRZ_TLV_TAG: u32 = 0x5F1F;

/// EF.DG1 — machine-readable zone.
#[derive(Debug, Clone)]
pub struct EfDG1 {
    encoded: Vec<u8>,
    mrz: Mrz,
}

impl EfDG1 {
    /// Parses EF.DG1 bytes.
    ///
    /// # Errors
    /// Returns [`EfParseError`] on malformed wrappers or invalid MRZ.
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> Result<Self, EfParseError> {
        let encoded = data.into();
        let inner = parse_dg_content(&encoded, EF_DG1_TAG.value())?;
        let mrz_tlv = Tlv::from_bytes(&inner)
            .map_err(|e| EfParseError::new(format!("Invalid inner TLV in EF.DG1: {e}")))?;
        if mrz_tlv.tag != MRZ_TLV_TAG {
            return Err(EfParseError::new(format!(
                "Invalid data object tag={:X}, expected object with tag=5F1F",
                mrz_tlv.tag
            )));
        }
        let mrz = Mrz::from_bytes(mrz_tlv.value)
            .map_err(|e| EfParseError::new(format!("Invalid MRZ in EF.DG1: {}", e.0)))?;
        Ok(Self { encoded, mrz })
    }

    /// Returns the parsed MRZ.
    pub fn mrz(&self) -> &Mrz {
        &self.mrz
    }
}

impl ElementaryFile for EfDG1 {
    const FID: u16 = EF_DG1_FID;
    const SFI: u8 = EF_DG1_SFI;

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

    fn wrap_mrz(mrz_bytes: &[u8]) -> Vec<u8> {
        let inner = Tlv::encode(MRZ_TLV_TAG, mrz_bytes);
        Tlv::encode(EF_DG1_TAG.value(), &inner)
    }

    #[test]
    fn parses_td3_mrz_through_dg1() {
        let mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
        let dg1 = EfDG1::from_bytes(wrap_mrz(mrz.as_bytes())).unwrap();
        assert_eq!(dg1.mrz().document_number(), "L898902C3");
        assert_eq!(dg1.mrz().last_name, "ERIKSSON");
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        let mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
        let inner = Tlv::encode(MRZ_TLV_TAG, mrz.as_bytes());
        let bogus = Tlv::encode(0x62, &inner);
        let err = EfDG1::from_bytes(bogus).unwrap_err();
        assert!(err.0.contains("expected tag=61"));
    }

    #[test]
    fn rejects_wrong_inner_tag() {
        let mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
        let inner = Tlv::encode(0x5F1E, mrz.as_bytes());
        let outer = Tlv::encode(EF_DG1_TAG.value(), &inner);
        let err = EfDG1::from_bytes(outer).unwrap_err();
        assert!(err.0.contains("expected object with tag=5F1F"));
    }

    #[test]
    fn propagates_mrz_parse_errors() {
        let bogus_mrz = vec![b'X'; 50]; // invalid length
        let err = EfDG1::from_bytes(wrap_mrz(&bogus_mrz)).unwrap_err();
        assert!(err.0.contains("Invalid MRZ"));
    }

    #[test]
    fn constants() {
        assert_eq!(EfDG1::FID, 0x0101);
        assert_eq!(EfDG1::SFI, 0x01);
        assert_eq!(EF_DG1_TAG.value(), 0x61);
    }

    /// ICAO 9303 p10 Appendix A.2.1 — TD1 sample. Composite check digit was
    /// tweaked from `4` to `8` in the reference trace to produce a valid MRZ.
    #[test]
    fn icao_a21_td1_sample_parses() {
        use crate::lds::mrz::MrzVersion;
        use chrono::NaiveDate;

        let bytes = hex::decode(
            "615D5F1F5A493C4E4C44584938353933354638363939393939393939303C3C3C3C\
             3C3C3732303831343846313130383236384E4C443C3C3C3C3C3C3C3C3C3C3C3856\
             414E3C4445523C535445454E3C3C4D415249414E4E453C4C4F55495345",
        )
        .unwrap();
        let dg1 = EfDG1::from_bytes(bytes.clone()).unwrap();
        assert_eq!(dg1.to_bytes(), bytes.as_slice());
        assert_eq!(dg1.mrz().version, MrzVersion::Td1);
        assert_eq!(dg1.mrz().document_code, "I");
        assert_eq!(dg1.mrz().document_number(), "XI85935F8");
        assert_eq!(dg1.mrz().country, "NLD");
        assert_eq!(dg1.mrz().nationality, "NLD");
        assert_eq!(dg1.mrz().first_name, "MARIANNE LOUISE");
        assert_eq!(dg1.mrz().last_name, "VAN DER STEEN");
        assert_eq!(dg1.mrz().gender, "F");
        assert_eq!(
            dg1.mrz().date_of_birth,
            NaiveDate::from_ymd_opt(1972, 8, 14).unwrap()
        );
        assert_eq!(
            dg1.mrz().date_of_expiry,
            NaiveDate::from_ymd_opt(2011, 8, 26).unwrap()
        );
        assert_eq!(dg1.mrz().optional_data(), "999999990");
        assert_eq!(dg1.mrz().optional_data2(), Some(""));
    }

    /// ICAO 9303 p04 Appendix B — TD3 sample (ERIKSSON passport).
    #[test]
    fn icao_p04_b_td3_sample_parses() {
        use crate::lds::mrz::MrzVersion;
        use chrono::NaiveDate;

        let bytes = hex::decode(
            "615B5F1F58503c55544f4552494b53534f4e3c3c414e4e413c4d415249413c3c3c\
             3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c4c38393839303243333655544f37343038\
             3132324631323034313539ZE184226B<<<<<10"
                .replace("ZE184226B<<<<<10", "5A45313834323236423c3c3c3c3c3130"),
        )
        .unwrap();
        let dg1 = EfDG1::from_bytes(bytes.clone()).unwrap();
        assert_eq!(dg1.mrz().version, MrzVersion::Td3);
        assert_eq!(dg1.mrz().document_code, "P");
        assert_eq!(dg1.mrz().document_number(), "L898902C3");
        assert_eq!(dg1.mrz().country, "UTO");
        assert_eq!(dg1.mrz().last_name, "ERIKSSON");
        assert_eq!(dg1.mrz().first_name, "ANNA MARIA");
        assert_eq!(dg1.mrz().gender, "F");
        assert_eq!(
            dg1.mrz().date_of_birth,
            NaiveDate::from_ymd_opt(1974, 8, 12).unwrap()
        );
        assert_eq!(
            dg1.mrz().date_of_expiry,
            NaiveDate::from_ymd_opt(2012, 4, 15).unwrap()
        );
        assert_eq!(dg1.mrz().optional_data(), "ZE184226B");
    }
}
