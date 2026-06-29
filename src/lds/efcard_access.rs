//! EF.CardAccess elementary file.
//!
//! EF.CardAccess contains a `SET OF` PACE access structures. ICAO 9303 p11
//! defines two possible elements:
//! - `PACEInfo`                (parsed)
//! - `PACEDomainParameterInfo` (not yet supported by this port)
//!
//! Only the first element of the set is consulted, matching the reference
//! implementation.

use asn1::{Sequence, Set};

use crate::lds::ef::{ElementaryFile, EfParseError};
use crate::lds::substruct::pace_info::PaceInfo;

/// EF.CardAccess file ID.
pub const EF_CARD_ACCESS_FID: u16 = 0x011C;
/// EF.CardAccess short file ID.
pub const EF_CARD_ACCESS_SFI: u8 = 0x1C;
/// EF.CardAccess tag byte (from the data group tag space).
pub const EF_CARD_ACCESS_TAG: u8 = 0x6C;

/// Parsed EF.CardAccess contents.
#[derive(Debug, Clone)]
pub struct EfCardAccess {
    encoded: Vec<u8>,
    pace_info: Option<PaceInfo>,
}

impl EfCardAccess {
    /// Parses an EF.CardAccess from its raw DER bytes.
    ///
    /// # Errors
    /// Returns [`EfParseError`] when the input is not a valid SET containing
    /// at least one SEQUENCE.
    pub fn from_bytes(encoded: impl Into<Vec<u8>>) -> Result<Self, EfParseError> {
        let encoded = encoded.into();

        let set = asn1::parse_single::<Set<'_>>(&encoded).map_err(|_| {
            EfParseError::new("Invalid structure of EF.CardAccess. No data to parse.")
        })?;

        // EF.CardAccess is a SET OF SecurityInfo; it may carry several elements
        // (e.g. PACEInfo alongside PACEDomainParameterInfo or other infos).
        // Consume *all* SEQUENCE elements — leaving any unread would make the
        // ASN.1 parser fail with ExtraData — and keep the first that parses as
        // a PACEInfo.
        let pace_info = set.parse(|parser| {
            if parser.is_empty() {
                return Err(EfParseError::new(
                    "Invalid structure of EF.CardAccess. Expected at least one element in set, got none.",
                ));
            }
            let mut found: Option<PaceInfo> = None;
            let mut last_err: Option<EfParseError> = None;
            while !parser.is_empty() {
                let seq: Sequence<'_> = parser.read_element().map_err(|_| {
                    EfParseError::new(
                        "Invalid structure of EF.CardAccess. Set element is not an ASN1Sequence.",
                    )
                })?;
                // PACEDomainParameterInfo (ICAO 9303 p11 §9.2.1) and other
                // SecurityInfos fail to parse as PaceInfo; skip them and keep
                // looking for the first PACEInfo.
                if found.is_none() {
                    match PaceInfo::from_sequence(seq) {
                        Ok(pi) => found = Some(pi),
                        Err(e) => last_err = Some(e),
                    }
                }
            }
            found.ok_or_else(|| {
                last_err.unwrap_or_else(|| {
                    EfParseError::new(
                        "Invalid structure of EF.CardAccess. No PACEInfo found in set.",
                    )
                })
            })
        })?;

        Ok(Self {
            encoded,
            pace_info: Some(pace_info),
        })
    }

    /// Returns the parsed PaceInfo, if any.
    pub fn pace_info(&self) -> Option<&PaceInfo> {
        self.pace_info.as_ref()
    }

    /// Returns `true` when a PaceInfo was parsed.
    pub fn is_pace_info_set(&self) -> bool {
        self.pace_info.is_some()
    }
}

impl ElementaryFile for EfCardAccess {
    const FID: u16 = EF_CARD_ACCESS_FID;
    const SFI: u8 = EF_CARD_ACCESS_SFI;

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
    use crate::lds::asn1_object_identifiers::{
        CipherAlgorithm, KeyLength, MappingType, TokenAgreementAlgo,
    };

    /// DER OID content for id-PACE-ECDH-GM-AES-CBC-CMAC-128 (0.4.0.127.0.7.2.2.4.2.2).
    const OID_ECDH_GM_AES128: &[u8] =
        &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02];

    fn make_pace_info_sequence() -> Vec<u8> {
        struct PaceInfoBuilder;
        impl asn1::SimpleAsn1Writable for PaceInfoBuilder {
            type Error = asn1::WriteError;
            const TAG: asn1::Tag =
                <asn1::SequenceWriter<'_> as asn1::SimpleAsn1Writable>::TAG;
            fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
                let oid = asn1::ObjectIdentifier::from_der(OID_ECDH_GM_AES128).unwrap();
                asn1::Writer::new(dest).write_element(&oid)?;
                asn1::Writer::new(dest).write_element(&2u32)?;
                asn1::Writer::new(dest).write_element(&12u32)?;
                Ok(())
            }
            fn data_length(&self) -> Option<usize> {
                None
            }
        }
        asn1::write_single(&PaceInfoBuilder).unwrap()
    }

    fn make_ef_card_access() -> Vec<u8> {
        let pi = make_pace_info_sequence();
        // Build a SET { SEQUENCE (pi) } manually.
        // SET = 0x31, length, content.
        let mut out = vec![0x31];
        // Length of the inner SEQUENCE bytes.
        let content_len = pi.len();
        // Encode length (short form up to 127, else long form).
        if content_len < 128 {
            out.push(content_len as u8);
        } else if content_len < 256 {
            out.extend_from_slice(&[0x81, content_len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (content_len >> 8) as u8, content_len as u8]);
        }
        out.extend_from_slice(&pi);
        out
    }

    #[test]
    fn parses_ef_card_access_with_pace_info() {
        let bytes = make_ef_card_access();
        let ef = EfCardAccess::from_bytes(bytes.clone()).unwrap();
        assert!(ef.is_pace_info_set());

        let pi = ef.pace_info().unwrap();
        assert_eq!(pi.version, 2);
        assert_eq!(pi.parameter_id, Some(12));
        assert_eq!(pi.protocol.cipher_algorithm, CipherAlgorithm::Aes);
        assert_eq!(pi.protocol.key_length, KeyLength::S128);
        assert_eq!(
            pi.protocol.token_agreement_algorithm,
            TokenAgreementAlgo::Ecdh
        );
        assert_eq!(pi.protocol.mapping_type, MappingType::Gm);

        assert_eq!(ef.to_bytes(), bytes.as_slice());
    }

    #[test]
    fn associated_constants() {
        assert_eq!(EfCardAccess::FID, 0x011C);
        assert_eq!(EfCardAccess::SFI, 0x1C);
    }

    #[test]
    fn rejects_non_set_input() {
        // A SEQUENCE instead of a SET at the outer level.
        let pi = make_pace_info_sequence();
        let err = EfCardAccess::from_bytes(pi).unwrap_err();
        assert!(err.0.contains("No data to parse"));
    }

    #[test]
    fn rejects_empty_set() {
        // Empty SET: 0x31, 0x00.
        let err = EfCardAccess::from_bytes(vec![0x31, 0x00]).unwrap_err();
        assert!(err.0.contains("got none"));
    }

    /// A multi-element SET (two SEQUENCEs) must parse and use the first
    /// PACEInfo instead of failing with trailing-data (ExtraData).
    #[test]
    fn parses_multi_element_set_uses_first_pace_info() {
        let pi = make_pace_info_sequence();
        // SET { SEQUENCE(pi), SEQUENCE(pi) } with two elements.
        let content_len = pi.len() * 2;
        let mut out = vec![0x31];
        if content_len < 128 {
            out.push(content_len as u8);
        } else if content_len < 256 {
            out.extend_from_slice(&[0x81, content_len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (content_len >> 8) as u8, content_len as u8]);
        }
        out.extend_from_slice(&pi);
        out.extend_from_slice(&pi);

        let ef = EfCardAccess::from_bytes(out).unwrap();
        assert!(ef.is_pace_info_set());
        assert_eq!(ef.pace_info().unwrap().parameter_id, Some(12));
    }
}
