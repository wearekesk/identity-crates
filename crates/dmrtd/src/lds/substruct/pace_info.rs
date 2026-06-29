//! PACEInfo ASN.1 sub-structure.
//!
//! ```text
//! PACEInfo ::= SEQUENCE {
//!     protocol    OBJECT IDENTIFIER (id-PACE-DH-GM-… | id-PACE-ECDH-IM-… | …),
//!     version     INTEGER (MUST be 2),
//!     parameterId INTEGER OPTIONAL
//! }
//! ```
//!
//! `parameterId` is OPTIONAL per the spec (it identifies the standardized or
//! conveyed domain parameters when several PACEInfos are present). Records that
//! omit it are accepted, with `parameter_id == None`.

use asn1::{ObjectIdentifier, Sequence};

use crate::lds::asn1_object_identifiers::{
    Asn1ObjectIdentifierType, OiePaceProtocol, TokenAgreementAlgo,
};
use crate::lds::ef::EfParseError;
use crate::proto::domain_parameter::{self, DomainParameterType};

/// Expected PACE protocol version — always `2`.
pub const PACE_VERSION: i64 = 2;

/// Parsed PACEInfo record.
#[derive(Debug, Clone)]
pub struct PaceInfo {
    pub protocol: OiePaceProtocol,
    pub version: i64,
    /// `parameterId` from the record, or `None` when omitted (it is OPTIONAL).
    pub parameter_id: Option<i64>,
    /// `true` when the `parameter_id` names a domain parameter that this
    /// library can evaluate (i.e. the entry exists in the ICAO 9303 table
    /// with `is_supported = true` and the correct GF(p) / EC(p) kind for the
    /// protocol's token-agreement algorithm).
    pub is_pace_domain_parameter_supported: bool,
}

impl PaceInfo {
    /// Parses a [`PaceInfo`] from an ASN.1 `SEQUENCE`.
    ///
    /// # Errors
    /// Returns [`EfParseError`] if the sequence structure, protocol OID, or
    /// version value is invalid.
    pub fn from_sequence(sequence: Sequence<'_>) -> Result<Self, EfParseError> {
        sequence
            .parse(|p| {
                // --- protocol OID ---
                let oid: ObjectIdentifier = p.read_element().map_err(|_| {
                    EfParseError::new("Invalid structure of PaceInfo. Expected OBJECT IDENTIFIER.")
                })?;
                let oid_string = oid.to_string();
                let registry = Asn1ObjectIdentifierType::instance();
                let oie = registry
                    .get_oid_by_identifier_string(&oid_string)
                    .map_err(|_| {
                        EfParseError::new(format!(
                            "Invalid protocol in PaceInfo. Protocol is not valid: {oid_string}"
                        ))
                    })?
                    .clone();
                let protocol = OiePaceProtocol::from_oie(oie).map_err(|e| {
                    EfParseError::new(format!("Invalid PACE protocol OID: {}", e.0))
                })?;

                // --- version ---
                let version: i64 = p.read_element().map_err(|_| {
                    EfParseError::new("Invalid version in PaceInfo. Expected INTEGER.")
                })?;
                if version != PACE_VERSION {
                    return Err(EfParseError::new(format!(
                        "Invalid version in PaceInfo. Version is not equal to {PACE_VERSION}."
                    )));
                }

                // --- parameterId (OPTIONAL) ---
                let parameter_id: Option<i64> = if p.is_empty() {
                    None
                } else {
                    Some(p.read_element().map_err(|_| {
                        EfParseError::new("Invalid parameterId in PaceInfo. Expected INTEGER.")
                    })?)
                };

                let is_supported = parameter_id
                    .map(|id| {
                        check_domain_parameter_supported(id, protocol.token_agreement_algorithm)
                    })
                    .unwrap_or(false);

                Ok::<PaceInfo, EfParseError>(PaceInfo {
                    protocol,
                    version,
                    parameter_id,
                    is_pace_domain_parameter_supported: is_supported,
                })
            })
            .map_err(|e: EfParseError| e)
    }

    /// Parses a [`PaceInfo`] from raw DER bytes of a `SEQUENCE` TLV.
    ///
    /// # Errors
    /// Returns [`EfParseError`] on any parse failure.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, EfParseError> {
        let seq = asn1::parse_single::<Sequence<'_>>(der_bytes)
            .map_err(|_| EfParseError::new("Invalid DER: not a SEQUENCE"))?;
        Self::from_sequence(seq)
    }
}

/// Looks up the domain parameter and returns `true` when the library can
/// evaluate it for the given token agreement algorithm.
fn check_domain_parameter_supported(id: i64, algo: TokenAgreementAlgo) -> bool {
    let id_u32 = match u32::try_from(id) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let Some(entry) = domain_parameter::get(id_u32) else {
        return false;
    };
    if !entry.is_supported {
        return false;
    }
    match (algo, entry.kind) {
        (TokenAgreementAlgo::Ecdh, DomainParameterType::Ecp) => true,
        (TokenAgreementAlgo::Dh, DomainParameterType::Gfp) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::asn1_object_identifiers::{CipherAlgorithm, KeyLength, MappingType};

    /// Hand-builds a DER PACEInfo SEQUENCE for testing.
    ///
    /// - `oid_der`      : raw OID contents (no tag/length), e.g. the PACE-ECDH
    ///   OID suffix.
    /// - `version`      : the INTEGER value to emit for the version field.
    /// - `parameter_id` : optional INTEGER value for the parameter field;
    ///                    `None` omits the element (to exercise the 3-elements
    ///                    check).
    fn build_pace_info(oid_der: &[u8], version: u32, parameter_id: Option<u32>) -> Vec<u8> {
        asn1::write_single(&PaceInfoBuilder {
            oid_der,
            version,
            parameter_id,
        })
        .expect("write PaceInfo")
    }

    struct PaceInfoBuilder<'a> {
        oid_der: &'a [u8],
        version: u32,
        parameter_id: Option<u32>,
    }

    impl asn1::SimpleAsn1Writable for PaceInfoBuilder<'_> {
        type Error = asn1::WriteError;
        const TAG: asn1::Tag = <asn1::SequenceWriter<'_> as asn1::SimpleAsn1Writable>::TAG;
        fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
            // OID
            let oid = ObjectIdentifier::from_der(self.oid_der).expect("valid oid");
            asn1::Writer::new(dest).write_element(&oid)?;
            // version
            asn1::Writer::new(dest).write_element(&self.version)?;
            if let Some(pid) = self.parameter_id {
                asn1::Writer::new(dest).write_element(&pid)?;
            }
            Ok(())
        }
        fn data_length(&self) -> Option<usize> {
            None
        }
    }

    /// DER OID content for id-PACE-ECDH-GM-AES-CBC-CMAC-128 (0.4.0.127.0.7.2.2.4.2.2).
    /// Computed: first octet = 40*0 + 4 = 4, then 0, 127 (0x7F), 0, 7, 2, 2, 4, 2, 2.
    const OID_ECDH_GM_AES128: &[u8] = &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02];

    #[test]
    fn parses_valid_pace_info() {
        let der = build_pace_info(OID_ECDH_GM_AES128, 2, Some(12));
        let info = PaceInfo::from_der(&der).unwrap();

        assert_eq!(info.version, 2);
        assert_eq!(info.parameter_id, Some(12));
        assert_eq!(info.protocol.cipher_algorithm, CipherAlgorithm::Aes);
        assert_eq!(info.protocol.key_length, KeyLength::S128);
        assert_eq!(
            info.protocol.token_agreement_algorithm,
            TokenAgreementAlgo::Ecdh
        );
        assert_eq!(info.protocol.mapping_type, MappingType::Gm);
        // NIST P-256 (id=12) is marked supported for ECDH in our domain param table.
        assert!(info.is_pace_domain_parameter_supported);
    }

    #[test]
    fn rejects_wrong_version() {
        let der = build_pace_info(OID_ECDH_GM_AES128, 3, Some(12));
        let err = PaceInfo::from_der(&der).unwrap_err();
        assert!(err.0.contains("Version is not equal to 2"));
    }

    #[test]
    fn accepts_missing_parameter_id() {
        // parameterId is OPTIONAL — a two-element record must parse, with the
        // parameter id reported as absent and the domain parameter unsupported.
        let der = build_pace_info(OID_ECDH_GM_AES128, 2, None);
        let info = PaceInfo::from_der(&der).unwrap();
        assert_eq!(info.parameter_id, None);
        assert!(!info.is_pace_domain_parameter_supported);
    }

    #[test]
    fn rejects_unknown_oid() {
        // 1.2.3 → first octet = 40*1 + 2 = 42 = 0x2A, then 3 = 0x03.
        let bogus_oid: &[u8] = &[0x2A, 0x03];
        let der = build_pace_info(bogus_oid, 2, Some(12));
        let err = PaceInfo::from_der(&der).unwrap_err();
        assert!(err.0.contains("not valid"));
    }

    #[test]
    fn unsupported_parameter_id_flag_is_false() {
        // parameter_id = 9 (BrainpoolP192r1) — not in our supported table.
        let der = build_pace_info(OID_ECDH_GM_AES128, 2, Some(9));
        let info = PaceInfo::from_der(&der).unwrap();
        assert!(!info.is_pace_domain_parameter_supported);
    }

    #[test]
    fn dh_protocol_with_ecp_param_is_unsupported() {
        // id-PACE-DH-GM-AES-CBC-CMAC-128 = 0.4.0.127.0.7.2.2.4.1.2
        let oid: &[u8] = &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x02];
        // parameter_id = 12 is ECP-based, so DH (GF(p)) is a mismatch.
        let der = build_pace_info(oid, 2, Some(12));
        let info = PaceInfo::from_der(&der).unwrap();
        assert_eq!(
            info.protocol.token_agreement_algorithm,
            TokenAgreementAlgo::Dh
        );
        assert!(!info.is_pace_domain_parameter_supported);
    }

    #[test]
    fn dh_protocol_with_gfp_param_is_supported() {
        // id-PACE-DH-GM-AES-CBC-CMAC-128 with a GF(p) RFC 5114 group (id 0).
        let oid: &[u8] = &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x02];
        let der = build_pace_info(oid, 2, Some(0));
        let info = PaceInfo::from_der(&der).unwrap();
        assert_eq!(
            info.protocol.token_agreement_algorithm,
            TokenAgreementAlgo::Dh
        );
        assert!(info.is_pace_domain_parameter_supported);
    }
}
