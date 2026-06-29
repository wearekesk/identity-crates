//! ASN.1 Object Identifiers for DMRTD.
//!
//! Defines:
//! - Custom PACE OIDs.
//! - [`Oie`] (Object Identifier Element) — the dotted-string form, a
//!   human-readable name, and the raw OID arc values.
//! - [`OiePaceProtocol`] — an [`Oie`] augmented with the cipher algorithm,
//!   key length, token agreement algorithm, and mapping type decoded from the
//!   readable name.
//! - [`Asn1ObjectIdentifierType`] — a registry of known OIDs, accessed via
//!   [`Asn1ObjectIdentifierType::instance`].
//!
//! [`KeyLength`] and [`CipherAlgorithm`] live in [`crate::crypto::aes`]
//! and are re-exported from here.

use once_cell::sync::Lazy;
use thiserror::Error;

pub use crate::crypto::aes::{CipherAlgorithm, KeyLength};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error raised by [`OiePaceProtocol`] construction or [`Oie`] validation.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("OIEexception: {0}")]
pub struct OieException(pub String);

/// Error raised by [`Asn1ObjectIdentifierType`] lookups.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("ASN1ObjectIdentifierObjectException: {0}")]
pub struct Asn1OidObjectException(pub String);

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Token agreement algorithm for PACE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAgreementAlgo {
    /// Diffie-Hellman.
    Dh,
    /// Elliptic-Curve Diffie-Hellman.
    Ecdh,
}

/// PACE mapping type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingType {
    /// Generic Mapping.
    Gm,
    /// Integrated Mapping.
    Im,
    /// Chip Authentication Mapping (not currently supported).
    Cam,
}

// ---------------------------------------------------------------------------
// Oie — Object Identifier Element
// ---------------------------------------------------------------------------

/// Object Identifier Element — the dotted-string form, a human-readable
/// name, and the raw arc values.
#[derive(Debug, Clone)]
pub struct Oie {
    pub identifier_string: String,
    pub readable_name: String,
    pub identifier: Vec<u32>,
}

impl Oie {
    /// Creates a new [`Oie`].
    pub fn new(
        identifier_string: impl Into<String>,
        readable_name: impl Into<String>,
        identifier: Vec<u32>,
    ) -> Self {
        Self {
            identifier_string: identifier_string.into(),
            readable_name: readable_name.into(),
            identifier,
        }
    }

    /// Returns `true` if this [`Oie`]'s `identifier` arc-sequence equals
    /// `other`.
    pub fn compare_only_identifier(&self, other: &[u32]) -> bool {
        self.identifier == other
    }
}

impl std::fmt::Display for Oie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OIE: {}, {}, {:?}",
            self.identifier_string, self.readable_name, self.identifier
        )
    }
}

/// Equality follows the `==`: compares only the arc-sequence.
impl PartialEq for Oie {
    fn eq(&self, other: &Self) -> bool {
        self.identifier == other.identifier
    }
}

impl Eq for Oie {}

impl std::hash::Hash for Oie {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identifier.hash(state);
    }
}

// ---------------------------------------------------------------------------
// OiePaceProtocol
// ---------------------------------------------------------------------------

/// PACE protocol OIE — an [`Oie`] with decoded cipher/key/agreement/mapping
/// parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OiePaceProtocol {
    pub oie: Oie,
    pub cipher_algorithm: CipherAlgorithm,
    pub key_length: KeyLength,
    pub token_agreement_algorithm: TokenAgreementAlgo,
    pub mapping_type: MappingType,
}

impl OiePaceProtocol {
    /// Construct from identifier string, readable name, and arc values.
    ///
    /// The identifier string and readable name are upper-cased; the readable
    /// name is then used to derive the cipher/key-length/token-agreement/
    /// mapping parameters.
    ///
    /// # Errors
    /// Returns [`OieException`] if the readable name does not match a known
    /// PACE protocol, or if it designates an unsupported CAM mapping.
    pub fn new(
        identifier_string: impl Into<String>,
        readable_name: impl Into<String>,
        identifier: Vec<u32>,
    ) -> Result<Self, OieException> {
        let identifier_string = identifier_string.into().to_uppercase();
        let readable_name = readable_name.into().to_uppercase();
        let params = Self::params_from_name(&readable_name, &identifier_string)?;

        // Consistency guard: if this OID string is registered, the supplied arc
        // sequence and readable name must agree with the canonical registry
        // entry. Without this, a caller could pair a valid protocol name with a
        // different protocol's OID (or arc) and get a silently-mismatched
        // protocol back. Unregistered OIDs are left to `params_from_name` alone.
        if let Ok(registered) =
            Asn1ObjectIdentifierType::instance().get_oid_by_identifier_string(&identifier_string)
        {
            if registered.readable_name.to_uppercase() != readable_name
                || registered.identifier != identifier
            {
                return Err(OieException(format!(
                    "OIEPaceProtocol; inconsistent PACE protocol for OID {identifier_string}: \
                     readable name {readable_name} / arc {identifier:?} does not match the \
                     registered entry ({})",
                    registered.readable_name
                )));
            }
        }

        Ok(Self {
            oie: Oie {
                identifier_string,
                readable_name,
                identifier,
            },
            cipher_algorithm: params.0,
            key_length: params.1,
            token_agreement_algorithm: params.2,
            mapping_type: params.3,
        })
    }

    /// Construct from an existing [`Oie`].
    pub fn from_oie(oie: Oie) -> Result<Self, OieException> {
        Self::new(oie.identifier_string, oie.readable_name, oie.identifier)
    }

    fn params_from_name(
        name: &str,
        id_str: &str,
    ) -> Result<
        (CipherAlgorithm, KeyLength, TokenAgreementAlgo, MappingType),
        OieException,
    > {
        use CipherAlgorithm::{Aes, DeSede};
        use KeyLength::{S128, S192, S256};
        use MappingType::{Gm, Im};
        use TokenAgreementAlgo::{Dh, Ecdh};

        match name {
            "ID-PACE-DH-GM-3DES-CBC-CBC"        => Ok((DeSede, S128, Dh,   Gm)),
            "ID-PACE-DH-GM-AES-CBC-CMAC-128"    => Ok((Aes,    S128, Dh,   Gm)),
            "ID-PACE-DH-GM-AES-CBC-CMAC-192"    => Ok((Aes,    S192, Dh,   Gm)),
            "ID-PACE-DH-GM-AES-CBC-CMAC-256"    => Ok((Aes,    S256, Dh,   Gm)),
            "ID-PACE-DH-IM-3DES-CBC-CBC"        => Ok((DeSede, S128, Dh,   Im)),
            "ID-PACE-DH-IM-AES-CBC-CMAC-128"    => Ok((Aes,    S128, Dh,   Im)),
            "ID-PACE-DH-IM-AES-CBC-CMAC-192"    => Ok((Aes,    S192, Dh,   Im)),
            "ID-PACE-DH-IM-AES-CBC-CMAC-256"    => Ok((Aes,    S256, Dh,   Im)),
            "ID-PACE-ECDH-GM-3DES-CBC-CBC"      => Ok((DeSede, S128, Ecdh, Gm)),
            "ID-PACE-ECDH-GM-AES-CBC-CMAC-128"  => Ok((Aes,    S128, Ecdh, Gm)),
            "ID-PACE-ECDH-GM-AES-CBC-CMAC-192"  => Ok((Aes,    S192, Ecdh, Gm)),
            "ID-PACE-ECDH-GM-AES-CBC-CMAC-256"  => Ok((Aes,    S256, Ecdh, Gm)),
            "ID-PACE-ECDH-IM-3DES-CBC-CBC"      => Ok((DeSede, S128, Ecdh, Im)),
            "ID-PACE-ECDH-IM-AES-CBC-CMAC-128"  => Ok((Aes,    S128, Ecdh, Im)),
            "ID-PACE-ECDH-IM-AES-CBC-CMAC-192"  => Ok((Aes,    S192, Ecdh, Im)),
            "ID-PACE-ECDH-IM-AES-CBC-CMAC-256"  => Ok((Aes,    S256, Ecdh, Im)),
            "ID-PACE-ECDH-CAM-AES-CBC-CMAC-128"
            | "ID-PACE-ECDH-CAM-AES-CBC-CMAC-192"
            | "ID-PACE-ECDH-CAM-AES-CBC-CMAC-256" => Err(OieException(format!(
                "OIEPaceProtocol; Mapping type CAM  not supported: {id_str}"
            ))),
            _ => Err(OieException(format!(
                "OIEPaceProtocol; Unknown identifierString: {id_str}"
            ))),
        }
    }
}

impl std::fmt::Display for OiePaceProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OIEPaceProtocol: {}, {}, {:?}, CipherAlgorithm: {:?}, KeyLength: {:?}, TokenAgreementAlgo: {:?}, MappingType: {:?}",
            self.oie.identifier_string,
            self.oie.readable_name,
            self.oie.identifier,
            self.cipher_algorithm,
            self.key_length,
            self.token_agreement_algorithm,
            self.mapping_type,
        )
    }
}

// ---------------------------------------------------------------------------
// Custom OIDs
// ---------------------------------------------------------------------------

/// Custom PACE OIDs defined by this module.
pub static CUSTOM_OIDS: Lazy<Vec<Oie>> = Lazy::new(|| {
    vec![
        Oie::new("0.4.0.127.0.7.2.2.4.1.1", "id-PACE-DH-GM-3DES-CBC-CBC",       vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 1]),
        Oie::new("0.4.0.127.0.7.2.2.4.1.2", "id-PACE-DH-GM-AES-CBC-CMAC-128",   vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2]),
        Oie::new("0.4.0.127.0.7.2.2.4.1.3", "id-PACE-DH-GM-AES-CBC-CMAC-192",   vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 3]),
        Oie::new("0.4.0.127.0.7.2.2.4.1.4", "id-PACE-DH-GM-AES-CBC-CMAC-256",   vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 4]),
        Oie::new("0.4.0.127.0.7.2.2.4.3.1", "id-PACE-DH-IM-3DES-CBC-CBC",       vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 1]),
        Oie::new("0.4.0.127.0.7.2.2.4.3.2", "id-PACE-DH-IM-AES-CBC-CMAC-128",   vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 2]),
        Oie::new("0.4.0.127.0.7.2.2.4.3.3", "id-PACE-DH-IM-AES-CBC-CMAC-192",   vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 3]),
        Oie::new("0.4.0.127.0.7.2.2.4.3.4", "id-PACE-DH-IM-AES-CBC-CMAC-256",   vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 4]),
        Oie::new("0.4.0.127.0.7.2.2.4.2.1", "id-PACE-ECDH-GM-3DES-CBC-CBC",     vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 1]),
        Oie::new("0.4.0.127.0.7.2.2.4.2.2", "id-PACE-ECDH-GM-AES-CBC-CMAC-128", vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2]),
        Oie::new("0.4.0.127.0.7.2.2.4.2.3", "id-PACE-ECDH-GM-AES-CBC-CMAC-192", vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 3]),
        Oie::new("0.4.0.127.0.7.2.2.4.2.4", "id-PACE-ECDH-GM-AES-CBC-CMAC-256", vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4]),
        Oie::new("0.4.0.127.0.7.2.2.4.4.1", "id-PACE-ECDH-IM-3DES-CBC-CBC",     vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 1]),
        Oie::new("0.4.0.127.0.7.2.2.4.4.2", "id-PACE-ECDH-IM-AES-CBC-CMAC-128", vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 2]),
        Oie::new("0.4.0.127.0.7.2.2.4.4.3", "id-PACE-ECDH-IM-AES-CBC-CMAC-192", vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 3]),
        Oie::new("0.4.0.127.0.7.2.2.4.4.4", "id-PACE-ECDH-IM-AES-CBC-CMAC-256", vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 4]),
    ]
});

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Registry of known object identifiers. Currently holds [`CUSTOM_OIDS`];
/// use [`Asn1ObjectIdentifierType::instance`] to access the shared instance.
pub struct Asn1ObjectIdentifierType {
    oids: Vec<Oie>,
}

impl Asn1ObjectIdentifierType {
    /// Returns the shared registry instance.
    pub fn instance() -> &'static Self {
        static INSTANCE: Lazy<Asn1ObjectIdentifierType> = Lazy::new(|| Asn1ObjectIdentifierType {
            oids: CUSTOM_OIDS.clone(),
        });
        &INSTANCE
    }

    /// Returns all registered OIDs.
    pub fn oids(&self) -> &[Oie] {
        &self.oids
    }

    /// Returns `true` if an OID with the given dotted-string form is
    /// registered.
    pub fn has_oid_with_identifier_string(&self, identifier_string: &str) -> bool {
        self.oids
            .iter()
            .any(|o| o.identifier_string == identifier_string)
    }

    /// Returns the OID with the given dotted-string form.
    ///
    /// # Errors
    /// Returns [`Asn1OidObjectException`] if no matching OID is registered.
    pub fn get_oid_by_identifier_string(
        &self,
        identifier_string: &str,
    ) -> Result<&Oie, Asn1OidObjectException> {
        self.oids
            .iter()
            .find(|o| o.identifier_string == identifier_string)
            .ok_or_else(|| {
                Asn1OidObjectException(format!(
                    "Object identifier with identifier string {identifier_string} does not exist."
                ))
            })
    }

    /// Returns `true` if an OID with the given arc-sequence is registered.
    pub fn has_oid_with_identifier(&self, identifier: &[u32]) -> bool {
        self.oids.iter().any(|o| o.identifier == identifier)
    }

    /// Returns the OID with the given arc-sequence.
    ///
    /// # Errors
    /// Returns [`Asn1OidObjectException`] if no matching OID is registered.
    pub fn get_oid_by_identifier(
        &self,
        identifier: &[u32],
    ) -> Result<&Oie, Asn1OidObjectException> {
        self.oids
            .iter()
            .find(|o| o.identifier == identifier)
            .ok_or_else(|| {
                Asn1OidObjectException(format!(
                    "Object identifier with identifier {identifier:?} does not exist."
                ))
            })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Oie
    // -----------------------------------------------------------------------

    #[test]
    fn oie_equality_uses_identifier_only() {
        let a = Oie::new("0.4.0.127.0.7.2.2.4.1.2", "name-a", vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2]);
        let b = Oie::new("DIFFERENT.STRING",        "name-b", vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2]);
        assert_eq!(a, b);
    }

    #[test]
    fn oie_compare_only_identifier() {
        let a = Oie::new("x", "y", vec![1, 2, 3]);
        assert!(a.compare_only_identifier(&[1, 2, 3]));
        assert!(!a.compare_only_identifier(&[1, 2, 4]));
    }

    // -----------------------------------------------------------------------
    // OiePaceProtocol
    // -----------------------------------------------------------------------

    #[test]
    fn pace_protocol_dh_gm_aes_128() {
        let p = OiePaceProtocol::new(
            "0.4.0.127.0.7.2.2.4.1.2",
            "id-PACE-DH-GM-AES-CBC-CMAC-128",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2],
        )
        .unwrap();
        assert_eq!(p.cipher_algorithm, CipherAlgorithm::Aes);
        assert_eq!(p.key_length, KeyLength::S128);
        assert_eq!(p.token_agreement_algorithm, TokenAgreementAlgo::Dh);
        assert_eq!(p.mapping_type, MappingType::Gm);
        // Uppercased on construction.
        assert_eq!(p.oie.readable_name, "ID-PACE-DH-GM-AES-CBC-CMAC-128");
    }

    #[test]
    fn pace_protocol_ecdh_im_aes_256() {
        let p = OiePaceProtocol::new(
            "0.4.0.127.0.7.2.2.4.4.4",
            "id-PACE-ECDH-IM-AES-CBC-CMAC-256",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 4],
        )
        .unwrap();
        assert_eq!(p.cipher_algorithm, CipherAlgorithm::Aes);
        assert_eq!(p.key_length, KeyLength::S256);
        assert_eq!(p.token_agreement_algorithm, TokenAgreementAlgo::Ecdh);
        assert_eq!(p.mapping_type, MappingType::Im);
    }

    #[test]
    fn pace_protocol_dh_gm_3des() {
        let p = OiePaceProtocol::new(
            "0.4.0.127.0.7.2.2.4.1.1",
            "id-PACE-DH-GM-3DES-CBC-CBC",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 1],
        )
        .unwrap();
        assert_eq!(p.cipher_algorithm, CipherAlgorithm::DeSede);
        assert_eq!(p.key_length, KeyLength::S128);
        assert_eq!(p.token_agreement_algorithm, TokenAgreementAlgo::Dh);
        assert_eq!(p.mapping_type, MappingType::Gm);
    }

    #[test]
    fn pace_protocol_cam_is_unsupported() {
        let err = OiePaceProtocol::new(
            "0.4.0.127.0.7.2.2.4.6.2",
            "id-PACE-ECDH-CAM-AES-CBC-CMAC-128",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 6, 2],
        )
        .unwrap_err();
        assert!(err.0.contains("Mapping type CAM"));
    }

    #[test]
    fn pace_protocol_unknown_name() {
        let err = OiePaceProtocol::new("1.2.3", "not-a-real-pace-oid", vec![1, 2, 3]).unwrap_err();
        assert!(err.0.contains("Unknown identifierString"));
    }

    #[test]
    fn pace_protocol_rejects_name_oid_mismatch() {
        // OID string is the DH-GM-AES-128 entry, but the readable name claims
        // ECDH-GM-AES-128. The name decodes to valid params, yet it disagrees
        // with the registered OID, so construction must fail.
        let err = OiePaceProtocol::new(
            "0.4.0.127.0.7.2.2.4.1.2",
            "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2],
        )
        .unwrap_err();
        assert!(err.0.contains("inconsistent PACE protocol"));
    }

    #[test]
    fn registry_dh_gm_aes_192_resolves_to_protocol() {
        // The DH-GM-AES-192 registry entry must use the hyphenated readable
        // name so `from_oie` can decode its parameters (previously it used
        // underscores and was rejected as "Unknown identifierString").
        let reg = Asn1ObjectIdentifierType::instance();
        let oie = reg
            .get_oid_by_identifier_string("0.4.0.127.0.7.2.2.4.1.3")
            .unwrap()
            .clone();
        let p = OiePaceProtocol::from_oie(oie).unwrap();
        assert_eq!(p.cipher_algorithm, CipherAlgorithm::Aes);
        assert_eq!(p.key_length, KeyLength::S192);
        assert_eq!(p.token_agreement_algorithm, TokenAgreementAlgo::Dh);
        assert_eq!(p.mapping_type, MappingType::Gm);
    }

    #[test]
    fn pace_protocol_from_oie() {
        let oie = Oie::new(
            "0.4.0.127.0.7.2.2.4.2.4",
            "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4],
        );
        let p = OiePaceProtocol::from_oie(oie).unwrap();
        assert_eq!(p.cipher_algorithm, CipherAlgorithm::Aes);
        assert_eq!(p.key_length, KeyLength::S256);
        assert_eq!(p.token_agreement_algorithm, TokenAgreementAlgo::Ecdh);
        assert_eq!(p.mapping_type, MappingType::Gm);
    }

    // -----------------------------------------------------------------------
    // Asn1ObjectIdentifierType
    // -----------------------------------------------------------------------

    #[test]
    fn registry_contains_all_custom_pace_oids() {
        let reg = Asn1ObjectIdentifierType::instance();
        assert_eq!(reg.oids().len(), 16);
    }

    #[test]
    fn registry_lookup_by_identifier_string() {
        let reg = Asn1ObjectIdentifierType::instance();
        let o = reg
            .get_oid_by_identifier_string("0.4.0.127.0.7.2.2.4.2.2")
            .unwrap();
        assert_eq!(o.readable_name, "id-PACE-ECDH-GM-AES-CBC-CMAC-128");
    }

    #[test]
    fn registry_has_oid_with_identifier_string() {
        let reg = Asn1ObjectIdentifierType::instance();
        assert!(reg.has_oid_with_identifier_string("0.4.0.127.0.7.2.2.4.1.1"));
        assert!(!reg.has_oid_with_identifier_string("9.9.9.9"));
    }

    #[test]
    fn registry_lookup_by_identifier() {
        let reg = Asn1ObjectIdentifierType::instance();
        let o = reg
            .get_oid_by_identifier(&[0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 4])
            .unwrap();
        assert_eq!(o.readable_name, "id-PACE-ECDH-IM-AES-CBC-CMAC-256");
    }

    #[test]
    fn registry_has_oid_with_identifier() {
        let reg = Asn1ObjectIdentifierType::instance();
        assert!(reg.has_oid_with_identifier(&[0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 4]));
        assert!(!reg.has_oid_with_identifier(&[1, 2, 3]));
    }

    #[test]
    fn registry_missing_identifier_string_returns_error() {
        let reg = Asn1ObjectIdentifierType::instance();
        let err = reg.get_oid_by_identifier_string("nope").unwrap_err();
        assert!(err.0.contains("does not exist"));
    }

    #[test]
    fn registry_missing_identifier_returns_error() {
        let reg = Asn1ObjectIdentifierType::instance();
        let err = reg.get_oid_by_identifier(&[9, 9, 9]).unwrap_err();
        assert!(err.0.contains("does not exist"));
    }
}
