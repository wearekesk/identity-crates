use isomdl::definitions::x509::trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose};
use isomdl::definitions::x509::validation::ValidationRuleset;
use x509_cert::der::{Decode, DecodePem};
use x509_cert::Certificate;

use crate::MdlError;

/// An Issuing Authority Certificate Authority (IACA) root certificate.
///
/// IACA roots are per-jurisdiction — US state DMVs distribute theirs through the
/// AAMVA Digital Trust Service, EU issuers through their own lists. Sourcing and
/// rotating them is the caller's job; this crate only consumes them, the same way
/// [`dmrtd`](https://docs.rs/dmrtd) consumes a CSCA masterlist.
///
/// Verifying with an empty anchor slice is allowed and useful: the issuer signature
/// and the element digests are still checked, and the result reports
/// `issuer_trusted = false`.
#[derive(Debug, Clone)]
pub struct IacaAnchor {
    pub(crate) certificate: Certificate,
}

impl IacaAnchor {
    /// Parse a DER-encoded X.509 certificate.
    pub fn from_certificate(der: &[u8]) -> Result<Self, MdlError> {
        Certificate::from_der(der)
            .map(|certificate| Self { certificate })
            .map_err(|e| MdlError::Anchor(e.to_string()))
    }

    /// Parse a PEM-encoded X.509 certificate.
    pub fn from_pem(pem: &str) -> Result<Self, MdlError> {
        Certificate::from_pem(pem)
            .map(|certificate| Self { certificate })
            .map_err(|e| MdlError::Anchor(e.to_string()))
    }
}

pub(crate) fn registry(anchors: &[IacaAnchor]) -> TrustAnchorRegistry {
    TrustAnchorRegistry {
        anchors: anchors
            .iter()
            .map(|anchor| TrustAnchor {
                certificate: anchor.certificate.clone(),
                purpose: TrustPurpose::Iaca,
            })
            .collect(),
    }
}

/// Which profile the Document Signer certificate is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustRules {
    /// ISO/IEC 18013-5 Annex B. The right default for any mDL, including the ones
    /// Apple Wallet and Google Wallet present.
    #[default]
    Iso18013_5,
    /// The AAMVA mDL Implementation Guidelines profile, which adds North-America
    /// specific constraints on top of Annex B. Use this for US state mDLs when you
    /// want the stricter check.
    Aamva,
}

impl From<TrustRules> for ValidationRuleset {
    fn from(rules: TrustRules) -> Self {
        match rules {
            TrustRules::Iso18013_5 => ValidationRuleset::Mdl,
            TrustRules::Aamva => ValidationRuleset::AamvaMdl,
        }
    }
}
