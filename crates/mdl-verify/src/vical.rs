//! VICAL — sourcing IACA trust anchors from a signed list.
//!
//! Everywhere else this crate takes IACA anchors as input and leaves sourcing to the
//! caller. For US state mDLs that is an awkward place to stop: there are dozens of
//! issuing authorities, their roots rotate, and hand-managing the set is exactly the
//! kind of job that quietly goes stale.
//!
//! A VICAL (ISO/IEC 18013-5 Annex C) solves it: a `COSE_Sign1` over a list of IACA
//! certificates, signed by a VICAL provider. AAMVA publishes one for the US through
//! its Digital Trust Service. Verify it once against the provider's root, and you
//! have every anchor it vouches for.
//!
//! ```no_run
//! use mdl_verify::{vical, VerifyOptions};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let vical_bytes: &[u8] = &[];
//! # let aamva_root_pem = "";
//! # let device_response: &[u8] = &[];
//! let authorities = [vical::VicalAuthority::from_pem(aamva_root_pem)?];
//! let list = vical::verify(vical_bytes, &authorities, &VerifyOptions::default())?;
//!
//! // Anchors for mDLs specifically — a VICAL may carry other document types.
//! let anchors = list.anchors_for(mdl_verify::MDL_DOC_TYPE);
//! let verification = mdl_verify::verify_issuer_auth(device_response, &anchors)?;
//! # let _ = verification;
//! # Ok(()) }
//! ```
//!
//! # What verifying a VICAL does and does not establish
//!
//! It establishes that the provider signed this list, that their signer chains to a
//! root you trust, and that the list has not been altered. It says nothing about
//! whether any *individual* IACA in it is still fit to trust — that is what the
//! per-document chain checks and CRLs are for, and they run as usual afterwards.
//!
//! Note also [`Vical::next_update`]: a VICAL is a snapshot. Serving a year-old list
//! is how a revoked issuer stays trusted, so treat a stale one as a fetch failure
//! rather than a fallback. [`Vical::is_stale_at`] answers the question.

use chrono::{DateTime, Utc};
use isomdl::definitions::namespaces::org_iso_18013_5_1::TDate;
use isomdl::definitions::x509::revocation::RevocationFetcher;
use isomdl::definitions::x509::trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose};
use isomdl::definitions::x509::validation::ValidationOptions;
use isomdl::vical::VerifiedVical;
use x509_cert::der::{Decode, DecodePem};
use x509_cert::Certificate;

use crate::block_on::try_block_on;
use crate::issuer::VerifyOptions;
use crate::{IacaAnchor, MdlError};

/// A root the VICAL provider's signer must chain to.
///
/// For AAMVA this is the DTS Root CA, published alongside the VICAL itself. It is a
/// different trust root from the IACAs *inside* the list: this one says "I trust this
/// organisation to tell me who the issuers are".
#[derive(Debug, Clone)]
pub struct VicalAuthority {
    certificate: Certificate,
}

impl VicalAuthority {
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

/// One issuing authority's entry in a verified VICAL.
#[derive(Debug, Clone)]
pub struct VicalEntry {
    /// The IACA certificate, ready to pass to [`crate::verify_issuer_auth`].
    pub anchor: IacaAnchor,
    /// The document types this anchor is vouched for — an entry good for
    /// `org.iso.18013.5.1.mDL` is not automatically good for a photo ID.
    pub doc_types: Vec<String>,
    /// e.g. `"New York DMV"`.
    pub issuing_authority: Option<String>,
    /// ISO 3166-1 or 3166-2, e.g. `"US"` or `"US-NY"`.
    pub issuing_country: Option<String>,
    pub state_or_province: Option<String>,
}

/// A verified VICAL.
#[derive(Debug, Clone)]
pub struct Vical {
    /// Who signed it, e.g. `"AAMVA"`.
    pub provider: String,
    /// When this issue was published.
    pub issued: DateTime<Utc>,
    /// When the provider expects to publish the next one. `None` means they made no
    /// promise, which is not the same as "never goes stale".
    pub next_update: Option<DateTime<Utc>>,
    /// Monotonically increasing issue number, when the provider sets one. Useful for
    /// refusing to roll backwards to an older list.
    pub issue_id: Option<u64>,
    /// Every entry whose certificate parsed.
    pub entries: Vec<VicalEntry>,
    /// Entries whose certificate did not parse, with the reason.
    ///
    /// Reported rather than fatal: one malformed entry in a list of fifty should not
    /// cost you the other forty-nine, but you should be able to see it happened.
    pub unusable: Vec<String>,
}

impl Vical {
    /// Every anchor in the list, regardless of document type.
    pub fn anchors(&self) -> Vec<IacaAnchor> {
        self.entries.iter().map(|e| e.anchor.clone()).collect()
    }

    /// The anchors vouched for a particular document type — normally
    /// [`crate::MDL_DOC_TYPE`].
    ///
    /// Prefer this over [`anchors`](Self::anchors): a VICAL entry names the doc types
    /// it is good for, and honouring that is the difference between trusting an
    /// issuer for mDLs and trusting them for everything.
    pub fn anchors_for(&self, doc_type: &str) -> Vec<IacaAnchor> {
        self.entries
            .iter()
            .filter(|e| e.doc_types.iter().any(|d| d == doc_type))
            .map(|e| e.anchor.clone())
            .collect()
    }

    /// The provider said the next issue would be out by now.
    ///
    /// A stale VICAL is a liability, not a fallback: it is how an issuer that was
    /// removed from the list stays trusted. Treat this as "refetch, and fail if you
    /// cannot" rather than "carry on".
    ///
    /// The deadline itself counts as stale — at `nextUpdate` the provider said a new
    /// list would already be out, so that instant is the first one where this is no
    /// longer current.
    pub fn is_stale_at(&self, at: DateTime<Utc>) -> bool {
        self.next_update.is_some_and(|next| at >= next)
    }
}

/// Verify a VICAL and read the IACA anchors out of it.
///
/// Checks the provider's `COSE_Sign1` signature, chains their signer certificate to
/// one of `authorities`, and then parses the list. Returns [`MdlError::Vical`] if any
/// of that fails — unlike issuer trust, there is no useful half-verified state here:
/// an unverified list of trust anchors is just a list of certificates.
///
/// `options.at` pins the time for the signer's validity check, as elsewhere.
/// Revocation of the VICAL signer is not checked on this path; use
/// [`crate::revocation::verify_vical`] for that.
pub fn verify(
    vical: &[u8],
    authorities: &[VicalAuthority],
    options: &VerifyOptions,
) -> Result<Vical, MdlError> {
    try_block_on(verify_with(vical, authorities, options, &()))
        .ok_or(MdlError::ValidationDidNotComplete)?
}

pub(crate) async fn verify_with<R: RevocationFetcher>(
    vical: &[u8],
    authorities: &[VicalAuthority],
    options: &VerifyOptions,
    revocation_fetcher: &R,
) -> Result<Vical, MdlError> {
    if authorities.is_empty() {
        return Err(MdlError::Vical(
            "no VICAL authority certificates were supplied; an unverified list of \
             trust anchors is worthless"
                .to_string(),
        ));
    }

    let at = options.at.unwrap_or_else(Utc::now);
    let registry = TrustAnchorRegistry {
        anchors: authorities
            .iter()
            .map(|authority| TrustAnchor {
                certificate: authority.certificate.clone(),
                purpose: TrustPurpose::VicalAuthority,
            })
            .collect(),
    };

    let validation = ValidationOptions {
        validation_time: Some(crate::issuer::to_offset_date_time(at)?),
    };

    let verified =
        VerifiedVical::from_bytes_with_options(vical, &registry, revocation_fetcher, &validation)
            .await
            .map_err(|e| MdlError::Vical(e.to_string()))?;

    let mut entries = Vec::new();
    let mut unusable = Vec::new();

    for info in &verified.vical.certificate_infos {
        match info.certificate() {
            Ok(certificate) => entries.push(VicalEntry {
                anchor: IacaAnchor { certificate },
                doc_types: info.doc_type.iter().cloned().collect(),
                issuing_authority: info.issuing_authority.clone(),
                issuing_country: info.issuing_country.clone(),
                state_or_province: info.state_or_province_name.clone(),
            }),
            Err(e) => unusable.push(format!(
                "{}: {e}",
                info.issuing_authority.as_deref().unwrap_or("<unnamed>")
            )),
        }
    }

    Ok(Vical {
        provider: verified.vical.vical_provider.clone(),
        issued: tdate_to_utc(verified.vical.date)?,
        next_update: verified.vical.next_update.map(tdate_to_utc).transpose()?,
        issue_id: verified.vical.vical_issue_id,
        entries,
        unusable,
    })
}

/// A `tdate` is an RFC 3339 timestamp carried as a tagged text string; upstream keeps
/// it as one rather than a parsed instant, so unwrap the tag and parse it here.
fn tdate_to_utc(date: TDate) -> Result<DateTime<Utc>, MdlError> {
    let value: ciborium::Value = date.into();

    let text = match &value {
        ciborium::Value::Tag(_, inner) => inner.as_text(),
        other => other.as_text(),
    }
    .ok_or_else(|| MdlError::Vical(format!("a VICAL date is not a text string: {value:?}")))?;

    DateTime::parse_from_rfc3339(text)
        .map(|at| at.with_timezone(&Utc))
        .map_err(|e| MdlError::Vical(format!("a VICAL date is not a valid RFC 3339 time: {e}")))
}
