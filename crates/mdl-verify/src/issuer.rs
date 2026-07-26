//! Phase 1 — issuer data authentication.
//!
//! Everything here works on a static `DeviceResponse`: no session, no nonce, no live
//! holder. It answers "is this data what the issuer signed, and do I trust that
//! issuer?" — not "is this holder present" (that is [`crate::device`]).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use isomdl::cbor;
use isomdl::definitions::device_response::{DeviceResponse, Document};
use isomdl::definitions::x509::revocation::RevocationFetcher;
use isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry;
use isomdl::definitions::x509::validation::{
    ValidationOptions, ValidationOutcome, ValidationRuleset,
};
use isomdl::definitions::x509::X5Chain;
use isomdl::definitions::ValidityInfo;
use isomdl::presentation::authentication::mdoc::issuer_authentication;

use crate::anchor::{registry, IacaAnchor, TrustRules};
use crate::block_on::try_block_on;
use crate::value::MdlValue;
use crate::MdlError;

/// The COSE header label carrying the `x5chain` (RFC 9360).
const X5CHAIN_HEADER_LABEL: i64 = 33;

/// Knobs for [`verify_issuer_auth_with`].
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// The instant to judge validity windows against — both the certificate chain's
    /// and the MSO's. Defaults to now. Pin it to make tests reproducible, or to
    /// re-verify an archived presentation as of when it was captured.
    pub at: Option<DateTime<Utc>>,
    /// Which certificate profile to hold the Document Signer to.
    pub rules: TrustRules,
}

/// The MSO's `validityInfo` (ISO/IEC 18013-5 §9.1.2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsoValidity {
    /// When the issuer signed the MSO.
    pub signed: DateTime<Utc>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// When the issuer expects to re-issue. Not a validity bound — an mdoc past this
    /// point is still valid, it is just stale.
    pub expected_update: Option<DateTime<Utc>>,
    /// Whether the verification time fell inside `[valid_from, valid_until]`.
    pub in_window: bool,
}

/// One verified document out of a `DeviceResponse`.
///
/// An `MdlDocument` only ever exists for a document that passed issuer data
/// authentication — a failure is [`MdlError::Tampered`], never a document with a
/// flag turned off. The flags that remain are the ones a caller can reasonably
/// decide about: whether the issuer chained to an anchor they trust, whether the
/// credential is inside its validity window, and whether the holder proved device
/// possession.
#[derive(Debug, Clone)]
pub struct MdlDocument {
    /// e.g. `org.iso.18013.5.1.mDL`.
    pub doc_type: String,
    /// Disclosed elements, keyed by namespace then element identifier. Only the
    /// elements the holder chose to disclose are present — an mDL can present
    /// `age_over_21` and `portrait` without ever revealing `birth_date`.
    pub namespaces: BTreeMap<String, BTreeMap<String, MdlValue>>,
    /// The `IssuerAuth` `COSE_Sign1` verified and every disclosed element's digest
    /// matched the MSO. Always `true`: see the type-level note above.
    pub signature_verified: bool,
    /// The Document Signer certificate chained to one of the supplied IACA anchors.
    /// `false` when no anchors were supplied, or when none of them matched — check
    /// [`trust_errors`](Self::trust_errors) to tell those apart.
    pub issuer_trusted: bool,
    /// Why the chain was not trusted, verbatim from the certificate profile checks.
    pub trust_errors: Vec<String>,
    /// Problems encountered *checking* revocation — a CRL that could not be fetched,
    /// parsed, or whose signature did not verify — as opposed to a certificate that
    /// actually is revoked, which is a trust failure and lands in
    /// [`trust_errors`](Self::trust_errors) with `issuer_trusted = false`.
    ///
    /// Always populated with a "revocation checking is disabled" note unless the
    /// `revocation` feature is on and the document went through
    /// [`crate::revocation`]. Infrastructure failures are reported rather than
    /// enforced: whether an unreachable CRL should block a presentation is the
    /// caller's policy call, not this crate's.
    pub revocation_errors: Vec<String>,
    /// The MSO's validity window and whether we were inside it.
    pub validity: MsoValidity,
    /// The holder proved possession of the device key bound in the MSO. Only ever
    /// `true` when the document went through [`crate::verify_presentation`]; the
    /// static path cannot establish this.
    pub device_authenticated: bool,
}

impl MdlDocument {
    /// Issuer-signed, chained to a trusted IACA anchor, and inside its validity
    /// window. This is the check to gate on for a static (Phase 1) verification.
    ///
    /// It says nothing about holder presence — a genuine mDL response captured off
    /// the wire and replayed passes this. Gate on
    /// [`device_authenticated`](Self::device_authenticated) too when the
    /// presentation was live.
    pub fn is_authentic(&self) -> bool {
        self.signature_verified && self.issuer_trusted && self.validity.in_window
    }

    /// A disclosed element from an explicit namespace.
    pub fn element(&self, namespace: &str, identifier: &str) -> Option<&MdlValue> {
        self.namespaces.get(namespace)?.get(identifier)
    }

    /// A disclosed element from the `org.iso.18013.5.1` namespace.
    pub fn iso(&self, identifier: &str) -> Option<&MdlValue> {
        self.element(crate::ISO_NAMESPACE, identifier)
    }

    pub fn family_name(&self) -> Option<&str> {
        self.iso("family_name")?.as_text()
    }

    pub fn given_name(&self) -> Option<&str> {
        self.iso("given_name")?.as_text()
    }

    pub fn birth_date(&self) -> Option<&str> {
        self.iso("birth_date")?.as_date()
    }

    pub fn issue_date(&self) -> Option<&str> {
        self.iso("issue_date")?.as_date()
    }

    pub fn expiry_date(&self) -> Option<&str> {
        self.iso("expiry_date")?.as_date()
    }

    pub fn document_number(&self) -> Option<&str> {
        self.iso("document_number")?.as_text()
    }

    pub fn issuing_country(&self) -> Option<&str> {
        self.iso("issuing_country")?.as_text()
    }

    pub fn issuing_authority(&self) -> Option<&str> {
        self.iso("issuing_authority")?.as_text()
    }

    /// The holder's portrait, as the raw JPEG/JPEG2000 bytes the issuer signed.
    pub fn portrait(&self) -> Option<&[u8]> {
        self.iso("portrait")?.as_bytes()
    }

    /// An `age_over_NN` attestation, if that particular one was disclosed.
    ///
    /// `age_over(21)` is the whole point of an mDL for a lot of verifiers: it is
    /// disclosed without `birth_date`, so the reader learns the answer and not the
    /// date of birth.
    pub fn age_over(&self, years: u8) -> Option<bool> {
        self.iso(&format!("age_over_{years}"))?.as_bool()
    }

    /// `driving_privileges`, as the array of category maps the issuer signed.
    pub fn driving_privileges(&self) -> Option<&[MdlValue]> {
        self.iso("driving_privileges")?.as_array()
    }
}

/// The result of verifying a `DeviceResponse`.
#[derive(Debug, Clone)]
pub struct MdlVerification {
    /// The `DeviceResponse` version string, e.g. `"1.0"`.
    pub version: String,
    /// Every document in the response, in the order the holder returned them.
    pub documents: Vec<MdlDocument>,
}

impl MdlVerification {
    /// The first `org.iso.18013.5.1.mDL` document, if the response carried one.
    ///
    /// A response may carry several documents of different doc types — a photo ID
    /// next to an mDL — so this is a convenience, not the only way in. Use
    /// [`documents`](Self::documents) when you care about the rest.
    pub fn mdl(&self) -> Option<&MdlDocument> {
        self.documents
            .iter()
            .find(|doc| doc.doc_type == crate::MDL_DOC_TYPE)
    }

    /// Every document passed [`MdlDocument::is_authentic`].
    pub fn all_authentic(&self) -> bool {
        !self.documents.is_empty() && self.documents.iter().all(MdlDocument::is_authentic)
    }
}

/// Verify issuer data authentication over a `DeviceResponse`, as of now.
///
/// `device_response` is the **decrypted** CBOR `DeviceResponse` — if you are running
/// a proximity or OpenID4VP flow, that is what comes out of the session layer, not
/// the bytes off the wire.
///
/// Returns [`MdlError::Tampered`] if any document's issuer signature or element
/// digests do not check out. Trust and validity are reported on each document rather
/// than raised as errors, so a caller can decide what an untrusted-but-genuine
/// credential is worth to them.
pub fn verify_issuer_auth(
    device_response: &[u8],
    anchors: &[IacaAnchor],
) -> Result<MdlVerification, MdlError> {
    verify_issuer_auth_with(device_response, anchors, &VerifyOptions::default())
}

/// [`verify_issuer_auth`] with an explicit verification time and certificate profile.
pub fn verify_issuer_auth_with(
    device_response: &[u8],
    anchors: &[IacaAnchor],
    options: &VerifyOptions,
) -> Result<MdlVerification, MdlError> {
    let response: DeviceResponse = cbor::from_slice(device_response)
        .map_err(|e| MdlError::Unreadable(format!("could not decode a DeviceResponse: {e}")))?;

    verify_documents(&response, anchors, options)
}

/// The no-network path: drive the async core with upstream's no-op fetcher.
///
/// Nothing in that future actually suspends, so the one-poll executor in
/// [`crate::block_on`] is enough — no runtime, no network. Enable the `revocation`
/// feature and use [`crate::revocation`] if you want CRLs checked.
pub(crate) fn verify_documents(
    response: &DeviceResponse,
    anchors: &[IacaAnchor],
    options: &VerifyOptions,
) -> Result<MdlVerification, MdlError> {
    try_block_on(verify_documents_with(response, anchors, options, &()))
        .ok_or(MdlError::ValidationDidNotComplete)?
}

/// The verification core, generic over how (or whether) CRLs are fetched.
pub(crate) async fn verify_documents_with<R: RevocationFetcher>(
    response: &DeviceResponse,
    anchors: &[IacaAnchor],
    options: &VerifyOptions,
    revocation_fetcher: &R,
) -> Result<MdlVerification, MdlError> {
    let documents = response.documents.as_ref().ok_or(MdlError::NoDocuments)?;

    let at = options.at.unwrap_or_else(Utc::now);
    let at_odt = to_offset_date_time(at)?;
    let registry = registry(anchors);

    let mut verified = Vec::new();
    for document in documents.iter() {
        let x5chain = x5chain(document)?;
        let mso = issuer_authentication(x5chain.clone(), &document.issuer_signed)
            .map_err(|e| MdlError::Tampered(e.to_string()))?;

        // ISO/IEC 18013-5 §8.3.2.1.2.2: the MSO's docType is what the issuer signed;
        // the Document's is what the holder claims. They must agree, or a holder
        // could present a genuine photo-ID MSO as an mDL.
        if mso.doc_type != document.doc_type {
            return Err(MdlError::Tampered(format!(
                "document claims docType {:?} but the issuer signed {:?}",
                document.doc_type, mso.doc_type
            )));
        }

        let validity = validity(&mso.validity_info, at)?;

        let (issuer_trusted, trust_errors, revocation_errors) = if anchors.is_empty() {
            (
                false,
                vec!["no IACA trust anchors were supplied".to_string()],
                Vec::new(),
            )
        } else {
            let outcome = validate_chain(
                options.rules,
                &x5chain,
                &registry,
                at_odt,
                revocation_fetcher,
            )
            .await;
            (outcome.success(), outcome.errors, outcome.revocation_errors)
        };

        verified.push(MdlDocument {
            doc_type: document.doc_type.clone(),
            namespaces: namespaces(document)?,
            signature_verified: true,
            issuer_trusted,
            trust_errors,
            revocation_errors,
            validity,
            device_authenticated: false,
        });
    }

    Ok(MdlVerification {
        version: response.version.clone(),
        documents: verified,
    })
}

/// Run the certificate profile checks against the anchors, at a pinned time.
async fn validate_chain<R: RevocationFetcher>(
    rules: TrustRules,
    x5chain: &X5Chain,
    registry: &TrustAnchorRegistry,
    at: time::OffsetDateTime,
    revocation_fetcher: &R,
) -> ValidationOutcome {
    let options = ValidationOptions {
        validation_time: Some(at),
    };
    ValidationRuleset::from(rules)
        .validate_with_options(x5chain, registry, revocation_fetcher, &options)
        .await
}

/// Pull the Document Signer's `x5chain` out of the `IssuerAuth` unprotected header.
fn x5chain(document: &Document) -> Result<X5Chain, MdlError> {
    document
        .issuer_signed
        .issuer_auth
        .unprotected
        .rest
        .iter()
        .find(|(label, _)| label == &coset::Label::Int(X5CHAIN_HEADER_LABEL))
        .map(|(_, value)| value.clone())
        .ok_or_else(|| {
            MdlError::MissingSignerCertificate(
                "IssuerAuth carries no x5chain header (label 33)".to_string(),
            )
        })
        .and_then(|value| {
            X5Chain::from_cbor(value).map_err(|e| MdlError::MissingSignerCertificate(e.to_string()))
        })
}

fn namespaces(
    document: &Document,
) -> Result<BTreeMap<String, BTreeMap<String, MdlValue>>, MdlError> {
    let Some(namespaces) = document.issuer_signed.namespaces.as_ref() else {
        // A response that discloses nothing is legal — the issuer signature still
        // verified, there is simply nothing in it.
        return Ok(BTreeMap::new());
    };

    let mut out = BTreeMap::new();
    for (namespace, items) in namespaces.iter() {
        let mut elements = BTreeMap::new();
        for item in items.iter() {
            let item = item.as_ref();
            elements.insert(
                item.element_identifier.clone(),
                MdlValue::try_from(&item.element_value)?,
            );
        }
        out.insert(namespace.clone(), elements);
    }
    Ok(out)
}

fn validity(info: &ValidityInfo, at: DateTime<Utc>) -> Result<MsoValidity, MdlError> {
    let convert = |t: time::OffsetDateTime| -> Result<DateTime<Utc>, MdlError> {
        DateTime::from_timestamp(t.unix_timestamp(), t.nanosecond()).ok_or_else(|| {
            MdlError::Unreadable(format!("MSO validityInfo holds an out-of-range date: {t}"))
        })
    };

    let signed = convert(info.signed)?;
    let valid_from = convert(info.valid_from)?;
    let valid_until = convert(info.valid_until)?;
    let expected_update = info.expected_update.map(convert).transpose()?;

    Ok(MsoValidity {
        signed,
        valid_from,
        valid_until,
        expected_update,
        in_window: at >= valid_from && at <= valid_until,
    })
}

/// Convert to the type the certificate checks want, keeping subsecond precision.
///
/// Truncating to whole seconds here would let the chain be judged at a marginally
/// earlier instant than the MSO — enough that a certificate which expired less than a
/// second ago could still be reported as trusted. Nanoseconds are carried through as
/// an `i128` rather than via `timestamp_nanos_opt`, which is only valid between 1677
/// and 2262.
fn to_offset_date_time(at: DateTime<Utc>) -> Result<time::OffsetDateTime, MdlError> {
    let nanos =
        i128::from(at.timestamp()) * 1_000_000_000 + i128::from(at.timestamp_subsec_nanos());

    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|e| MdlError::Unreadable(format!("verification time is out of range: {e}")))
}
