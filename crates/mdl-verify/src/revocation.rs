//! CRL revocation checking — the one part of this crate that touches the network,
//! and only when you call it.
//!
//! Issuer data authentication proves an mdoc was signed by a Document Signer that
//! chains to a trusted IACA. It cannot tell you that the DS certificate was revoked
//! last week — for that the verifier has to go and look, which means fetching the CRL
//! named in the certificate's CRL distribution point.
//!
//! ```no_run
//! use mdl_verify::{revocation::{verify_issuer_auth, CrlChecker}, IacaAnchor, VerifyOptions};
//!
//! # async fn example(device_response: &[u8], iaca_der: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! // Build one and keep it: it caches CRLs, so a busy verifier is not refetching
//! // the same list for every presentation.
//! let crl = CrlChecker::new()?;
//! let anchors = [IacaAnchor::from_certificate(iaca_der)?];
//!
//! let verification =
//!     verify_issuer_auth(device_response, &anchors, &VerifyOptions::default(), &crl).await?;
//!
//! let mdl = verification.mdl().ok_or("no mDL")?;
//! if !mdl.revocation_errors.is_empty() {
//!     // The CRL could not be checked — your policy decides whether that is fatal.
//!     eprintln!("revocation not established: {:?}", mdl.revocation_errors);
//! }
//! # Ok(()) }
//! ```
//!
//! # Two outcomes, deliberately kept apart
//!
//! - The DS certificate **is on the CRL** → a trust failure:
//!   `issuer_trusted = false`, with the reason in
//!   [`MdlDocument::trust_errors`](crate::MdlDocument::trust_errors).
//! - The CRL **could not be checked** (host down, TLS failure, malformed list, bad
//!   signature) → [`MdlDocument::revocation_errors`](crate::MdlDocument::revocation_errors),
//!   leaving `issuer_trusted` decided by the rest of the chain checks.
//!
//! Conflating those would mean a verifier that fails open the moment a DMV's CRL
//! endpoint has a bad afternoon, or one that hard-fails every presentation for the
//! same reason. Which of the two is right depends on the deployment, so the decision
//! is left where it belongs.
//!
//! # Why these entry points are `async`
//!
//! Fetching is I/O. The rest of the crate is synchronous because it genuinely never
//! blocks; these functions do, so they are honest about it and take the caller's
//! runtime rather than smuggling one in.

use isomdl::cbor;
use isomdl::definitions::device_response::DeviceResponse;
use isomdl::definitions::x509::revocation::{CachingRevocationFetcher, ReqwestClient};

use crate::issuer::{verify_documents_with, MdlVerification, VerifyOptions};
use crate::{IacaAnchor, MdlError, SessionTranscript};

/// A CRL fetcher with an in-memory cache.
///
/// Build one per process and share it. CRLs are cached by URL until they go stale,
/// so a verifier handling many presentations against the same issuer fetches once
/// rather than once per presentation.
pub struct CrlChecker {
    fetcher: CachingRevocationFetcher<ReqwestClient>,
}

// The upstream fetcher is not `Debug`; the crate lints for missing Debug impls, and
// there is nothing worth printing here beyond "it exists".
impl std::fmt::Debug for CrlChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlChecker").finish_non_exhaustive()
    }
}

impl CrlChecker {
    /// A checker with upstream's default timeout and cache policy.
    pub fn new() -> Result<Self, MdlError> {
        Ok(Self {
            fetcher: CachingRevocationFetcher::new(
                ReqwestClient::new().map_err(|e| MdlError::Revocation(e.to_string()))?,
            ),
        })
    }

    /// A checker with an explicit HTTP timeout, cache size and staleness bound.
    ///
    /// `cache_capacity` is the number of distinct CRL URLs held; `max_stale` is how
    /// long a cached CRL is served past its `nextUpdate` when a refetch fails.
    pub fn with_config(
        timeout: std::time::Duration,
        cache_capacity: u64,
        max_stale: std::time::Duration,
    ) -> Result<Self, MdlError> {
        let client = ReqwestClient::with_timeout(timeout)
            .map_err(|e| MdlError::Revocation(e.to_string()))?;

        Ok(Self {
            fetcher: CachingRevocationFetcher::with_config(client, cache_capacity, max_stale),
        })
    }
}

/// [`crate::verify_issuer_auth`], additionally checking the Document Signer against
/// its CRL.
///
/// Revocation is only checked when trust anchors are supplied — there is no CRL to
/// validate a signature against without the IACA that signed it.
pub async fn verify_issuer_auth(
    device_response: &[u8],
    anchors: &[IacaAnchor],
    options: &VerifyOptions,
    crl: &CrlChecker,
) -> Result<MdlVerification, MdlError> {
    let response: DeviceResponse = cbor::from_slice(device_response)
        .map_err(|e| MdlError::Unreadable(format!("could not decode a DeviceResponse: {e}")))?;

    verify_documents_with(&response, anchors, options, &crl.fetcher).await
}

/// [`crate::verify_presentation`], additionally checking the Document Signer against
/// its CRL.
pub async fn verify_presentation(
    device_response: &[u8],
    anchors: &[IacaAnchor],
    transcript: &SessionTranscript,
    e_reader_key_private: Option<&[u8; 32]>,
    options: &VerifyOptions,
    crl: &CrlChecker,
) -> Result<MdlVerification, MdlError> {
    let response: DeviceResponse = cbor::from_slice(device_response)
        .map_err(|e| MdlError::Unreadable(format!("could not decode a DeviceResponse: {e}")))?;

    let mut verification = verify_documents_with(&response, anchors, options, &crl.fetcher).await?;
    crate::device::verify_response_device_auth(&response, transcript, e_reader_key_private)?;

    for document in &mut verification.documents {
        document.device_authenticated = true;
    }

    Ok(verification)
}
