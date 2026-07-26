//! CRL revocation checking — the one part of this crate that touches the network,
//! and only when you call it.
//!
//! Issuer data authentication proves an mdoc was signed by a Document Signer that
//! chains to a trusted IACA. It cannot tell you that the DS certificate was revoked
//! last week — for that the verifier has to go and look, which means fetching the CRL
//! named in the certificate's CRL distribution point.
//!
//! Build a [`CrlChecker`] once and hand it to each verification. With the default
//! `bundled-http-client` feature it caches, so a busy verifier is not refetching the
//! same list for every presentation; without that feature the fetch is uncached and
//! you should wrap your own client in whatever cache the platform offers.
//!
//! ```no_run
//! use mdl_verify::{
//!     revocation::{verify_issuer_auth, CrlChecker, HttpClient},
//!     IacaAnchor, VerifyOptions,
//! };
//!
//! # async fn example<C: HttpClient>(
//! #     device_response: &[u8],
//! #     iaca_der: &[u8],
//! #     crl: &CrlChecker<C>,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let anchors = [IacaAnchor::from_certificate(iaca_der)?];
//!
//! let verification =
//!     verify_issuer_auth(device_response, &anchors, &VerifyOptions::default(), crl).await?;
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
//! # On a phone
//!
//! A reader app is a verifier like any other, and runs the same code — but it should
//! usually not do its own HTTP. [`CrlChecker::with_http_client`] takes any
//! [`HttpClient`], so a CRL fetch can go through `URLSession` on iOS or OkHttp on
//! Android and inherit the platform's proxy settings, TLS policy, VPN routing and
//! certificate pinning instead of quietly bypassing all of it:
//!
//! ```no_run
//! use mdl_verify::revocation::{async_trait, CrlChecker, HttpClient, HttpRequest, HttpResponse};
//!
//! struct PlatformHttp;   // an FFI bridge to URLSession / OkHttp
//!
//! #[async_trait]
//! impl HttpClient for PlatformHttp {
//!     type Error = std::io::Error;
//!
//!     async fn request(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
//!         # let _ = request;
//!         todo!("hand the URL to the platform, return status + body")
//!     }
//! }
//!
//! let crl = CrlChecker::with_http_client(PlatformHttp);
//! ```
//!
//! Across an FFI boundary an `async fn` is awkward, so [`BlockingCrlChecker`] owns a
//! small runtime and exposes the same two calls synchronously — build it once, hold
//! it, call it from whatever thread the platform hands you.
//!
//! # Why the async entry points are `async`
//!
//! Fetching is I/O. The rest of the crate is synchronous because it genuinely never
//! blocks; these functions do, so they are honest about it and take the caller's
//! runtime rather than smuggling one in. Servers should use them directly.

use isomdl::cbor;
use isomdl::definitions::device_response::DeviceResponse;

use crate::issuer::{verify_documents_with, MdlVerification, VerifyOptions};
use crate::{IacaAnchor, MdlError, SessionTranscript};

/// Implement [`HttpClient`] for your own transport.
///
/// Re-exported so implementors do not have to depend on `async-trait` directly, or
/// guess which version to match.
pub use async_trait::async_trait;
pub use isomdl::definitions::x509::revocation::{
    HttpClient, HttpMethod, HttpRequest, HttpResponse,
};

/// The bundled HTTP client. Present with the default `bundled-http-client` feature.
#[cfg(feature = "bundled-http-client")]
pub use isomdl::definitions::x509::revocation::ReqwestClient;

/// The caching fetcher rides along with the bundled client upstream, so a build
/// without it fetches uncached. Documented on the feature in `Cargo.toml`.
#[cfg(feature = "bundled-http-client")]
type Fetcher<C> = isomdl::definitions::x509::revocation::CachingRevocationFetcher<C>;
#[cfg(not(feature = "bundled-http-client"))]
type Fetcher<C> = isomdl::definitions::x509::revocation::SimpleRevocationFetcher<C>;

/// A CRL fetcher.
///
/// Build one per process and share it. With the default `bundled-http-client`
/// feature the CRLs are cached by URL until they go stale, so a verifier handling
/// many presentations against the same issuer fetches once rather than once per
/// presentation.
///
/// [`CrlChecker::new`] uses the bundled reqwest client, which is the right answer on
/// a server. On a phone, prefer [`with_http_client`](Self::with_http_client) and the
/// platform's own networking stack.
pub struct CrlChecker<C> {
    fetcher: Fetcher<C>,
}

// The upstream fetcher is not `Debug`; the crate lints for missing Debug impls, and
// there is nothing worth printing here beyond "it exists".
impl<C> std::fmt::Debug for CrlChecker<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlChecker").finish_non_exhaustive()
    }
}

#[cfg(feature = "bundled-http-client")]
impl CrlChecker<ReqwestClient> {
    /// A checker using the bundled HTTP client, with its default timeout and cache
    /// policy.
    ///
    /// ```no_run
    /// use mdl_verify::revocation::CrlChecker;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let crl = CrlChecker::new()?;
    /// # let _ = crl;
    /// # Ok(()) }
    /// ```
    pub fn new() -> Result<Self, MdlError> {
        Ok(Self::with_http_client(
            ReqwestClient::new().map_err(|e| MdlError::Revocation(e.to_string()))?,
        ))
    }

    /// A checker using the bundled HTTP client, with an explicit timeout, cache size
    /// and staleness bound.
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

        Ok(Self::with_http_client_and_config(
            client,
            cache_capacity,
            max_stale,
        ))
    }
}

impl<C: HttpClient> CrlChecker<C> {
    /// A checker over your own transport — `URLSession`, OkHttp, a corporate proxy
    /// stack, or a test double.
    pub fn with_http_client(client: C) -> Self {
        Self {
            fetcher: Fetcher::new(client),
        }
    }

    /// [`with_http_client`](Self::with_http_client) with an explicit cache size and
    /// staleness bound.
    ///
    /// Only meaningful with the default `bundled-http-client` feature, which is what
    /// brings the caching fetcher in; without it there is no cache to configure and
    /// the arguments are ignored.
    #[cfg_attr(
        not(feature = "bundled-http-client"),
        allow(unused_variables, clippy::needless_pass_by_value)
    )]
    pub fn with_http_client_and_config(
        client: C,
        cache_capacity: u64,
        max_stale: std::time::Duration,
    ) -> Self {
        #[cfg(feature = "bundled-http-client")]
        let fetcher = Fetcher::with_config(client, cache_capacity, max_stale);
        #[cfg(not(feature = "bundled-http-client"))]
        let fetcher = Fetcher::new(client);

        Self { fetcher }
    }
}

/// [`crate::verify_issuer_auth`], additionally checking the Document Signer against
/// its CRL.
///
/// Revocation is only checked when trust anchors are supplied — there is no CRL to
/// validate a signature against without the IACA that signed it.
pub async fn verify_issuer_auth<C: HttpClient>(
    device_response: &[u8],
    anchors: &[IacaAnchor],
    options: &VerifyOptions,
    crl: &CrlChecker<C>,
) -> Result<MdlVerification, MdlError> {
    let response: DeviceResponse = cbor::from_slice(device_response)
        .map_err(|e| MdlError::Unreadable(format!("could not decode a DeviceResponse: {e}")))?;

    verify_documents_with(&response, anchors, options, &crl.fetcher).await
}

/// [`crate::verify_presentation`], additionally checking the Document Signer against
/// its CRL.
pub async fn verify_presentation<C: HttpClient>(
    device_response: &[u8],
    anchors: &[IacaAnchor],
    transcript: &SessionTranscript,
    e_reader_key_private: Option<&[u8; 32]>,
    options: &VerifyOptions,
    crl: &CrlChecker<C>,
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

/// A [`CrlChecker`] with its own runtime, for callers that have none.
///
/// This exists for reader apps reaching the crate through an FFI boundary — UniFFI,
/// JNI, a C shim — where handing back a Rust future is more trouble than it is worth.
/// Build one at startup, hold it for the life of the process, and call it from
/// whatever thread the platform gives you.
///
/// A server inside an async runtime should **not** use this: driving a runtime from
/// inside another one panics. Use [`verify_issuer_auth`] and
/// [`verify_presentation`] there, which is also cheaper.
pub struct BlockingCrlChecker<C> {
    checker: CrlChecker<C>,
    runtime: tokio::runtime::Runtime,
}

impl<C> std::fmt::Debug for BlockingCrlChecker<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingCrlChecker").finish_non_exhaustive()
    }
}

#[cfg(feature = "bundled-http-client")]
impl BlockingCrlChecker<ReqwestClient> {
    /// A blocking checker over the bundled HTTP client.
    pub fn new() -> Result<Self, MdlError> {
        Self::wrap(CrlChecker::new()?)
    }
}

impl<C: HttpClient> BlockingCrlChecker<C> {
    /// A blocking checker over your own transport.
    pub fn with_http_client(client: C) -> Result<Self, MdlError> {
        Self::wrap(CrlChecker::with_http_client(client))
    }

    fn wrap(checker: CrlChecker<C>) -> Result<Self, MdlError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| MdlError::Revocation(format!("could not start a runtime: {e}")))?;

        Ok(Self { checker, runtime })
    }

    /// [`verify_issuer_auth`], driven to completion on this checker's runtime.
    ///
    /// # Panics
    ///
    /// If called from inside another async runtime.
    pub fn verify_issuer_auth(
        &self,
        device_response: &[u8],
        anchors: &[IacaAnchor],
        options: &VerifyOptions,
    ) -> Result<MdlVerification, MdlError> {
        self.runtime.block_on(verify_issuer_auth(
            device_response,
            anchors,
            options,
            &self.checker,
        ))
    }

    /// [`verify_presentation`], driven to completion on this checker's runtime.
    ///
    /// # Panics
    ///
    /// If called from inside another async runtime.
    pub fn verify_presentation(
        &self,
        device_response: &[u8],
        anchors: &[IacaAnchor],
        transcript: &SessionTranscript,
        e_reader_key_private: Option<&[u8; 32]>,
        options: &VerifyOptions,
    ) -> Result<MdlVerification, MdlError> {
        self.runtime.block_on(verify_presentation(
            device_response,
            anchors,
            transcript,
            e_reader_key_private,
            options,
            &self.checker,
        ))
    }
}
