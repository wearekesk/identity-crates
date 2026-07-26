use thiserror::Error;

/// Everything that can go wrong verifying an mdoc presentation.
///
/// The split that matters is [`MdlError::Unreadable`] (we could not make sense of
/// the bytes) versus [`MdlError::Tampered`] (we understood the bytes and they are
/// not what the issuer signed). The second is a security event; the first usually
/// means the caller handed us the wrong blob — an undecrypted `SessionData`, a
/// base64 string, or an `IssuerSigned` rather than a whole `DeviceResponse`.
#[derive(Debug, Error)]
pub enum MdlError {
    /// The bytes are not a well-formed CBOR `DeviceResponse`.
    #[error("the device response is not well-formed: {0}")]
    Unreadable(String),

    /// The response parsed but carries no documents (the holder returned only
    /// `documentErrors`, or an empty response).
    #[error("the device response contains no documents")]
    NoDocuments,

    /// Issuer data authentication failed: either the `COSE_Sign1` over the MSO does
    /// not verify against the Document Signer certificate, or a disclosed element's
    /// digest does not match the `valueDigests` the issuer committed to.
    ///
    /// The data must not be used. This is deliberately an error rather than a `false`
    /// flag — there is no safe way to consume elements that failed this check.
    #[error("the document is not issuer-authentic: {0}")]
    Tampered(String),

    /// The document signer certificate is missing from the `IssuerAuth` unprotected
    /// header, or is not a parseable `x5chain`.
    #[error("the document signer certificate chain is missing or unparseable: {0}")]
    MissingSignerCertificate(String),

    /// Device authentication failed — the `DeviceSignature` / `DeviceMac` does not
    /// verify against the device key bound in the MSO, for the supplied session
    /// transcript. The presentation may be a replay of a genuine mdoc.
    #[error("device authentication failed: {0}")]
    DeviceAuth(String),

    /// The document is authenticated with a `COSE_Mac0`, whose key is derived by
    /// ECDH between the mdoc authentication key and the reader's ephemeral key.
    /// Verifying it needs that private key; the transcript alone is not enough.
    #[error(
        "the document uses DeviceMac; verifying it requires the reader's ephemeral private key"
    )]
    EReaderKeyRequired,

    /// A supplied IACA trust anchor could not be parsed as an X.509 certificate.
    #[error("the IACA trust anchor could not be parsed: {0}")]
    Anchor(String),

    /// A VICAL could not be verified: the provider's signature did not check out,
    /// their signer did not chain to a supplied authority, or the list itself was
    /// malformed.
    ///
    /// There is no half-verified state worth returning here — an unverified list of
    /// trust anchors is just a list of certificates.
    #[error("the VICAL could not be verified: {0}")]
    Vical(String),

    /// The CRL checker could not be built — a bad TLS or HTTP client configuration.
    ///
    /// Failures to *fetch* a CRL are not errors: they land in
    /// [`MdlDocument::revocation_errors`](crate::MdlDocument::revocation_errors), and
    /// an actually-revoked certificate makes the document untrusted rather than
    /// unreadable.
    #[error("the CRL checker could not be created: {0}")]
    Revocation(String),

    /// The session transcript is not deterministically-encoded CBOR: re-encoding the
    /// decoded value did not reproduce the input byte-for-byte.
    ///
    /// Device authentication signs the transcript bytes, so a transcript we cannot
    /// reproduce exactly would silently produce a wrong verification result. Rejecting
    /// it is the only safe option. See [`crate::SessionTranscript::from_cbor`].
    #[error("the session transcript is not deterministically encoded CBOR")]
    NonCanonicalTranscript,

    /// Certificate-chain validation did not run to completion.
    ///
    /// The chain validator is `async` upstream; this crate drives it to completion
    /// synchronously with revocation checking disabled, so it never actually suspends.
    /// This error means it did, which would be an upstream change rather than
    /// something a caller can trigger.
    #[error("certificate chain validation did not complete")]
    ValidationDidNotComplete,
}
