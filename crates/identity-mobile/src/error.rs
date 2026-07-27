use thiserror::Error;

/// Everything that can go wrong reading or verifying a document.
///
/// The split that matters for a UI: [`Nfc`](Self::Nfc) and [`Access`](Self::Access)
/// mean "try again" (the phone moved, the key was mistyped), while
/// [`NotAuthentic`](Self::NotAuthentic) means "stop" — and the two must not be shown
/// the same way.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// The chip could not be talked to: the phone moved out of range, the tag was
    /// lost, the platform's NFC call failed.
    ///
    /// Recoverable. Ask the holder to hold the document still and try again.
    #[error("could not talk to the chip: {0}")]
    Nfc(String),

    /// The chip refused the session key — almost always a mistyped or misread MRZ.
    ///
    /// Recoverable, and worth saying so plainly: the document is probably fine, the
    /// key is wrong.
    #[error(
        "the document rejected the access key; check the document number, date of birth and expiry"
    )]
    Access,

    /// A file could not be parsed as what it claims to be.
    #[error("the document is not readable: {0}")]
    Unreadable(String),

    /// The data does not match what the issuer signed.
    ///
    /// Not recoverable and not a retry: either the document is forged, or it was
    /// altered after issuance. Never show this as a transient failure.
    #[error("the document is not authentic: {0}")]
    NotAuthentic(String),

    /// The holder authenticated with `DeviceMac`, whose key is derived by ECDH with
    /// the reader's ephemeral key — so it cannot be checked without that key.
    ///
    /// Its own variant because the caller can fix it, unlike everything else here: the
    /// session key exists, it just was not passed in. Reported as "unreadable" it looks
    /// like a bad document.
    #[error("this presentation needs the reader's ephemeral private key to verify")]
    SessionKeyRequired,

    /// A supplied trust anchor could not be parsed.
    #[error("a trust anchor could not be parsed: {0}")]
    Anchor(String),

    /// The signature algorithm is one this build cannot verify. A refusal to answer,
    /// never a pass — see `mdl-verify`'s `preflight` for finding this out in advance.
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
}
