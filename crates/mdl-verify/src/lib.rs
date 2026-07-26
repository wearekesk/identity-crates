//! ISO/IEC 18013-5 mobile driving licence (mDL / mdoc) verification.
//!
//! Turns a client-presented mdoc into verified identity fields, server-side. Give it
//! a decrypted CBOR `DeviceResponse` and a set of IACA trust anchors; get back the
//! disclosed elements plus what was actually proven about them.
//!
//! ```no_run
//! use mdl_verify::{verify_issuer_auth, IacaAnchor};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let device_response: &[u8] = &[];
//! # let iaca_root_der: &[u8] = &[];
//! let anchors = [IacaAnchor::from_certificate(iaca_root_der)?];
//! let verification = verify_issuer_auth(device_response, &anchors)?;
//!
//! let mdl = verification.mdl().ok_or("no mDL in the response")?;
//! if mdl.is_authentic() && mdl.age_over(21) == Some(true) {
//!     println!("{} {}", mdl.given_name().unwrap_or(""), mdl.family_name().unwrap_or(""));
//! }
//! # Ok(()) }
//! ```
//!
//! # The two signature layers
//!
//! An mdoc presentation carries two independent proofs, and they answer different
//! questions:
//!
//! | Layer | Proves | Entry point |
//! |---|---|---|
//! | **Issuer data authentication** — `COSE_Sign1` over the MSO, Document Signer chaining to an IACA root, each disclosed element's digest matching `valueDigests` | the data is genuine, issuer-signed and unmodified | [`verify_issuer_auth`] |
//! | **Device authentication** — `DeviceSignature` / `DeviceMac` over a transcript containing the verifier's nonce | this holder controls the device key bound in the MSO, right now | [`verify_device_auth`] |
//!
//! Only the first is verifiable from a static blob. The second needs the session
//! transcript, so it lives behind its own entry point; [`verify_presentation`] runs
//! both when you have one.
//!
//! Without device authentication, a genuine `DeviceResponse` captured once can be
//! replayed forever. That is fine for some server-side flows and fatal for others —
//! it is a decision this crate makes you make, not one it makes for you.
//!
//! # Revocation
//!
//! A Document Signer certificate can be revoked after it was issued, and neither
//! layer above notices. [`revocation::verify_issuer_auth`] fetches and checks the CRL
//! named in the certificate; those entry points are `async` because fetching is I/O.
//! A revoked signer comes back as `issuer_trusted = false`, while a CRL that could
//! not be reached is reported in [`MdlDocument::revocation_errors`] and left for the
//! caller to have a policy about.
//!
//! # What this crate does not do
//!
//! No transport, no session establishment, no decryption, no holder side. It takes
//! the plaintext `DeviceResponse` your reader or OpenID4VP layer produces. Anything
//! that touches BLE or NFC is out of scope. The only network access is the CRL fetch
//! in [`revocation`], and only when you call it.
//!
//! # Failure model
//!
//! Anything that means "these bytes are not what the issuer signed" is an
//! [`MdlError`], not a flag: [`MdlError::Tampered`] for a bad signature or a digest
//! mismatch, [`MdlError::DeviceAuth`] for a failed device signature. There is no way
//! to get element values out of this crate without that having passed.
//!
//! Judgements a caller can reasonably disagree about stay as fields:
//! [`MdlDocument::issuer_trusted`] (did the Document Signer chain to an anchor you
//! supplied) and [`MsoValidity::in_window`] (was the credential inside its validity
//! window). [`MdlDocument::is_authentic`] bundles them.
//!
//! # Selective disclosure
//!
//! An mDL discloses only what was asked for — `age_over_21` and `portrait` with no
//! `birth_date` is a normal, fully-valid response. [`MdlDocument::namespaces`]
//! contains exactly what was disclosed; the accessors return `Option`. The MSO
//! legitimately holds digests for undisclosed elements and for decoys, so a missing
//! element is never an error.
//!
//! # Status
//!
//! `0.0.0`, unpublished. The crate depends on [`isomdl`] by git revision because the
//! released 0.2.0 never binds disclosed elements to the MSO digests and never checks
//! the MSO validity window — a holder could disclose arbitrary values under a genuine
//! issuer signature. Both are fixed upstream (spruceid/isomdl#132, #133) but
//! unreleased, and a crate with a git dependency cannot be published. See `PLAN.md`
//! at the workspace root.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod anchor;
mod block_on;
mod device;
mod error;
mod issuer;
mod transcript;
mod value;

pub mod revocation;

pub use anchor::{IacaAnchor, TrustRules};
pub use device::{verify_device_auth, verify_presentation};
pub use error::MdlError;
pub use issuer::{
    verify_issuer_auth, verify_issuer_auth_with, MdlDocument, MdlVerification, MsoValidity,
    VerifyOptions,
};
pub use transcript::SessionTranscript;
pub use value::MdlValue;

/// Re-exported so callers can build a handover for [`SessionTranscript::from_parts`]
/// without pinning the CBOR crate version themselves.
pub use ciborium;

/// The mDL document type.
pub const MDL_DOC_TYPE: &str = "org.iso.18013.5.1.mDL";

/// The mDL data namespace — `family_name`, `birth_date`, `portrait`, `age_over_NN`, …
pub const ISO_NAMESPACE: &str = "org.iso.18013.5.1";

/// The AAMVA namespace US and Canadian issuers add alongside the ISO one —
/// `domestic_driving_privileges`, `organ_donor`, `veteran`, …
pub const AAMVA_NAMESPACE: &str = "org.iso.18013.5.1.aamva";
