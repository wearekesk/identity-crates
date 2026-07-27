//! One identity-verification API over ePassport chips and mobile driving licences,
//! shaped for Android, iOS and Flutter.
//!
//! Two very different documents — an ICAO 9303 chip read over NFC, an ISO/IEC 18013-5
//! credential presented from a wallet — come back as the same
//! [`VerifiedIdentity`], so an app that accepts both has one code path and one result
//! to reason about.
//!
//! ```no_run
//! use identity_mobile::{mdl, passport, VerifiedIdentity};
//!
//! # fn example(response: &[u8], iaca: Vec<u8>, files: passport::PassportFiles, csca: Vec<u8>)
//! #     -> Result<(), Box<dyn std::error::Error>> {
//! // From a wallet:
//! let identity: VerifiedIdentity = mdl::verify_mdl(response, &[iaca], None)?;
//!
//! // From a passport chip, already read:
//! let identity: VerifiedIdentity = passport::verify_passport(&files, &[csca])?;
//!
//! if identity.authenticity.is_trustworthy() {
//!     println!("{}", identity.display_name().unwrap_or_default());
//! }
//! # Ok(()) }
//! ```
//!
//! # What the same shape does and does not mean
//!
//! The two documents prove different things, and [`Authenticity`] keeps that visible
//! rather than flattening it into one boolean:
//!
//! | | Passport chip | mDL |
//! |---|---|---|
//! | `data_authentic` | data group hashes match EF.SOD | MSO signature + element digests |
//! | `issuer_trusted` | Document Signer chains to a CSCA you supplied | chains to an IACA you supplied |
//! | `holder_bound` | chip active authentication — not a clone | device authentication — not a replay |
//!
//! `holder_bound` is `None` when it was not attempted, which is not `Some(false)`.
//! [`Authenticity::is_trustworthy`] deliberately excludes it; use
//! [`Authenticity::is_present_and_trustworthy`] when you are checking a document in
//! person and a copy would not do.
//!
//! # NFC comes from the platform
//!
//! This crate contains no transport. Passport reads drive the chip through
//! [`passport::ApduChannel`], which you implement over `IsoDep` on Android or
//! `NFCISO7816Tag` on iOS; mDL presentations arrive already decrypted from your
//! proximity or OpenID4VP layer. See `docs/flutter.md` for the wiring.
//!
//! # Mobile builds
//!
//! Nothing here compiles C. `mdl-verify` is depended on with `default-features =
//! false`, which keeps `ring` out of the graph, so an Android build needs no NDK —
//! `cargo check --target aarch64-linux-android` works with nothing but rustup. The
//! cost is that CRL revocation needs an HTTP client from you; see
//! [`mdl_verify::revocation`], re-exported below.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod error;
mod identity;

pub mod mdl;
pub mod passport;

pub use error::IdentityError;
pub use identity::{Authenticity, DocumentSource, VerifiedIdentity};

/// The mDL verification layer, for the parts this crate does not wrap — CRL
/// revocation with your own HTTP client, VICAL-sourced trust anchors, and the
/// `preflight` check for whether an issuer's algorithm is one we can verify.
pub use mdl_verify;

/// The eMRTD reader core, for reads this crate's high-level API does not cover —
/// individual data groups, EF.CardAccess, chip authentication.
pub use dmrtd;
