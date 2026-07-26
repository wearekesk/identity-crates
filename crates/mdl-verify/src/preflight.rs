//! Ask whether this crate can verify something, before you promise that it can.
//!
//! ISO/IEC 18013-5 permits several signature algorithms for the Document Signer;
//! this crate verifies ECDSA over P-256 and P-384. Every deployment in the wild uses
//! P-256 — AAMVA in practice, and the EUDI ARF mandates ES256 as its floor — so the
//! gap is theoretical. It is still better to find out from a sample response than
//! from a failed integration.
//!
//! ```no_run
//! use mdl_verify::preflight;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let sample_response: &[u8] = &[];
//! for key in preflight::response_signer_keys(sample_response)? {
//!     println!("{}: {}", key.algorithm, if key.verifiable { "ok" } else { "NOT SUPPORTED" });
//! }
//! # Ok(()) }
//! ```
//!
//! Nothing here verifies anything — it reads the public key algorithm out of a
//! certificate and reports it. A `verifiable: true` says the algorithm is one we
//! implement, not that any particular signature is good.

use isomdl::cbor;
use isomdl::definitions::device_response::DeviceResponse;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, DecodePem};
use x509_cert::Certificate;

use crate::MdlError;

/// What a certificate's public key is, and whether this crate can verify with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerKey {
    /// A familiar name where we recognise the algorithm — `"P-256"`, `"Ed25519"`,
    /// `"brainpoolP256r1"` — otherwise the bare OID.
    pub algorithm: String,
    /// Whether [`crate::verify_issuer_auth`] can check a signature made with this key.
    ///
    /// When this is `false`, verification returns
    /// [`MdlError::UnsupportedAlgorithm`](crate::MdlError::UnsupportedAlgorithm) —
    /// a refusal to answer, never a pass.
    pub verifiable: bool,
}

/// id-ecPublicKey: the key is an EC point and the curve is in the parameters.
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// Curves and key algorithms worth naming. Anything absent is reported by OID, which
/// is more useful than "unknown" when you are about to go and look it up.
const NAMED: &[(&str, &str, bool)] = &[
    // (OID, name, can this crate verify with it)
    ("1.2.840.10045.3.1.7", "P-256", true),
    ("1.3.132.0.34", "P-384", true),
    ("1.3.132.0.35", "P-521", false),
    ("1.3.101.112", "Ed25519", false),
    ("1.3.101.113", "Ed448", false),
    ("1.2.840.113549.1.1.1", "RSA", false),
    ("1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1", false),
    ("1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1", false),
    ("1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1", false),
];

impl SignerKey {
    pub(crate) fn of(certificate: &Certificate) -> Self {
        let spki = &certificate.tbs_certificate.subject_public_key_info;
        let algorithm = spki.algorithm.oid.to_string();

        // For an EC key the algorithm OID is the same for every curve; which curve it
        // is lives in the parameters. For Ed25519 and friends there are no
        // parameters at all, and the algorithm OID is the answer.
        let oid = if algorithm == ID_EC_PUBLIC_KEY {
            spki.algorithm
                .parameters
                .as_ref()
                .and_then(|params| params.decode_as::<ObjectIdentifier>().ok())
                .map(|curve| curve.to_string())
                .unwrap_or(algorithm)
        } else {
            algorithm
        };

        match NAMED.iter().find(|(known, _, _)| *known == oid) {
            Some((_, name, verifiable)) => Self {
                algorithm: (*name).to_string(),
                verifiable: *verifiable,
            },
            None => Self {
                algorithm: oid,
                verifiable: false,
            },
        }
    }
}

/// Read the key algorithm out of a DER-encoded certificate.
pub fn certificate_signer_key(der: &[u8]) -> Result<SignerKey, MdlError> {
    Certificate::from_der(der)
        .map(|certificate| SignerKey::of(&certificate))
        .map_err(|e| MdlError::Unreadable(format!("could not parse the certificate: {e}")))
}

/// Read the key algorithm out of a PEM-encoded certificate.
pub fn certificate_signer_key_pem(pem: &str) -> Result<SignerKey, MdlError> {
    Certificate::from_pem(pem)
        .map(|certificate| SignerKey::of(&certificate))
        .map_err(|e| MdlError::Unreadable(format!("could not parse the certificate: {e}")))
}

/// Read the key algorithm of every Document Signer in a `DeviceResponse`, in document
/// order.
///
/// The quickest way to answer "will this work against their issuer?" from a sample
/// presentation, without needing their PKI documentation.
pub fn response_signer_keys(device_response: &[u8]) -> Result<Vec<SignerKey>, MdlError> {
    let response: DeviceResponse = cbor::from_slice(device_response)
        .map_err(|e| MdlError::Unreadable(format!("could not decode a DeviceResponse: {e}")))?;

    let documents = response.documents.as_ref().ok_or(MdlError::NoDocuments)?;

    documents
        .iter()
        .map(|document| {
            let x5chain = crate::issuer::x5chain(document)?;
            Ok(SignerKey::of(x5chain.end_entity_certificate()))
        })
        .collect()
}
