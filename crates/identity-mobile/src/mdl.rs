//! Mobile driving licences (ISO/IEC 18013-5), mapped to the same identity shape.
//!
//! A thin layer over [`mdl_verify`]. What it adds is the mapping: an mDL and a
//! passport come back as the same [`VerifiedIdentity`], so an app that accepts both
//! has one code path rather than two.

use mdl_verify::{
    IacaAnchor, MdlDocument, MdlError, SessionTranscript, VerifyOptions, ISO_NAMESPACE,
};

use crate::identity::{Authenticity, DocumentSource, VerifiedIdentity};
use crate::IdentityError;

/// Verify an mDL presentation.
///
/// `device_response` is the **decrypted** CBOR `DeviceResponse` — whatever your
/// proximity or OpenID4VP layer produced. `anchors` are DER-encoded IACA certificates.
///
/// Without a session transcript this is issuer data authentication only:
/// `holder_bound` comes back `None`, and a response captured once can be replayed
/// forever. Pass the transcript when you have one.
pub fn verify_mdl(
    device_response: &[u8],
    anchors: &[Vec<u8>],
    session: Option<&Session>,
) -> Result<VerifiedIdentity, IdentityError> {
    let anchors = anchors
        .iter()
        .map(|der| {
            IacaAnchor::from_certificate(der)
                .map_err(|e| IdentityError::Anchor(format!("IACA certificate: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let options = VerifyOptions::default();

    let verification = match session {
        Some(session) => mdl_verify::verify_presentation(
            device_response,
            &anchors,
            &session.transcript,
            session.e_reader_key.as_ref(),
            &options,
        ),
        None => mdl_verify::verify_issuer_auth_with(device_response, &anchors, &options),
    }
    .map_err(map_error)?;

    // Only an actual mDL. Falling back to "whatever document came first" would let a
    // photo ID be returned as a driving licence, which is precisely the confusion the
    // docType check inside `mdl-verify` exists to prevent.
    let document = verification.mdl().ok_or_else(|| {
        IdentityError::Unreadable(format!(
            "the response carried no mDL (found: {})",
            match verification.documents.len() {
                0 => "nothing".to_string(),
                _ => verification
                    .documents
                    .iter()
                    .map(|d| d.doc_type.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
            }
        ))
    })?;

    Ok(identity(document))
}

/// The session an mDL was presented in, which is what makes device authentication
/// possible.
pub struct Session {
    /// The `SessionTranscript` your session layer built.
    pub transcript: SessionTranscript,
    /// The reader's ephemeral private key from that session. Required when the holder
    /// authenticated with `DeviceMac` — without it the MAC key cannot be derived, and
    /// you get an error rather than a wrong answer.
    pub e_reader_key: Option<[u8; 32]>,
}

// Written by hand, not derived: `e_reader_key` is the reader's ephemeral private key,
// and a derived `Debug` would put every byte of it into any log line that formats a
// `Session`.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("transcript", &self.transcript)
            .field(
                "e_reader_key",
                &self.e_reader_key.map(|_| "<redacted>").unwrap_or("None"),
            )
            .finish()
    }
}

impl Session {
    /// Adopt a CBOR-encoded transcript.
    pub fn from_cbor(
        transcript: &[u8],
        e_reader_key: Option<[u8; 32]>,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            transcript: SessionTranscript::from_cbor(transcript).map_err(map_error)?,
            e_reader_key,
        })
    }
}

fn identity(document: &MdlDocument) -> VerifiedIdentity {
    let mut warnings = document.trust_errors.clone();
    warnings.extend(document.revocation_errors.iter().cloned());

    VerifiedIdentity {
        family_name: document.family_name().map(str::to_owned),
        given_name: document.given_name().map(str::to_owned),
        date_of_birth: document.birth_date().map(str::to_owned),
        date_of_expiry: document.expiry_date().map(str::to_owned),
        document_number: document.document_number().map(str::to_owned),
        nationality: document.issuing_country().map(str::to_owned),
        sex: document
            .iso("sex")
            .and_then(|v| v.as_int())
            .map(|code| match code {
                // ISO/IEC 5218, which the mDL uses and the MRZ does not. The MRZ
                // spells the unknown cases as `<`, so they normalise to empty here
                // rather than arriving as a bare number the caller has to decode.
                1 => "M".to_string(),
                2 => "F".to_string(),
                0 | 9 => String::new(),
                other => other.to_string(),
            }),
        portrait: document.portrait().map(<[u8]>::to_vec),
        // Read from what was disclosed rather than from a list of ages we thought to
        // ask about: `age_over_NN` is open-ended, and an issuer attesting age_over_30
        // should not have it silently dropped.
        age_attestations: age_attestations(document),
        source: Some(DocumentSource::MobileDrivingLicence {
            doc_type: document.doc_type.clone(),
            issuing_authority: document.issuing_authority().map(str::to_owned),
        }),
        authenticity: Authenticity {
            // An `MdlDocument` only exists for a document that passed issuer
            // authentication; failure is an error, not a flag.
            data_authentic: document.signature_verified,
            issuer_trusted: document.issuer_trusted,
            holder_bound: document.device_authenticated.then_some(true),
            not_expired: document.validity.in_window,
            warnings,
        },
    }
}

/// Every `age_over_NN` the document disclosed.
fn age_attestations(document: &MdlDocument) -> Vec<(u8, bool)> {
    let Some(namespace) = document.namespaces.get(ISO_NAMESPACE) else {
        return Vec::new();
    };

    let mut attestations: Vec<(u8, bool)> = namespace
        .iter()
        .filter_map(|(identifier, value)| {
            let years = identifier.strip_prefix("age_over_")?.parse().ok()?;
            Some((years, value.as_bool()?))
        })
        .collect();

    attestations.sort_unstable();
    attestations
}

fn map_error(error: MdlError) -> IdentityError {
    match error {
        MdlError::Tampered(why) => IdentityError::NotAuthentic(why),
        MdlError::DeviceAuth(why) => IdentityError::NotAuthentic(format!(
            "the holder did not prove possession of the device key: {why}"
        )),
        MdlError::UnsupportedAlgorithm(what) => IdentityError::UnsupportedAlgorithm(what),
        MdlError::EReaderKeyRequired => IdentityError::SessionKeyRequired,
        MdlError::Anchor(why) => IdentityError::Anchor(why),
        other => IdentityError::Unreadable(other.to_string()),
    }
}
