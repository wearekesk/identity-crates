//! Mobile driving licences (ISO/IEC 18013-5), mapped to the same identity shape.
//!
//! A thin layer over [`mdl_verify`]. What it adds is the mapping: an mDL and a
//! passport come back as the same [`VerifiedIdentity`], so an app that accepts both
//! has one code path rather than two.

use mdl_verify::{IacaAnchor, MdlDocument, MdlError, SessionTranscript, VerifyOptions};

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

    let document = verification
        .mdl()
        .or_else(|| verification.documents.first())
        .ok_or_else(|| IdentityError::Unreadable("the response carried no documents".into()))?;

    Ok(identity(document))
}

/// The session an mDL was presented in, which is what makes device authentication
/// possible.
#[derive(Debug)]
pub struct Session {
    /// The `SessionTranscript` your session layer built.
    pub transcript: SessionTranscript,
    /// The reader's ephemeral private key from that session. Required when the holder
    /// authenticated with `DeviceMac` — without it the MAC key cannot be derived, and
    /// you get an error rather than a wrong answer.
    pub e_reader_key: Option<[u8; 32]>,
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
                // ISO/IEC 5218, which the mDL uses and the MRZ does not.
                1 => "M".to_string(),
                2 => "F".to_string(),
                other => other.to_string(),
            }),
        portrait: document.portrait().map(<[u8]>::to_vec),
        // The whole point of an mDL for an age check: the answer without the date.
        age_attestations: (13..=25)
            .chain([60, 62, 65, 68])
            .filter_map(|years| document.age_over(years).map(|answer| (years, answer)))
            .collect(),
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

fn map_error(error: MdlError) -> IdentityError {
    match error {
        MdlError::Tampered(why) => IdentityError::NotAuthentic(why),
        MdlError::DeviceAuth(why) => IdentityError::NotAuthentic(format!(
            "the holder did not prove possession of the device key: {why}"
        )),
        MdlError::UnsupportedAlgorithm(what) => IdentityError::UnsupportedAlgorithm(what),
        MdlError::Anchor(why) => IdentityError::Anchor(why),
        other => IdentityError::Unreadable(other.to_string()),
    }
}
