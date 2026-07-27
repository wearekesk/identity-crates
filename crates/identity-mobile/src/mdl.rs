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

    let (verification, matched) = match session {
        // A session with nothing in it is a caller mistake, and saying so beats letting
        // it arrive as "the holder did not prove possession of the device key" — which
        // is what it would look like coming back from `mdl-verify`.
        Some(session) if session.candidates.is_empty() => {
            return Err(IdentityError::Unreadable(
                "the session carried no candidate transcripts; pass None to skip device \
                 authentication deliberately"
                    .to_string(),
            ))
        }
        Some(session) => {
            let transcripts = session
                .candidates
                .iter()
                .map(|c| c.transcript.clone())
                .collect::<Vec<_>>();

            let (verification, index) = mdl_verify::verify_presentation_any(
                device_response,
                &anchors,
                &transcripts,
                session.e_reader_key.as_ref(),
                &options,
            )
            .map_err(map_error)?;

            // Reported so a deployment can find out what its wallets actually emit and
            // then stop offering the profiles they never use.
            let label = session.candidates[index].label.clone();
            (verification, Some(label))
        }
        None => (
            mdl_verify::verify_issuer_auth_with(device_response, &anchors, &options)
                .map_err(map_error)?,
            None,
        ),
    };

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

    Ok(identity(document, matched))
}

/// One way the session transcript might have been built, and the name to report it by.
///
/// The label exists because a bare index is useless in a log line six months later:
/// `openid4vp-1.0` tells you what your wallets actually do, which is the thing worth
/// knowing.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub label: String,
    pub transcript: SessionTranscript,
}

/// The session an mDL was presented in, which is what makes device authentication
/// possible.
///
/// Holds *candidates* rather than one transcript. Over OpenID4VP the verifier supplies
/// every input to the transcript — the nonce, the `client_id`, the `response_uri` — so
/// the only open question is which encoding the wallet used, and there are two live
/// profiles that answer it differently. Trying both is a question about encoding, not
/// about trust: the holder still has to have signed one of them with the device key the
/// issuer bound into the MSO.
pub struct Session {
    /// Tried in order; the first that device authentication accepts wins.
    pub candidates: Vec<Candidate>,
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
            .field(
                "candidates",
                &self.candidates.iter().map(|c| &c.label).collect::<Vec<_>>(),
            )
            .field(
                "e_reader_key",
                &self.e_reader_key.map(|_| "<redacted>").unwrap_or("None"),
            )
            .finish()
    }
}

impl Session {
    /// Adopt a CBOR-encoded transcript your session layer already built.
    pub fn from_cbor(
        transcript: &[u8],
        e_reader_key: Option<[u8; 32]>,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            candidates: vec![Candidate {
                label: "cbor".to_string(),
                transcript: SessionTranscript::from_cbor(transcript).map_err(map_error)?,
            }],
            e_reader_key,
        })
    }

    /// An empty session to add candidates to. Verifying with no candidates is an error,
    /// not a silent skip of device authentication — pass `None` for that.
    pub fn candidates(e_reader_key: Option<[u8; 32]>) -> Self {
        Self {
            candidates: Vec::new(),
            e_reader_key,
        }
    }

    /// The OpenID4VP 1.0 redirect handover (Appendix B.2.6.1).
    ///
    /// `jwk_thumbprint` is the RFC 7638 thumbprint of the key the response is encrypted
    /// to, and `None` when the response is not encrypted — the spec wants a CBOR `null`
    /// there, which an empty byte string is not.
    pub fn openid4vp_1_0(
        mut self,
        client_id: &str,
        nonce: &str,
        jwk_thumbprint: Option<&[u8]>,
        response_uri: &str,
    ) -> Result<Self, IdentityError> {
        self.candidates.push(Candidate {
            label: "openid4vp-1.0".to_string(),
            transcript: SessionTranscript::openid4vp_1_0(
                client_id,
                nonce,
                jwk_thumbprint,
                response_uri,
            )
            .map_err(map_error)?,
        });
        Ok(self)
    }

    /// The OpenID4VP 1.0 Digital Credentials API handover (Appendix B.2.6.2).
    ///
    /// `origin` carries no `origin:` prefix. Pass `None` for the thumbprint when the
    /// response mode is `dc_api` rather than `dc_api.jwt`.
    pub fn openid4vp_dcapi(
        mut self,
        origin: &str,
        nonce: &str,
        jwk_thumbprint: Option<&[u8]>,
    ) -> Result<Self, IdentityError> {
        self.candidates.push(Candidate {
            label: "openid4vp-dcapi".to_string(),
            transcript: SessionTranscript::openid4vp_dcapi(origin, nonce, jwk_thumbprint)
                .map_err(map_error)?,
        });
        Ok(self)
    }

    /// The older ISO/IEC 18013-7 Annex B handover, identifiable by its wallet-supplied
    /// `mdoc_generated_nonce`.
    ///
    /// Still worth offering as a candidate: wallets on the earlier draft are in the
    /// field, and they build the transcript from the same session inputs by a different
    /// route.
    pub fn openid4vp_iso_18013_7(
        mut self,
        client_id: &str,
        response_uri: &str,
        nonce: &str,
        mdoc_generated_nonce: &str,
    ) -> Result<Self, IdentityError> {
        self.candidates.push(Candidate {
            label: "iso-18013-7".to_string(),
            transcript: SessionTranscript::openid4vp_iso_18013_7(
                client_id,
                response_uri,
                nonce,
                mdoc_generated_nonce,
            )
            .map_err(map_error)?,
        });
        Ok(self)
    }
}

fn identity(document: &MdlDocument, session_profile: Option<String>) -> VerifiedIdentity {
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
            session_profile,
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
