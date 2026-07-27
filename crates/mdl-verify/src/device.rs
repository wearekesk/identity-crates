//! Phase 2 — device authentication.
//!
//! Issuer data authentication proves the *data* is genuine. It does not prove the
//! *holder* is there: a `DeviceResponse` captured off the wire and replayed passes
//! issuer authentication perfectly. Device authentication closes that gap by binding
//! the response to a session transcript the verifier contributed randomness to, signed
//! (or MACed) with the device key the issuer committed to in the MSO.
//!
//! This only means anything inside a real presentation exchange — you need the
//! transcript. Hence the separate entry point.

use isomdl::cbor;
use isomdl::definitions::device_response::DeviceResponse;
use isomdl::definitions::device_signed::DeviceAuth;
use isomdl::definitions::x509::revocation::RevocationFetcher;
use isomdl::presentation::authentication::mdoc::device_authentication;

use crate::issuer::{verify_documents, verify_documents_with, MdlVerification, VerifyOptions};
use crate::{IacaAnchor, MdlError, SessionTranscript};

/// Unused on the `DeviceSignature` path, where no ECDH happens. Upstream takes the
/// key unconditionally; we only reach that call with a real key when the document is
/// MACed (see [`MdlError::EReaderKeyRequired`]).
const NO_READER_KEY: [u8; 32] = [0u8; 32];

/// Verify device authentication for every document in a `DeviceResponse`.
///
/// `e_reader_key_private` is the reader's ephemeral P-256 private key from this
/// session. It is only needed for documents authenticated with `COSE_Mac0`, where the
/// MAC key comes from ECDH between the mdoc authentication key and the reader key —
/// pass `None` if you know the holder signs (`COSE_Sign1`), and you will get
/// [`MdlError::EReaderKeyRequired`] rather than a wrong answer if you were wrong.
///
/// This checks holder presence only. Run [`crate::verify_issuer_auth`] as well — or
/// use [`verify_presentation`], which does both — because a device signature over
/// data no issuer vouched for proves nothing worth having.
pub fn verify_device_auth(
    device_response: &[u8],
    transcript: &SessionTranscript,
    e_reader_key_private: Option<&[u8; 32]>,
) -> Result<(), MdlError> {
    let response: DeviceResponse = cbor::from_slice(device_response)
        .map_err(|e| MdlError::Unreadable(format!("could not decode a DeviceResponse: {e}")))?;

    verify_response_device_auth(&response, transcript, e_reader_key_private)
}

/// Verify both layers: issuer data authentication *and* device authentication.
///
/// This is what a live presentation should call. Every document in the returned
/// [`MdlVerification`] has `device_authenticated = true`, because a failure on either
/// layer is an error rather than a flag.
pub fn verify_presentation(
    device_response: &[u8],
    anchors: &[IacaAnchor],
    transcript: &SessionTranscript,
    e_reader_key_private: Option<&[u8; 32]>,
    options: &VerifyOptions,
) -> Result<MdlVerification, MdlError> {
    let response: DeviceResponse = cbor::from_slice(device_response)
        .map_err(|e| MdlError::Unreadable(format!("could not decode a DeviceResponse: {e}")))?;

    let mut verification = verify_documents(&response, anchors, options)?;
    verify_response_device_auth(&response, transcript, e_reader_key_private)?;

    for document in &mut verification.documents {
        document.device_authenticated = true;
    }

    Ok(verification)
}

/// Verify a presentation against several candidate transcripts, using whichever one
/// the holder actually signed over.
///
/// The online mDL profiles disagree about how the handover is built — ISO/IEC 18013-7
/// Annex B, OpenID4VP 1.0, and the Digital Credentials API each specify a different
/// shape, and which one a wallet emits depends on the wallet. Rather than making that
/// a deployment question you answer wrongly once and debug for a day, hand in the
/// candidates and find out.
///
/// Returns the verification and the index of the transcript that matched.
///
/// This does not weaken anything. Every candidate is built by *you* from the same
/// session inputs — your nonce, your `client_id`, your `response_uri` — so trying
/// several is a question about encoding, not about trust. The holder still has to have
/// signed one of them with the device key the issuer bound into the MSO. What it costs
/// is a signature check per candidate.
///
/// Log which index matched: after a day of real traffic you will know what your
/// wallets emit, and can narrow it.
pub fn verify_presentation_any(
    device_response: &[u8],
    anchors: &[IacaAnchor],
    transcripts: &[SessionTranscript],
    e_reader_key_private: Option<&[u8; 32]>,
    options: &VerifyOptions,
) -> Result<(MdlVerification, usize), MdlError> {
    crate::block_on::try_block_on(verify_presentation_any_with(
        device_response,
        anchors,
        transcripts,
        e_reader_key_private,
        options,
        &(),
    ))
    .ok_or(MdlError::ValidationDidNotComplete)?
}

pub(crate) async fn verify_presentation_any_with<R: RevocationFetcher>(
    device_response: &[u8],
    anchors: &[IacaAnchor],
    transcripts: &[SessionTranscript],
    e_reader_key_private: Option<&[u8; 32]>,
    options: &VerifyOptions,
    revocation_fetcher: &R,
) -> Result<(MdlVerification, usize), MdlError> {
    if transcripts.is_empty() {
        return Err(MdlError::DeviceAuth(
            "no candidate session transcripts were supplied".to_string(),
        ));
    }

    let response: DeviceResponse = cbor::from_slice(device_response)
        .map_err(|e| MdlError::Unreadable(format!("could not decode a DeviceResponse: {e}")))?;

    // Issuer authentication first, and only once: it does not depend on the transcript,
    // and a document that is not issuer-authentic should fail as that rather than as a
    // device-authentication problem.
    let mut verification =
        verify_documents_with(&response, anchors, options, revocation_fetcher).await?;

    // Ask about the reader key before trying anything. A `DeviceMac` document cannot be
    // checked without it whichever transcript is used, and finding that out only after
    // every candidate has failed would report a capability gap as a handover mismatch.
    if e_reader_key_private.is_none() {
        let documents = response.documents.as_ref().ok_or(MdlError::NoDocuments)?;
        if documents
            .iter()
            .any(|d| matches!(d.device_signed.device_auth, DeviceAuth::DeviceMac(_)))
        {
            return Err(MdlError::EReaderKeyRequired);
        }
    }

    let mut last = None;
    for (index, transcript) in transcripts.iter().enumerate() {
        match verify_response_device_auth(&response, transcript, e_reader_key_private) {
            Ok(()) => {
                for document in &mut verification.documents {
                    document.device_authenticated = true;
                }
                return Ok((verification, index));
            }
            Err(e @ MdlError::EReaderKeyRequired) => return Err(e),
            Err(e) => last = Some(e),
        }
    }

    Err(MdlError::DeviceAuth(format!(
        "none of the {} candidate transcripts matched the holder's signature; \
         the last attempt said: {}",
        transcripts.len(),
        last.map(|e| e.to_string()).unwrap_or_default()
    )))
}

pub(crate) fn verify_response_device_auth(
    response: &DeviceResponse,
    transcript: &SessionTranscript,
    e_reader_key_private: Option<&[u8; 32]>,
) -> Result<(), MdlError> {
    let documents = response.documents.as_ref().ok_or(MdlError::NoDocuments)?;

    for document in documents.iter() {
        let is_maced = matches!(document.device_signed.device_auth, DeviceAuth::DeviceMac(_));

        let reader_key = match (is_maced, e_reader_key_private) {
            (true, None) => return Err(MdlError::EReaderKeyRequired),
            (_, Some(key)) => *key,
            (false, None) => NO_READER_KEY,
        };

        device_authentication(document, transcript.clone(), &reader_key)
            .map_err(|e| MdlError::DeviceAuth(e.to_string()))?;
    }

    Ok(())
}
