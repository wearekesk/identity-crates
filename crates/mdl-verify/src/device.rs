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
use isomdl::presentation::authentication::mdoc::device_authentication;

use crate::issuer::{verify_documents, MdlVerification, VerifyOptions};
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
