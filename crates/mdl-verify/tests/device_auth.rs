//! Phase 2 — device authentication.

mod common;

use common::{iaca_anchor, test_time, transcript, DeviceAuthKind, ResponseBuilder};
use mdl_verify::{
    verify_device_auth, verify_presentation, MdlError, SessionTranscript, VerifyOptions,
};

fn options() -> VerifyOptions {
    VerifyOptions {
        at: Some(test_time()),
        ..Default::default()
    }
}

#[test]
fn a_live_presentation_proves_holder_possession() {
    let session = transcript("nonce-from-the-verifier");
    let response = ResponseBuilder::default()
        .transcript(session.clone())
        .build();

    let verification = verify_presentation(&response, &[iaca_anchor()], &session, None, &options())
        .expect("both layers verify");

    let mdl = verification.mdl().expect("mDL");
    assert!(mdl.is_authentic());
    assert!(mdl.device_authenticated);
}

#[test]
fn device_auth_alone_verifies_against_the_right_transcript() {
    let session = transcript("nonce-from-the-verifier");
    let response = ResponseBuilder::default()
        .transcript(session.clone())
        .build();

    verify_device_auth(&response, &session, None).expect("device signature verifies");
}

/// The replay case: a genuine, issuer-signed response captured from one session and
/// presented in another. Issuer authentication cannot tell the difference — device
/// authentication is the only thing that can.
#[test]
fn a_response_replayed_into_another_session_fails_device_auth() {
    let recorded = transcript("nonce-from-the-original-session");
    let response = ResponseBuilder::default().transcript(recorded).build();

    // Issuer data authentication is perfectly happy with a replay.
    let verification = mdl_verify::verify_issuer_auth_with(&response, &[iaca_anchor()], &options())
        .expect("issuer auth passes");
    assert!(verification.mdl().unwrap().is_authentic());

    // Our session used a different nonce, so the device signature does not verify.
    let ours = transcript("nonce-from-our-session");
    let result = verify_device_auth(&response, &ours, None);
    assert!(
        matches!(result, Err(MdlError::DeviceAuth(_))),
        "a replayed response must fail device authentication: {result:?}"
    );

    let result = verify_presentation(&response, &[iaca_anchor()], &ours, None, &options());
    assert!(matches!(result, Err(MdlError::DeviceAuth(_))), "{result:?}");
}

/// `DeviceMac` derives its key by ECDH with the reader's ephemeral key. Without that
/// key the honest answer is "I cannot check this", not "invalid".
#[test]
fn a_maced_response_without_the_reader_key_is_refused_not_failed() {
    let session = transcript("nonce-from-the-verifier");
    let response = ResponseBuilder::default()
        .transcript(session.clone())
        .device_auth(DeviceAuthKind::UnverifiableMac)
        .build();

    let result = verify_device_auth(&response, &session, None);
    assert!(
        matches!(result, Err(MdlError::EReaderKeyRequired)),
        "{result:?}"
    );
}

#[test]
fn a_transcript_round_trips_through_its_encoding() {
    let session = transcript("nonce");
    let reparsed = SessionTranscript::from_cbor(session.as_bytes()).expect("round trips");
    assert_eq!(session, reparsed);
}

/// A transcript we cannot re-encode byte-for-byte would silently verify against
/// something the holder never signed, so it is rejected outright.
#[test]
fn a_non_deterministically_encoded_transcript_is_rejected() {
    // An indefinite-length array holding [null, null, []] — valid CBOR, not the
    // deterministic encoding ISO 18013-5 §9.1.5 requires.
    let indefinite = [0x9f, 0xf6, 0xf6, 0x80, 0xff];

    let result = SessionTranscript::from_cbor(&indefinite);
    assert!(
        matches!(result, Err(MdlError::NonCanonicalTranscript)),
        "{result:?}"
    );
}

#[test]
fn the_dcapi_handover_shape_is_accepted() {
    let session =
        SessionTranscript::openid4vp_dcapi_handover(&[0x11; 32]).expect("build DC API transcript");
    let response = ResponseBuilder::default()
        .transcript(session.clone())
        .build();

    verify_device_auth(&response, &session, None).expect("verifies against a DC API transcript");
}
