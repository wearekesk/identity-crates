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

/// The Annex B handover, built from the values a verifier actually holds. The point of
/// the constructor is that the hashing — SHA-256 over a CBOR pair, not a concatenation
/// — lives in one place rather than in every backend.
#[test]
fn the_18013_7_handover_is_built_from_its_inputs() {
    let built = SessionTranscript::openid4vp_iso_18013_7(
        "https://verifier.example/cb",
        "https://verifier.example/response",
        "verifier-nonce",
        "wallet-nonce",
    )
    .expect("builds");

    // The same thing, hashed by hand, as a backend would have had to do.
    let hash = |value: &str| {
        use sha2::{Digest, Sha256};
        let pair = ciborium::Value::Array(vec![
            ciborium::Value::Text(value.to_string()),
            ciborium::Value::Text("wallet-nonce".to_string()),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&pair, &mut encoded).unwrap();
        Sha256::digest(&encoded).to_vec()
    };

    let expected = SessionTranscript::openid4vp_handover(
        &hash("https://verifier.example/cb"),
        &hash("https://verifier.example/response"),
        "verifier-nonce",
    )
    .expect("builds");

    assert_eq!(built, expected);
}

/// Changing any input changes the transcript, which is what binds the response to
/// this session and no other.
#[test]
fn every_handover_input_is_bound() {
    let base = SessionTranscript::openid4vp_iso_18013_7("a", "b", "c", "d").unwrap();

    for other in [
        SessionTranscript::openid4vp_iso_18013_7("z", "b", "c", "d").unwrap(),
        SessionTranscript::openid4vp_iso_18013_7("a", "z", "c", "d").unwrap(),
        SessionTranscript::openid4vp_iso_18013_7("a", "b", "z", "d").unwrap(),
        // The wallet's own nonce matters too: it is inside both hashes.
        SessionTranscript::openid4vp_iso_18013_7("a", "b", "c", "z").unwrap(),
    ] {
        assert_ne!(base, other);
    }
}

#[test]
fn the_dcapi_handover_is_built_from_its_inputs() {
    let built =
        SessionTranscript::openid4vp_dcapi("https://verifier.example", "nonce", &[0xAB; 32])
            .expect("builds");

    // The preimage the DC API profile specifies: SHA-256 over CBOR
    // `[origin, nonce, jwk_thumbprint]`.
    let expected = {
        use sha2::{Digest, Sha256};
        let info = ciborium::Value::Array(vec![
            ciborium::Value::Text("https://verifier.example".to_string()),
            ciborium::Value::Text("nonce".to_string()),
            ciborium::Value::Bytes(vec![0xAB; 32]),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&info, &mut encoded).unwrap();
        SessionTranscript::openid4vp_dcapi_handover(&Sha256::digest(&encoded)).unwrap()
    };

    assert_eq!(built, expected);

    // All three inputs are bound, not just the origin.
    for other in [
        SessionTranscript::openid4vp_dcapi("https://other.example", "nonce", &[0xAB; 32]).unwrap(),
        SessionTranscript::openid4vp_dcapi("https://verifier.example", "other", &[0xAB; 32])
            .unwrap(),
        SessionTranscript::openid4vp_dcapi("https://verifier.example", "nonce", &[0xCD; 32])
            .unwrap(),
    ] {
        assert_ne!(built, other);
    }
}

/// The question a verifier should not have to answer in advance: which profile is this
/// wallet on? Hand in the candidates and be told.
///
/// The wallet here signs over a transcript built by the **Annex B constructor**, so a
/// regression in its hashing fails here rather than being masked by a hand-built
/// transcript that happens to match.
#[test]
fn a_presentation_verifies_against_the_annex_b_candidate() {
    let signed = SessionTranscript::openid4vp_iso_18013_7(
        "https://verifier.example/client",
        "https://verifier.example/response",
        "verifier-nonce",
        "wallet-nonce",
    )
    .expect("builds");

    let response = ResponseBuilder::default()
        .transcript(signed.clone())
        .build();

    let candidates = [
        // A plausible-but-wrong shape first, as a real deployment would have.
        SessionTranscript::openid4vp_dcapi("https://verifier.example", "verifier-nonce", &[0; 32])
            .expect("builds"),
        signed,
    ];

    let (verification, matched) = mdl_verify::verify_presentation_any(
        &response,
        &[iaca_anchor()],
        &candidates,
        None,
        &options(),
    )
    .expect("one candidate matches");

    assert_eq!(matched, 1, "and it says which");
    assert!(verification.mdl().unwrap().device_authenticated);
}

/// The mirror case, so neither constructor is only ever exercised as the *wrong*
/// candidate.
#[test]
fn a_presentation_verifies_against_the_dcapi_candidate() {
    let signed = SessionTranscript::openid4vp_dcapi("https://verifier.example", "nonce", &[7; 32])
        .expect("builds");

    let response = ResponseBuilder::default()
        .transcript(signed.clone())
        .build();

    let candidates = [
        SessionTranscript::openid4vp_iso_18013_7("client", "uri", "nonce", "wallet").unwrap(),
        signed,
    ];

    let (_, matched) = mdl_verify::verify_presentation_any(
        &response,
        &[iaca_anchor()],
        &candidates,
        None,
        &options(),
    )
    .expect("one candidate matches");

    assert_eq!(matched, 1);
}

/// A `DeviceMac` document without the reader key is a caller mistake, and has to be
/// named as one before the candidates are tried — otherwise it surfaces as "none of
/// your transcripts matched", which sends the reader looking in the wrong place.
#[test]
fn a_missing_reader_key_is_named_before_candidates_are_tried() {
    let response = ResponseBuilder::default()
        .device_auth(DeviceAuthKind::UnverifiableMac)
        .build();

    let result = mdl_verify::verify_presentation_any(
        &response,
        &[iaca_anchor()],
        &[transcript("a"), transcript("b")],
        None,
        &options(),
    );

    assert!(
        matches!(result, Err(MdlError::EReaderKeyRequired)),
        "{result:?}"
    );
}

/// Trying several candidates must not become a way to pass without matching any.
#[test]
fn no_matching_candidate_is_still_a_failure() {
    let response = ResponseBuilder::default()
        .transcript(transcript("what-the-wallet-signed"))
        .build();

    let wrong = [
        transcript("not-this-one"),
        SessionTranscript::openid4vp_iso_18013_7("a", "b", "c", "d").unwrap(),
    ];

    let result =
        mdl_verify::verify_presentation_any(&response, &[iaca_anchor()], &wrong, None, &options());

    assert!(matches!(result, Err(MdlError::DeviceAuth(_))), "{result:?}");
}

#[test]
fn no_candidates_at_all_is_refused() {
    let response = ResponseBuilder::default().build();

    let result =
        mdl_verify::verify_presentation_any(&response, &[iaca_anchor()], &[], None, &options());

    assert!(matches!(result, Err(MdlError::DeviceAuth(_))), "{result:?}");
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
