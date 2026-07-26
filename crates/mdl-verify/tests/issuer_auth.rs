//! Phase 1 — issuer data authentication.

mod common;

use common::{
    age_only_elements, encode, iaca_anchor, test_time, unrelated_anchor, ResponseBuilder, Validity,
};
use isomdl::definitions::helpers::{NonEmptyMap, NonEmptyVec, Tag24};
use isomdl::definitions::issuer_signed::IssuerSignedItemBytes;
use mdl_verify::{
    verify_issuer_auth, verify_issuer_auth_with, IacaAnchor, MdlError, TrustRules, VerifyOptions,
};

fn options() -> VerifyOptions {
    VerifyOptions {
        at: Some(test_time()),
        ..Default::default()
    }
}

#[test]
fn genuine_response_chains_to_its_iaca_and_is_authentic() {
    let response = ResponseBuilder::default().build();
    let anchors = [iaca_anchor()];

    let verification = verify_issuer_auth_with(&response, &anchors, &options()).expect("verifies");
    let mdl = verification.mdl().expect("response carries an mDL");

    assert!(mdl.signature_verified);
    assert!(
        mdl.issuer_trusted,
        "chain should validate against its own IACA: {:?}",
        mdl.trust_errors
    );
    assert!(mdl.validity.in_window);
    assert!(mdl.is_authentic());
    assert!(verification.all_authentic());

    // Device authentication is a separate layer; the static path cannot establish it.
    assert!(!mdl.device_authenticated);
}

#[test]
fn discloses_the_elements_the_issuer_signed() {
    let response = ResponseBuilder::default().build();
    let anchors = [iaca_anchor()];

    let verification = verify_issuer_auth_with(&response, &anchors, &options()).expect("verifies");
    let mdl = verification.mdl().expect("mDL");

    assert_eq!(mdl.family_name(), Some("Sharma"));
    assert_eq!(mdl.given_name(), Some("Priya"));
    assert_eq!(mdl.birth_date(), Some("1988-03-14"));
    assert_eq!(mdl.expiry_date(), Some("2030-01-01"));
    assert_eq!(mdl.document_number(), Some("NY-1234567"));
    assert_eq!(mdl.issuing_country(), Some("US"));
    assert_eq!(mdl.age_over(21), Some(true));
    assert_eq!(
        mdl.portrait(),
        Some(&[0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10][..])
    );

    let privileges = mdl.driving_privileges().expect("driving_privileges");
    assert_eq!(
        privileges[0]
            .as_map()
            .and_then(|m| m.get("vehicle_category_code"))
            .and_then(|v| v.as_text()),
        Some("B")
    );
}

/// The attack the crates.io release of the underlying library is vulnerable to: keep
/// the genuine issuer signature, change what is disclosed under it.
#[test]
fn tampered_element_is_rejected() {
    let mut response = ResponseBuilder::default().build_response();

    let document = &mut response
        .documents
        .as_mut()
        .unwrap()
        .iter_mut()
        .next()
        .unwrap();
    let namespaces = document.issuer_signed.namespaces.take().unwrap();

    let mut by_namespace = namespaces.into_inner();
    let items = by_namespace.get_mut(mdl_verify::ISO_NAMESPACE).unwrap();
    let tampered: Vec<IssuerSignedItemBytes> = items
        .clone()
        .into_inner()
        .into_iter()
        .map(|item_bytes| {
            let mut item = item_bytes.as_ref().clone();
            if item.element_identifier == "age_over_21" {
                // Flip the answer, leave the issuer's signature alone.
                item.element_value = ciborium::Value::Bool(false);
                return Tag24::new(item).unwrap();
            }
            item_bytes
        })
        .collect();
    *items = NonEmptyVec::maybe_new(tampered).unwrap();
    document.issuer_signed.namespaces = Some(NonEmptyMap::maybe_new(by_namespace).unwrap());

    let anchors = [iaca_anchor()];
    let result = verify_issuer_auth_with(&encode(&response), &anchors, &options());

    assert!(
        matches!(result, Err(MdlError::Tampered(_))),
        "a flipped age_over_21 must not verify: {result:?}"
    );
}

/// A holder presenting a genuine MSO for one document type under another.
#[test]
fn doc_type_mismatch_is_rejected() {
    let mut response = ResponseBuilder::default().build_response();
    response
        .documents
        .as_mut()
        .unwrap()
        .iter_mut()
        .next()
        .unwrap()
        .doc_type = "org.iso.23220.photoid.1".to_string();

    let anchors = [iaca_anchor()];
    let result = verify_issuer_auth_with(&encode(&response), &anchors, &options());

    assert!(
        matches!(result, Err(MdlError::Tampered(_))),
        "docType must match the one the issuer signed: {result:?}"
    );
}

#[test]
fn without_anchors_the_data_still_verifies_but_is_not_trusted() {
    let response = ResponseBuilder::default().build();

    let verification = verify_issuer_auth_with(&response, &[], &options()).expect("verifies");
    let mdl = verification.mdl().expect("mDL");

    assert!(mdl.signature_verified);
    assert!(!mdl.issuer_trusted);
    assert!(!mdl.is_authentic());
    assert_eq!(mdl.trust_errors.len(), 1);
    // The data is readable — it is genuine, it is just not attributable to an issuer
    // the caller told us to trust.
    assert_eq!(mdl.family_name(), Some("Sharma"));
}

#[test]
fn an_unrelated_iaca_does_not_confer_trust() {
    let response = ResponseBuilder::default().build();
    let anchors = [unrelated_anchor()];

    let verification = verify_issuer_auth_with(&response, &anchors, &options()).expect("verifies");
    let mdl = verification.mdl().expect("mDL");

    assert!(!mdl.issuer_trusted);
    assert!(!mdl.trust_errors.is_empty());
}

#[test]
fn the_aamva_profile_also_accepts_a_conforming_chain() {
    let response = ResponseBuilder::default().build();
    let anchors = [iaca_anchor()];

    let verification = verify_issuer_auth_with(
        &response,
        &anchors,
        &VerifyOptions {
            at: Some(test_time()),
            rules: TrustRules::Aamva,
        },
    )
    .expect("verifies");

    let mdl = verification.mdl().expect("mDL");
    assert!(
        mdl.issuer_trusted,
        "AAMVA rules add a state-name comparison the fixtures satisfy: {:?}",
        mdl.trust_errors
    );
}

#[test]
fn an_expired_credential_verifies_but_is_out_of_window() {
    let response = ResponseBuilder::default()
        .validity(Validity::Expired)
        .build();
    let anchors = [iaca_anchor()];

    let verification = verify_issuer_auth_with(&response, &anchors, &options()).expect("verifies");
    let mdl = verification.mdl().expect("mDL");

    assert!(mdl.signature_verified);
    assert!(!mdl.validity.in_window);
    assert!(!mdl.is_authentic());
    assert!(mdl.validity.valid_until < test_time());
}

#[test]
fn a_not_yet_valid_credential_is_out_of_window() {
    let response = ResponseBuilder::default()
        .validity(Validity::NotYetValid)
        .build();
    let anchors = [iaca_anchor()];

    let verification = verify_issuer_auth_with(&response, &anchors, &options()).expect("verifies");
    let mdl = verification.mdl().expect("mDL");

    assert!(!mdl.validity.in_window);
    assert!(mdl.validity.valid_from > test_time());
}

/// Selective disclosure: the whole point of an mDL for an age check.
#[test]
fn a_partial_disclosure_is_valid_and_reveals_nothing_else() {
    let response = ResponseBuilder::default()
        .elements(age_only_elements())
        .build();
    let anchors = [iaca_anchor()];

    let verification = verify_issuer_auth_with(&response, &anchors, &options()).expect("verifies");
    let mdl = verification.mdl().expect("mDL");

    assert!(mdl.is_authentic());
    assert_eq!(mdl.age_over(21), Some(true));
    assert_eq!(mdl.birth_date(), None);
    assert_eq!(mdl.family_name(), None);
    assert_eq!(mdl.document_number(), None);
}

#[test]
fn a_non_mdl_doc_type_is_returned_but_not_as_an_mdl() {
    let response = ResponseBuilder::default()
        .doc_type("org.iso.23220.photoid.1")
        .build();
    let anchors = [iaca_anchor()];

    let verification = verify_issuer_auth_with(&response, &anchors, &options()).expect("verifies");

    assert!(verification.mdl().is_none());
    assert_eq!(verification.documents.len(), 1);
    assert!(verification.documents[0].is_authentic());
}

#[test]
fn garbage_input_is_unreadable_not_tampered() {
    let result = verify_issuer_auth(b"not cbor at all", &[]);
    assert!(matches!(result, Err(MdlError::Unreadable(_))), "{result:?}");
}

#[test]
fn a_malformed_anchor_is_rejected_up_front() {
    let result = IacaAnchor::from_certificate(b"\x30\x82 nope");
    assert!(matches!(result, Err(MdlError::Anchor(_))), "{result:?}");
}
