//! VICAL — sourcing IACA anchors from AAMVA's signed list.
//!
//! These run against the real thing: the VICAL published by the AAMVA Digital Trust
//! Service on 2025-11-18, and the DTS root and intermediate from
//! <https://vical.dts.aamva.org/trustcertificates>. Nothing here is synthesised.

mod common;

use chrono::{TimeZone, Utc};
use common::iaca_anchor;
use mdl_verify::{vical, MdlError, VerifyOptions, MDL_DOC_TYPE};

static AAMVA_VICAL: &[u8] = include_bytes!("fixtures/vical/aamva-vical-2025-11-18.cbor");
static AAMVA_ROOT: &str = include_str!("fixtures/vical/aamva_ca_root.crt");
static AAMVA_INTERMEDIATE: &str = include_str!("fixtures/vical/aamva_ca_intermediate.crt");

/// Pinned so the fixture does not rot, and chosen to sit *after* the list was
/// published (2025-11-18) and before its signer expired (2026-04-18). Verifying at a
/// time before publication would happily accept a future-dated list, which is not a
/// property worth testing for.
fn at_signing_time() -> VerifyOptions {
    VerifyOptions {
        at: Some(Utc.with_ymd_and_hms(2025, 12, 1, 0, 0, 0).unwrap()),
        ..Default::default()
    }
}

fn root() -> vical::VicalAuthority {
    vical::VicalAuthority::from_pem(AAMVA_ROOT).expect("parse the AAMVA DTS root")
}

#[test]
fn the_aamva_vical_verifies_and_yields_issuer_anchors() {
    let list = vical::verify(AAMVA_VICAL, &[root()], &at_signing_time()).expect("verifies");

    assert!(!list.provider.is_empty(), "the provider names itself");
    assert!(
        !list.entries.is_empty(),
        "a VICAL with no issuers would be useless"
    );
    assert!(
        list.unusable.is_empty(),
        "every certificate in AAMVA's list should parse: {:?}",
        list.unusable
    );

    // Real US jurisdictions, with the metadata that makes an operator able to reason
    // about which anchor is which.
    assert!(list
        .entries
        .iter()
        .any(|e| e.issuing_country.as_deref() == Some("US")));
    assert!(list
        .entries
        .iter()
        .any(|e| e.issuing_authority.is_some() && e.state_or_province.is_some()));

    assert!(
        list.issued < at_signing_time().at.unwrap(),
        "verifying before the list was published would not prove much"
    );

    println!(
        "{} issued {} with {} issuers",
        list.provider,
        list.issued,
        list.entries.len()
    );
}

/// The point of the exercise: anchors that go straight into issuer verification.
#[test]
fn the_anchors_are_scoped_to_the_document_type() {
    let list = vical::verify(AAMVA_VICAL, &[root()], &at_signing_time()).expect("verifies");

    let mdl_anchors = list.anchors_for(MDL_DOC_TYPE);
    assert!(
        !mdl_anchors.is_empty(),
        "AAMVA's list exists to vouch for mDL issuers"
    );
    assert!(mdl_anchors.len() <= list.anchors().len());

    // An entry is only good for the doc types it names.
    assert!(list
        .anchors_for("org.iso.18013.5.1.definitely-not-a-doctype")
        .is_empty());
}

/// Trusting the intermediate directly is a legitimate deployment choice, and the
/// chain has to validate either way.
#[test]
fn the_intermediate_can_be_the_authority() {
    let intermediate =
        vical::VicalAuthority::from_pem(AAMVA_INTERMEDIATE).expect("parse the intermediate");

    let list = vical::verify(AAMVA_VICAL, &[intermediate], &at_signing_time()).expect("verifies");
    assert!(!list.entries.is_empty());
}

/// The whole security property: a list signed by someone you did not name is not a
/// list of trust anchors, it is a list of certificates.
#[test]
fn an_unrelated_authority_is_rejected() {
    // Our own test IACA — a perfectly valid certificate, just not AAMVA's.
    let impostor = vical::VicalAuthority::from_certificate(common::IACA_CERT.as_bytes()).err();
    assert!(impostor.is_some(), "PEM bytes are not DER");

    let impostor = vical::VicalAuthority::from_pem(common::IACA_CERT).expect("parse test IACA");
    let result = vical::verify(AAMVA_VICAL, &[impostor], &at_signing_time());

    assert!(matches!(result, Err(MdlError::Vical(_))), "{result:?}");
    // Sanity: that same certificate is a working IACA anchor elsewhere, so the
    // rejection is about who signed the VICAL, not about the certificate.
    let _ = iaca_anchor();
}

#[test]
fn a_vical_with_no_authority_is_refused() {
    let result = vical::verify(AAMVA_VICAL, &[], &at_signing_time());
    assert!(matches!(result, Err(MdlError::Vical(_))), "{result:?}");
}

/// The signer certificate expired on 2026-04-18. After that the list must not verify,
/// however genuine it was when published.
#[test]
fn an_expired_signer_is_rejected() {
    let options = VerifyOptions {
        at: Some(Utc.with_ymd_and_hms(2026, 4, 19, 0, 0, 0).unwrap()),
        ..Default::default()
    };

    let result = vical::verify(AAMVA_VICAL, &[root()], &options);
    assert!(matches!(result, Err(MdlError::Vical(_))), "{result:?}");
}

#[test]
fn garbage_is_not_a_vical() {
    let result = vical::verify(b"not cbor", &[root()], &at_signing_time());
    assert!(matches!(result, Err(MdlError::Vical(_))), "{result:?}");
}

/// A VICAL is a snapshot. Serving a stale one is how an issuer that was removed stays
/// trusted, so callers get a straight answer about it.
#[test]
fn staleness_is_reported_against_next_update() {
    let list = vical::verify(AAMVA_VICAL, &[root()], &at_signing_time()).expect("verifies");

    let Some(next_update) = list.next_update else {
        // The provider promised nothing; nothing to assert.
        return;
    };

    assert!(!list.is_stale_at(next_update - chrono::Duration::days(1)));
    // The deadline itself is already past due — the provider said a new list would be
    // out by then.
    assert!(list.is_stale_at(next_update));
    assert!(list.is_stale_at(next_update + chrono::Duration::days(1)));
}
