//! The passport half, against a real CMS EF.SOD.
//!
//! The fixtures are built by `tests/fixtures/generate.sh`: a CSCA certifies a Document
//! Signer, which signs an LDS security object over data groups that `dmrtd`'s own TLV
//! encoder produced. Nothing here is a canned blob from the code under test.

use identity_mobile::passport::{self, PassportFiles};
use identity_mobile::{DocumentSource, IdentityError};

static DG1: &[u8] = include_bytes!("fixtures/dg1.bin");
static DG2: &[u8] = include_bytes!("fixtures/dg2.bin");
static SOD: &[u8] = include_bytes!("fixtures/efsod.bin");
static CSCA: &[u8] = include_bytes!("fixtures/csca.der");
static OTHER_CSCA: &[u8] = include_bytes!("fixtures/other-csca.der");

fn files() -> PassportFiles {
    PassportFiles {
        sod: SOD.to_vec(),
        dg1: DG1.to_vec(),
        dg2: Some(DG2.to_vec()),
        active_authentication: None,
    }
}

#[test]
fn a_genuine_passport_verifies_and_yields_the_holder() {
    let identity = passport::verify_passport(&files(), &[CSCA.to_vec()]).expect("verifies");

    assert_eq!(identity.family_name.as_deref(), Some("SHARMA"));
    assert_eq!(identity.given_name.as_deref(), Some("PRIYA"));
    assert_eq!(identity.date_of_birth.as_deref(), Some("1988-03-14"));
    assert_eq!(identity.date_of_expiry.as_deref(), Some("2030-01-01"));
    assert_eq!(identity.document_number.as_deref(), Some("123456789"));
    assert_eq!(identity.nationality.as_deref(), Some("FRA"));
    assert_eq!(identity.display_name().as_deref(), Some("PRIYA SHARMA"));

    assert!(identity.authenticity.data_authentic);
    assert!(
        identity.authenticity.issuer_trusted,
        "the Document Signer chains to the supplied CSCA: {:?}",
        identity.authenticity.warnings
    );
    assert!(identity.authenticity.is_trustworthy());

    // Active authentication was not attempted, which is not the same as failing it.
    assert_eq!(identity.authenticity.holder_bound, None);
    assert!(!identity.authenticity.is_present_and_trustworthy());
}

#[test]
fn the_portrait_comes_back_as_the_signed_jpeg() {
    let identity = passport::verify_passport(&files(), &[CSCA.to_vec()]).expect("verifies");

    let portrait = identity.portrait.expect("DG2 carries a facial image");
    assert_eq!(
        &portrait[..4],
        &[0xFF, 0xD8, 0xFF, 0xE0],
        "the JPEG the issuer signed, byte for byte"
    );
}

/// The security property: alter a data group and EF.SOD no longer matches it.
#[test]
fn a_tampered_data_group_is_rejected() {
    let mut tampered = files();
    // Flip a character in the surname. The chip's signature is left untouched.
    let position = tampered
        .dg1
        .windows(6)
        .position(|w| w == b"SHARMA")
        .expect("the surname is in DG1");
    tampered.dg1[position] = b'C';

    let result = passport::verify_passport(&tampered, &[CSCA.to_vec()]);

    assert!(
        matches!(result, Err(IdentityError::NotAuthentic(_))),
        "an altered MRZ must not verify: {result:?}"
    );
}

#[test]
fn a_tampered_portrait_is_rejected() {
    let mut tampered = files();
    let dg2 = tampered.dg2.as_mut().unwrap();
    let last = dg2.len() - 1;
    dg2[last] ^= 0xFF;

    let result = passport::verify_passport(&tampered, &[CSCA.to_vec()]);
    assert!(
        matches!(result, Err(IdentityError::NotAuthentic(_))),
        "{result:?}"
    );
}

/// Genuine data, unknown issuer. The read succeeds and the fields are readable — they
/// are what the signer signed — but nothing attributes them to a country.
#[test]
fn without_anchors_the_data_is_authentic_but_the_issuer_is_not_trusted() {
    let identity = passport::verify_passport(&files(), &[]).expect("verifies");

    assert!(identity.authenticity.data_authentic);
    assert!(!identity.authenticity.issuer_trusted);
    assert!(!identity.authenticity.is_trustworthy());
    assert_eq!(identity.family_name.as_deref(), Some("SHARMA"));
}

#[test]
fn an_unrelated_csca_confers_no_trust() {
    let identity = passport::verify_passport(&files(), &[OTHER_CSCA.to_vec()]).expect("verifies");

    assert!(identity.authenticity.data_authentic);
    assert!(!identity.authenticity.issuer_trusted);
}

/// Passive authentication vouches for the groups it was given and no others. Reading
/// only DG1 must not imply anything about the photograph.
#[test]
fn skipping_the_portrait_is_reported_as_uncovered() {
    let mut without_portrait = files();
    without_portrait.dg2 = None;

    let identity =
        passport::verify_passport(&without_portrait, &[CSCA.to_vec()]).expect("verifies");

    assert!(identity.authenticity.is_trustworthy());
    assert!(identity.portrait.is_none());

    let Some(DocumentSource::Passport {
        verified_data_groups,
        signed_data_groups,
        ..
    }) = &identity.source
    else {
        panic!("a passport source");
    };

    assert_eq!(verified_data_groups, &[1]);
    assert_eq!(signed_data_groups, &[1, 2]);
    assert!(
        identity
            .authenticity
            .warnings
            .iter()
            .any(|w| w.contains("not read")),
        "an unread but signed group has to be surfaced: {:?}",
        identity.authenticity.warnings
    );
}

#[test]
fn a_failed_active_authentication_is_carried_through_as_a_warning() {
    let mut cloned = files();
    cloned.active_authentication = Some(false);

    let identity = passport::verify_passport(&cloned, &[CSCA.to_vec()]).expect("verifies");

    assert_eq!(identity.authenticity.holder_bound, Some(false));
    assert!(!identity.authenticity.is_present_and_trustworthy());
    assert!(identity
        .authenticity
        .warnings
        .iter()
        .any(|w| w.contains("active authentication")));
}

#[test]
fn a_document_source_names_the_document_type() {
    let identity = passport::verify_passport(&files(), &[CSCA.to_vec()]).expect("verifies");

    let Some(DocumentSource::Passport {
        document_code,
        issuing_state,
        ..
    }) = &identity.source
    else {
        panic!("a passport source");
    };

    assert_eq!(document_code, "P");
    // The state that issued the document, which is not the holder's nationality —
    // the fixture sets them differently so conflating the two fails here.
    assert_eq!(issuing_state, "GBR");
    assert_eq!(identity.nationality.as_deref(), Some("FRA"));
}

#[test]
fn garbage_is_not_a_security_object() {
    let mut broken = files();
    broken.sod = b"not a CMS structure".to_vec();

    assert!(passport::verify_passport(&broken, &[CSCA.to_vec()]).is_err());
}

#[test]
fn a_malformed_anchor_is_rejected_up_front() {
    let result = passport::verify_passport(&files(), &[b"not a certificate".to_vec()]);
    assert!(
        matches!(result, Err(IdentityError::Anchor(_))),
        "{result:?}"
    );
}
