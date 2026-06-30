//! End-to-end tests against real PAN-QR samples.
//!
//! These tests are gated on environment variables so that public CI (which does
//! not have access to a real sample) passes by skipping them:
//!
//! - `PANQR_SAMPLE_FILE` — path to a file holding an individual QR's scanned
//!   numeric string.
//! - `PANQR_SAMPLE_IMAGE` — path to a card image containing an individual QR.
//! - `PANQR_COMPANY_SAMPLE_FILE` — path to a file holding a company/organization
//!   QR's scanned numeric string.
//! - `PANQR_COMPANY_SAMPLE_IMAGE` — path to a card image containing a
//!   company/organization QR.
//!
//! The assertions only check structural properties (PII variant, PAN valid,
//! image presence, signature verifies). No PII is ever printed.

use incometax_pan_qr::{check_pan_details, PanPii, PanQr};
use std::{env, fs};

/// Asserts an individual QR has an [`PanPii::Individual`] layout, a valid PAN, an
/// embedded photo, and a verifying signature, without revealing any PII.
fn assert_individual_ok(qr: &PanQr) {
    let pii = qr.pii().expect("PII should be present");
    assert!(
        matches!(pii, PanPii::Individual { .. }),
        "individual sample should decode as PanPii::Individual"
    );
    assert!(
        pii.pan_valid(),
        "extracted PAN should be structurally valid"
    );
    assert!(
        check_pan_details(pii.pan()).is_valid,
        "check_pan_details should report the PAN as valid"
    );
    assert!(qr.image().is_some(), "embedded image should be present");
    assert!(
        qr.verify().expect("verification should not error"),
        "signature should verify"
    );
}

/// Returns `true` if `s` looks like a `dd.mm.yyyy` or `dd/mm/yyyy` date.
fn looks_like_date(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    let sep = bytes[2];
    if (sep != b'.' && sep != b'/') || bytes[5] != sep {
        return false;
    }
    let digit_positions = [0, 1, 3, 4, 6, 7, 8, 9];
    digit_positions.iter().all(|&i| bytes[i].is_ascii_digit())
}

/// Asserts a company QR has a [`PanPii::Organization`] layout, a valid PAN, a
/// date of incorporation, no photo, and a verifying signature, without revealing
/// any PII.
fn assert_company_ok(qr: &PanQr) {
    let pii = qr.pii().expect("PII should be present");
    assert!(
        pii.pan_valid(),
        "extracted PAN should be structurally valid"
    );
    assert!(
        check_pan_details(pii.pan()).is_valid,
        "check_pan_details should report the PAN as valid"
    );
    let PanPii::Organization {
        date_of_incorporation,
        ..
    } = pii
    else {
        panic!("company sample should decode as PanPii::Organization");
    };
    assert!(
        !date_of_incorporation.is_empty(),
        "date of incorporation should be present"
    );
    assert!(
        looks_like_date(date_of_incorporation),
        "date of incorporation should look like a dd.mm.yyyy / dd/mm/yyyy date"
    );
    assert!(
        qr.image().is_none(),
        "company QR should have no embedded photo"
    );
    assert!(
        qr.verify().expect("verification should not error"),
        "signature should verify"
    );
}

#[test]
fn scanned_string_sample_decodes_and_verifies() {
    let Ok(path) = env::var("PANQR_SAMPLE_FILE") else {
        eprintln!("PANQR_SAMPLE_FILE not set; skipping");
        return;
    };
    let scanned = fs::read_to_string(&path).expect("read sample file");
    let qr = PanQr::from_scanned_string(scanned.trim()).expect("decode scanned string");
    assert_individual_ok(&qr);
}

#[test]
fn image_sample_decodes_and_verifies() {
    let Ok(path) = env::var("PANQR_SAMPLE_IMAGE") else {
        eprintln!("PANQR_SAMPLE_IMAGE not set; skipping");
        return;
    };
    let bytes = fs::read(&path).expect("read sample image");
    let qr = PanQr::from_image_bytes(&bytes).expect("decode image");
    assert_individual_ok(&qr);
}

#[test]
fn company_scanned_string_sample_decodes_and_verifies() {
    let Ok(path) = env::var("PANQR_COMPANY_SAMPLE_FILE") else {
        eprintln!("PANQR_COMPANY_SAMPLE_FILE not set; skipping");
        return;
    };
    let scanned = fs::read_to_string(&path).expect("read company sample file");
    let qr = PanQr::from_scanned_string(scanned.trim()).expect("decode company scanned string");
    assert_company_ok(&qr);
}

#[test]
fn company_image_sample_decodes_and_verifies() {
    let Ok(path) = env::var("PANQR_COMPANY_SAMPLE_IMAGE") else {
        eprintln!("PANQR_COMPANY_SAMPLE_IMAGE not set; skipping");
        return;
    };
    let bytes = fs::read(&path).expect("read company sample image");
    let qr = PanQr::from_image_bytes(&bytes).expect("decode company image");
    assert_company_ok(&qr);
}
