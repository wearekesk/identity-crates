//! End-to-end tests against a real PAN-QR sample.
//!
//! These tests are gated on environment variables so that public CI (which does
//! not have access to a real sample) passes by skipping them:
//!
//! - `PANQR_SAMPLE_FILE` — path to a file holding the scanned QR numeric string.
//! - `PANQR_SAMPLE_IMAGE` — path to a card image containing the QR.
//!
//! The assertions only check structural properties (PII present, PAN valid,
//! image present, signature verifies). No PII is ever printed.

use incometax_pan_qr::{check_pan_details, PanQr};
use std::{env, fs};

/// Asserts the decoded QR has valid PII, a valid PAN, an embedded image, and a
/// verifying signature, without revealing any PII.
fn assert_decoded_ok(qr: &PanQr) {
    let pii = qr.pii().expect("PII should be present");
    assert!(pii.pan_valid, "extracted PAN should be structurally valid");
    assert!(
        check_pan_details(&pii.pan).is_valid,
        "check_pan_details should report the PAN as valid"
    );
    assert!(qr.image().is_some(), "embedded image should be present");
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
    assert_decoded_ok(&qr);
}

#[test]
fn image_sample_decodes_and_verifies() {
    let Ok(path) = env::var("PANQR_SAMPLE_IMAGE") else {
        eprintln!("PANQR_SAMPLE_IMAGE not set; skipping");
        return;
    };
    let bytes = fs::read(&path).expect("read sample image");
    let qr = PanQr::from_image_bytes(&bytes).expect("decode image");
    assert_decoded_ok(&qr);
}
