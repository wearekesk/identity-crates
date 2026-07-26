//! CRL revocation checking.
//!
//! These tests fetch the CRL over a real socket from a real HTTP client, so they
//! exercise the whole path: distribution point extraction, fetch, CRL profile
//! validation against the IACA, and the serial-number check.
//!
//! They share a fixed loopback port (the CRL distribution point is baked into the
//! Document Signer certificate), so they take a lock rather than running in parallel.

// The port lock is held across the await deliberately: it serialises whole tests,
// each of which runs on its own single-threaded runtime, so there is no other task
// to starve and an async mutex would buy nothing.
#![allow(clippy::await_holding_lock)]

mod common;

use std::sync::Mutex;

use common::{iaca_anchor, test_time, CrlServer, ResponseBuilder, CRL_CLEAN, CRL_REVOKED};
use mdl_verify::revocation::{verify_issuer_auth, CrlChecker};
use mdl_verify::VerifyOptions;

/// One fixed port, one test at a time.
static PORT: Mutex<()> = Mutex::new(());

fn options() -> VerifyOptions {
    VerifyOptions {
        at: Some(test_time()),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_clean_crl_leaves_the_chain_trusted() {
    let _guard = PORT.lock().unwrap_or_else(|e| e.into_inner());
    let _server = CrlServer::serve(CRL_CLEAN);

    let response = ResponseBuilder::default().build();
    let checker = CrlChecker::new().expect("build CRL checker");

    let verification = verify_issuer_auth(&response, &[iaca_anchor()], &options(), &checker)
        .await
        .expect("verifies");
    let mdl = verification.mdl().expect("mDL");

    assert!(
        mdl.issuer_trusted,
        "a document signer absent from the CRL stays trusted: {:?} / {:?}",
        mdl.trust_errors, mdl.revocation_errors
    );
    assert!(
        mdl.revocation_errors.is_empty(),
        "the CRL was fetched and validated, so nothing should be reported: {:?}",
        mdl.revocation_errors
    );
    assert!(mdl.is_authentic());
}

/// The case the whole feature exists for: the issuer signature is still perfectly
/// valid, and the credential must still be refused.
#[tokio::test]
async fn a_revoked_document_signer_is_not_trusted() {
    let _guard = PORT.lock().unwrap_or_else(|e| e.into_inner());
    let _server = CrlServer::serve(CRL_REVOKED);

    let response = ResponseBuilder::default().build();
    let checker = CrlChecker::new().expect("build CRL checker");

    let verification = verify_issuer_auth(&response, &[iaca_anchor()], &options(), &checker)
        .await
        .expect("still parses and verifies the issuer signature");
    let mdl = verification.mdl().expect("mDL");

    // The data is genuine — the issuer really did sign it.
    assert!(mdl.signature_verified);

    // But the key that signed it has been revoked, so it is not trustworthy.
    assert!(
        !mdl.issuer_trusted,
        "a revoked document signer must not be trusted"
    );
    assert!(
        mdl.trust_errors.iter().any(|e| e.contains("revoked")),
        "revocation should be reported as a trust failure: {:?}",
        mdl.trust_errors
    );
    assert!(!mdl.is_authentic());
}

/// An unreachable CRL endpoint is an infrastructure problem, not a verdict. It is
/// reported separately so the caller can decide whether to fail open or closed —
/// hard-failing every presentation because a DMV's CRL host is down is a policy
/// choice, not one this crate should make.
#[tokio::test]
async fn an_unreachable_crl_is_reported_not_enforced() {
    let _guard = PORT.lock().unwrap_or_else(|e| e.into_inner());
    // Deliberately no server on the port.

    let response = ResponseBuilder::default().build();
    let checker = CrlChecker::new().expect("build CRL checker");

    let verification = verify_issuer_auth(&response, &[iaca_anchor()], &options(), &checker)
        .await
        .expect("verifies");
    let mdl = verification.mdl().expect("mDL");

    assert!(
        !mdl.revocation_errors.is_empty(),
        "a failed CRL fetch must be surfaced"
    );
    assert!(
        mdl.issuer_trusted,
        "an unreachable CRL is not a trust failure on its own: {:?}",
        mdl.trust_errors
    );
    assert!(
        !mdl.trust_errors.iter().any(|e| e.contains("revoked")),
        "an unreachable CRL must never be reported as revocation: {:?}",
        mdl.trust_errors
    );
}

/// Without the checker, the no-network path says so rather than staying silent.
#[test]
fn the_default_path_reports_that_revocation_was_not_checked() {
    let response = ResponseBuilder::default().build();

    let verification = mdl_verify::verify_issuer_auth_with(&response, &[iaca_anchor()], &options())
        .expect("verifies");
    let mdl = verification.mdl().expect("mDL");

    assert!(
        !mdl.revocation_errors.is_empty(),
        "the skipped-revocation path should leave a note behind"
    );
    assert!(mdl.issuer_trusted);
}
