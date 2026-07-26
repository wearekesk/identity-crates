//! Answering "can we verify this issuer?" without running a verification.

mod common;

use common::{ResponseBuilder, DS_CERT, P521_DS_CERT};
use mdl_verify::preflight;

#[test]
fn a_p256_signer_is_reported_as_verifiable() {
    let key = preflight::certificate_signer_key_pem(DS_CERT).expect("parse the DS certificate");

    assert_eq!(key.algorithm, "P-256");
    assert!(key.verifiable);
}

/// The point of the module: name the gap plainly instead of letting someone discover
/// it during an integration.
#[test]
fn a_p521_signer_is_named_and_flagged() {
    let key = preflight::certificate_signer_key_pem(P521_DS_CERT).expect("parse the certificate");

    assert_eq!(key.algorithm, "P-521");
    assert!(
        !key.verifiable,
        "P-521 is permitted by the spec and not implemented here; say so"
    );
}

/// Reading it straight off a sample presentation is the case that actually gets used.
#[test]
fn the_signers_of_a_response_are_reported_in_order() {
    let response = ResponseBuilder::default().build();

    let keys = preflight::response_signer_keys(&response).expect("reads the response");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].algorithm, "P-256");
    assert!(keys[0].verifiable);
}

/// Against a real production certificate rather than one we generated: AAMVA's own
/// DTS root, which is P-256 — the concrete reason this gap has never bitten anyone.
#[test]
fn a_production_certificate_reads_correctly() {
    let key =
        preflight::certificate_signer_key_pem(include_str!("fixtures/vical/aamva_ca_root.crt"))
            .expect("parse the AAMVA root");

    assert_eq!(key.algorithm, "P-256");
    assert!(key.verifiable);
}

#[test]
fn garbage_is_not_a_certificate() {
    assert!(preflight::certificate_signer_key(b"not a certificate").is_err());
}
