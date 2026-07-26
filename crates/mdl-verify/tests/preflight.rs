//! Answering "can we verify this issuer?" without running a verification.

mod common;

use common::{ResponseBuilder, DS_CERT, P521_DS_CERT};
use isomdl::definitions::x509::X5Chain;
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
fn a_single_signer_is_read_from_the_response() {
    let response = ResponseBuilder::default().build();

    let keys = preflight::response_signer_keys(&response).expect("reads the response");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].algorithm, "P-256");
    assert!(keys[0].verifiable);
}

/// With two documents signed by different keys, position has to mean something —
/// otherwise a caller cannot tell which document is the one they cannot verify.
#[test]
fn signers_are_reported_in_document_order() {
    let mut response = ResponseBuilder::default().build_response();

    // A second document, identical but re-pointed at the P-521 signer.
    let mut second = ResponseBuilder::default()
        .doc_type("org.iso.23220.photoid.1")
        .build_response()
        .documents
        .unwrap()
        .into_inner()
        .remove(0);

    let p521 = X5Chain::builder()
        .with_pem_certificate(common::P521_DS_CERT.as_bytes())
        .expect("load the P-521 certificate")
        .build()
        .expect("build x5chain");

    for (label, value) in &mut second.issuer_signed.issuer_auth.unprotected.rest {
        if label == &coset::Label::Int(33) {
            *value = p521.into_cbor();
        }
    }

    response.documents.as_mut().unwrap().push(second);

    let keys = preflight::response_signer_keys(&common::encode(&response)).expect("reads");

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].algorithm, "P-256");
    assert!(keys[0].verifiable);
    assert_eq!(keys[1].algorithm, "P-521");
    assert!(
        !keys[1].verifiable,
        "the second document is the unverifiable one"
    );
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
