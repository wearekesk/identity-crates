//! End-to-end passive authentication against a *real* CMS SignedData.
//!
//! The fixtures are produced by OpenSSL (see the repo's test-data notes), not by the
//! same code under test, so this exercises the actual RFC 5652 / X.509 encodings a
//! passport emits — the unit tests in `auth::passive` only cover hand-built structures.
//!
//! Chain: a self-signed **CSCA** signs a **Document Signer** certificate, which signs
//! a CMS SignedData whose eContent is an LDSSecurityObject hashing `dg1`/`dg2`. All in
//! `tests/fixtures/`.

use dmrtd::auth::passive::{self, ChainStatus, DataGroup, PassiveAuthError, TrustAnchor};

const EFSOD: &[u8] = include_bytes!("fixtures/efsod.bin");
const CSCA: &[u8] = include_bytes!("fixtures/csca.der");
const OTHER_CSCA: &[u8] = include_bytes!("fixtures/other_csca.der");
const DG1: &[u8] = include_bytes!("fixtures/dg1.bin");
const DG2: &[u8] = include_bytes!("fixtures/dg2.bin");

fn groups() -> Vec<DataGroup<'static>> {
    vec![
        DataGroup {
            number: 1,
            bytes: DG1,
        },
        DataGroup {
            number: 2,
            bytes: DG2,
        },
    ]
}

#[test]
fn full_chain_with_the_real_csca_is_authentic() {
    let anchor = TrustAnchor::from_certificate(CSCA).expect("CSCA parses");
    let result = passive::verify(EFSOD, &groups(), &[anchor]).expect("PA succeeds");

    assert_eq!(result.verified_groups, vec![1, 2]);
    assert!(result.is_authentic(), "chain should reach the trusted CSCA");
    assert!(matches!(result.chain, ChainStatus::Trusted { .. }));
}

#[test]
fn internally_consistent_but_unverified_without_a_trust_anchor() {
    // No CSCA supplied: the data-group hashes and the Document Signer's signature
    // still check out, but nothing anchors the chain — must NOT read as authentic.
    let result = passive::verify(EFSOD, &groups(), &[]).expect("steps 1–2 pass");
    assert_eq!(result.verified_groups, vec![1, 2]);
    assert!(!result.is_authentic());
    assert_eq!(result.chain, ChainStatus::Unverified);
}

#[test]
fn an_unrelated_csca_does_not_anchor_the_chain() {
    // A different, valid CSCA that did not sign this Document Signer. The SOD is
    // internally fine, so verify() succeeds — but the chain stays Unverified.
    let anchor = TrustAnchor::from_certificate(OTHER_CSCA).expect("parses");
    let result = passive::verify(EFSOD, &groups(), &[anchor]).unwrap();
    assert!(!result.is_authentic());
    assert_eq!(result.chain, ChainStatus::Unverified);
}

#[test]
fn a_tampered_data_group_is_rejected() {
    let tampered = b"DG1-MRZ-DATA-ALTERED";
    let groups = vec![
        DataGroup {
            number: 1,
            bytes: tampered,
        },
        DataGroup {
            number: 2,
            bytes: DG2,
        },
    ];
    let anchor = TrustAnchor::from_certificate(CSCA).unwrap();
    assert_eq!(
        passive::verify(EFSOD, &groups, &[anchor]).unwrap_err(),
        PassiveAuthError::DataGroupHashMismatch(1),
    );
}

#[test]
fn a_data_group_not_in_the_sod_is_rejected() {
    let groups = vec![DataGroup {
        number: 7,
        bytes: b"never hashed",
    }];
    let anchor = TrustAnchor::from_certificate(CSCA).unwrap();
    assert_eq!(
        passive::verify(EFSOD, &groups, &[anchor]).unwrap_err(),
        PassiveAuthError::DataGroupHashMismatch(7),
    );
}

#[test]
fn altering_the_committed_hash_in_the_sod_is_caught() {
    // The crown-jewel property: an attacker cannot change the data-group hash the SOD
    // commits to (which, paired with a swapped DG, is how you'd substitute a face).
    // Flip a byte of the stored SHA-256(DG1) inside EF.SOD and it must stop verifying.
    use sha2::{Digest, Sha256};
    let dg1_hash = Sha256::digest(DG1);
    let at = find(EFSOD, &dg1_hash).expect("DG1 hash is embedded in the SOD");

    let mut sod = EFSOD.to_vec();
    sod[at + 5] ^= 0xFF;

    let anchor = TrustAnchor::from_certificate(CSCA).unwrap();
    // Either the DG1 check now mismatches, or the messageDigest binding breaks — but
    // it can never come back authentic.
    let authentic = passive::verify(&sod, &groups(), &[anchor])
        .map(|r| r.is_authentic())
        .unwrap_or(false);
    assert!(!authentic);
}

#[test]
fn corrupting_the_document_signer_signature_is_caught() {
    // The signerInfo signature is the last structure in the CMS, so the final bytes of
    // EF.SOD are signature. Flipping one must break step 2 (the DSC signature over the
    // security object) and can never authenticate.
    let anchor = TrustAnchor::from_certificate(CSCA).unwrap();
    let mut sod = EFSOD.to_vec();
    let last = sod.len() - 3;
    sod[last] ^= 0xFF;
    assert!(passive::verify(&sod, &groups(), &[anchor]).is_err());
}

/// Offset of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
