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
    // Altering the committed hash must make verification *fail* — not merely lose the
    // chain. (unwrap_or(false) would also pass for Ok(Unverified), masking a regression
    // that accepted the modified hash.)
    assert!(passive::verify(&sod, &groups(), &[anchor]).is_err());
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

#[test]
fn a_sod_wrapping_the_wrong_content_type_is_rejected() {
    // Same signed chain, but the eContentType is pkcs7-data instead of the ICAO LDS
    // security object OID — not a passport SOD, so it must not verify.
    const WRONG_CT: &[u8] = include_bytes!("fixtures/efsod_wrong_ct.bin");
    let anchor = TrustAnchor::from_certificate(CSCA).unwrap();
    assert_eq!(
        passive::verify(WRONG_CT, &groups(), &[anchor]).unwrap_err(),
        PassiveAuthError::MalformedSod,
    );
}

/// Offset of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// EC, as passports are signed: explicit curve parameters, a NULL ECDSA parameter.
// `tests/fixtures/ec/make.py` makes them.
// ---------------------------------------------------------------------------

const BP256_EFSOD: &[u8] = include_bytes!("fixtures/ec/bp256_efsod.bin");
const BP256_CSCA: &[u8] = include_bytes!("fixtures/ec/bp256_csca.der");
const P256_CSCA: &[u8] = include_bytes!("fixtures/ec/p256_csca.der");

/// Each curve's EF.SOD and CSCA: the ones RustCrypto's crates verify, and
/// brainpoolP512r1, which `auth::ecdsa` verifies itself.
const EC_CHAINS: &[(&str, &[u8], &[u8])] = &[
    (
        "P-256",
        include_bytes!("fixtures/ec/p256_efsod.bin"),
        P256_CSCA,
    ),
    (
        "P-384",
        include_bytes!("fixtures/ec/p384_efsod.bin"),
        include_bytes!("fixtures/ec/p384_csca.der"),
    ),
    (
        "P-521",
        include_bytes!("fixtures/ec/p521_efsod.bin"),
        include_bytes!("fixtures/ec/p521_csca.der"),
    ),
    ("brainpoolP256r1", BP256_EFSOD, BP256_CSCA),
    (
        "brainpoolP384r1",
        include_bytes!("fixtures/ec/bp384_efsod.bin"),
        include_bytes!("fixtures/ec/bp384_csca.der"),
    ),
    (
        "brainpoolP512r1",
        include_bytes!("fixtures/ec/bp512_efsod.bin"),
        include_bytes!("fixtures/ec/bp512_csca.der"),
    ),
];

#[test]
fn ec_chains_with_explicit_parameters_and_a_null_ecdsa_parameter_are_authentic() {
    for (curve, sod, csca) in EC_CHAINS {
        let anchor =
            TrustAnchor::from_certificate(csca).unwrap_or_else(|e| panic!("{curve} CSCA: {e}"));
        let result =
            passive::verify(sod, &groups(), &[anchor]).unwrap_or_else(|e| panic!("{curve}: {e}"));
        assert_eq!(result.verified_groups, vec![1, 2], "{curve}");
        assert!(result.is_authentic(), "{curve}");
    }
}

#[test]
fn a_corrupted_ec_signature_is_caught() {
    for (curve, sod, _) in EC_CHAINS {
        // The SignerInfo's signature is the last thing in EF.SOD: an ECDSA-Sig-Value
        // whose final byte is the low byte of s.
        let mut sod = sod.to_vec();
        *sod.last_mut().unwrap() ^= 1;
        assert_eq!(
            passive::verify(&sod, &groups(), &[]).unwrap_err(),
            PassiveAuthError::BadDocumentSignature,
            "{curve}"
        );
    }
}

#[test]
fn an_ec_csca_on_another_curve_does_not_anchor_the_chain() {
    let anchor = TrustAnchor::from_certificate(P256_CSCA).unwrap();
    let result = passive::verify(BP256_EFSOD, &groups(), &[anchor]).unwrap();
    assert_eq!(result.chain, ChainStatus::Unverified);
}

#[test]
fn explicit_parameters_of_no_known_curve_are_refused() {
    // Change one byte of the CSCA's curve coefficient b: no longer brainpoolP256r1.
    // b's first bytes also occur inside a (brainpoolP256r1's b reuses part of a),
    // which comes first, so take the last occurrence: b's.
    const BP256_B: &[u8] = &[0x26, 0xDC, 0x5C, 0x6C, 0xE9, 0x4A, 0x4B, 0x44];
    let mut csca = BP256_CSCA.to_vec();
    let at = csca
        .windows(BP256_B.len())
        .rposition(|w| w == BP256_B)
        .expect("b is in the CSCA's parameters");
    assert_ne!(
        find(&csca, BP256_B),
        Some(at),
        "a holds b's first bytes too"
    );
    csca[at + 7] ^= 1;
    assert_eq!(
        TrustAnchor::from_certificate(&csca).unwrap_err(),
        PassiveAuthError::UnsupportedKey
    );
}
