//! The mDL half, and the thing this crate exists for: the same result shape as a
//! passport.
//!
//! The mdoc is issued here at test time, signed by the Document Signer from
//! `mdl-verify`'s fixtures under its Annex-B-conforming IACA — so this exercises the
//! real verification path, not a stub.

use std::collections::BTreeMap;

use chrono::Utc;
use identity_mobile::{mdl, DocumentSource, IdentityError};
use isomdl::cbor;
use isomdl::definitions::device_key::cose_key::{CoseKey, EC2Curve, EC2Y};
use isomdl::definitions::device_key::DeviceKeyInfo;
use isomdl::definitions::device_response::{DeviceResponse, Document, Status};
use isomdl::definitions::device_signed::{DeviceAuth, DeviceNamespaces, DeviceSigned};
use isomdl::definitions::helpers::{NonEmptyVec, Tag24};
use isomdl::definitions::issuer_signed::IssuerSigned;
use isomdl::definitions::mso::DigestAlgorithm;
use isomdl::definitions::x509::X5Chain;
use isomdl::definitions::ValidityInfo;
use isomdl::issuance::Mdoc;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use p256::PublicKey;

static DS_CERT: &str = include_str!("../../mdl-verify/tests/fixtures/ds-cert.pem");
static DS_KEY: &str = include_str!("../../mdl-verify/tests/fixtures/ds-key.pem");
static IACA_CERT: &str = include_str!("../../mdl-verify/tests/fixtures/iaca-cert.pem");

/// The credential is issued around *now*, because that is what these entry points
/// judge against — a wallet presents something currently valid, and `verify_mdl` has
/// no time parameter to pin.
///
/// The `mdl-verify` fixture Document Signer runs to 2027-08-30 (ISO 18013-5 caps a DS
/// certificate at 457 days). When it expires, regenerate that PKI with
/// `crates/mdl-verify/tests/fixtures/generate.sh` — these tests go with it.
fn signed_at() -> chrono::DateTime<Utc> {
    Utc::now()
}

fn iaca_der() -> Vec<u8> {
    pem_to_der(IACA_CERT)
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    use x509_cert_shim::decode;
    decode(pem)
}

/// A three-line PEM decoder, so the test does not need another dependency.
mod x509_cert_shim {
    pub fn decode(pem: &str) -> Vec<u8> {
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        base64_decode(&body)
    }

    fn base64_decode(input: &str) -> Vec<u8> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut out = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0u32;

        for byte in input
            .bytes()
            .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        {
            let value = TABLE
                .iter()
                .position(|c| *c == byte)
                .expect("valid base64 in a PEM fixture") as u32;
            // Masked to the bits still owed. Without it the accumulator relies on
            // shift-out to discard consumed bits, which is correct but reads like a
            // bug and would become one the moment the type changed.
            buffer = ((buffer << 6) | value) & 0xFFFF;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buffer >> bits) as u8);
            }
        }

        out
    }
}

fn elements() -> BTreeMap<String, ciborium::Value> {
    let mut elements = BTreeMap::new();
    elements.insert(
        "family_name".to_string(),
        ciborium::Value::Text("Sharma".to_string()),
    );
    elements.insert(
        "given_name".to_string(),
        ciborium::Value::Text("Priya".to_string()),
    );
    elements.insert(
        "birth_date".to_string(),
        ciborium::Value::Tag(
            1004,
            Box::new(ciborium::Value::Text("1988-03-14".to_string())),
        ),
    );
    elements.insert(
        "expiry_date".to_string(),
        ciborium::Value::Tag(
            1004,
            Box::new(ciborium::Value::Text("2030-01-01".to_string())),
        ),
    );
    elements.insert(
        "document_number".to_string(),
        ciborium::Value::Text("NY-1234567".to_string()),
    );
    elements.insert(
        "issuing_country".to_string(),
        ciborium::Value::Text("US".to_string()),
    );
    elements.insert(
        "issuing_authority".to_string(),
        ciborium::Value::Text("NY DMV".to_string()),
    );
    elements.insert("age_over_21".to_string(), ciborium::Value::Bool(true));
    elements.insert("age_over_18".to_string(), ciborium::Value::Bool(true));
    // Not one of the ages a hard-coded list would have thought to ask about.
    elements.insert("age_over_30".to_string(), ciborium::Value::Bool(true));
    elements.insert("sex".to_string(), ciborium::Value::Integer(2.into()));
    elements.insert(
        "portrait".to_string(),
        ciborium::Value::Bytes(vec![0xFF, 0xD8, 0xFF, 0xE0]),
    );
    elements
}

/// Issue and encode a `DeviceResponse` the way a wallet would present one.
fn device_response(elements: BTreeMap<String, ciborium::Value>) -> Vec<u8> {
    device_response_with_doc_type(elements, "org.iso.18013.5.1.mDL")
}

fn device_response_with_doc_type(
    elements: BTreeMap<String, ciborium::Value>,
    doc_type: &str,
) -> Vec<u8> {
    let at = signed_at();
    let odt = |t: chrono::DateTime<Utc>| {
        time::OffsetDateTime::from_unix_timestamp(t.timestamp()).unwrap()
    };

    let device_key = SigningKey::from_bytes(&[0x42; 32].into()).unwrap();
    let point = PublicKey::from(device_key.verifying_key()).to_encoded_point(false);

    let mut namespaces = BTreeMap::new();
    namespaces.insert("org.iso.18013.5.1".to_string(), elements);

    let mdoc = Mdoc::builder()
        .doc_type(doc_type.to_string())
        .namespaces(namespaces)
        .validity_info(ValidityInfo {
            signed: odt(at - chrono::Duration::days(1)),
            valid_from: odt(at - chrono::Duration::days(1)),
            valid_until: odt(at + chrono::Duration::days(30)),
            expected_update: None,
        })
        .digest_algorithm(DigestAlgorithm::SHA256)
        .device_key_info(DeviceKeyInfo {
            device_key: CoseKey::EC2 {
                crv: EC2Curve::P256,
                x: point.x().unwrap().to_vec(),
                y: EC2Y::Value(point.y().unwrap().to_vec()),
            },
            key_authorizations: None,
            key_info: None,
        })
        .issue::<SigningKey, Signature>(
            X5Chain::builder()
                .with_pem_certificate(DS_CERT.as_bytes())
                .unwrap()
                .build()
                .unwrap(),
            SigningKey::from_pkcs8_pem(DS_KEY).unwrap(),
        )
        .expect("issue the mdoc");

    // Device authentication is a separate layer; this test covers issuer
    // authentication, so the device signature is a placeholder that is never checked.
    let device_namespaces: DeviceNamespaces = BTreeMap::new();
    let mac0 = coset::CoseMac0Builder::new()
        .protected(
            coset::HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::HMAC_256_256)
                .build(),
        )
        .tag(vec![0u8; 32])
        .build();

    let response = DeviceResponse {
        version: "1.0".to_string(),
        documents: Some(NonEmptyVec::new(Document {
            doc_type: doc_type.to_string(),
            issuer_signed: IssuerSigned {
                namespaces: Some(mdoc.namespaces),
                issuer_auth: mdoc.issuer_auth,
            },
            device_signed: DeviceSigned {
                namespaces: Tag24::new(device_namespaces).unwrap(),
                device_auth: DeviceAuth::DeviceMac(isomdl::cose::MaybeTagged::new(false, mac0)),
            },
            errors: None,
        })),
        document_errors: None,
        status: Status::OK,
    };

    cbor::to_vec(&response).expect("encode the response")
}

#[test]
fn an_mdl_comes_back_in_the_same_shape_as_a_passport() {
    let response = device_response(elements());

    let identity = mdl::verify_mdl(&response, &[iaca_der()], None).expect("verifies");

    assert_eq!(identity.family_name.as_deref(), Some("Sharma"));
    assert_eq!(identity.given_name.as_deref(), Some("Priya"));
    assert_eq!(identity.date_of_birth.as_deref(), Some("1988-03-14"));
    assert_eq!(identity.document_number.as_deref(), Some("NY-1234567"));
    assert_eq!(identity.nationality.as_deref(), Some("US"));
    assert_eq!(identity.display_name().as_deref(), Some("Priya Sharma"));
    // ISO/IEC 5218 in the credential, the MRZ's letter in the result — one shape.
    assert_eq!(identity.sex.as_deref(), Some("F"));
    assert_eq!(
        identity.portrait.as_deref(),
        Some(&[0xFF, 0xD8, 0xFF, 0xE0][..])
    );

    assert!(identity.authenticity.data_authentic);
    assert!(
        identity.authenticity.issuer_trusted,
        "the DS chains to the fixture IACA: {:?}",
        identity.authenticity.warnings
    );

    let Some(DocumentSource::MobileDrivingLicence {
        doc_type,
        issuing_authority,
    }) = &identity.source
    else {
        panic!("an mDL source");
    };
    assert_eq!(doc_type, "org.iso.18013.5.1.mDL");
    assert_eq!(issuing_authority.as_deref(), Some("NY DMV"));
}

/// The thing a passport cannot do: answer the age question without giving up the date.
#[test]
fn age_attestations_survive_the_mapping() {
    let mut only_age = BTreeMap::new();
    only_age.insert("age_over_21".to_string(), ciborium::Value::Bool(true));
    only_age.insert("age_over_18".to_string(), ciborium::Value::Bool(true));
    only_age.insert("age_over_25".to_string(), ciborium::Value::Bool(false));

    let identity =
        mdl::verify_mdl(&device_response(only_age), &[iaca_der()], None).expect("verifies");

    assert_eq!(identity.age_over(21), Some(true));
    assert_eq!(identity.age_over(25), Some(false));
    assert_eq!(identity.age_over(65), None);
    assert_eq!(
        identity.date_of_birth, None,
        "the date of birth was never disclosed, and must not be invented"
    );
}

/// Attestations come from what the issuer actually disclosed, not from a list of ages
/// this crate happened to enumerate.
#[test]
fn any_disclosed_age_attestation_survives() {
    let identity =
        mdl::verify_mdl(&device_response(elements()), &[iaca_der()], None).expect("verifies");

    assert_eq!(identity.age_over(21), Some(true));
    assert_eq!(identity.age_over(30), Some(true));
    assert_eq!(identity.age_over(99), None);
}

/// A response carrying some other document must not be handed back as a driving
/// licence just because it was the only thing present.
#[test]
fn a_non_mdl_document_is_not_returned_as_an_mdl() {
    let response = device_response_with_doc_type(elements(), "org.iso.23220.photoid.1");

    let result = mdl::verify_mdl(&response, &[iaca_der()], None);

    assert!(
        matches!(result, Err(IdentityError::Unreadable(_))),
        "{result:?}"
    );
    let message = result.unwrap_err().to_string();
    assert!(message.contains("photoid"), "{message}");
}

/// The reader's private key must not reach a log line.
#[test]
fn a_session_does_not_print_the_reader_key() {
    let session = mdl::Session::from_cbor(&[0x83, 0xf6, 0xf6, 0x80], Some([0xAB; 32]))
        .expect("a well-formed transcript");

    let rendered = format!("{session:?}");

    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(
        !rendered.contains("171"),
        "the key bytes leaked: {rendered}"
    );
    assert!(!rendered.to_lowercase().contains("ab, ab"), "{rendered}");
}

/// Without a session transcript there is no proof of presence, and the result has to
/// say so rather than implying one.
#[test]
fn the_static_path_does_not_claim_holder_binding() {
    let identity =
        mdl::verify_mdl(&device_response(elements()), &[iaca_der()], None).expect("verifies");

    assert_eq!(identity.authenticity.holder_bound, None);
    assert!(identity.authenticity.is_trustworthy());
    assert!(
        !identity.authenticity.is_present_and_trustworthy(),
        "a captured response replays; only device authentication rules that out"
    );
}

#[test]
fn without_anchors_the_issuer_is_not_trusted() {
    let identity = mdl::verify_mdl(&device_response(elements()), &[], None).expect("verifies");

    assert!(identity.authenticity.data_authentic);
    assert!(!identity.authenticity.issuer_trusted);
    assert!(!identity.authenticity.is_trustworthy());
}

#[test]
fn garbage_is_unreadable_rather_than_inauthentic() {
    let result = mdl::verify_mdl(b"not an mdoc", &[iaca_der()], None);
    assert!(
        matches!(result, Err(IdentityError::Unreadable(_))),
        "{result:?}"
    );
}

#[test]
fn a_malformed_anchor_is_rejected_up_front() {
    let result = mdl::verify_mdl(&device_response(elements()), &[b"nonsense".to_vec()], None);
    assert!(
        matches!(result, Err(IdentityError::Anchor(_))),
        "{result:?}"
    );
}
