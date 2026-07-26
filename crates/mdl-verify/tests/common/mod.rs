//! Builds real, issuer-signed mdoc presentations for the tests to pick apart.
//!
//! Nothing here is a canned blob: every response is signed at test time by the
//! Document Signer in `tests/fixtures`, which is itself issued by an IACA root that
//! conforms to the ISO/IEC 18013-5 Annex B profile. That is what lets the tests
//! assert on the *trusted* path and not just on failures.

#![allow(dead_code)]

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use isomdl::cbor;
use isomdl::cose::MaybeTagged;
use isomdl::definitions::device_key::cose_key::{CoseKey, EC2Curve, EC2Y};
use isomdl::definitions::device_key::DeviceKeyInfo;
use isomdl::definitions::device_response::{DeviceResponse, Document, Status};
use isomdl::definitions::device_signed::{
    DeviceAuth, DeviceAuthentication, DeviceNamespaces, DeviceSigned,
};
use isomdl::definitions::helpers::{NonEmptyVec, Tag24};
use isomdl::definitions::issuer_signed::IssuerSigned;
use isomdl::definitions::mso::DigestAlgorithm;
use isomdl::definitions::x509::X5Chain;
use isomdl::definitions::ValidityInfo;
use isomdl::issuance::Mdoc;
use mdl_verify::{IacaAnchor, SessionTranscript};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use p256::PublicKey;

pub const DS_CERT: &str = include_str!("../fixtures/ds-cert.pem");
pub const DS_KEY: &str = include_str!("../fixtures/ds-key.pem");
pub const IACA_CERT: &str = include_str!("../fixtures/iaca-cert.pem");
pub const OTHER_IACA_CERT: &str = include_str!("../fixtures/other-iaca-cert.pem");

/// Verification time for every test.
///
/// Pinned rather than "now" because the Document Signer certificate is short-lived
/// by design (Annex B caps DS validity at 457 days) — with a pinned time the
/// committed fixtures never age out. Regenerating the PKI means moving this.
pub fn test_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
}

fn odt(at: DateTime<Utc>) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(at.timestamp()).unwrap()
}

pub fn iaca_anchor() -> IacaAnchor {
    IacaAnchor::from_pem(IACA_CERT).expect("parse IACA fixture")
}

pub fn unrelated_anchor() -> IacaAnchor {
    IacaAnchor::from_pem(OTHER_IACA_CERT).expect("parse unrelated IACA fixture")
}

fn document_signer() -> SigningKey {
    SigningKey::from_pkcs8_pem(DS_KEY).expect("parse document signer key")
}

/// The holder's mdoc authentication key. Fixed so device-auth tests are reproducible.
pub fn device_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32].into()).expect("valid P-256 scalar")
}

fn device_cose_key(key: &SigningKey) -> CoseKey {
    let point = PublicKey::from(key.verifying_key()).to_encoded_point(false);
    CoseKey::EC2 {
        crv: EC2Curve::P256,
        x: point.x().expect("uncompressed point").to_vec(),
        y: EC2Y::Value(point.y().expect("uncompressed point").to_vec()),
    }
}

/// A plain "everything disclosed" element set.
pub fn full_elements() -> BTreeMap<String, ciborium::Value> {
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
    elements.insert("age_over_21".to_string(), ciborium::Value::Bool(true));
    elements.insert("age_over_18".to_string(), ciborium::Value::Bool(true));
    elements.insert(
        "portrait".to_string(),
        ciborium::Value::Bytes(vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]),
    );
    elements.insert(
        "driving_privileges".to_string(),
        ciborium::Value::Array(vec![ciborium::Value::Map(vec![(
            ciborium::Value::Text("vehicle_category_code".to_string()),
            ciborium::Value::Text("B".to_string()),
        )])]),
    );
    elements
}

/// What a bar gets asked to check: the age attestation and the portrait, and
/// nothing that would identify the holder further.
pub fn age_only_elements() -> BTreeMap<String, ciborium::Value> {
    let mut elements = BTreeMap::new();
    elements.insert("age_over_21".to_string(), ciborium::Value::Bool(true));
    elements.insert(
        "portrait".to_string(),
        ciborium::Value::Bytes(vec![0xff, 0xd8, 0xff, 0xe0]),
    );
    elements
}

/// How the MSO's validity window should sit relative to [`test_time`].
pub enum Validity {
    Current,
    Expired,
    NotYetValid,
}

pub struct ResponseBuilder {
    doc_type: String,
    elements: BTreeMap<String, ciborium::Value>,
    validity: Validity,
    transcript: SessionTranscript,
    device_auth: DeviceAuthKind,
}

pub enum DeviceAuthKind {
    /// A genuine `COSE_Sign1` by the device key over the transcript.
    Signature,
    /// A `COSE_Mac0` with a junk tag — enough to exercise the "this needs the
    /// reader's key" path without doing the ECDH.
    UnverifiableMac,
}

impl Default for ResponseBuilder {
    fn default() -> Self {
        Self {
            doc_type: mdl_verify::MDL_DOC_TYPE.to_string(),
            elements: full_elements(),
            validity: Validity::Current,
            transcript: transcript("nonce-from-the-verifier"),
            device_auth: DeviceAuthKind::Signature,
        }
    }
}

impl ResponseBuilder {
    pub fn doc_type(mut self, doc_type: &str) -> Self {
        self.doc_type = doc_type.to_string();
        self
    }

    pub fn elements(mut self, elements: BTreeMap<String, ciborium::Value>) -> Self {
        self.elements = elements;
        self
    }

    pub fn validity(mut self, validity: Validity) -> Self {
        self.validity = validity;
        self
    }

    pub fn transcript(mut self, transcript: SessionTranscript) -> Self {
        self.transcript = transcript;
        self
    }

    pub fn device_auth(mut self, kind: DeviceAuthKind) -> Self {
        self.device_auth = kind;
        self
    }

    /// Issue, assemble and encode the `DeviceResponse`.
    pub fn build(self) -> Vec<u8> {
        let response = self.build_response();
        cbor::to_vec(&response).expect("encode DeviceResponse")
    }

    pub fn build_response(self) -> DeviceResponse {
        let at = test_time();
        let (valid_from, valid_until) = match self.validity {
            Validity::Current => (
                at - chrono::Duration::days(1),
                at + chrono::Duration::days(30),
            ),
            Validity::Expired => (
                at - chrono::Duration::days(30),
                at - chrono::Duration::days(1),
            ),
            Validity::NotYetValid => (
                at + chrono::Duration::days(1),
                at + chrono::Duration::days(30),
            ),
        };

        let validity_info = ValidityInfo {
            signed: odt(at - chrono::Duration::days(1)),
            valid_from: odt(valid_from),
            valid_until: odt(valid_until),
            expected_update: None,
        };

        let device_key = device_key();
        let device_key_info = DeviceKeyInfo {
            device_key: device_cose_key(&device_key),
            key_authorizations: None,
            key_info: None,
        };

        let mut namespaces = BTreeMap::new();
        namespaces.insert(mdl_verify::ISO_NAMESPACE.to_string(), self.elements);

        let x5chain = X5Chain::builder()
            .with_pem_certificate(DS_CERT.as_bytes())
            .expect("load DS certificate")
            .build()
            .expect("build x5chain");

        let mdoc = Mdoc::builder()
            .doc_type(self.doc_type.clone())
            .namespaces(namespaces)
            .validity_info(validity_info)
            .digest_algorithm(DigestAlgorithm::SHA256)
            .device_key_info(device_key_info)
            .issue::<SigningKey, Signature>(x5chain, document_signer())
            .expect("issue mdoc");

        let device_namespaces: DeviceNamespaces = BTreeMap::new();
        let device_namespaces_bytes = Tag24::new(device_namespaces).expect("encode namespaces");

        let device_auth = match self.device_auth {
            DeviceAuthKind::Signature => {
                let payload = cbor::to_vec(
                    &Tag24::new(DeviceAuthentication::new(
                        self.transcript.clone(),
                        self.doc_type.clone(),
                        device_namespaces_bytes.clone(),
                    ))
                    .expect("encode DeviceAuthentication"),
                )
                .expect("encode DeviceAuthentication bytes");

                let protected = coset::HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::ES256)
                    .build();

                let sign1 = coset::CoseSign1Builder::new()
                    .protected(protected)
                    .create_detached_signature(&payload, &[], |data| {
                        let signature: Signature = device_key.sign(data);
                        signature.to_vec()
                    })
                    .build();

                DeviceAuth::DeviceSignature(MaybeTagged::new(false, sign1))
            }
            DeviceAuthKind::UnverifiableMac => {
                let protected = coset::HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::HMAC_256_256)
                    .build();

                let mac0 = coset::CoseMac0Builder::new()
                    .protected(protected)
                    .tag(vec![0u8; 32])
                    .build();

                DeviceAuth::DeviceMac(MaybeTagged::new(false, mac0))
            }
        };

        let document = Document {
            doc_type: self.doc_type,
            issuer_signed: IssuerSigned {
                namespaces: Some(mdoc.namespaces),
                issuer_auth: mdoc.issuer_auth,
            },
            device_signed: DeviceSigned {
                namespaces: device_namespaces_bytes,
                device_auth,
            },
            errors: None,
        };

        DeviceResponse {
            version: "1.0".to_string(),
            documents: Some(NonEmptyVec::new(document)),
            document_errors: None,
            status: Status::OK,
        }
    }
}

/// A minimal ISO 18013-7 style transcript: no device engagement, no reader key,
/// a handover that commits to the verifier's nonce.
pub fn transcript(nonce: &str) -> SessionTranscript {
    SessionTranscript::openid4vp_handover(&[0xaa; 32], &[0xbb; 32], nonce)
        .expect("build session transcript")
}

/// Re-encode a response after mutating it.
pub fn encode(response: &DeviceResponse) -> Vec<u8> {
    cbor::to_vec(response).expect("encode DeviceResponse")
}
