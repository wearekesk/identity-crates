//! Aadhaar **Paperless Offline e-KYC** (UIDAI) — the share-phrase-protected
//! ZIP/XML the holder downloads from myAadhaar.
//!
//! Pipeline: ZIP (password = share phrase) → `OfflinePaperlessKyc` XML → fields
//! ([`OfflineEkyc`]) → UIDAI RSA digital-signature verification → optional
//! mobile/email hash checks.
//!
//! Spec: <https://uidai.gov.in/> "Aadhaar Paperless Offline e-KYC". The XML is
//! enveloped-signed (RSA-SHA1, SHA-256 digest) by a UIDAI document-signer cert;
//! the production certs are embedded below.

use crate::data::Gender;
use crate::error::AadhaarError;
use base64::Engine as _;
use chrono::NaiveDate;
use std::io::Read as _;

/// Embedded UIDAI document-signer certificates (public), newest first. We trust
/// the **public keys** here as pinned roots, so an *expired* cert does not break
/// verification (the key still validates signatures it made). Keep this list
/// current — add UIDAI's latest signer cert as they rotate, so freshly downloaded
/// e-KYC documents still verify.
const UIDAI_CERTS: &[&str] = &[
    include_str!("../certs/uidai_prod_2023.pem"),
    include_str!("../certs/uidai_prod.pem"),
];

/// Parsed Aadhaar Paperless Offline e-KYC record.
#[derive(Debug, Clone)]
pub struct OfflineEkyc {
    /// `referenceId` = last-4 Aadhaar digits + download timestamp.
    pub reference_id: String,
    pub name: String,
    pub dob: Option<NaiveDate>,
    pub gender: Option<Gender>,
    // address (Poa)
    pub care_of: Option<String>,
    pub country: Option<String>,
    pub district: Option<String>,
    pub house: Option<String>,
    pub location: Option<String>,
    pub pincode: Option<String>,
    pub post_office: Option<String>,
    pub state: Option<String>,
    pub street: Option<String>,
    pub sub_district: Option<String>,
    pub village_town_city: Option<String>,
    /// Photo (JP2000 / JPEG-2000 bytes) — low resolution.
    pub photo_jp2000: Option<Vec<u8>>,
    /// Hashed mobile (`m` attr) — verify with [`verify_mobile`].
    pub mobile_hash: Option<String>,
    /// Hashed email (`e` attr) — verify with [`verify_email`].
    pub email_hash: Option<String>,
    /// True iff the UIDAI signature verified against an embedded cert.
    pub signature_verified: bool,
}

/// Last-4 of the Aadhaar is the first 4 chars of `referenceId`; the **last digit**
/// drives the mobile/email hash iteration count (0 ⇒ 1).
fn aadhaar_last_digit(reference_id: &str) -> u32 {
    reference_id
        .chars()
        .nth(3)
        .and_then(|c| c.to_digit(10))
        .unwrap_or(1)
}

/// Decrypt the share-phrase-protected ZIP and return the inner XML string.
pub fn decrypt_offline_zip(zip_bytes: &[u8], share_phrase: &str) -> Result<String, AadhaarError> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| AadhaarError::Zip(e.to_string()))?;
    // the offline pack holds a single XML entry
    let mut file = archive
        .by_index_decrypt(0, share_phrase.as_bytes())
        .map_err(|e| AadhaarError::Zip(e.to_string()))?;
    let mut xml = String::new();
    file.read_to_string(&mut xml)
        .map_err(|e| AadhaarError::Zip(e.to_string()))?;
    Ok(xml)
}

/// Parse the `OfflinePaperlessKyc` XML into fields (does **not** verify the signature).
pub fn parse_offline_xml(xml: &str) -> Result<OfflineEkyc, AadhaarError> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| AadhaarError::Xml(e.to_string()))?;
    let root = doc.root_element();
    if root.tag_name().name() != "OfflinePaperlessKyc" {
        return Err(AadhaarError::Xml("root is not OfflinePaperlessKyc".into()));
    }
    let reference_id = root
        .attribute("referenceId")
        .unwrap_or_default()
        .to_string();
    let uid = root
        .children()
        .find(|n| n.has_tag_name("UidData"))
        .ok_or_else(|| AadhaarError::Xml("missing UidData".into()))?;
    let poi = uid.children().find(|n| n.has_tag_name("Poi"));
    let poa = uid.children().find(|n| n.has_tag_name("Poa"));
    let pht = uid.children().find(|n| n.has_tag_name("Pht"));

    let attr = |node: &Option<roxmltree::Node>, k: &str| -> Option<String> {
        node.and_then(|n| n.attribute(k))
            .filter(|s| !s.is_empty())
            .map(String::from)
    };

    let photo_jp2000 = pht
        .and_then(|p| p.text())
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok());

    Ok(OfflineEkyc {
        reference_id,
        name: attr(&poi, "name").unwrap_or_default(),
        dob: attr(&poi, "dob").as_deref().and_then(parse_offline_dob),
        gender: attr(&poi, "gender").as_deref().and_then(parse_gender),
        care_of: attr(&poa, "careof"),
        country: attr(&poa, "country"),
        district: attr(&poa, "dist"),
        house: attr(&poa, "house"),
        location: attr(&poa, "loc"),
        pincode: attr(&poa, "pc"),
        post_office: attr(&poa, "po"),
        state: attr(&poa, "state"),
        street: attr(&poa, "street"),
        sub_district: attr(&poa, "subdist"),
        village_town_city: attr(&poa, "vtc"),
        photo_jp2000,
        mobile_hash: attr(&poi, "m"),
        email_hash: attr(&poi, "e"),
        signature_verified: false,
    })
}

/// Full path: decrypt the ZIP, parse the XML, and verify the UIDAI signature.
pub fn parse_offline_ekyc(
    zip_bytes: &[u8],
    share_phrase: &str,
) -> Result<OfflineEkyc, AadhaarError> {
    let xml = decrypt_offline_zip(zip_bytes, share_phrase)?;
    let mut ekyc = parse_offline_xml(&xml)?;
    ekyc.signature_verified = verify_signature(&xml).unwrap_or(false);
    Ok(ekyc)
}

fn parse_gender(g: &str) -> Option<Gender> {
    match g.trim().to_ascii_uppercase().as_str() {
        "M" => Some(Gender::Male),
        "F" => Some(Gender::Female),
        "T" => Some(Gender::Transgender),
        _ => None,
    }
}

/// DOB in `DDMMYYYY` or `YYYY` (year-only ⇒ Jan 1).
fn parse_offline_dob(dob: &str) -> Option<NaiveDate> {
    let d = dob.trim();
    if d.len() == 8 {
        NaiveDate::parse_from_str(d, "%d%m%Y").ok()
    } else if d.len() == 4 {
        d.parse::<i32>()
            .ok()
            .and_then(|y| NaiveDate::from_ymd_opt(y, 1, 1))
    } else {
        // also accept ISO DD-MM-YYYY just in case
        NaiveDate::parse_from_str(d, "%d-%m-%Y").ok()
    }
}

/// Mobile/email hash per UIDAI: `sha256` of `value || share_phrase`, then re-hashed
/// so the total count of SHA-256 applications equals the Aadhaar's last digit
/// (0 ⇒ 1). Hex, lower-case.
fn contact_hash(value: &str, share_phrase: &str, reference_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let n = aadhaar_last_digit(reference_id).max(1);
    let mut h = Sha256::digest(format!("{value}{share_phrase}").as_bytes()).to_vec();
    for _ in 1..n {
        h = Sha256::digest(&h).to_vec();
    }
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify a claimed mobile number against the offline e-KYC `m` hash.
pub fn verify_mobile(ekyc: &OfflineEkyc, mobile: &str, share_phrase: &str) -> bool {
    ekyc.mobile_hash.as_deref().is_some_and(|h| {
        h.eq_ignore_ascii_case(&contact_hash(mobile, share_phrase, &ekyc.reference_id))
    })
}

/// Verify a claimed email against the offline e-KYC `e` hash.
pub fn verify_email(ekyc: &OfflineEkyc, email: &str, share_phrase: &str) -> bool {
    ekyc.email_hash.as_deref().is_some_and(|h| {
        h.eq_ignore_ascii_case(&contact_hash(email, share_phrase, &ekyc.reference_id))
    })
}

/// Verify the enveloped XML signature against the embedded UIDAI certs.
///
/// Uses [`xml_sec`] (pure-Rust XML-DSig) which performs the **full** check —
/// canonicalization (C14N), the RSA-SHA1 signature over `<SignedInfo>`, **and**
/// every `<Reference>`/`<DigestValue>` against the actual signed document — so a
/// `SignedInfo`+`SignatureValue` lifted from another document will not verify
/// (no signature-replay). Returns `Ok(true)` only when a UIDAI key validates it.
pub fn verify_signature(xml: &str) -> Result<bool, AadhaarError> {
    for cert_pem in UIDAI_CERTS {
        let Ok(pubkey_pem) = cert_public_key_pem(cert_pem) else {
            continue;
        };
        if let Ok(res) = xml_sec::xmldsig::verify_signature_with_pem_key(xml, &pubkey_pem, false) {
            if matches!(res.status, xml_sec::xmldsig::DsigStatus::Valid) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Extract the SubjectPublicKeyInfo from an X.509 PEM cert and re-encode it as a
/// `PUBLIC KEY` PEM (the form xml-sec's verifier consumes).
fn cert_public_key_pem(cert_pem: &str) -> Result<String, AadhaarError> {
    use base64::Engine;
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| AadhaarError::Signature(e.to_string()))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| AadhaarError::Signature(e.to_string()))?;
    let spki_der = cert.public_key().raw;
    let b64 = base64::engine::general_purpose::STANDARD.encode(spki_der);
    let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END PUBLIC KEY-----\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<OfflinePaperlessKyc referenceId="363220181001134543123">
<UidData>
<Poi dob="01-01-1990" gender="M" name="Anand Kumar" e="" m="abc123"/>
<Poa careof="S/O: Ram" country="India" dist="Bangalore" house="12" loc="BTM" pc="560076" po="BTM Layout" state="Karnataka" street="1st Main" subdist="South" vtc="Bangalore"/>
<Pht>aGVsbG8=</Pht>
</UidData>
</OfflinePaperlessKyc>"#;

    #[test]
    fn parses_offline_xml_fields() {
        let e = parse_offline_xml(SAMPLE).unwrap();
        assert_eq!(e.reference_id, "363220181001134543123");
        assert_eq!(e.name, "Anand Kumar");
        assert_eq!(e.gender, Some(Gender::Male));
        assert_eq!(e.state.as_deref(), Some("Karnataka"));
        assert_eq!(e.pincode.as_deref(), Some("560076"));
        assert_eq!(e.photo_jp2000.as_deref(), Some(&b"hello"[..])); // base64 "aGVsbG8="
        assert_eq!(e.mobile_hash.as_deref(), Some("abc123"));
        assert!(e.email_hash.is_none()); // empty attr → None
        assert!(!e.signature_verified);
    }

    #[test]
    fn mobile_hash_roundtrips() {
        // reference_id last digit (idx 3) = '2' → 2 SHA-256 applications
        let e = parse_offline_xml(SAMPLE).unwrap();
        let expected = contact_hash("9999999999", "Lock@487", &e.reference_id);
        let e2 = OfflineEkyc {
            mobile_hash: Some(expected),
            ..e
        };
        assert!(verify_mobile(&e2, "9999999999", "Lock@487"));
        assert!(!verify_mobile(&e2, "8888888888", "Lock@487"));
    }

    #[test]
    fn uidai_certs_yield_public_key_pem() {
        for pem in UIDAI_CERTS {
            let pk = cert_public_key_pem(pem).expect("cert -> public key PEM");
            assert!(pk.contains("BEGIN PUBLIC KEY") && pk.contains("END PUBLIC KEY"));
        }
    }
}
