//! Passive Authentication (ICAO 9303 part 11, §5.1) — is the data genuine?
//!
//! EF.SOD is a CMS `SignedData` (RFC 5652). It carries an *LDS Security Object*: the
//! hash of every data group, signed by a **Document Signer**. The Document Signer's
//! certificate is signed by the issuing country's **CSCA**. So the chain is:
//!
//! ```text
//! CSCA  ──signs──▶  Document Signer Cert  ──signs──▶  LDS Security Object  ──hashes──▶  DG1, DG2, …
//! (you trust it)     (carried in EF.SOD)              (carried in EF.SOD)
//! ```
//!
//! [`verify`] walks it end to end:
//!
//! 1. hash each data group you read and match it to the value SOD attests to,
//! 2. verify the Document Signer's signature over the security object,
//! 3. verify the Document Signer certificate against a CSCA you supply.
//!
//! Only then is the data proven issued-by-that-country and unmodified. **PA is not
//! AA**: it says nothing about whether the chip is a clone (a copy passes PA) — pair
//! it with [`super::active`].
//!
//! ## Trust anchor
//!
//! Step 3 needs the CSCA certificates for the issuing country, from the ICAO PKD
//! masterlist. This library does not ship a trust store — you pass one in. With no
//! anchors, [`verify`] does steps 1–2 and reports [`ChainStatus::Unverified`], which a
//! caller must not treat as authentic.

use std::collections::BTreeMap;

use thiserror::Error;

use super::der;
use super::rsa::RsaPublicKey;
use super::HashAlgo;

/// id-signedData — 1.2.840.113549.1.7.2
const OID_SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];
/// id-contentType attribute — 1.2.840.113549.1.9.3
const OID_CONTENT_TYPE: &[u64] = &[1, 2, 840, 113549, 1, 9, 3];
/// id-messageDigest attribute — 1.2.840.113549.1.9.4
const OID_MESSAGE_DIGEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 4];
/// rsaEncryption — 1.2.840.113549.1.1.1
const OID_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
/// id-ecPublicKey — 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PassiveAuthError {
    #[error("EF.SOD is not a well-formed CMS SignedData")]
    MalformedSod,

    #[error("the LDS security object could not be parsed")]
    MalformedSecurityObject,

    #[error("unsupported or unknown hash algorithm in EF.SOD")]
    UnsupportedHash,

    #[error("EF.SOD names no signer")]
    NoSigner,

    #[error("the Document Signer certificate could not be parsed")]
    MalformedCertificate,

    #[error("unsupported Document Signer key algorithm")]
    UnsupportedKey,

    /// A data group's hash does not match EF.SOD — that group has been altered.
    #[error("data group {0} does not match the value in EF.SOD")]
    DataGroupHashMismatch(u8),

    /// The Document Signer's signature over the security object is invalid.
    #[error("the EF.SOD signature is not valid for the Document Signer certificate")]
    BadDocumentSignature,

    #[error("the signed message digest does not match the security object")]
    BadSignedAttributes,
}

/// How far the trust chain was verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// The Document Signer certificate verified against one of the supplied CSCA
    /// anchors — a full chain. Carries the subject of the CSCA that anchored it.
    Trusted { csca_subject: Vec<u8> },
    /// EF.SOD is internally consistent (data-group hashes and the signer's signature
    /// both check out) but no supplied CSCA signed the Document Signer — or none were
    /// supplied. **Not** proof of authenticity.
    Unverified,
}

/// The result of a passive-authentication pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassiveAuth {
    /// Every data group whose hash matched EF.SOD (e.g. `1`, `2`).
    pub verified_groups: Vec<u8>,
    /// How far the certificate chain was established.
    pub chain: ChainStatus,
}

impl PassiveAuth {
    /// Fully authentic: hashes matched, the signer's signature is valid, and the
    /// Document Signer chained to a trusted CSCA.
    pub fn is_authentic(&self) -> bool {
        matches!(self.chain, ChainStatus::Trusted { .. })
    }
}

/// A trust anchor: a CSCA certificate's subject and public key.
///
/// Build these from your CSCA masterlist with [`TrustAnchor::from_certificate`].
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    subject: Vec<u8>,
    key: PublicKey,
}

impl TrustAnchor {
    /// Parse a DER X.509 CSCA certificate into an anchor.
    pub fn from_certificate(der_cert: &[u8]) -> Result<Self, PassiveAuthError> {
        let cert = Certificate::parse(der_cert)?;
        Ok(Self {
            subject: cert.subject.to_vec(),
            key: cert.public_key,
        })
    }
}

/// A data group you read off the chip, ready to be hashed against EF.SOD. `number` is
/// the DG number (1 for EF.DG1, 2 for EF.DG2, …); `bytes` is the raw file content.
pub struct DataGroup<'a> {
    pub number: u8,
    pub bytes: &'a [u8],
}

/// Passively authenticate a chip read.
///
/// `sod` is the raw EF.SOD file. `groups` are the data groups to check. `anchors` are
/// the CSCA certificates you trust — pass an empty slice to run steps 1–2 only and get
/// [`ChainStatus::Unverified`].
///
/// `Ok` means the data-group hashes matched and the Document Signer's signature is
/// valid; inspect [`PassiveAuth::chain`] (or call [`PassiveAuth::is_authentic`]) for
/// whether the chain reached a trusted CSCA. `Err` means EF.SOD is inconsistent — a
/// tampered or forged document.
pub fn verify(
    sod: &[u8],
    groups: &[DataGroup<'_>],
    anchors: &[TrustAnchor],
) -> Result<PassiveAuth, PassiveAuthError> {
    let signed = SignedData::parse(sod)?;
    let lds = LdsSecurityObject::parse(&signed.encap_content)?;

    // 1. every supplied data group must match its hash in EF.SOD
    let mut verified_groups = Vec::new();
    for dg in groups {
        let expected = lds
            .hashes
            .get(&dg.number)
            .ok_or(PassiveAuthError::DataGroupHashMismatch(dg.number))?;
        if &lds.hash_algo.digest(dg.bytes) != expected {
            return Err(PassiveAuthError::DataGroupHashMismatch(dg.number));
        }
        verified_groups.push(dg.number);
    }
    verified_groups.sort_unstable();

    // 2. the Document Signer signed the security object.
    //
    // With signed attributes present (the common case) the signature is over the
    // attributes, not the eContent directly — but one of those attributes is the
    // messageDigest, which must equal the hash of the eContent. So check that binding,
    // then verify the signature over the attributes. Without signed attributes, the
    // signature is over the eContent itself.
    let dsc = Certificate::parse(&signed.signer_cert)?;
    let signed_message = match &signed.signed_attrs {
        Some(attrs) => {
            let want = signed.digest_algo.digest(&signed.encap_content);
            if attrs.message_digest != want || !attrs.has_content_type {
                return Err(PassiveAuthError::BadSignedAttributes);
            }
            attrs.der.clone()
        }
        None => signed.encap_content.clone(),
    };

    if !dsc
        .public_key
        .verify(signed.signature_hash, &signed_message, &signed.signature)
    {
        return Err(PassiveAuthError::BadDocumentSignature);
    }

    // 3. the CSCA signed the Document Signer certificate
    let chain = anchors
        .iter()
        .find(|a| {
            a.subject == dsc.issuer && a.key.verify(dsc.signature_hash, dsc.tbs, &dsc.signature)
        })
        .map(|a| ChainStatus::Trusted {
            csca_subject: a.subject.clone(),
        })
        .unwrap_or(ChainStatus::Unverified);

    Ok(PassiveAuth {
        verified_groups,
        chain,
    })
}

// ---------------------------------------------------------------------------
// CMS SignedData
// ---------------------------------------------------------------------------

struct SignedData {
    /// The signer's digestAlgorithm — the hash bound into messageDigest.
    digest_algo: HashAlgo,
    /// The hash the DSC signature is computed with.
    signature_hash: HashAlgo,
    encap_content: Vec<u8>,
    signer_cert: Vec<u8>,
    signed_attrs: Option<SignedAttrs>,
    signature: Vec<u8>,
}

struct SignedAttrs {
    /// The attributes re-encoded for signing: an explicit SET OF (tag 0x31), per
    /// RFC 5652 §5.4 — not the `[0] IMPLICIT` form they appear as in the message.
    der: Vec<u8>,
    message_digest: Vec<u8>,
    has_content_type: bool,
}

impl SignedData {
    fn parse(sod: &[u8]) -> Result<Self, PassiveAuthError> {
        let e = || PassiveAuthError::MalformedSod;

        // EF.SOD wraps the CMS in an [APPLICATION 23] tag (0x77).
        let cms = match der::next(sod).ok_or(PassiveAuthError::MalformedSod)? {
            (0x77, inner, _) => inner,
            _ => sod, // tolerate a bare ContentInfo
        };

        // ContentInfo ::= SEQUENCE { contentType OID, content [0] SignedData }
        let ci = der::expect(cms, der::SEQUENCE).ok_or(PassiveAuthError::MalformedSod)?;
        let (oid, after_oid) = der::take(ci, der::OID).ok_or(PassiveAuthError::MalformedSod)?;
        if der::oid_arcs(oid).as_deref() != Some(OID_SIGNED_DATA) {
            return Err(PassiveAuthError::MalformedSod);
        }
        let (_, explicit, _) = der::next(after_oid).ok_or(PassiveAuthError::MalformedSod)?; // [0]
        let sd = der::expect(explicit, der::SEQUENCE).ok_or(PassiveAuthError::MalformedSod)?;

        // SignedData ::= SEQUENCE {
        //   version, digestAlgorithms SET, encapContentInfo,
        //   certificates [0] OPT, crls [1] OPT, signerInfos SET }
        let (_version, r1) = der::take(sd, der::INTEGER).ok_or_else(e)?;
        let (_digest_algs, r2) = der::take(r1, der::SET).ok_or_else(e)?;
        let (encap, r3) = der::take(r2, der::SEQUENCE).ok_or_else(e)?;
        let encap_content = parse_encap_content(encap)?;

        // certificates [0] IMPLICIT, then optional crls [1], then signerInfos SET
        let mut rest = r3;
        let mut signer_cert = None;
        while let Some((tag, contents, tail)) = der::next(rest) {
            match tag {
                0xA0 => signer_cert = Some(first_certificate(contents)?),
                der::SET => {
                    let si = SignerInfo::parse(contents)?;
                    return Ok(SignedData {
                        digest_algo: si.digest_algo,
                        signature_hash: si.digest_algo,
                        encap_content,
                        signer_cert: signer_cert.ok_or(PassiveAuthError::MalformedCertificate)?,
                        signed_attrs: si.signed_attrs,
                        signature: si.signature,
                    });
                }
                _ => {} // crls [1] or anything else — skip
            }
            rest = tail;
        }
        Err(PassiveAuthError::NoSigner)
    }
}

struct SignerInfo {
    digest_algo: HashAlgo,
    signed_attrs: Option<SignedAttrs>,
    signature: Vec<u8>,
}

impl SignerInfo {
    /// SignerInfo ::= SEQUENCE {
    ///   version, sid, digestAlgorithm, signedAttrs [0] OPT,
    ///   signatureAlgorithm, signature OCTET STRING, unsignedAttrs [1] OPT }
    fn parse(set: &[u8]) -> Result<Self, PassiveAuthError> {
        let si = der::expect(set, der::SEQUENCE).ok_or(PassiveAuthError::NoSigner)?;
        let e = || PassiveAuthError::NoSigner;

        let (_version, r1) = der::take(si, der::INTEGER).ok_or_else(e)?;
        // sid — SEQUENCE (issuerAndSerialNumber) or [0] (subjectKeyIdentifier)
        let (_sid_tag, _sid, r2) = der::next(r1).ok_or(PassiveAuthError::NoSigner)?;
        let (digest_alg, r3) = der::take(r2, der::SEQUENCE).ok_or_else(e)?;
        let digest_algo = algo_hash(digest_alg)?;

        // signedAttrs [0] IMPLICIT, optional
        let (signed_attrs, r4) = match der::next(r3) {
            Some((0xA0, contents, tail)) => (Some(parse_signed_attrs(contents)?), tail),
            _ => (None, r3),
        };

        let (_sig_alg, r5) = der::take(r4, der::SEQUENCE).ok_or_else(e)?;
        let (signature, _) = der::take(r5, der::OCTET_STRING).ok_or_else(e)?;

        Ok(Self {
            digest_algo,
            signed_attrs,
            signature: signature.to_vec(),
        })
    }
}

/// The hash named by an AlgorithmIdentifier (SEQUENCE { OID, params OPT }).
fn algo_hash(alg: &[u8]) -> Result<HashAlgo, PassiveAuthError> {
    let (oid, _) = der::take(alg, der::OID).ok_or(PassiveAuthError::UnsupportedHash)?;
    let arcs = der::oid_arcs(oid).ok_or(PassiveAuthError::UnsupportedHash)?;
    HashAlgo::from_oid(&arcs).ok_or(PassiveAuthError::UnsupportedHash)
}

/// encapContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }
fn parse_encap_content(encap: &[u8]) -> Result<Vec<u8>, PassiveAuthError> {
    let (_ctype, after) = der::take(encap, der::OID).ok_or(PassiveAuthError::MalformedSod)?;
    let (_, explicit, _) = der::next(after).ok_or(PassiveAuthError::MalformedSod)?;
    let octets = der::expect(explicit, der::OCTET_STRING).ok_or(PassiveAuthError::MalformedSod)?;
    Ok(octets.to_vec())
}

/// certificates [0] holds one or more certs; take the first (the Document Signer).
fn first_certificate(contents: &[u8]) -> Result<Vec<u8>, PassiveAuthError> {
    let (_tag, cert, _rest) = der::next(contents).ok_or(PassiveAuthError::MalformedCertificate)?;
    // re-wrap as its own SEQUENCE TLV so Certificate::parse sees a whole cert
    let mut out = Vec::with_capacity(cert.len() + 4);
    out.push(der::SEQUENCE);
    push_len(&mut out, cert.len());
    out.extend_from_slice(cert);
    Ok(out)
}

/// Parse signedAttrs, and re-encode them as an explicit SET OF for signature
/// verification (RFC 5652 §5.4: the `[0]` tag is replaced by `0x31`).
fn parse_signed_attrs(implicit: &[u8]) -> Result<SignedAttrs, PassiveAuthError> {
    let mut message_digest = None;
    let mut has_content_type = false;

    let mut rest = implicit;
    while let Some((tag, attr, tail)) = der::next(rest) {
        if tag == der::SEQUENCE {
            // Attribute ::= SEQUENCE { attrType OID, attrValues SET }
            if let Some((oid, after)) = der::take(attr, der::OID) {
                match der::oid_arcs(oid).as_deref() {
                    Some(OID_MESSAGE_DIGEST) => {
                        message_digest = der::expect(after, der::SET)
                            .and_then(|v| der::expect(v, der::OCTET_STRING))
                            .map(<[u8]>::to_vec);
                    }
                    Some(OID_CONTENT_TYPE) => has_content_type = true,
                    _ => {}
                }
            }
        }
        rest = tail;
    }

    let mut der = vec![der::SET];
    push_len(&mut der, implicit.len());
    der.extend_from_slice(implicit);

    Ok(SignedAttrs {
        der,
        message_digest: message_digest.ok_or(PassiveAuthError::BadSignedAttributes)?,
        has_content_type,
    })
}

// ---------------------------------------------------------------------------
// LDS Security Object
// ---------------------------------------------------------------------------

struct LdsSecurityObject {
    hash_algo: HashAlgo,
    hashes: BTreeMap<u8, Vec<u8>>,
}

impl LdsSecurityObject {
    /// LDSSecurityObject ::= SEQUENCE {
    ///   version INTEGER, hashAlgorithm AlgorithmIdentifier,
    ///   dataGroupHashValues SEQUENCE OF DataGroupHash }
    fn parse(bytes: &[u8]) -> Result<Self, PassiveAuthError> {
        let e = || PassiveAuthError::MalformedSecurityObject;
        let seq =
            der::expect(bytes, der::SEQUENCE).ok_or(PassiveAuthError::MalformedSecurityObject)?;

        let (_version, r1) = der::take(seq, der::INTEGER).ok_or_else(e)?;
        let (hash_alg, r2) = der::take(r1, der::SEQUENCE).ok_or_else(e)?;
        let hash_algo = algo_hash(hash_alg)?;

        let (list, _) = der::take(r2, der::SEQUENCE).ok_or_else(e)?;
        let mut hashes = BTreeMap::new();
        let mut rest = list;
        while let Some((tag, dgh, tail)) = der::next(rest) {
            if tag == der::SEQUENCE {
                // DataGroupHash ::= SEQUENCE { number INTEGER, hash OCTET STRING }
                let (num, after) = der::take(dgh, der::INTEGER).ok_or_else(e)?;
                let (hash, _) = der::take(after, der::OCTET_STRING).ok_or_else(e)?;
                if let Some(&n) = num.last() {
                    hashes.insert(n, hash.to_vec());
                }
            }
            rest = tail;
        }
        if hashes.is_empty() {
            return Err(PassiveAuthError::MalformedSecurityObject);
        }
        Ok(Self { hash_algo, hashes })
    }
}

// ---------------------------------------------------------------------------
// X.509 (only what PA needs: issuer, subject, SPKI, TBS, signature)
// ---------------------------------------------------------------------------

/// One of the two eMRTD signature key kinds.
#[derive(Debug, Clone)]
enum PublicKey {
    Rsa(RsaPublicKey),
    EcP256(Vec<u8>),
}

impl PublicKey {
    /// Verify `sig` over `message` under `hash`.
    fn verify(&self, hash: HashAlgo, message: &[u8], sig: &[u8]) -> bool {
        match self {
            PublicKey::Rsa(k) => k.verify_pkcs1v15(hash, message, sig),
            PublicKey::EcP256(point) => verify_ec_p256(point, hash, message, sig),
        }
    }
}

fn verify_ec_p256(point: &[u8], hash: HashAlgo, message: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let Ok(key) = VerifyingKey::from_sec1_bytes(point) else {
        return false;
    };
    // eMRTD ECDSA signatures are DER-encoded in the certificate / SignerInfo
    let Ok(sig) = Signature::from_der(sig) else {
        return false;
    };
    key.verify_prehash(&hash.digest(message), &sig).is_ok()
}

struct Certificate<'a> {
    tbs: &'a [u8],
    issuer: Vec<u8>,
    subject: Vec<u8>,
    public_key: PublicKey,
    signature_hash: HashAlgo,
    signature: Vec<u8>,
}

impl<'a> Certificate<'a> {
    /// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature BIT STRING }
    fn parse(der_bytes: &'a [u8]) -> Result<Self, PassiveAuthError> {
        let e = || PassiveAuthError::MalformedCertificate;
        let body =
            der::expect(der_bytes, der::SEQUENCE).ok_or(PassiveAuthError::MalformedCertificate)?;

        // tbsCertificate — capture its raw TLV: that whole encoding is what was signed
        let (tbs_tag, tbs_inner, after_tbs) =
            der::next(body).ok_or(PassiveAuthError::MalformedCertificate)?;
        if tbs_tag != der::SEQUENCE {
            return Err(PassiveAuthError::MalformedCertificate);
        }
        let tbs = &body[..body.len() - after_tbs.len()];

        let (sig_alg, after_sig_alg) = der::take(after_tbs, der::SEQUENCE).ok_or_else(e)?;
        let signature_hash = sig_alg_hash(sig_alg)?;
        let (sig_bits, _) = der::take(after_sig_alg, der::BIT_STRING).ok_or_else(e)?;
        let signature = der::bit_string_bytes(sig_bits)
            .ok_or(PassiveAuthError::MalformedCertificate)?
            .to_vec();

        let (issuer, subject, public_key) = Self::parse_tbs(tbs_inner)?;
        Ok(Self {
            tbs,
            issuer,
            subject,
            public_key,
            signature_hash,
            signature,
        })
    }

    /// TBSCertificate ::= SEQUENCE {
    ///   [0] version OPT, serialNumber, signature, issuer Name, validity,
    ///   subject Name, subjectPublicKeyInfo, ... }
    fn parse_tbs(tbs: &[u8]) -> Result<(Vec<u8>, Vec<u8>, PublicKey), PassiveAuthError> {
        let e = || PassiveAuthError::MalformedCertificate;

        let rest = match der::next(tbs) {
            Some((0xA0, _, tail)) => tail, // optional [0] version
            _ => tbs,
        };
        let (_serial, r1) = der::take(rest, der::INTEGER).ok_or_else(e)?;
        let (_sigalg, r2) = der::take(r1, der::SEQUENCE).ok_or_else(e)?;
        let (issuer, r3) = der::take(r2, der::SEQUENCE).ok_or_else(e)?;
        let (_validity, r4) = der::take(r3, der::SEQUENCE).ok_or_else(e)?;
        let (subject, r5) = der::take(r4, der::SEQUENCE).ok_or_else(e)?;
        let (spki, _) = der::take(r5, der::SEQUENCE).ok_or_else(e)?;

        let public_key = Self::parse_spki(spki)?;
        Ok((issuer.to_vec(), subject.to_vec(), public_key))
    }

    /// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, key BIT STRING }
    fn parse_spki(spki: &[u8]) -> Result<PublicKey, PassiveAuthError> {
        let e = || PassiveAuthError::MalformedCertificate;
        let (alg, after_alg) = der::take(spki, der::SEQUENCE).ok_or_else(e)?;
        let (oid, _params) = der::take(alg, der::OID).ok_or_else(e)?;
        let arcs = der::oid_arcs(oid).ok_or(PassiveAuthError::MalformedCertificate)?;

        let (key_bits, _) = der::take(after_alg, der::BIT_STRING).ok_or_else(e)?;
        let key_bytes =
            der::bit_string_bytes(key_bits).ok_or(PassiveAuthError::MalformedCertificate)?;

        if arcs == OID_RSA {
            RsaPublicKey::from_pkcs1_der(key_bytes)
                .map(PublicKey::Rsa)
                .ok_or(PassiveAuthError::UnsupportedKey)
        } else if arcs == OID_EC_PUBLIC_KEY {
            // only P-256 today (uncompressed 65 / compressed 33 SEC1 point)
            if matches!(key_bytes.len(), 33 | 65) {
                Ok(PublicKey::EcP256(key_bytes.to_vec()))
            } else {
                Err(PassiveAuthError::UnsupportedKey)
            }
        } else {
            Err(PassiveAuthError::UnsupportedKey)
        }
    }
}

/// The hash from a signatureAlgorithm OID (e.g. sha256WithRSAEncryption, ecdsa-with-SHA256).
fn sig_alg_hash(alg: &[u8]) -> Result<HashAlgo, PassiveAuthError> {
    let (oid, _) = der::take(alg, der::OID).ok_or(PassiveAuthError::UnsupportedHash)?;
    let arcs = der::oid_arcs(oid).ok_or(PassiveAuthError::UnsupportedHash)?;
    match arcs.as_slice() {
        // sha{1,224,256,384,512}WithRSAEncryption — 1.2.840.113549.1.1.{5,14,11,12,13}
        [1, 2, 840, 113549, 1, 1, 5] => Ok(HashAlgo::Sha1),
        [1, 2, 840, 113549, 1, 1, 14] => Ok(HashAlgo::Sha224),
        [1, 2, 840, 113549, 1, 1, 11] => Ok(HashAlgo::Sha256),
        [1, 2, 840, 113549, 1, 1, 12] => Ok(HashAlgo::Sha384),
        [1, 2, 840, 113549, 1, 1, 13] => Ok(HashAlgo::Sha512),
        // ecdsa-with-SHA{1,224,256,384,512} — 1.2.840.10045.4.{1,3.1,3.2,3.3,3.4}
        [1, 2, 840, 10045, 4, 1] => Ok(HashAlgo::Sha1),
        [1, 2, 840, 10045, 4, 3, 1] => Ok(HashAlgo::Sha224),
        [1, 2, 840, 10045, 4, 3, 2] => Ok(HashAlgo::Sha256),
        [1, 2, 840, 10045, 4, 3, 3] => Ok(HashAlgo::Sha384),
        [1, 2, 840, 10045, 4, 3, 4] => Ok(HashAlgo::Sha512),
        _ => Err(PassiveAuthError::UnsupportedHash),
    }
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len < 0x1_0000 {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
    } else {
        out.extend_from_slice(&[
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_lds(groups: &[(u8, &[u8])]) -> Vec<u8> {
        let mut dgh_list = Vec::new();
        for (n, data) in groups {
            let h = HashAlgo::Sha256.digest(data);
            let mut inner = vec![der::INTEGER, 0x01, *n, der::OCTET_STRING];
            push_len(&mut inner, h.len());
            inner.extend_from_slice(&h);
            let mut seq = vec![der::SEQUENCE];
            push_len(&mut seq, inner.len());
            seq.extend_from_slice(&inner);
            dgh_list.extend_from_slice(&seq);
        }
        let sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let mut alg = vec![der::OID, sha256_oid.len() as u8];
        alg.extend_from_slice(&sha256_oid);
        let mut alg_seq = vec![der::SEQUENCE];
        push_len(&mut alg_seq, alg.len());
        alg_seq.extend_from_slice(&alg);
        let mut list_seq = vec![der::SEQUENCE];
        push_len(&mut list_seq, dgh_list.len());
        list_seq.extend_from_slice(&dgh_list);
        let mut body = vec![der::INTEGER, 0x01, 0x00];
        body.extend_from_slice(&alg_seq);
        body.extend_from_slice(&list_seq);
        let mut lds = vec![der::SEQUENCE];
        push_len(&mut lds, body.len());
        lds.extend_from_slice(&body);
        lds
    }

    #[test]
    fn lds_security_object_round_trips() {
        let lds = build_lds(&[(1, b"dg1 contents"), (2, b"dg2 contents")]);
        let parsed = LdsSecurityObject::parse(&lds).unwrap();
        assert_eq!(parsed.hash_algo, HashAlgo::Sha256);
        assert_eq!(parsed.hashes[&1], HashAlgo::Sha256.digest(b"dg1 contents"));
        assert_eq!(parsed.hashes[&2], HashAlgo::Sha256.digest(b"dg2 contents"));
    }

    #[test]
    fn a_tampered_data_group_is_caught() {
        let lds = build_lds(&[(1, b"genuine dg1")]);
        let so = LdsSecurityObject::parse(&lds).unwrap();
        assert_eq!(so.hashes[&1], HashAlgo::Sha256.digest(b"genuine dg1"));
        assert_ne!(so.hashes[&1], HashAlgo::Sha256.digest(b"tampered dg1"));
    }

    #[test]
    fn sig_alg_oids_map_to_hashes() {
        let rsa256 = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
        let mut alg = vec![der::OID, rsa256.len() as u8];
        alg.extend_from_slice(&rsa256);
        assert_eq!(sig_alg_hash(&alg).unwrap(), HashAlgo::Sha256);

        let ec384 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
        let mut alg = vec![der::OID, ec384.len() as u8];
        alg.extend_from_slice(&ec384);
        assert_eq!(sig_alg_hash(&alg).unwrap(), HashAlgo::Sha384);
    }

    #[test]
    fn malformed_sod_is_rejected_cleanly() {
        assert_eq!(
            verify(&[], &[], &[]).unwrap_err(),
            PassiveAuthError::MalformedSod
        );
        assert_eq!(
            verify(&[0x30, 0x00], &[], &[]).unwrap_err(),
            PassiveAuthError::MalformedSod
        );
        assert_eq!(
            verify(&[0x77, 0x01, 0x00], &[], &[]).unwrap_err(),
            PassiveAuthError::MalformedSod
        );
    }
}
