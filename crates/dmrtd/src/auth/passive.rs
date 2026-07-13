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
/// prime256v1 / NIST P-256 named curve — 1.2.840.10045.3.1.7
const OID_EC_P256: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
/// id-icao-mrtd-security-ldsSecurityObject — 2.23.136.1.1.1 (EF.SOD eContentType)
const OID_LDS_SECURITY_OBJECT: &[u64] = &[2, 23, 136, 1, 1, 1];
/// RSA PKCS#1 signature-algorithm OID prefix — 1.2.840.113549.1.1.*
const OID_RSA_SIG_PREFIX: &[u64] = &[1, 2, 840, 113549, 1, 1];
/// ECDSA signature-algorithm OID prefix — 1.2.840.10045.4.*
const OID_ECDSA_SIG_PREFIX: &[u64] = &[1, 2, 840, 10045, 4];

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
    // EF.SOD's encapsulated content must actually be an LDS security object — a
    // SignedData wrapping some other content type is not a passport SOD.
    if signed.content_type != OID_LDS_SECURITY_OBJECT {
        return Err(PassiveAuthError::MalformedSod);
    }
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

    // The signatureAlgorithm the signer declared must match the DSC key it is
    // verified with — a SignerInfo declaring ECDSA can't be honoured by an RSA key.
    if !scheme_matches_key(&dsc.public_key, signed.sig_scheme) {
        return Err(PassiveAuthError::BadDocumentSignature);
    }

    let signed_message = match &signed.signed_attrs {
        Some(attrs) => {
            let want = signed.digest_algo.digest(&signed.encap_content);
            // messageDigest must equal the eContent hash, and the content-type
            // attribute must be present *and* equal the encapsulated eContentType
            // (RFC 5652 §5.3) — checking mere presence let a mismatch through.
            let content_type_ok = attrs.content_type.as_deref() == Some(&signed.content_type);
            if attrs.message_digest != want || !content_type_ok {
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

    // 3. the CSCA signed the Document Signer certificate — with a key whose scheme
    // matches the algorithm the DSC declares it was signed with.
    let chain = anchors
        .iter()
        .find(|a| {
            a.subject == dsc.issuer
                && scheme_matches_key(&a.key, dsc.sig_scheme)
                && a.key.verify(dsc.signature_hash, dsc.tbs, &dsc.signature)
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

/// Which signature scheme the SignerInfo declares — cross-checked against the DSC key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigScheme {
    Rsa,
    Ecdsa,
}

struct SignedData {
    /// The signer's digestAlgorithm — the hash bound into messageDigest.
    digest_algo: HashAlgo,
    /// The hash the DSC signature is computed with (from the signatureAlgorithm).
    signature_hash: HashAlgo,
    /// The scheme the signatureAlgorithm declares — must match the DSC key kind.
    sig_scheme: SigScheme,
    content_type: Vec<u64>,
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
    /// The content-type attribute's value (its arcs), if the attribute was present.
    content_type: Option<Vec<u64>>,
}

/// How the SignerInfo names its certificate (RFC 5652 §5.3).
enum SignerId {
    IssuerAndSerial { issuer: Vec<u8>, serial: Vec<u8> },
    Ski(Vec<u8>),
}

impl SignedData {
    fn parse(sod: &[u8]) -> Result<Self, PassiveAuthError> {
        let e = || PassiveAuthError::MalformedSod;

        // EF.SOD wraps the CMS in an [APPLICATION 23] tag (0x77) with nothing after it.
        let cms = match der::next(sod).ok_or(PassiveAuthError::MalformedSod)? {
            (0x77, inner, []) => inner,
            (0x77, ..) => return Err(PassiveAuthError::MalformedSod),
            _ => sod, // tolerate a bare ContentInfo
        };

        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
        let ci = der::expect(cms, der::SEQUENCE).ok_or(PassiveAuthError::MalformedSod)?;
        let (oid, after_oid) = der::take(ci, der::OID).ok_or(PassiveAuthError::MalformedSod)?;
        if der::oid_arcs(oid).as_deref() != Some(OID_SIGNED_DATA) {
            return Err(PassiveAuthError::MalformedSod);
        }
        // the content field must be the [0] EXPLICIT context tag, and the only thing
        // left in the ContentInfo
        let explicit = match der::next(after_oid) {
            Some((0xA0, body, [])) => body,
            _ => return Err(PassiveAuthError::MalformedSod),
        };
        let sd = der::expect(explicit, der::SEQUENCE).ok_or(PassiveAuthError::MalformedSod)?;

        // SignedData ::= SEQUENCE {
        //   version, digestAlgorithms SET, encapContentInfo,
        //   certificates [0] OPT, crls [1] OPT, signerInfos SET }
        let (_version, r1) = der::take(sd, der::INTEGER).ok_or_else(e)?;
        let (_digest_algs, r2) = der::take(r1, der::SET).ok_or_else(e)?;
        let (encap, r3) = der::take(r2, der::SEQUENCE).ok_or_else(e)?;
        let (content_type, encap_content) = parse_encap_content(encap)?;

        // certificates [0] IMPLICIT, then optional crls [1], then signerInfos SET.
        // Every element must parse — a malformed tail is an error, not a silent stop.
        let mut rest = r3;
        let mut certs: Vec<Vec<u8>> = Vec::new();
        while !rest.is_empty() {
            let (tag, contents, tail) = der::next(rest).ok_or_else(e)?;
            match tag {
                0xA0 => certs = collect_certificates(contents)?,
                der::SET => {
                    let si = SignerInfo::parse(contents)?;
                    // Pick the certificate the signer names, not just the first one —
                    // a SOD may carry several and the DSC needn't be first.
                    let signer_cert = select_dsc(&certs, &si.sid)?;
                    return Ok(SignedData {
                        digest_algo: si.digest_algo,
                        signature_hash: si.signature_hash,
                        sig_scheme: si.sig_scheme,
                        content_type,
                        encap_content,
                        signer_cert,
                        signed_attrs: si.signed_attrs,
                        signature: si.signature,
                    });
                }
                0xA1 => {} // crls [1] — ignored
                _ => return Err(PassiveAuthError::MalformedSod),
            }
            rest = tail;
        }
        Err(PassiveAuthError::NoSigner)
    }
}

struct SignerInfo {
    sid: SignerId,
    digest_algo: HashAlgo,
    signature_hash: HashAlgo,
    sig_scheme: SigScheme,
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
        // sid — SEQUENCE (issuerAndSerialNumber) or [0] IMPLICIT (subjectKeyIdentifier)
        let (sid_tag, sid_body, r2) = der::next(r1).ok_or(PassiveAuthError::NoSigner)?;
        let sid = parse_sid(sid_tag, sid_body)?;
        let (digest_alg, r3) = der::take(r2, der::SEQUENCE).ok_or_else(e)?;
        let digest_algo = algo_hash(digest_alg)?;

        // signedAttrs [0] IMPLICIT, optional
        let (signed_attrs, r4) = match der::next(r3) {
            Some((0xA0, contents, tail)) => (Some(parse_signed_attrs(contents)?), tail),
            _ => (None, r3),
        };

        // signatureAlgorithm: names RSA vs ECDSA and (for RSA) the hash. Don't ignore
        // it — verifying with a scheme/hash the signer didn't declare would let a
        // mismatched algorithm through.
        let (sig_alg, r5) = der::take(r4, der::SEQUENCE).ok_or_else(e)?;
        let (sig_scheme, sig_alg_hash) = parse_sig_alg(sig_alg)?;
        // RSA signature OIDs name the hash; ECDSA-with-SHA* do too. Where the sig-alg
        // OID pins a hash it must agree with the digestAlgorithm.
        let signature_hash = match sig_alg_hash {
            Some(h) if h != digest_algo => return Err(PassiveAuthError::UnsupportedHash),
            Some(h) => h,
            None => digest_algo,
        };
        let (signature, _) = der::take(r5, der::OCTET_STRING).ok_or_else(e)?;

        Ok(Self {
            sid,
            digest_algo,
            signature_hash,
            sig_scheme,
            signed_attrs,
            signature: signature.to_vec(),
        })
    }
}

/// Parse the SignerInfo `sid`: `SEQUENCE { issuer, serial }` or `[0]` SKI.
fn parse_sid(tag: u8, body: &[u8]) -> Result<SignerId, PassiveAuthError> {
    match tag {
        der::SEQUENCE => {
            let (issuer, after) =
                der::take(body, der::SEQUENCE).ok_or(PassiveAuthError::NoSigner)?;
            let (serial, _) = der::take(after, der::INTEGER).ok_or(PassiveAuthError::NoSigner)?;
            Ok(SignerId::IssuerAndSerial {
                issuer: issuer.to_vec(),
                serial: serial.to_vec(),
            })
        }
        0x80 => Ok(SignerId::Ski(body.to_vec())),
        _ => Err(PassiveAuthError::NoSigner),
    }
}

/// The scheme and (optional) pinned hash named by a SignerInfo signatureAlgorithm.
fn parse_sig_alg(alg: &[u8]) -> Result<(SigScheme, Option<HashAlgo>), PassiveAuthError> {
    let (oid, params) = der::take(alg, der::OID).ok_or(PassiveAuthError::MalformedSod)?;
    let arcs = der::oid_arcs(oid).ok_or(PassiveAuthError::MalformedSod)?;

    // plain rsaEncryption (1.2.840.113549.1.1.1) names no hash; sha*WithRSAEncryption
    // and ecdsa-with-SHA* do. For any *other* prefixed OID the hash must be recognised
    // — propagate the error rather than dropping to an unpinned hash, so an algorithm
    // we don't honour (e.g. RSA-PSS, which is not PKCS#1 v1.5) can't be verified with
    // the wrong scheme.
    if arcs == OID_RSA {
        require_params_null_or_absent(params)?; // rsaEncryption: NULL/absent (RFC 4055)
        return Ok((SigScheme::Rsa, None));
    }
    if arcs.starts_with(OID_RSA_SIG_PREFIX) {
        require_params_null_or_absent(params)?; // sha*WithRSAEncryption: NULL/absent
        return Ok((SigScheme::Rsa, Some(sig_alg_hash(alg)?)));
    }
    if arcs.starts_with(OID_ECDSA_SIG_PREFIX) {
        require_params_absent(params)?; // ecdsa-with-SHA*: parameters absent (RFC 5758)
        return Ok((SigScheme::Ecdsa, Some(sig_alg_hash(alg)?)));
    }
    Err(PassiveAuthError::UnsupportedHash)
}

/// Select the Document Signer certificate the SignerInfo names.
///
/// The SID identifies the signer's certificate (RFC 5652 §5.3), so an unmatched SID is
/// a failure — even with a single certificate. No "just use the only cert" fallback:
/// that would honour a SignerInfo naming a certificate that isn't present.
fn select_dsc(certs: &[Vec<u8>], sid: &SignerId) -> Result<Vec<u8>, PassiveAuthError> {
    for der_cert in certs {
        let cert = Certificate::parse(der_cert)?;
        let hit = match sid {
            SignerId::IssuerAndSerial { issuer, serial } => {
                &cert.issuer == issuer && &cert.serial == serial
            }
            SignerId::Ski(ski) => cert.ski.as_deref() == Some(ski.as_slice()),
        };
        if hit {
            return Ok(der_cert.clone());
        }
    }
    Err(PassiveAuthError::MalformedCertificate)
}

/// The hash named by an AlgorithmIdentifier (SEQUENCE { OID, params OPT }).
fn algo_hash(alg: &[u8]) -> Result<HashAlgo, PassiveAuthError> {
    let (oid, params) = der::take(alg, der::OID).ok_or(PassiveAuthError::UnsupportedHash)?;
    // hash AlgorithmIdentifiers carry either NULL or absent parameters (RFC 4055) —
    // reject a stray trailing TLV in the parameters position.
    require_params_null_or_absent(params).map_err(|_| PassiveAuthError::UnsupportedHash)?;
    let arcs = der::oid_arcs(oid).ok_or(PassiveAuthError::UnsupportedHash)?;
    HashAlgo::from_oid(&arcs).ok_or(PassiveAuthError::UnsupportedHash)
}

/// AlgorithmIdentifier parameters: absent, or a single ASN.1 NULL. Nothing else.
fn require_params_null_or_absent(params: &[u8]) -> Result<(), PassiveAuthError> {
    if params.is_empty() || params == [0x05, 0x00] {
        Ok(())
    } else {
        Err(PassiveAuthError::UnsupportedHash)
    }
}

/// AlgorithmIdentifier parameters that must be entirely absent (ECDSA, RFC 5758).
fn require_params_absent(params: &[u8]) -> Result<(), PassiveAuthError> {
    if params.is_empty() {
        Ok(())
    } else {
        Err(PassiveAuthError::UnsupportedHash)
    }
}

/// encapContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }
/// Returns `(eContentType arcs, eContent)`.
fn parse_encap_content(encap: &[u8]) -> Result<(Vec<u64>, Vec<u8>), PassiveAuthError> {
    let (ctype, after) = der::take(encap, der::OID).ok_or(PassiveAuthError::MalformedSod)?;
    let content_type = der::oid_arcs(ctype).ok_or(PassiveAuthError::MalformedSod)?;
    let (_, explicit, _) = der::next(after).ok_or(PassiveAuthError::MalformedSod)?;
    let octets = der::expect(explicit, der::OCTET_STRING).ok_or(PassiveAuthError::MalformedSod)?;
    Ok((content_type, octets.to_vec()))
}

/// certificates [0] holds one or more certs; return each as its own cert DER. A
/// malformed tail is an error, not a silent end-of-list — a truncated set must not pass.
fn collect_certificates(contents: &[u8]) -> Result<Vec<Vec<u8>>, PassiveAuthError> {
    let mut certs = Vec::new();
    let mut rest = contents;
    while !rest.is_empty() {
        let (_tag, cert, tail) = der::next(rest).ok_or(PassiveAuthError::MalformedCertificate)?;
        // re-wrap as its own SEQUENCE TLV so Certificate::parse sees a whole cert
        let mut out = Vec::with_capacity(cert.len() + 4);
        out.push(der::SEQUENCE);
        push_len(&mut out, cert.len());
        out.extend_from_slice(cert);
        certs.push(out);
        rest = tail;
    }
    Ok(certs)
}

/// Parse signedAttrs, and re-encode them as an explicit SET OF for signature
/// verification (RFC 5652 §5.4: the `[0]` tag is replaced by `0x31`).
fn parse_signed_attrs(implicit: &[u8]) -> Result<SignedAttrs, PassiveAuthError> {
    let mut message_digest = None;
    let mut content_type = None;

    let mut rest = implicit;
    while !rest.is_empty() {
        let (tag, attr, tail) = der::next(rest).ok_or(PassiveAuthError::BadSignedAttributes)?;
        if tag == der::SEQUENCE {
            // Attribute ::= SEQUENCE { attrType OID, attrValues SET }
            if let Some((oid, after)) = der::take(attr, der::OID) {
                match der::oid_arcs(oid).as_deref() {
                    Some(OID_MESSAGE_DIGEST) => {
                        message_digest = der::expect(after, der::SET)
                            .and_then(|v| der::expect(v, der::OCTET_STRING))
                            .map(<[u8]>::to_vec);
                    }
                    Some(OID_CONTENT_TYPE) => {
                        // keep the *value*, not just presence — it has to equal the
                        // encapsulated eContentType (checked in `verify`).
                        content_type = der::expect(after, der::SET)
                            .and_then(|v| der::expect(v, der::OID))
                            .and_then(der::oid_arcs);
                    }
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
        content_type,
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
        while !rest.is_empty() {
            // the list is SEQUENCE OF DataGroupHash — every element must be one
            let (dgh, tail) = der::take(rest, der::SEQUENCE).ok_or_else(e)?;
            // DataGroupHash ::= SEQUENCE { number INTEGER, hash OCTET STRING }
            let (num, after) = der::take(dgh, der::INTEGER).ok_or_else(e)?;
            let (hash, _) = der::take(after, der::OCTET_STRING).ok_or_else(e)?;
            if let Some(&n) = num.last() {
                hashes.insert(n, hash.to_vec());
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

/// Does this key's kind match a declared signature scheme?
fn scheme_matches_key(key: &PublicKey, scheme: SigScheme) -> bool {
    matches!(
        (key, scheme),
        (PublicKey::Rsa(_), SigScheme::Rsa) | (PublicKey::EcP256(_), SigScheme::Ecdsa)
    )
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
    serial: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    /// subjectKeyIdentifier extension (2.5.29.14), if present — for SID matching.
    ski: Option<Vec<u8>>,
    public_key: PublicKey,
    /// Scheme of the *outer* signatureAlgorithm — the one the issuer signed this cert
    /// with. The verifying (issuer) key must be of this scheme.
    sig_scheme: SigScheme,
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

        let (outer_alg, after_sig_alg) = der::take(after_tbs, der::SEQUENCE).ok_or_else(e)?;
        let (sig_scheme, sig_hash) = parse_sig_alg(outer_alg).map_err(|_| e())?;
        // a certificate signatureAlgorithm always pins a hash (sha*With… / ecdsa-with-…)
        let signature_hash = sig_hash.ok_or(PassiveAuthError::MalformedCertificate)?;
        let (sig_bits, tail) = der::take(after_sig_alg, der::BIT_STRING).ok_or_else(e)?;
        if !tail.is_empty() {
            return Err(PassiveAuthError::MalformedCertificate);
        }
        let signature = der::bit_string_bytes(sig_bits)
            .ok_or(PassiveAuthError::MalformedCertificate)?
            .to_vec();

        let parsed = Self::parse_tbs(tbs_inner)?;
        // RFC 5280 §4.1.1.2: the inner (TBS) signature AlgorithmIdentifier must be
        // identical to the outer signatureAlgorithm.
        if parsed.inner_sig_alg != outer_alg {
            return Err(PassiveAuthError::MalformedCertificate);
        }
        Ok(Self {
            tbs,
            serial: parsed.serial,
            issuer: parsed.issuer,
            subject: parsed.subject,
            ski: parsed.ski,
            public_key: parsed.public_key,
            sig_scheme,
            signature_hash,
            signature,
        })
    }

    /// TBSCertificate ::= SEQUENCE {
    ///   [0] version OPT, serialNumber, signature, issuer Name, validity,
    ///   subject Name, subjectPublicKeyInfo, ..., extensions [3] OPT }
    fn parse_tbs(tbs: &[u8]) -> Result<ParsedTbs, PassiveAuthError> {
        let e = || PassiveAuthError::MalformedCertificate;

        let rest = match der::next(tbs) {
            Some((0xA0, _, tail)) => tail, // optional [0] version
            _ => tbs,
        };
        let (serial, r1) = der::take(rest, der::INTEGER).ok_or_else(e)?;
        let (inner_sig_alg, r2) = der::take(r1, der::SEQUENCE).ok_or_else(e)?;
        let (issuer, r3) = der::take(r2, der::SEQUENCE).ok_or_else(e)?;
        let (_validity, r4) = der::take(r3, der::SEQUENCE).ok_or_else(e)?;
        let (subject, r5) = der::take(r4, der::SEQUENCE).ok_or_else(e)?;
        let (spki, r6) = der::take(r5, der::SEQUENCE).ok_or_else(e)?;

        let public_key = Self::parse_spki(spki)?;
        let ski = find_ski(r6);
        Ok(ParsedTbs {
            serial: serial.to_vec(),
            inner_sig_alg: inner_sig_alg.to_vec(),
            issuer: issuer.to_vec(),
            subject: subject.to_vec(),
            ski,
            public_key,
        })
    }

    /// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, key BIT STRING }
    fn parse_spki(spki: &[u8]) -> Result<PublicKey, PassiveAuthError> {
        let e = || PassiveAuthError::MalformedCertificate;
        let (alg, after_alg) = der::take(spki, der::SEQUENCE).ok_or_else(e)?;
        let (oid, params) = der::take(alg, der::OID).ok_or_else(e)?;
        let arcs = der::oid_arcs(oid).ok_or(PassiveAuthError::MalformedCertificate)?;

        let (key_bits, _) = der::take(after_alg, der::BIT_STRING).ok_or_else(e)?;
        let key_bytes =
            der::bit_string_bytes(key_bits).ok_or(PassiveAuthError::MalformedCertificate)?;

        if arcs == OID_RSA {
            RsaPublicKey::from_pkcs1_der(key_bytes)
                .map(PublicKey::Rsa)
                .ok_or(PassiveAuthError::UnsupportedKey)
        } else if arcs == OID_EC_PUBLIC_KEY {
            // The namedCurve parameter must actually say P-256 — otherwise a 33/65-byte
            // point on a different (e.g. experimental) curve would be accepted as P-256
            // purely by its length.
            let (curve_oid, _) =
                der::take(params, der::OID).ok_or(PassiveAuthError::UnsupportedKey)?;
            if der::oid_arcs(curve_oid).as_deref() != Some(OID_EC_P256) {
                return Err(PassiveAuthError::UnsupportedKey);
            }
            // uncompressed 65 / compressed 33 SEC1 point
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

/// The fields `parse_tbs` extracts from a TBSCertificate.
struct ParsedTbs {
    serial: Vec<u8>,
    /// The inner `signature` AlgorithmIdentifier content — must equal the outer one.
    inner_sig_alg: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    ski: Option<Vec<u8>>,
    public_key: PublicKey,
}

/// id-ce-subjectKeyIdentifier — 2.5.29.14
const OID_SKI: &[u64] = &[2, 5, 29, 14];

/// Find the subjectKeyIdentifier in the TBS bytes that follow subjectPublicKeyInfo.
/// Returns `None` if there is no `extensions [3]` or no SKI extension in it — the SID
/// match simply won't hit on SKI then, which the single-cert fallback covers.
fn find_ski(after_spki: &[u8]) -> Option<Vec<u8>> {
    // walk optional issuerUniqueID [1], subjectUniqueID [2] to reach extensions [3]
    let mut rest = after_spki;
    let ext_seq = loop {
        let (tag, body, tail) = der::next(rest)?;
        if tag == 0xA3 {
            // [3] EXPLICIT SEQUENCE OF Extension
            break der::expect(body, der::SEQUENCE)?;
        }
        rest = tail;
    };

    let mut rest = ext_seq;
    while let Some((tag, ext, tail)) = der::next(rest) {
        if tag == der::SEQUENCE {
            // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPT, extnValue OCTET STRING }
            if let Some((oid, after)) = der::take(ext, der::OID) {
                if der::oid_arcs(oid).as_deref() == Some(OID_SKI) {
                    // skip an optional critical BOOLEAN, then take the OCTET STRING,
                    // whose content is itself an OCTET STRING of the key id
                    let value = match der::next(after)? {
                        (0x01, _, t) => der::expect(t, der::OCTET_STRING)?, // critical present
                        (der::OCTET_STRING, v, _) => v,
                        _ => return None,
                    };
                    return der::expect(value, der::OCTET_STRING).map(<[u8]>::to_vec);
                }
            }
        }
        rest = tail;
    }
    None
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

    /// The *contents* of an AlgorithmIdentifier (its OID TLV) — what `parse_sig_alg`
    /// and `sig_alg_hash` take, not the enclosing SEQUENCE.
    fn alg_id(oid: &[u8]) -> Vec<u8> {
        let mut inner = vec![der::OID, oid.len() as u8];
        inner.extend_from_slice(oid);
        inner
    }

    #[test]
    fn signature_algorithm_parsing_binds_scheme_and_hash() {
        // bare rsaEncryption: RSA, no pinned hash
        let rsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        assert_eq!(
            parse_sig_alg(&alg_id(&rsa)).unwrap(),
            (SigScheme::Rsa, None)
        );

        // sha256WithRSAEncryption: RSA, SHA-256 pinned
        let rsa256 = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
        assert_eq!(
            parse_sig_alg(&alg_id(&rsa256)).unwrap(),
            (SigScheme::Rsa, Some(HashAlgo::Sha256))
        );

        // RSASSA-PSS (…1.1.10) shares the RSA prefix but is NOT PKCS#1 v1.5 — must be
        // rejected, not silently verified with the wrong scheme.
        let pss = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
        assert!(parse_sig_alg(&alg_id(&pss)).is_err());
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
