//! Active Authentication (ICAO 9303 part 11, §6.1) — is this chip a clone?
//!
//! The chip holds a private key whose public half is published in EF.DG15 and hashed
//! into EF.SOD. We send an 8-byte challenge, it signs it, we verify. A cloned chip
//! can copy every data group but cannot copy the private key, so it cannot answer.
//!
//! **AA is not PA.** It proves the chip is not a copy; it says nothing about whether
//! the data is genuine. A forger who mints their own keypair, writes their own DG15
//! and signs the challenge with it passes AA — and fails [`super::passive`], which is
//! the check that would catch them. Run both.
//!
//! ## The two signature schemes
//!
//! - **RSA** — ISO/IEC 9796-2 Digital Signature Scheme 1, *with message recovery*.
//!   The chip generates its own random `M1`, which the signature itself carries; the
//!   digest covers `M1 || challenge`. So verification means undoing the RSA operation,
//!   pulling `M1` back out of the recovered block, re-hashing it with our challenge,
//!   and comparing. This is why a plain PKCS#1 verify does not work here.
//! - **ECDSA** — a plain signature over the hashed challenge, as raw `r || s`.

use thiserror::Error;

use crate::crypto::aa_pubkey::{AAPublicKey, AAPublicKeyType};

use super::rsa::{constant_time_eq, RsaPublicKey};
use super::HashAlgo;

/// ISO 9796-2 header for a signature with partial message recovery.
const HEADER_PARTIAL_RECOVERY: u8 = 0x6A;
/// Implicit trailer: the hash is SHA-1 and is not named in the block.
const TRAILER_IMPLICIT: u8 = 0xBC;
/// Explicit trailer: the preceding byte identifies the hash.
const TRAILER_EXPLICIT: u8 = 0xCC;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ActiveAuthError {
    #[error("the challenge must be 8 bytes, got {0}")]
    BadChallenge(usize),

    #[error("EF.DG15 does not hold a usable public key")]
    BadPublicKey,

    #[error("the chip's response is not a well-formed signature")]
    MalformedSignature,

    #[error("unsupported elliptic curve — only NIST P-256 is implemented")]
    UnsupportedCurve,

    #[error("unsupported ISO 9796-2 hash identifier {0:#04x}")]
    UnsupportedHash(u8),

    /// The signature did not verify. The chip is not the one that owns this DG15 key.
    #[error("active authentication failed — the chip did not prove it holds the key")]
    Failed,
}

/// Verify the chip's answer to `challenge`, against the public key from EF.DG15.
///
/// `Ok(())` means this chip holds the private key for that DG15 — it is not a clone.
pub fn verify(key: &AAPublicKey, challenge: &[u8], response: &[u8]) -> Result<(), ActiveAuthError> {
    // ICAO fixes the challenge at 8 bytes. Enforce it: a caller passing a short or
    // empty challenge would otherwise be "verifying" something an attacker can replay.
    if challenge.len() != 8 {
        return Err(ActiveAuthError::BadChallenge(challenge.len()));
    }

    match key.key_type() {
        AAPublicKeyType::Rsa => {
            verify_rsa_iso9796(key.raw_subject_public_key(), challenge, response)
        }
        AAPublicKeyType::Ecc => verify_ecdsa(key.raw_subject_public_key(), challenge, response),
    }
}

/// RSA: ISO/IEC 9796-2 DSS1, partial recovery.
fn verify_rsa_iso9796(
    spki_key_bytes: &[u8],
    challenge: &[u8],
    signature: &[u8],
) -> Result<(), ActiveAuthError> {
    let key = RsaPublicKey::from_pkcs1_der(spki_key_bytes).ok_or(ActiveAuthError::BadPublicKey)?;
    let block = key
        .raw_public(signature)
        .ok_or(ActiveAuthError::MalformedSignature)?;

    // header ‖ M1 ‖ H ‖ trailer
    let (&header, after_header) = block
        .split_first()
        .ok_or(ActiveAuthError::MalformedSignature)?;
    if header != HEADER_PARTIAL_RECOVERY {
        return Err(ActiveAuthError::Failed);
    }

    let (&last, before_last) = after_header
        .split_last()
        .ok_or(ActiveAuthError::MalformedSignature)?;

    // The trailer names the hash — implicitly (0xBC ⇒ SHA-1) or explicitly (0xCC,
    // preceded by an identifier byte).
    let (hash, body) = match last {
        TRAILER_IMPLICIT => (HashAlgo::Sha1, before_last),
        TRAILER_EXPLICIT => {
            let (&id, rest) = before_last
                .split_last()
                .ok_or(ActiveAuthError::MalformedSignature)?;
            let hash = HashAlgo::from_iso9796_id(id).ok_or(ActiveAuthError::UnsupportedHash(id))?;
            (hash, rest)
        }
        _ => return Err(ActiveAuthError::Failed),
    };

    // what is left is M1 ‖ H
    let split = body
        .len()
        .checked_sub(hash.digest_len())
        .ok_or(ActiveAuthError::MalformedSignature)?;
    let (m1, h) = body.split_at(split);

    // The chip hashed its own recovered message followed by our challenge. Recomputing
    // it with *our* challenge is what makes this unreplayable.
    let mut signed = Vec::with_capacity(m1.len() + challenge.len());
    signed.extend_from_slice(m1);
    signed.extend_from_slice(challenge);

    if constant_time_eq(&hash.digest(&signed), h) {
        Ok(())
    } else {
        Err(ActiveAuthError::Failed)
    }
}

/// ECDSA over the hashed challenge, signature as raw `r ‖ s`.
///
/// Only NIST P-256 today: it is the curve `dmrtd`'s PACE stack already carries. A
/// brainpool or P-384 chip returns [`ActiveAuthError::UnsupportedCurve`] rather than a
/// silent pass.
///
/// ICAO permits any SHA-2 variant for ECDSA AA, and — unlike RSA, where the ISO 9796-2
/// trailer names the hash — the EC public key does not say which was used. So try each
/// permitted digest and accept if any verifies. (Trying several is safe: a forged
/// response has to forge under one *specific* hash, and none of the wrong hashes will
/// verify a genuine signature either.)
fn verify_ecdsa(
    spki_key_bytes: &[u8],
    challenge: &[u8],
    signature: &[u8],
) -> Result<(), ActiveAuthError> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    // SEC1 point for P-256: uncompressed (0x04 ‖ X ‖ Y, 65 bytes) or compressed (33).
    // Any other length is a curve we do not implement — say so rather than guess.
    if !matches!(spki_key_bytes.len(), 33 | 65) {
        return Err(ActiveAuthError::UnsupportedCurve);
    }
    let key =
        VerifyingKey::from_sec1_bytes(spki_key_bytes).map_err(|_| ActiveAuthError::BadPublicKey)?;

    let sig = Signature::from_slice(signature).map_err(|_| ActiveAuthError::MalformedSignature)?;

    let verified = [
        HashAlgo::Sha256,
        HashAlgo::Sha384,
        HashAlgo::Sha512,
        HashAlgo::Sha224,
    ]
    .iter()
    .any(|h| key.verify_prehash(&h.digest(challenge), &sig).is_ok());

    if verified {
        Ok(())
    } else {
        Err(ActiveAuthError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::der;

    /// Build the SubjectPublicKeyInfo that EF.DG15 carries, around a raw key.
    fn spki(oid: &[u8], key_bytes: &[u8]) -> Vec<u8> {
        let mut alg = vec![der::OID, oid.len() as u8];
        alg.extend_from_slice(oid);
        let mut alg_seq = vec![der::SEQUENCE, alg.len() as u8];
        alg_seq.extend_from_slice(&alg);

        let mut bits = vec![0x00];
        bits.extend_from_slice(key_bytes);
        let mut bit_string = vec![der::BIT_STRING];
        push_len(&mut bit_string, bits.len());
        bit_string.extend_from_slice(&bits);

        let body_len = alg_seq.len() + bit_string.len();
        let mut out = vec![der::SEQUENCE];
        push_len(&mut out, body_len);
        out.extend_from_slice(&alg_seq);
        out.extend_from_slice(&bit_string);
        out
    }

    fn push_len(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
        }
    }

    const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

    /// A real 1024-bit RSA keypair (openssl-generated, fixed here so the tests are
    /// deterministic). It has to be a genuine keypair, not made-up numbers: signing
    /// only round-trips if `d` really is `e⁻¹ mod φ(n)`.
    const N_HEX: &[u8] = b"D7E99350EAEFFF9044757169506684FFE9C84BCE49B449FAF0CEB2E1B4ADEEE2\
                           206FEE447617AC882D70B84695DCD5DD57BC52619E6C1F9DF628073C782DFA88\
                           C9CE8AD08227424ED36A8AA889B4C63CA9A8FA2361A09917B3A8DD5572E784A4\
                           27A19B5C1FF7336857DA3943B06B804E60240948A03EF35A4D981568745727E3";
    const D_HEX: &[u8] = b"79FE126B64E3078DD6F0588CFD8D7F562D1C2BA0B9CA3106A52AD4AD6C6DDE0C\
                           4BF192398253EBFAE159CFF4A9D625CC33374780BA8732F20854238A8A08C885\
                           98F0D8AD01D98FAC9E58FC0CD0788197943BF5352B7E9A86E17ACE2E84668438\
                           12331BFA4F7319C076938B1417E081AC06B01772DE148A707AEEB4BC80BB1411";

    fn rsa_key_1024() -> (
        num_bigint::BigUint,
        num_bigint::BigUint,
        num_bigint::BigUint,
    ) {
        use num_bigint::BigUint;
        let hex = |h: &[u8]| {
            let cleaned: Vec<u8> = h
                .iter()
                .copied()
                .filter(|b| b.is_ascii_hexdigit())
                .collect();
            BigUint::parse_bytes(&cleaned, 16).unwrap()
        };
        (hex(N_HEX), BigUint::from(65537u32), hex(D_HEX))
    }

    /// Sign like a chip does: build the ISO 9796-2 block, then `block^d mod n`.
    fn chip_sign_iso9796(
        n: &num_bigint::BigUint,
        d: &num_bigint::BigUint,
        m1: &[u8],
        challenge: &[u8],
        hash: HashAlgo,
        explicit_trailer: Option<u8>,
    ) -> Vec<u8> {
        use num_bigint::BigUint;
        let k = n.bits().div_ceil(8) as usize;

        let mut signed = m1.to_vec();
        signed.extend_from_slice(challenge);
        let h = hash.digest(&signed);

        let mut block = vec![HEADER_PARTIAL_RECOVERY];
        block.extend_from_slice(m1);
        block.extend_from_slice(&h);
        match explicit_trailer {
            Some(id) => block.extend_from_slice(&[id, TRAILER_EXPLICIT]),
            None => block.push(TRAILER_IMPLICIT),
        }
        assert_eq!(block.len(), k, "test must fill the modulus exactly");

        let m = BigUint::from_bytes_be(&block);
        let sig = m.modpow(d, n);
        let mut out = sig.to_bytes_be();
        while out.len() < k {
            out.insert(0, 0);
        }
        out
    }

    fn rsa_dg15(n: &num_bigint::BigUint, e: &num_bigint::BigUint) -> AAPublicKey {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        fn int(v: &[u8]) -> Vec<u8> {
            let mut body = v.to_vec();
            if body[0] & 0x80 != 0 {
                body.insert(0, 0); // keep it positive
            }
            let mut out = vec![der::INTEGER];
            push_len(&mut out, body.len());
            out.extend_from_slice(&body);
            out
        }
        let mut inner = int(&n.to_bytes_be());
        inner.extend_from_slice(&int(&e.to_bytes_be()));
        let mut pkcs1 = vec![der::SEQUENCE];
        push_len(&mut pkcs1, inner.len());
        pkcs1.extend_from_slice(&inner);

        AAPublicKey::from_bytes(spki(RSA_OID, &pkcs1)).expect("valid SPKI")
    }

    #[test]
    fn a_chip_holding_the_rsa_key_passes() {
        let (n, e, d) = rsa_key_1024();
        let key = rsa_dg15(&n, &e);
        let challenge = [1u8, 2, 3, 4, 5, 6, 7, 8];

        // block = header(1) + m1 + sha1(20) + trailer(1) == k
        let k = n.bits().div_ceil(8) as usize;
        let m1 = vec![0xA5; k - 1 - 20 - 1];

        let sig = chip_sign_iso9796(&n, &d, &m1, &challenge, HashAlgo::Sha1, None);
        assert_eq!(verify(&key, &challenge, &sig), Ok(()));
    }

    #[test]
    fn a_different_challenge_fails_so_a_recorded_response_cannot_be_replayed() {
        let (n, e, d) = rsa_key_1024();
        let key = rsa_dg15(&n, &e);
        let k = n.bits().div_ceil(8) as usize;
        let m1 = vec![0x5A; k - 1 - 20 - 1];

        let sig = chip_sign_iso9796(&n, &d, &m1, &[1, 2, 3, 4, 5, 6, 7, 8], HashAlgo::Sha1, None);
        // the same signature replayed against a fresh challenge must not verify
        assert_eq!(
            verify(&key, &[8, 7, 6, 5, 4, 3, 2, 1], &sig),
            Err(ActiveAuthError::Failed)
        );
    }

    #[test]
    fn an_explicit_sha256_trailer_is_honoured() {
        let (n, e, d) = rsa_key_1024();
        let key = rsa_dg15(&n, &e);
        let challenge = [9u8; 8];
        let k = n.bits().div_ceil(8) as usize;
        // header(1) + m1 + sha256(32) + id(1) + trailer(1) == k
        let m1 = vec![0x11; k - 1 - 32 - 2];

        let sig = chip_sign_iso9796(&n, &d, &m1, &challenge, HashAlgo::Sha256, Some(0x34));
        assert_eq!(verify(&key, &challenge, &sig), Ok(()));
    }

    #[test]
    fn a_forged_signature_fails() {
        let (n, e, _d) = rsa_key_1024();
        let key = rsa_dg15(&n, &e);
        let k = n.bits().div_ceil(8) as usize;
        // a clone that cannot sign can only guess
        assert!(verify(&key, &[0u8; 8], &vec![0x42; k]).is_err());
    }

    #[test]
    fn the_challenge_must_be_eight_bytes() {
        let (n, e, _d) = rsa_key_1024();
        let key = rsa_dg15(&n, &e);
        assert_eq!(
            verify(&key, &[], &[0; 128]),
            Err(ActiveAuthError::BadChallenge(0))
        );
        assert_eq!(
            verify(&key, &[1; 4], &[0; 128]),
            Err(ActiveAuthError::BadChallenge(4))
        );
    }

    #[test]
    fn a_chip_holding_the_ecdsa_key_passes() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::SigningKey;

        let signing = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let public = signing.verifying_key().to_sec1_bytes();
        let key = AAPublicKey::from_bytes(spki(EC_OID, &public)).unwrap();

        let challenge = [7u8; 8];
        let digest = HashAlgo::Sha256.digest(&challenge);
        let (sig, _): (p256::ecdsa::Signature, _) = signing.sign_prehash(&digest).unwrap();

        assert_eq!(verify(&key, &challenge, &sig.to_bytes()), Ok(()));
        // and a chip that signed a different challenge does not pass
        let other = HashAlgo::Sha256.digest(&[8u8; 8]);
        let (bad, _): (p256::ecdsa::Signature, _) = signing.sign_prehash(&other).unwrap();
        assert_eq!(
            verify(&key, &challenge, &bad.to_bytes()),
            Err(ActiveAuthError::Failed)
        );
    }

    #[test]
    fn ecdsa_with_a_non_sha256_digest_still_verifies() {
        // A chip that signs the SHA-384 digest of the challenge (ICAO permits it, and
        // the EC key doesn't say which hash). This used to fail on the hard-coded
        // SHA-256 path.
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::SigningKey;

        let signing = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let key = AAPublicKey::from_bytes(spki(EC_OID, &signing.verifying_key().to_sec1_bytes()))
            .unwrap();

        let challenge = [3u8; 8];
        for hash in [HashAlgo::Sha384, HashAlgo::Sha512, HashAlgo::Sha224] {
            let (sig, _): (p256::ecdsa::Signature, _) =
                signing.sign_prehash(&hash.digest(&challenge)).unwrap();
            assert_eq!(
                verify(&key, &challenge, &sig.to_bytes()),
                Ok(()),
                "{hash:?}"
            );
        }
    }
}
