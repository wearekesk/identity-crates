//! RSA public-key operations, on `num-bigint`.
//!
//! Only ever the *public* operation (`s^e mod n`) — verification and the ISO 9796-2
//! recovery both need nothing else, so there is no private key, no padding oracle to
//! worry about, and no reason to pull in a full RSA implementation.

use num_bigint::BigUint;
use num_traits::Zero;

use super::der;
use super::HashAlgo;

/// An RSA public key: modulus and exponent.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

impl RsaPublicKey {
    /// Parse a DER `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
    /// — the payload of a SubjectPublicKeyInfo BIT STRING for `rsaEncryption`.
    ///
    /// Strict: exactly two positive, minimally-encoded INTEGERs and nothing after them,
    /// and the exponent must be odd and ≥ 3. `e = 1` is the important one to reject —
    /// with it `raw_public` is the identity, so any forged PKCS#1 block would "verify"
    /// without a private key.
    pub fn from_pkcs1_der(der_bytes: &[u8]) -> Option<Self> {
        let seq = der::expect(der_bytes, der::SEQUENCE)?;
        let (n_bytes, rest) = der::take(seq, der::INTEGER)?;
        let (e_bytes, tail) = der::take(rest, der::INTEGER)?;
        if !tail.is_empty() {
            return None; // no trailing fields
        }
        let n = parse_der_uint(n_bytes)?;
        let e = parse_der_uint(e_bytes)?;
        if e < BigUint::from(3u32) || (&e % 2u32).is_zero() {
            return None; // exponent must be odd and at least 3
        }
        Some(Self { n, e })
    }

    /// Modulus size in bytes — the length every signature must have.
    pub fn size(&self) -> usize {
        self.n.bits().div_ceil(8) as usize
    }

    /// The RSA public operation: `s^e mod n`, left-padded to the modulus length.
    ///
    /// Rejects a signature that is not a valid representative — the wrong byte length,
    /// or `s >= n` (RFC 8017). `s` of 0 or 1 is in range and left to the caller: the
    /// PKCS#1 v1.5 / ISO 9796-2 block checks reject those degenerate blocks anyway.
    pub fn raw_public(&self, sig: &[u8]) -> Option<Vec<u8>> {
        let k = self.size();
        if sig.len() != k || self.n.is_zero() {
            return None;
        }
        let s = BigUint::from_bytes_be(sig);
        if s >= self.n {
            return None;
        }
        let m = s.modpow(&self.e, &self.n);
        let mut out = m.to_bytes_be();
        if out.len() > k {
            return None;
        }
        // left-pad: to_bytes_be() drops leading zeros, but the block is fixed-width
        let mut padded = vec![0u8; k - out.len()];
        padded.append(&mut out);
        Some(padded)
    }

    /// Verify an RSASSA-PKCS1-v1_5 signature over `message` (RFC 8017 §8.2.2).
    ///
    /// Rebuilds the expected `EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo` and
    /// compares it whole, which is what makes this immune to the classic Bleichenbacher
    /// "parse the padding loosely" forgery.
    pub fn verify_pkcs1v15(&self, hash: HashAlgo, message: &[u8], sig: &[u8]) -> bool {
        let k = self.size();
        let digest = hash.digest(message);
        let prefix = hash.digest_info_prefix();

        // 0x00 0x01 <PS: at least 8 bytes of 0xFF> 0x00 <DigestInfo>
        let t_len = prefix.len() + digest.len();
        if k < t_len + 11 {
            return false;
        }
        let mut expected = Vec::with_capacity(k);
        expected.extend_from_slice(&[0x00, 0x01]);
        expected.extend(std::iter::repeat_n(0xFF, k - t_len - 3));
        expected.push(0x00);
        expected.extend_from_slice(prefix);
        expected.extend_from_slice(&digest);

        match self.raw_public(sig) {
            Some(em) => constant_time_eq(&em, &expected),
            None => false,
        }
    }
}

/// Parse a DER INTEGER's content as a positive, minimally-encoded unsigned integer.
///
/// DER INTEGERs are signed and minimal, so: no empty content; a top bit set means a
/// negative value (rejected); and a leading `0x00` is legal *only* to keep a following
/// high-bit byte positive — a `0x00` before a byte with the high bit clear is a
/// non-minimal encoding and is rejected.
fn parse_der_uint(bytes: &[u8]) -> Option<BigUint> {
    match bytes {
        [] => None,                                // empty: not a valid INTEGER
        [b0, ..] if *b0 & 0x80 != 0 => None,       // negative
        [0x00] => None,                            // zero — never a valid RSA n or e
        [0x00, b1, ..] if *b1 & 0x80 == 0 => None, // non-minimal leading zero
        [0x00, rest @ ..] => Some(BigUint::from_bytes_be(rest)),
        b => Some(BigUint::from_bytes_be(b)),
    }
}

/// Compare without leaking where the first difference is.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 1024-bit RSA public key (128-byte modulus + e=65537).
    fn key() -> RsaPublicKey {
        // fixed here so the test is deterministic
        let n = BigUint::parse_bytes(
            b"C4F8E9A1B7D3F5E2A9C6B8D4E1F3A5C7B9D2E4F6A8C1B3D5E7F9A2C4B6D8E0F2\
              A4C6B8D1E3F5A7C9B2D4E6F8A1C3B5D7E9F2A4C6B8D0E2F4A6C8B1D3E5F7A9C2\
              B4D6E8F1A3C5B7D9E2F4A6C8B0D2E4F6A8C1B3D5E7F9A2C4B6D8E0F2A4C6B8D1\
              E3F5A7C9B2D4E6F8A1C3B5D7E9F2A4C6B8D0E2F4A6C8B1D3E5F7A9C2B4D6E8F3",
            16,
        )
        .unwrap();
        RsaPublicKey {
            n,
            e: BigUint::from(65537u32),
        }
    }

    #[test]
    fn rejects_a_signature_that_is_not_a_valid_representative() {
        let k = key();
        // s == n is out of range, as is anything longer than the modulus
        let n_bytes = k.n.to_bytes_be();
        assert!(k.raw_public(&n_bytes).is_none());
        assert!(k.raw_public(&[0u8; 4]).is_none()); // wrong length
    }

    #[test]
    fn public_operation_is_fixed_width() {
        let k = key();
        // s = 1 → 1^e mod n = 1, which must still come back left-padded to k bytes
        let mut one = vec![0u8; k.size()];
        *one.last_mut().unwrap() = 1;
        let out = k.raw_public(&one).unwrap();
        assert_eq!(out.len(), k.size());
        assert_eq!(*out.last().unwrap(), 1);
        assert!(out[..out.len() - 1].iter().all(|b| *b == 0));
    }

    #[test]
    fn garbage_signatures_do_not_verify() {
        let k = key();
        assert!(!k.verify_pkcs1v15(HashAlgo::Sha256, b"hello", &vec![0xAB; k.size()]));
    }

    #[test]
    fn parses_a_pkcs1_public_key() {
        // SEQUENCE { INTEGER 0x00CA (leading zero keeps it positive), INTEGER 65537 }
        let der_bytes = [
            0x30, 0x09, // SEQUENCE, 9 bytes
            0x02, 0x02, 0x00, 0xca, // INTEGER 0x00CA -> 202
            0x02, 0x03, 0x01, 0x00, 0x01, // INTEGER 65537 (minimal)
        ];
        let k = RsaPublicKey::from_pkcs1_der(&der_bytes).unwrap();
        assert_eq!(k.n, BigUint::from(0xCAu32));
        assert_eq!(k.e, BigUint::from(65537u32));
    }

    #[test]
    fn rejects_degenerate_and_malformed_keys() {
        // e = 1 (the forgery vector)
        let e_one = [0x30, 0x07, 0x02, 0x02, 0x00, 0xca, 0x02, 0x01, 0x01];
        assert!(RsaPublicKey::from_pkcs1_der(&e_one).is_none());
        // even exponent
        let e_even = [0x30, 0x07, 0x02, 0x02, 0x00, 0xca, 0x02, 0x01, 0x04];
        assert!(RsaPublicKey::from_pkcs1_der(&e_even).is_none());
        // non-minimal modulus (leading 0x00 before a high-bit-clear byte)
        let n_nonmin = [0x30, 0x07, 0x02, 0x02, 0x00, 0x7f, 0x02, 0x01, 0x03];
        assert!(RsaPublicKey::from_pkcs1_der(&n_nonmin).is_none());
        // trailing field after the exponent
        let trailing = [
            0x30, 0x0c, 0x02, 0x02, 0x00, 0xca, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x01, 0x05,
        ];
        assert!(RsaPublicKey::from_pkcs1_der(&trailing).is_none());
    }
}
