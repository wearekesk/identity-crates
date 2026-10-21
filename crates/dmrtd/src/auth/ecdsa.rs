//! ECDSA verification over the prime curves eMRTDs are signed on.
//!
//! ICAO 9303 part 12 asks Document Signer and CSCA certificates to carry their EC
//! domain parameters *explicitly* — the prime, coefficients, base point and order
//! written out — rather than as a named-curve OID, and many do. [`Curve::from_params`]
//! takes either form, but only for a curve it knows: explicit parameters are matched
//! against the table below, never used as given, so a certificate can't bring its
//! own (weak, or enormous) curve.
//!
//! Signatures are verified by RustCrypto's curve crates, except on brainpoolP512r1,
//! which has none yet (RustCrypto/elliptic-curves#114): that one is verified here
//! over `num-bigint`. Verification is over public data only — the key, the message
//! and the signature — so plain big-integer arithmetic is fine: nothing secret to
//! leak through timing. Once RustCrypto has a brainpoolP512r1 crate, use it instead.

use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::der;
use super::HashAlgo;

/// id-ecPublicKey parameters: a named curve (1.2.840.10045.3.1.7, …).
const OID_PRIME_FIELD: &[u64] = &[1, 2, 840, 10045, 1, 1];

/// A short-Weierstrass curve y² = x³ + ax + b over GF(p), with base point G of
/// prime order n (cofactor 1 for every curve here).
pub(crate) struct Curve {
    pub(crate) name: &'static str,
    oid: &'static [u64],
    p: &'static str,
    a: &'static str,
    b: &'static str,
    gx: &'static str,
    gy: &'static str,
    n: &'static str,
}

/// The curves eMRTDs use: NIST's (FIPS 186-4) and Brainpool's (RFC 5639).
pub(crate) static CURVES: &[&Curve] = &[
    &P256,
    &P384,
    &P521,
    &BRAINPOOL_P256R1,
    &BRAINPOOL_P384R1,
    &BRAINPOOL_P512R1,
];

pub(crate) static P256: Curve = Curve {
    name: "P-256",
    oid: &[1, 2, 840, 10045, 3, 1, 7],
    p: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    a: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
    b: "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
    gx: "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
    gy: "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    n: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
};

static P384: Curve = Curve {
    name: "P-384",
    oid: &[1, 3, 132, 0, 34],
    p: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
    a: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
    b: "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
    gx: "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
    gy: "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
    n: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
};

static P521: Curve = Curve {
    name: "P-521",
    oid: &[1, 3, 132, 0, 35],
    p: "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    a: "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
    b: "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
    gx: "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
    gy: "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
    n: "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
};

static BRAINPOOL_P256R1: Curve = Curve {
    name: "brainpoolP256r1",
    oid: &[1, 3, 36, 3, 3, 2, 8, 1, 1, 7],
    p: "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
    a: "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
    b: "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
    gx: "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
    gy: "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
    n: "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
};

static BRAINPOOL_P384R1: Curve = Curve {
    name: "brainpoolP384r1",
    oid: &[1, 3, 36, 3, 3, 2, 8, 1, 1, 11],
    p: "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
    a: "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
    b: "4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
    gx: "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
    gy: "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
    n: "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
};

static BRAINPOOL_P512R1: Curve = Curve {
    name: "brainpoolP512r1",
    oid: &[1, 3, 36, 3, 3, 2, 8, 1, 1, 13],
    p: "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
    a: "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
    b: "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
    gx: "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
    gy: "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
    n: "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
};

impl std::fmt::Debug for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

fn hex(digits: &str) -> BigUint {
    BigUint::parse_bytes(digits.as_bytes(), 16).expect("curve constants are hex")
}

/// A curve's parameters as numbers.
struct Params {
    p: BigUint,
    a: BigUint,
    b: BigUint,
    g: (BigUint, BigUint),
    n: BigUint,
}

impl Curve {
    fn params(&self) -> Params {
        Params {
            p: hex(self.p),
            a: hex(self.a),
            b: hex(self.b),
            g: (hex(self.gx), hex(self.gy)),
            n: hex(self.n),
        }
    }

    /// Bytes in a field element.
    pub(crate) fn field_len(&self) -> usize {
        (hex(self.p).bits() as usize).div_ceil(8)
    }

    /// Whether a compressed SEC1 point (02/03 ‖ x) can be verified on this curve:
    /// RustCrypto's crates decompress, the num-bigint verifier for brainpoolP512r1
    /// doesn't.
    pub(crate) fn takes_compressed_points(&self) -> bool {
        !std::ptr::eq(self, &BRAINPOOL_P512R1)
    }

    /// The curve an id-ecPublicKey AlgorithmIdentifier's parameters name: a
    /// namedCurve OID, or explicit ECParameters (RFC 3279 §2.3.5) equal to a known
    /// curve's. `implicitlyCA`, an unknown curve, or anything malformed: `None`.
    pub(crate) fn from_params(params: &[u8]) -> Option<&'static Curve> {
        match der::next(params)? {
            (der::OID, oid, []) => {
                let arcs = der::oid_arcs(oid)?;
                CURVES.iter().copied().find(|c| c.oid == arcs.as_slice())
            }
            (der::SEQUENCE, explicit, []) => Self::from_explicit(explicit),
            _ => None,
        }
    }

    /// ECParameters ::= SEQUENCE { version INTEGER (1), fieldID SEQUENCE { prime-field
    /// OID, p INTEGER }, curve SEQUENCE { a OCTET STRING, b OCTET STRING, seed BIT
    /// STRING OPT }, base OCTET STRING, order INTEGER, cofactor INTEGER OPT }
    fn from_explicit(explicit: &[u8]) -> Option<&'static Curve> {
        let (version, rest) = der::take(explicit, der::INTEGER)?;
        if version != [1] {
            return None;
        }
        let (field, rest) = der::take(rest, der::SEQUENCE)?;
        let (field_type, field_rest) = der::take(field, der::OID)?;
        if der::oid_arcs(field_type).as_deref() != Some(OID_PRIME_FIELD) {
            return None;
        }
        let p = BigUint::from_bytes_be(der::expect(field_rest, der::INTEGER)?);
        let (curve, rest) = der::take(rest, der::SEQUENCE)?;
        let (a, curve_rest) = der::take(curve, der::OCTET_STRING)?;
        let (b, _seed) = der::take(curve_rest, der::OCTET_STRING)?;
        let (base, rest) = der::take(rest, der::OCTET_STRING)?;
        // The seed and cofactor are left unchecked: p, a, b, G and n already pin the
        // curve, and every curve here has cofactor 1.
        let (n, _cofactor) = der::take(rest, der::INTEGER)?;
        let (a, b, n) = (
            BigUint::from_bytes_be(a),
            BigUint::from_bytes_be(b),
            BigUint::from_bytes_be(n),
        );

        CURVES.iter().copied().find(|curve| {
            let known = curve.params();
            known.p == p
                && known.a == a
                && known.b == b
                && known.n == n
                && decode_point(&known, base).as_ref() == Some(&known.g)
        })
    }

    /// Verify a DER `ECDSA-Sig-Value` over `message`, hashed with `hash`, under the
    /// SEC1 public point `point`.
    pub(crate) fn verify(
        &self,
        point: &[u8],
        hash: HashAlgo,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let digest = hash.digest(message);
        if std::ptr::eq(self, &P256) {
            verify_p256(point, &digest, signature)
        } else if std::ptr::eq(self, &P384) {
            verify_p384(point, &digest, signature)
        } else if std::ptr::eq(self, &P521) {
            verify_p521(point, &digest, signature)
        } else if std::ptr::eq(self, &BRAINPOOL_P256R1) {
            verify_bp256(point, &digest, signature)
        } else if std::ptr::eq(self, &BRAINPOOL_P384R1) {
            verify_bp384(point, &digest, signature)
        } else {
            self.verify_bigint(point, &digest, signature)
        }
    }

    /// Verify over `num-bigint`: for brainpoolP512r1, which RustCrypto has no crate
    /// for yet (RustCrypto/elliptic-curves#114).
    fn verify_bigint(&self, point: &[u8], digest: &[u8], signature: &[u8]) -> bool {
        let curve = self.params();
        let Some(q) = decode_point(&curve, point) else {
            return false;
        };
        let Some((r, s)) = parse_signature(signature) else {
            return false;
        };
        let n = &curve.n;
        if r.is_zero() || s.is_zero() || &r >= n || &s >= n {
            return false;
        }

        // e: the hash's leftmost bits, as many as n has (SEC1 §4.1.4 step 5).
        let mut e = BigUint::from_bytes_be(digest);
        let (digest_bits, n_bits) = (digest.len() as u64 * 8, n.bits());
        if digest_bits > n_bits {
            e >>= digest_bits - n_bits;
        }

        let w = s.modpow(&(n - 2u32), n);
        let u1 = (e * &w) % n;
        let u2 = (&r * &w) % n;
        let g = Jacobian::from_affine(&curve.g);
        let q = Jacobian::from_affine(&q);
        let sum = g.add(&q, &curve);
        // Shamir's trick: u1·G + u2·Q in one pass of doublings.
        let mut acc = Jacobian::infinity();
        for bit in (0..u1.bits().max(u2.bits())).rev() {
            acc = acc.double(&curve);
            acc = match (u1.bit(bit), u2.bit(bit)) {
                (true, true) => acc.add(&sum, &curve),
                (true, false) => acc.add(&g, &curve),
                (false, true) => acc.add(&q, &curve),
                (false, false) => acc,
            };
        }
        match acc.to_affine_x(&curve) {
            Some(x) => x % n == r,
            None => false,
        }
    }
}

fn verify_p256(point: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(point),
        Signature::from_der(signature),
    ) else {
        return false;
    };
    key.verify_prehash(digest, &signature).is_ok()
}

fn verify_p384(point: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    use p384::ecdsa::signature::hazmat::PrehashVerifier;
    use p384::ecdsa::{Signature, VerifyingKey};
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(point),
        Signature::from_der(signature),
    ) else {
        return false;
    };
    key.verify_prehash(&padded(digest, 48), &signature).is_ok()
}

fn verify_p521(point: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    use p521::ecdsa::signature::hazmat::PrehashVerifier;
    use p521::ecdsa::{Signature, VerifyingKey};
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(point),
        Signature::from_der(signature),
    ) else {
        return false;
    };
    key.verify_prehash(&padded(digest, 66), &signature).is_ok()
}

fn verify_bp256(point: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    use bp256::r1::BrainpoolP256r1;
    use ecdsa::signature::hazmat::PrehashVerifier;
    let (Ok(key), Ok(signature)) = (
        ecdsa::VerifyingKey::<BrainpoolP256r1>::from_sec1_bytes(point),
        ecdsa::Signature::<BrainpoolP256r1>::from_der(signature),
    ) else {
        return false;
    };
    key.verify_prehash(digest, &signature).is_ok()
}

fn verify_bp384(point: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    use bp384::r1::BrainpoolP384r1;
    use ecdsa::signature::hazmat::PrehashVerifier;
    let (Ok(key), Ok(signature)) = (
        ecdsa::VerifyingKey::<BrainpoolP384r1>::from_sec1_bytes(point),
        ecdsa::Signature::<BrainpoolP384r1>::from_der(signature),
    ) else {
        return false;
    };
    key.verify_prehash(digest, &signature).is_ok()
}

/// `digest`, zero-padded on the left to `len` bytes if it's shorter: the same number.
/// p384 and p521 (ecdsa 0.16) refuse a prehash shorter than half their field — SHA-256
/// on P-521, say — although ECDSA takes any hash as the integer it spells.
fn padded(digest: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0; len.saturating_sub(digest.len())];
    out.extend_from_slice(digest);
    out
}

/// An uncompressed SEC1 point (04 ‖ x ‖ y) that lies on the curve.
fn decode_point(curve: &Params, bytes: &[u8]) -> Option<(BigUint, BigUint)> {
    let len = (curve.p.bits() as usize).div_ceil(8);
    if bytes.len() != 1 + 2 * len || bytes[0] != 0x04 {
        return None;
    }
    let x = BigUint::from_bytes_be(&bytes[1..=len]);
    let y = BigUint::from_bytes_be(&bytes[1 + len..]);
    let p = &curve.p;
    if &x >= p || &y >= p {
        return None;
    }
    let rhs = (x.modpow(&BigUint::from(3u32), p) + &curve.a * &x + &curve.b) % p;
    (y.modpow(&BigUint::from(2u32), p) == rhs).then_some((x, y))
}

/// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
fn parse_signature(signature: &[u8]) -> Option<(BigUint, BigUint)> {
    let body = der::expect(signature, der::SEQUENCE)?;
    let (r, rest) = der::take(body, der::INTEGER)?;
    let (s, rest) = der::take(rest, der::INTEGER)?;
    if !rest.is_empty() {
        return None;
    }
    Some((BigUint::from_bytes_be(r), BigUint::from_bytes_be(s)))
}

/// A point in Jacobian coordinates (X/Z², Y/Z³); Z = 0 is the point at infinity.
#[derive(Clone)]
struct Jacobian {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

fn sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a + p - b % p) % p
}

impl Jacobian {
    fn infinity() -> Self {
        Self {
            x: BigUint::one(),
            y: BigUint::one(),
            z: BigUint::zero(),
        }
    }

    fn from_affine((x, y): &(BigUint, BigUint)) -> Self {
        Self {
            x: x.clone(),
            y: y.clone(),
            z: BigUint::one(),
        }
    }

    fn double(&self, curve: &Params) -> Self {
        let p = &curve.p;
        if self.z.is_zero() || self.y.is_zero() {
            return Self::infinity();
        }
        let yy = &self.y * &self.y % p;
        let zz = &self.z * &self.z % p;
        let s = 4u32 * &self.x * &yy % p;
        let m = (3u32 * &self.x * &self.x + &curve.a * &zz % p * &zz) % p;
        let x3 = sub(&(&m * &m % p), &(2u32 * &s % p), p);
        let y3 = sub(&(&m * sub(&s, &x3, p) % p), &(8u32 * &yy * &yy % p), p);
        let z3 = 2u32 * &self.y * &self.z % p;
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn add(&self, other: &Self, curve: &Params) -> Self {
        let p = &curve.p;
        if self.z.is_zero() {
            return other.clone();
        }
        if other.z.is_zero() {
            return self.clone();
        }
        let z1z1 = &self.z * &self.z % p;
        let z2z2 = &other.z * &other.z % p;
        let u1 = &self.x * &z2z2 % p;
        let u2 = &other.x * &z1z1 % p;
        let s1 = &self.y * &other.z % p * &z2z2 % p;
        let s2 = &other.y * &self.z % p * &z1z1 % p;
        if u1 == u2 {
            return if s1 == s2 {
                self.double(curve)
            } else {
                Self::infinity()
            };
        }
        let h = sub(&u2, &u1, p);
        let r = sub(&s2, &s1, p);
        let hh = &h * &h % p;
        let hhh = &hh * &h % p;
        let v = &u1 * &hh % p;
        let x3 = sub(&sub(&(&r * &r % p), &hhh, p), &(2u32 * &v % p), p);
        let y3 = sub(&(&r * sub(&v, &x3, p) % p), &(&s1 * &hhh % p), p);
        let z3 = &h * &self.z % p * &other.z % p;
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// The affine x, or `None` at infinity.
    fn to_affine_x(&self, curve: &Params) -> Option<BigUint> {
        let p = &curve.p;
        if self.z.is_zero() {
            return None;
        }
        let zz = &self.z * &self.z % p;
        Some(&self.x * zz.modpow(&(p - 2u32), p) % p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> &'static Curve {
        CURVES.iter().copied().find(|c| c.name == name).unwrap()
    }

    #[test]
    fn every_base_point_is_on_its_curve() {
        for curve in CURVES {
            let params = curve.params();
            let len = curve.field_len();
            let pad = |v: &BigUint| {
                let bytes = v.to_bytes_be();
                [vec![0; len - bytes.len()], bytes].concat()
            };
            let g = [vec![0x04], pad(&params.g.0), pad(&params.g.1)].concat();
            assert!(decode_point(&params, &g).is_some(), "{}", curve.name);
        }
    }

    #[test]
    fn the_bigint_verifier_agrees_with_the_p256_crate() {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let sig: Signature = key.sign(b"a security object");
        let der = sig.to_der();
        let curve = named("P-256");
        let digest = HashAlgo::Sha256.digest(b"a security object");
        assert!(curve.verify_bigint(point.as_bytes(), &digest, der.as_bytes()));
        let other = HashAlgo::Sha256.digest(b"another security object");
        assert!(!curve.verify_bigint(point.as_bytes(), &other, der.as_bytes()));
    }

    #[test]
    fn the_bigint_verifier_agrees_with_the_p384_crate() {
        use p384::ecdsa::signature::Signer;
        use p384::ecdsa::{Signature, SigningKey};
        let key = SigningKey::from_slice(&[9; 48]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let sig: Signature = key.sign(b"a security object");
        let der = sig.to_der();
        let curve = named("P-384");
        let digest = HashAlgo::Sha384.digest(b"a security object");
        assert!(curve.verify_bigint(point.as_bytes(), &digest, der.as_bytes()));
        let other = HashAlgo::Sha256.digest(b"a security object");
        assert!(!curve.verify_bigint(point.as_bytes(), &other, der.as_bytes()));
    }

    #[test]
    fn a_point_off_the_curve_is_refused() {
        use p256::ecdsa::SigningKey;
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let mut point = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        point[64] ^= 1;
        assert!(decode_point(&named("P-256").params(), &point).is_none());
    }

    #[test]
    fn a_named_curve_or_explicit_parameters_equal_to_one() {
        let bp256_oid = [
            0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
        ];
        assert_eq!(
            Curve::from_params(&bp256_oid).map(|c| c.name),
            Some("brainpoolP256r1")
        );
        // an unknown named curve, and implicitlyCA (NULL)
        assert!(Curve::from_params(&[0x06, 0x03, 0x2B, 0x81, 0x04]).is_none());
        assert!(Curve::from_params(&[0x05, 0x00]).is_none());
    }
}
