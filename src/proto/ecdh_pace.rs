//! ECDH PACE engine.
//!
//! The reference supports 11 ICAO curves (ids 8-18). This Rust port
//! currently implements only **NIST P-256 (id 12)** — the only curve marked
//! `is_supported = true` in [`domain_parameter`]. Other ids return
//! [`ECDHPaceError::UnsupportedCurve`]; add additional back-ends as needed.
//!
//! PACE-GM mapped generator formula (ICAO 9303 p11 §4.3.3.3.1 - ECDH):
//! ```text
//! G' = s · G + H
//! ```
//! where `s` is the nonce, `G` the predefined generator, and `H` the
//! shared-secret point derived from our private key and the other party's
//! public key.

use elliptic_curve::{
    group::Group,
    ops::Reduce,
    sec1::{FromSec1Point, ToSec1Point},
    Generate, NonZeroScalar, PrimeField,
};
use num_bigint::BigUint;
use p256::{
    AffinePoint, NistP256, ProjectivePoint, PublicKey, Scalar, Sec1Point as EncodedPoint, SecretKey,
};
use rand::rand_core::UnwrapErr;
use rand::{rngs::StdRng, rngs::SysRng, Rng, SeedableRng};
use thiserror::Error;

use crate::proto::domain_parameter;
use crate::proto::public_key_pace::PublicKeyPace;

/// ICAO domain-parameter id for NIST P-256 (the only curve supported by this
/// Rust port today).
pub const NIST_P256_ID: u32 = 12;

/// Error returned by [`ECDHPace`] operations.
///
/// Consolidates the `ECDHPaceError` and `ECDHBasicAgreementPACEError`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ECDHPaceError {
    #[error("Domain parameter with id {0} does not exist.")]
    UnknownId(u32),
    #[error("Curve for id {0} is not yet supported by this Rust port")]
    UnsupportedCurve(u32),
    #[error("Public key is null. Generate key pair first.")]
    NoPublicKey,
    #[error("Ephemeral public key is null. Generate ephemeral key pair first.")]
    NoEphemeralPublicKey,
    #[error("Infinity is not a valid public key for ECDH")]
    InfinityPoint,
    #[error("Infinity is not a valid agreement value for ECDH")]
    InfinityAgreement,
    #[error("Invalid public key encoding")]
    InvalidEncoding,
    #[error("Invalid private key scalar")]
    InvalidScalar,
    #[error("Seed must be 256 bits long.")]
    InvalidSeedLen,
}

// ---------------------------------------------------------------------------
// ECDHPace
// ---------------------------------------------------------------------------

/// ECDH PACE engine for NIST P-256. Holds a main key pair plus an optional
/// ephemeral one used during PACE-GM mapping.
#[derive(Debug)]
pub struct ECDHPace {
    priv_key: Option<SecretKey>,
    pub_key: Option<PublicKey>,
    ephemeral_priv: Option<Scalar>,
    ephemeral_pub: Option<ProjectivePoint>,
    /// Mapped generator used with the ephemeral scalar (PACE-GM).
    ephemeral_generator: Option<ProjectivePoint>,
}

impl ECDHPace {
    /// Constructs an ECDH PACE engine for the given ICAO domain-parameter id.
    ///
    /// # Errors
    /// - [`ECDHPaceError::UnknownId`] if `id` is not listed in the ICAO table.
    /// - [`ECDHPaceError::UnsupportedCurve`] if `id` is listed but this port
    ///   does not yet back it.
    pub fn new(id: u32) -> Result<Self, ECDHPaceError> {
        if domain_parameter::get(id).is_none() {
            return Err(ECDHPaceError::UnknownId(id));
        }
        if id != NIST_P256_ID {
            return Err(ECDHPaceError::UnsupportedCurve(id));
        }
        Ok(Self {
            priv_key: None,
            pub_key: None,
            ephemeral_priv: None,
            ephemeral_pub: None,
            ephemeral_generator: None,
        })
    }

    /// Generates a new main key pair using the OS RNG (`SysRng`) or a seeded
    /// RNG if `seed` is provided (must be exactly 32 bytes).
    pub fn generate_key_pair(&mut self, seed32: Option<&[u8]>) -> Result<(), ECDHPaceError> {
        let sk = match seed32 {
            None => {
                let mut rng = UnwrapErr(SysRng);
                SecretKey::generate_from_rng(&mut rng)
            }
            Some(s) if s.len() == 32 => {
                let mut seed_arr = [0u8; 32];
                seed_arr.copy_from_slice(s);
                let mut rng = StdRng::from_seed(seed_arr);
                // Sample the scalar manually via rejection so the seeded path
                // has stable, reproducible output independent of any RNG helper.
                let scalar = loop {
                    let mut bytes = [0u8; 32];
                    rng.fill_bytes(&mut bytes);
                    if let Ok(nz) = Scalar::from_repr(bytes.into()).into_option().ok_or(())
                        .and_then(|s| NonZeroScalar::new(s).into_option().ok_or(()))
                    {
                        break nz;
                    }
                };
                SecretKey::from(scalar)
            }
            Some(_) => return Err(ECDHPaceError::InvalidSeedLen),
        };
        self.pub_key = Some(sk.public_key());
        self.priv_key = Some(sk);
        Ok(())
    }

    /// Returns the main public key as a [`PublicKeyPace::Ecdh`].
    pub fn get_pub_key(&self) -> Result<PublicKeyPace, ECDHPaceError> {
        let pk = self.pub_key.as_ref().ok_or(ECDHPaceError::NoPublicKey)?;
        point_to_pubkey_pace(pk.to_projective())
    }

    /// Returns the ephemeral public key as a [`PublicKeyPace::Ecdh`].
    pub fn get_pub_key_ephemeral(&self) -> Result<PublicKeyPace, ECDHPaceError> {
        let pk = self
            .ephemeral_pub
            .as_ref()
            .ok_or(ECDHPaceError::NoEphemeralPublicKey)?;
        point_to_pubkey_pace(*pk)
    }

    /// Converts a [`PublicKeyPace::Ecdh`] into an on-curve [`PublicKey`].
    pub fn transform_public(pub_key: &PublicKeyPace) -> Result<PublicKey, ECDHPaceError> {
        match pub_key {
            PublicKeyPace::Ecdh { x, y, .. } => pubkey_from_xy(x, y),
            _ => Err(ECDHPaceError::InvalidEncoding),
        }
    }

    /// Computes the shared secret point `P = priv · other`. P-256 has
    /// cofactor `h = 1`, so no cofactor correction is needed.
    pub fn get_shared_secret(
        &self,
        other_pub_key: &PublicKey,
    ) -> Result<ProjectivePoint, ECDHPaceError> {
        let sk = self.priv_key.as_ref().ok_or(ECDHPaceError::NoPublicKey)?;
        compute_shared_point(sk.to_nonzero_scalar().as_ref(), other_pub_key)
    }

    /// Ephemeral variant of [`get_shared_secret`].
    pub fn get_ephemeral_shared_secret(
        &self,
        other_ephemeral_pub_key: &PublicKey,
    ) -> Result<ProjectivePoint, ECDHPaceError> {
        let scalar = self
            .ephemeral_priv
            .as_ref()
            .ok_or(ECDHPaceError::NoEphemeralPublicKey)?;
        compute_shared_point(scalar, other_ephemeral_pub_key)
    }

    /// Computes the PACE-GM mapped generator:
    /// `G' = s · G + H`, where `H = priv · other`.
    pub fn get_mapped_generator(
        &self,
        other_pub_key: &PublicKey,
        nonce: &[u8],
    ) -> Result<ProjectivePoint, ECDHPaceError> {
        let h = self.get_shared_secret(other_pub_key)?;
        let s = scalar_from_bytes(nonce);
        let g = ProjectivePoint::GENERATOR;
        Ok(g * s + h)
    }

    /// Builds an ephemeral key pair using the given mapped generator and a
    /// seeded / random scalar. The generator is stored so that subsequent
    /// ephemeral shared-secret computations use the correct base point.
    pub fn generate_ephemeral_with_custom_generator(
        &mut self,
        mapped_generator: ProjectivePoint,
        seed32: Option<&[u8]>,
    ) -> Result<(), ECDHPaceError> {
        let scalar = sample_scalar(seed32)?;
        let pub_point = mapped_generator * *scalar.as_ref();
        self.ephemeral_priv = Some(*scalar.as_ref());
        self.ephemeral_pub = Some(pub_point);
        self.ephemeral_generator = Some(mapped_generator);
        Ok(())
    }

}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn scalar_from_bytes(bytes: &[u8]) -> Scalar {
    // Right-align the big-endian input into a fixed 32-byte buffer, then let
    // the scalar's standard reduction wrap it modulo n (the P-256 order).
    // Working on the slice directly avoids the BigUint round-trip allocation.
    let mut buf = [0u8; 32];
    if bytes.len() <= 32 {
        buf[32 - bytes.len()..].copy_from_slice(bytes);
    } else {
        // Take the least-significant 32 bytes (then reduce). Unreachable with
        // well-formed PACE nonces (16 bytes), but kept defensive.
        buf.copy_from_slice(&bytes[bytes.len() - 32..]);
    }
    <Scalar as Reduce<p256::U256>>::reduce(&p256::U256::from_be_slice(&buf))
}

fn sample_scalar(seed32: Option<&[u8]>) -> Result<NonZeroScalar<NistP256>, ECDHPaceError> {
    match seed32 {
        None => {
            let mut rng = UnwrapErr(SysRng);
            Ok(NonZeroScalar::generate_from_rng(&mut rng))
        }
        Some(s) if s.len() == 32 => {
            let mut seed_arr = [0u8; 32];
            seed_arr.copy_from_slice(s);
            let mut rng = StdRng::from_seed(seed_arr);
            loop {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                if let Some(s) = Scalar::from_repr(bytes.into()).into_option() {
                    if let Some(nz) = NonZeroScalar::new(s).into_option() {
                        return Ok(nz);
                    }
                }
            }
        }
        Some(_) => Err(ECDHPaceError::InvalidSeedLen),
    }
}

fn compute_shared_point(
    scalar: &Scalar,
    other: &PublicKey,
) -> Result<ProjectivePoint, ECDHPaceError> {
    let other_point = other.to_projective();
    if bool::from(other_point.is_identity()) {
        return Err(ECDHPaceError::InfinityPoint);
    }
    let shared = other_point * *scalar;
    if bool::from(shared.is_identity()) {
        return Err(ECDHPaceError::InfinityAgreement);
    }
    Ok(shared)
}

fn point_to_pubkey_pace(point: ProjectivePoint) -> Result<PublicKeyPace, ECDHPaceError> {
    let affine: AffinePoint = point.to_affine();
    let encoded: EncodedPoint = affine.to_sec1_point(false);
    // The identity (point at infinity) has no affine coordinates; reject it
    // instead of panicking on the missing X/Y.
    let x_bytes = encoded.x().ok_or(ECDHPaceError::InfinityPoint)?;
    let y_bytes = encoded.y().ok_or(ECDHPaceError::InfinityPoint)?;
    // SEC1 uncompressed coordinates are fixed-width (32 bytes for P-256); carry
    // that width so the X||Y form is always emitted at full length.
    let coord_len = x_bytes.len();
    Ok(PublicKeyPace::new_ecdh_fixed(
        BigUint::from_bytes_be(x_bytes),
        BigUint::from_bytes_be(y_bytes),
        coord_len,
    ))
}

fn pubkey_from_xy(x: &BigUint, y: &BigUint) -> Result<PublicKey, ECDHPaceError> {
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    let x_be = x.to_bytes_be();
    let y_be = y.to_bytes_be();
    if x_be.len() > 32 || y_be.len() > 32 {
        return Err(ECDHPaceError::InvalidEncoding);
    }
    x_bytes[32 - x_be.len()..].copy_from_slice(&x_be);
    y_bytes[32 - y_be.len()..].copy_from_slice(&y_be);

    let encoded = EncodedPoint::from_affine_coordinates(&x_bytes.into(), &y_bytes.into(), false);
    let affine =
        Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&encoded))
            .ok_or(ECDHPaceError::InvalidEncoding)?;
    Ok(PublicKey::from_affine(affine).map_err(|_| ECDHPaceError::InvalidEncoding)?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_id_is_rejected() {
        assert_eq!(
            ECDHPace::new(99).unwrap_err(),
            ECDHPaceError::UnknownId(99),
        );
    }

    #[test]
    fn unsupported_curve_is_rejected() {
        // id 8 = NIST P-192, present in table but not yet backed.
        assert_eq!(
            ECDHPace::new(8).unwrap_err(),
            ECDHPaceError::UnsupportedCurve(8),
        );
    }

    #[test]
    fn p256_engine_constructs() {
        let e = ECDHPace::new(NIST_P256_ID).unwrap();
        // No key pair generated yet, so the public key is unavailable.
        assert_eq!(e.get_pub_key().unwrap_err(), ECDHPaceError::NoPublicKey);
    }

    #[test]
    fn seeded_key_pair_is_deterministic() {
        let seed = [0x11u8; 32];
        let mut a = ECDHPace::new(NIST_P256_ID).unwrap();
        let mut b = ECDHPace::new(NIST_P256_ID).unwrap();
        a.generate_key_pair(Some(&seed)).unwrap();
        b.generate_key_pair(Some(&seed)).unwrap();
        let pka = a.get_pub_key().unwrap().to_bytes();
        let pkb = b.get_pub_key().unwrap().to_bytes();
        assert_eq!(pka, pkb);
    }

    #[test]
    fn seed_wrong_length_errors() {
        let mut e = ECDHPace::new(NIST_P256_ID).unwrap();
        let err = e.generate_key_pair(Some(&[0u8; 16])).unwrap_err();
        assert_eq!(err, ECDHPaceError::InvalidSeedLen);
    }

    #[test]
    fn shared_secret_is_symmetric() {
        let mut alice = ECDHPace::new(NIST_P256_ID).unwrap();
        let mut bob = ECDHPace::new(NIST_P256_ID).unwrap();
        alice.generate_key_pair(Some(&[0x01u8; 32])).unwrap();
        bob.generate_key_pair(Some(&[0x02u8; 32])).unwrap();

        let alice_pk = alice.get_pub_key().unwrap();
        let bob_pk = bob.get_pub_key().unwrap();
        let alice_pk_ec = ECDHPace::transform_public(&alice_pk).unwrap();
        let bob_pk_ec = ECDHPace::transform_public(&bob_pk).unwrap();

        let s_ab = alice.get_shared_secret(&bob_pk_ec).unwrap();
        let s_ba = bob.get_shared_secret(&alice_pk_ec).unwrap();
        assert_eq!(s_ab, s_ba);
    }

    #[test]
    fn transform_public_roundtrip() {
        let mut e = ECDHPace::new(NIST_P256_ID).unwrap();
        e.generate_key_pair(Some(&[0x03u8; 32])).unwrap();
        let pk = e.get_pub_key().unwrap();
        let back = ECDHPace::transform_public(&pk).unwrap();
        // Re-serialise and compare.
        let pk2 = point_to_pubkey_pace(back.to_projective()).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn transform_public_rejects_dh_input() {
        let bad = PublicKeyPace::new_dh(vec![0x01, 0x02]);
        assert_eq!(
            ECDHPace::transform_public(&bad).unwrap_err(),
            ECDHPaceError::InvalidEncoding,
        );
    }

    #[test]
    fn mapped_generator_is_on_curve_and_matches_formula() {
        let mut alice = ECDHPace::new(NIST_P256_ID).unwrap();
        let mut bob = ECDHPace::new(NIST_P256_ID).unwrap();
        alice.generate_key_pair(Some(&[0x04u8; 32])).unwrap();
        bob.generate_key_pair(Some(&[0x05u8; 32])).unwrap();

        let bob_pk = ECDHPace::transform_public(&bob.get_pub_key().unwrap()).unwrap();
        let nonce = hex::decode("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0").unwrap();

        let g_prime = alice.get_mapped_generator(&bob_pk, &nonce).unwrap();
        // Manual recomputation.
        let h = alice.get_shared_secret(&bob_pk).unwrap();
        let s = scalar_from_bytes(&nonce);
        let expected = ProjectivePoint::GENERATOR * s + h;
        assert_eq!(g_prime, expected);
    }

    #[test]
    fn ephemeral_flow_with_mapped_generator() {
        let mut alice = ECDHPace::new(NIST_P256_ID).unwrap();
        let mut bob = ECDHPace::new(NIST_P256_ID).unwrap();
        alice.generate_key_pair(Some(&[0x04u8; 32])).unwrap();
        bob.generate_key_pair(Some(&[0x05u8; 32])).unwrap();

        let bob_pk = ECDHPace::transform_public(&bob.get_pub_key().unwrap()).unwrap();
        let g_prime = alice
            .get_mapped_generator(&bob_pk, &[0xA1, 0xA2, 0xA3, 0xA4])
            .unwrap();
        alice
            .generate_ephemeral_with_custom_generator(g_prime, Some(&[0x0Au8; 32]))
            .unwrap();
        assert!(alice.get_pub_key_ephemeral().is_ok());
    }
}
