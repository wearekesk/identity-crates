//! ECDH PACE engine supporting NIST and Brainpool curves.
//!
//! Handles PACE key agreement using ECDH-GM mapped generator formula:
//! ```text
//! G' = s · G + H
//! ```
//! where `s` is the nonce, `G` the predefined generator, and `H` the
//! shared-secret point derived from our private key and the other party's
//! public key.

use num_bigint::BigUint;
use rand::rand_core::UnwrapErr;
use rand::{rngs::StdRng, rngs::SysRng, Rng, SeedableRng};
use thiserror::Error;

use crate::proto::domain_parameter;
use crate::proto::public_key_pace::PublicKeyPace;

/// ICAO domain-parameter id for NIST P-256.
pub const NIST_P256_ID: u32 = 12;

/// Error returned by [`ECDHPace`] operations.
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
    #[error(transparent)]
    InvalidCoordinate(#[from] crate::proto::public_key_pace::PublicKeyPaceError),
}

macro_rules! impl_curve_ops {
    (modern, $struct_name:ident, $curve_crate:ident, $curve_type:ty, $secret_key:ty, $scalar:ty, $projective:ty, $affine:ty, $coord_len:expr, $order_str:expr) => {
        #[derive(Debug)]
        pub struct $struct_name {
            priv_key: Option<$secret_key>,
            pub_key: Option<$curve_crate::elliptic_curve::PublicKey<$curve_type>>,
            ephemeral_priv: Option<$scalar>,
            ephemeral_pub: Option<$projective>,
            ephemeral_generator: Option<$projective>,
        }

        impl $struct_name {
            pub fn new() -> Self {
                Self {
                    priv_key: None,
                    pub_key: None,
                    ephemeral_priv: None,
                    ephemeral_pub: None,
                    ephemeral_generator: None,
                }
            }

            fn scalar_from_bytes(&self, bytes: &[u8]) -> $scalar {
                let n = BigUint::parse_bytes($order_str, 10).unwrap();
                let val = BigUint::from_bytes_be(bytes);
                let reduced = val % &n;
                let r_bytes = reduced.to_bytes_be();
                let mut buf = vec![0u8; $coord_len];
                if r_bytes.len() <= $coord_len {
                    buf[$coord_len - r_bytes.len()..].copy_from_slice(&r_bytes);
                } else {
                    buf.copy_from_slice(&r_bytes[r_bytes.len() - $coord_len..]);
                }
                let field_bytes = *<$curve_crate::elliptic_curve::FieldBytes<$curve_type>>::from_slice(&buf);
                <$scalar as $curve_crate::elliptic_curve::ff::PrimeField>::from_repr(field_bytes).unwrap()
            }

            pub fn generate_key_pair(&mut self, seed32: Option<&[u8]>) -> Result<(), ECDHPaceError> {
                let sk = match seed32 {
                    None => {
                        let mut rng = UnwrapErr(SysRng);
                        <$secret_key>::random(&mut rng)
                    }
                    Some(s) if s.len() == 32 => {
                        let mut seed_arr = [0u8; 32];
                        seed_arr.copy_from_slice(s);
                        let mut rng = StdRng::from_seed(seed_arr);
                        loop {
                            let mut bytes = vec![0u8; $coord_len];
                            rng.fill_bytes(&mut bytes);
                            if let Ok(sk) = <$secret_key>::from_slice(&bytes) {
                                break sk;
                            }
                        }
                    }
                    Some(_) => return Err(ECDHPaceError::InvalidSeedLen),
                };
                self.pub_key = Some(sk.public_key());
                self.priv_key = Some(sk);
                Ok(())
            }

            pub fn get_pub_key(&self) -> Result<PublicKeyPace, ECDHPaceError> {
                let pk = self.pub_key.as_ref().ok_or(ECDHPaceError::NoPublicKey)?;
                self.point_to_pubkey_pace(pk.to_projective())
            }

            pub fn get_pub_key_ephemeral(&self) -> Result<PublicKeyPace, ECDHPaceError> {
                let pk = self
                    .ephemeral_pub
                    .as_ref()
                    .ok_or(ECDHPaceError::NoEphemeralPublicKey)?;
                self.point_to_pubkey_pace(*pk)
            }

            pub fn map_and_generate_ephemeral(
                &mut self,
                other_pub_key: &PublicKeyPace,
                nonce: &[u8],
                seed32: Option<&[u8]>,
            ) -> Result<(), ECDHPaceError> {
                use $curve_crate::elliptic_curve::group::Group;

                let other = self.transform_public(other_pub_key)?;
                let h = self.compute_shared_point(&other)?;
                let s = self.scalar_from_bytes(nonce);
                let g = <$projective as Group>::generator();
                let g_prime = g * s + h;

                // Sample ephemeral scalar
                let scalar = match seed32 {
                    None => {
                        let mut rng = UnwrapErr(SysRng);
                        let sk = <$secret_key>::random(&mut rng);
                        self.scalar_from_bytes(&sk.to_bytes())
                    }
                    Some(s) if s.len() == 32 => {
                        let mut seed_arr = [0u8; 32];
                        seed_arr.copy_from_slice(s);
                        let mut rng = StdRng::from_seed(seed_arr);
                        loop {
                            let mut bytes = vec![0u8; $coord_len];
                            rng.fill_bytes(&mut bytes);
                            if let Ok(sk) = <$secret_key>::from_slice(&bytes) {
                                break self.scalar_from_bytes(&sk.to_bytes());
                            }
                        }
                    }
                    Some(_) => return Err(ECDHPaceError::InvalidSeedLen),
                };

                let pub_point = g_prime * scalar;
                self.ephemeral_priv = Some(scalar);
                self.ephemeral_pub = Some(pub_point);
                self.ephemeral_generator = Some(g_prime);
                Ok(())
            }

            pub fn get_ephemeral_shared_seed(
                &self,
                other_ephemeral_pub_key: &PublicKeyPace,
            ) -> Result<Vec<u8>, ECDHPaceError> {
                use $curve_crate::elliptic_curve::group::Group;

                let other = self.transform_public(other_ephemeral_pub_key)?;
                let scalar = self
                    .ephemeral_priv
                    .as_ref()
                    .ok_or(ECDHPaceError::NoEphemeralPublicKey)?;
                
                let other_point = other.to_projective();
                if bool::from(other_point.is_identity()) {
                    return Err(ECDHPaceError::InfinityPoint);
                }
                let shared = other_point * *scalar;
                if bool::from(shared.is_identity()) {
                    return Err(ECDHPaceError::InfinityAgreement);
                }

                let pk = <$curve_crate::elliptic_curve::PublicKey<$curve_type>>::from_affine(
                    shared.to_affine()
                ).map_err(|_| ECDHPaceError::InfinityAgreement)?;
                let sec1_bytes = pk.to_sec1_bytes();
                if sec1_bytes.len() != 1 + 2 * $coord_len || sec1_bytes[0] != 0x04 {
                    return Err(ECDHPaceError::InvalidEncoding);
                }
                let x_bytes = &sec1_bytes[1..1 + $coord_len];
                Ok(x_bytes.to_vec())
            }

            fn compute_shared_point(
                &self,
                other: &$curve_crate::elliptic_curve::PublicKey<$curve_type>,
            ) -> Result<$projective, ECDHPaceError> {
                use $curve_crate::elliptic_curve::group::Group;

                let sk = self.priv_key.as_ref().ok_or(ECDHPaceError::NoPublicKey)?;
                let scalar = self.scalar_from_bytes(&sk.to_bytes());
                let other_point = other.to_projective();
                if bool::from(other_point.is_identity()) {
                    return Err(ECDHPaceError::InfinityPoint);
                }
                let shared = other_point * scalar;
                if bool::from(shared.is_identity()) {
                    return Err(ECDHPaceError::InfinityAgreement);
                }
                Ok(shared)
            }

            fn point_to_pubkey_pace(&self, point: $projective) -> Result<PublicKeyPace, ECDHPaceError> {
                let affine = point.to_affine();
                let pk = <$curve_crate::elliptic_curve::PublicKey<$curve_type>>::from_affine(affine).map_err(|_| ECDHPaceError::InfinityPoint)?;
                let sec1_bytes = pk.to_sec1_bytes();
                if sec1_bytes.len() != 1 + 2 * $coord_len || sec1_bytes[0] != 0x04 {
                    return Err(ECDHPaceError::InvalidEncoding);
                }
                let x_bytes = &sec1_bytes[1..1 + $coord_len];
                let y_bytes = &sec1_bytes[1 + $coord_len..];
                Ok(PublicKeyPace::new_ecdh_fixed(
                    BigUint::from_bytes_be(x_bytes),
                    BigUint::from_bytes_be(y_bytes),
                    $coord_len,
                )?)
            }

            fn transform_public(&self, pub_key: &PublicKeyPace) -> Result<$curve_crate::elliptic_curve::PublicKey<$curve_type>, ECDHPaceError> {
                match pub_key {
                    PublicKeyPace::Ecdh { x, y, .. } => {
                        let mut x_bytes = vec![0u8; $coord_len];
                        let mut y_bytes = vec![0u8; $coord_len];
                        let x_be = x.to_bytes_be();
                        let y_be = y.to_bytes_be();
                        if x_be.len() > $coord_len || y_be.len() > $coord_len {
                            return Err(ECDHPaceError::InvalidEncoding);
                        }
                        x_bytes[$coord_len - x_be.len()..].copy_from_slice(&x_be);
                        y_bytes[$coord_len - y_be.len()..].copy_from_slice(&y_be);

                        let mut bytes = vec![0x04];
                        bytes.extend_from_slice(&x_bytes);
                        bytes.extend_from_slice(&y_bytes);
                        <$curve_crate::elliptic_curve::PublicKey<$curve_type>>::from_sec1_bytes(&bytes).map_err(|_| ECDHPaceError::InvalidEncoding)
                    }
                    _ => Err(ECDHPaceError::InvalidEncoding),
                }
            }
        }
    };

    (legacy, $struct_name:ident, $curve_crate:ident, $curve_type:ty, $secret_key:ty, $scalar:ty, $projective:ty, $affine:ty, $coord_len:expr, $order_str:expr) => {
        #[derive(Debug)]
        pub struct $struct_name {
            priv_key: Option<$secret_key>,
            pub_key: Option<$curve_crate::elliptic_curve::PublicKey<$curve_type>>,
            ephemeral_priv: Option<$scalar>,
            ephemeral_pub: Option<$projective>,
            ephemeral_generator: Option<$projective>,
        }

        impl $struct_name {
            pub fn new() -> Self {
                Self {
                    priv_key: None,
                    pub_key: None,
                    ephemeral_priv: None,
                    ephemeral_pub: None,
                    ephemeral_generator: None,
                }
            }

            fn scalar_from_bytes(&self, bytes: &[u8]) -> $scalar {
                let n = BigUint::parse_bytes($order_str, 10).unwrap();
                let val = BigUint::from_bytes_be(bytes);
                let reduced = val % &n;
                let r_bytes = reduced.to_bytes_be();
                let mut buf = vec![0u8; $coord_len];
                if r_bytes.len() <= $coord_len {
                    buf[$coord_len - r_bytes.len()..].copy_from_slice(&r_bytes);
                } else {
                    buf.copy_from_slice(&r_bytes[r_bytes.len() - $coord_len..]);
                }
                let field_bytes = *<$curve_crate::elliptic_curve::FieldBytes<$curve_type>>::from_slice(&buf);
                <$scalar as $curve_crate::elliptic_curve::ff::PrimeField>::from_repr(field_bytes).unwrap()
            }

            pub fn generate_key_pair(&mut self, seed32: Option<&[u8]>) -> Result<(), ECDHPaceError> {
                struct RngBridge<'a, R>(&'a mut R);

                impl<'a, R: rand::rand_core::RngCore> $curve_crate::elliptic_curve::rand_core::RngCore for RngBridge<'a, R> {
                    fn next_u32(&mut self) -> u32 {
                        self.0.next_u32()
                    }
                    fn next_u64(&mut self) -> u64 {
                        self.0.next_u64()
                    }
                    fn fill_bytes(&mut self, dest: &mut [u8]) {
                        self.0.fill_bytes(dest)
                    }
                    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), $curve_crate::elliptic_curve::rand_core::Error> {
                        self.0.try_fill_bytes(dest).map_err(|_| $curve_crate::elliptic_curve::rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap()))
                    }
                }

                impl<'a, R: rand::rand_core::CryptoRng> $curve_crate::elliptic_curve::rand_core::CryptoRng for RngBridge<'a, R> {}

                let sk = match seed32 {
                    None => {
                        let mut sys_rng = UnwrapErr(SysRng);
                        let mut rng = RngBridge(&mut sys_rng);
                        <$secret_key>::random(&mut rng)
                    }
                    Some(s) if s.len() == 32 => {
                        let mut seed_arr = [0u8; 32];
                        seed_arr.copy_from_slice(s);
                        let mut rng = StdRng::from_seed(seed_arr);
                        loop {
                            let mut bytes = vec![0u8; $coord_len];
                            rng.fill_bytes(&mut bytes);
                            if let Ok(sk) = <$secret_key>::from_slice(&bytes) {
                                break sk;
                            }
                        }
                    }
                    Some(_) => return Err(ECDHPaceError::InvalidSeedLen),
                };
                self.pub_key = Some(sk.public_key());
                self.priv_key = Some(sk);
                Ok(())
            }

            pub fn get_pub_key(&self) -> Result<PublicKeyPace, ECDHPaceError> {
                let pk = self.pub_key.as_ref().ok_or(ECDHPaceError::NoPublicKey)?;
                self.point_to_pubkey_pace(pk.to_projective())
            }

            pub fn get_pub_key_ephemeral(&self) -> Result<PublicKeyPace, ECDHPaceError> {
                let pk = self
                    .ephemeral_pub
                    .as_ref()
                    .ok_or(ECDHPaceError::NoEphemeralPublicKey)?;
                self.point_to_pubkey_pace(*pk)
            }

            pub fn map_and_generate_ephemeral(
                &mut self,
                other_pub_key: &PublicKeyPace,
                nonce: &[u8],
                seed32: Option<&[u8]>,
            ) -> Result<(), ECDHPaceError> {
                use $curve_crate::elliptic_curve::group::Group;

                struct RngBridge<'a, R>(&'a mut R);

                impl<'a, R: rand::rand_core::RngCore> $curve_crate::elliptic_curve::rand_core::RngCore for RngBridge<'a, R> {
                    fn next_u32(&mut self) -> u32 {
                        self.0.next_u32()
                    }
                    fn next_u64(&mut self) -> u64 {
                        self.0.next_u64()
                    }
                    fn fill_bytes(&mut self, dest: &mut [u8]) {
                        self.0.fill_bytes(dest)
                    }
                    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), $curve_crate::elliptic_curve::rand_core::Error> {
                        self.0.try_fill_bytes(dest).map_err(|_| $curve_crate::elliptic_curve::rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap()))
                    }
                }

                impl<'a, R: rand::rand_core::CryptoRng> $curve_crate::elliptic_curve::rand_core::CryptoRng for RngBridge<'a, R> {}

                let other = self.transform_public(other_pub_key)?;
                let h = self.compute_shared_point(&other)?;
                let s = self.scalar_from_bytes(nonce);
                let g = <$projective as Group>::generator();
                let g_prime = g * s + h;

                // Sample ephemeral scalar
                let scalar = match seed32 {
                    None => {
                        let mut sys_rng = UnwrapErr(SysRng);
                        let mut rng = RngBridge(&mut sys_rng);
                        let sk = <$secret_key>::random(&mut rng);
                        self.scalar_from_bytes(&sk.to_bytes())
                    }
                    Some(s) if s.len() == 32 => {
                        let mut seed_arr = [0u8; 32];
                        seed_arr.copy_from_slice(s);
                        let mut rng = StdRng::from_seed(seed_arr);
                        loop {
                            let mut bytes = vec![0u8; $coord_len];
                            rng.fill_bytes(&mut bytes);
                            if let Ok(sk) = <$secret_key>::from_slice(&bytes) {
                                break self.scalar_from_bytes(&sk.to_bytes());
                            }
                        }
                    }
                    Some(_) => return Err(ECDHPaceError::InvalidSeedLen),
                };

                let pub_point = g_prime * scalar;
                self.ephemeral_priv = Some(scalar);
                self.ephemeral_pub = Some(pub_point);
                self.ephemeral_generator = Some(g_prime);
                Ok(())
            }

            pub fn get_ephemeral_shared_seed(
                &self,
                other_ephemeral_pub_key: &PublicKeyPace,
            ) -> Result<Vec<u8>, ECDHPaceError> {
                use $curve_crate::elliptic_curve::group::Group;

                let other = self.transform_public(other_ephemeral_pub_key)?;
                let scalar = self
                    .ephemeral_priv
                    .as_ref()
                    .ok_or(ECDHPaceError::NoEphemeralPublicKey)?;
                
                let other_point = other.to_projective();
                if bool::from(other_point.is_identity()) {
                    return Err(ECDHPaceError::InfinityPoint);
                }
                let shared = other_point * *scalar;
                if bool::from(shared.is_identity()) {
                    return Err(ECDHPaceError::InfinityAgreement);
                }

                let pk = <$curve_crate::elliptic_curve::PublicKey<$curve_type>>::from_affine(
                    shared.to_affine()
                ).map_err(|_| ECDHPaceError::InfinityAgreement)?;
                let sec1_bytes = pk.to_sec1_bytes();
                if sec1_bytes.len() != 1 + 2 * $coord_len || sec1_bytes[0] != 0x04 {
                    return Err(ECDHPaceError::InvalidEncoding);
                }
                let x_bytes = &sec1_bytes[1..1 + $coord_len];
                Ok(x_bytes.to_vec())
            }

            fn compute_shared_point(
                &self,
                other: &$curve_crate::elliptic_curve::PublicKey<$curve_type>,
            ) -> Result<$projective, ECDHPaceError> {
                use $curve_crate::elliptic_curve::group::Group;

                let sk = self.priv_key.as_ref().ok_or(ECDHPaceError::NoPublicKey)?;
                let scalar = self.scalar_from_bytes(&sk.to_bytes());
                let other_point = other.to_projective();
                if bool::from(other_point.is_identity()) {
                    return Err(ECDHPaceError::InfinityPoint);
                }
                let shared = other_point * scalar;
                if bool::from(shared.is_identity()) {
                    return Err(ECDHPaceError::InfinityAgreement);
                }
                Ok(shared)
            }

            fn point_to_pubkey_pace(&self, point: $projective) -> Result<PublicKeyPace, ECDHPaceError> {
                let affine = point.to_affine();
                let pk = <$curve_crate::elliptic_curve::PublicKey<$curve_type>>::from_affine(affine).map_err(|_| ECDHPaceError::InfinityPoint)?;
                let sec1_bytes = pk.to_sec1_bytes();
                if sec1_bytes.len() != 1 + 2 * $coord_len || sec1_bytes[0] != 0x04 {
                    return Err(ECDHPaceError::InvalidEncoding);
                }
                let x_bytes = &sec1_bytes[1..1 + $coord_len];
                let y_bytes = &sec1_bytes[1 + $coord_len..];
                Ok(PublicKeyPace::new_ecdh_fixed(
                    BigUint::from_bytes_be(x_bytes),
                    BigUint::from_bytes_be(y_bytes),
                    $coord_len,
                )?)
            }

            fn transform_public(&self, pub_key: &PublicKeyPace) -> Result<$curve_crate::elliptic_curve::PublicKey<$curve_type>, ECDHPaceError> {
                match pub_key {
                    PublicKeyPace::Ecdh { x, y, .. } => {
                        let mut x_bytes = vec![0u8; $coord_len];
                        let mut y_bytes = vec![0u8; $coord_len];
                        let x_be = x.to_bytes_be();
                        let y_be = y.to_bytes_be();
                        if x_be.len() > $coord_len || y_be.len() > $coord_len {
                            return Err(ECDHPaceError::InvalidEncoding);
                        }
                        x_bytes[$coord_len - x_be.len()..].copy_from_slice(&x_be);
                        y_bytes[$coord_len - y_be.len()..].copy_from_slice(&y_be);

                        let mut bytes = vec![0x04];
                        bytes.extend_from_slice(&x_bytes);
                        bytes.extend_from_slice(&y_bytes);
                        <$curve_crate::elliptic_curve::PublicKey<$curve_type>>::from_sec1_bytes(&bytes).map_err(|_| ECDHPaceError::InvalidEncoding)
                    }
                    _ => Err(ECDHPaceError::InvalidEncoding),
                }
            }
        }
    };
}

impl_curve_ops!(modern, NistP256Engine, p256, p256::NistP256, p256::SecretKey, p256::Scalar, p256::ProjectivePoint, p256::AffinePoint, 32, b"115792089210356248762485316520336594248464673199859591410292408985888941275213");
impl_curve_ops!(modern, BrainpoolP256r1Engine, bp256, bp256::r1::BrainpoolP256r1, bp256::r1::SecretKey, bp256::r1::Scalar, bp256::r1::ProjectivePoint, bp256::r1::AffinePoint, 32, b"115792089237316195423570985008687907852837564279074904382605163141518161494337");
impl_curve_ops!(modern, BrainpoolP256t1Engine, bp256, bp256::t1::BrainpoolP256t1, bp256::t1::SecretKey, bp256::t1::Scalar, bp256::t1::ProjectivePoint, bp256::t1::AffinePoint, 32, b"115792089237316195423570985008687907852837564279074904382605163141518161494337");
impl_curve_ops!(legacy, NistP384Engine, p384, p384::NistP384, p384::SecretKey, p384::Scalar, p384::ProjectivePoint, p384::AffinePoint, 48, b"39402006196394479212279040100143613805079739270464620022646276856019566907421111663185381673890280521949313936996367");
impl_curve_ops!(modern, BrainpoolP384r1Engine, bp384, bp384::r1::BrainpoolP384r1, bp384::r1::SecretKey, bp384::r1::Scalar, bp384::r1::ProjectivePoint, bp384::r1::AffinePoint, 48, b"39402006196394479212279040100143613805079739270464620022648719277063462947702816912384784949216075932598370503046777");
impl_curve_ops!(modern, BrainpoolP384t1Engine, bp384, bp384::t1::BrainpoolP384t1, bp384::t1::SecretKey, bp384::t1::Scalar, bp384::t1::ProjectivePoint, bp384::t1::AffinePoint, 48, b"39402006196394479212279040100143613805079739270464620022648719277063462947702816912384784949216075932598370503046777");
impl_curve_ops!(legacy, NistP521Engine, p521, p521::NistP521, p521::SecretKey, p521::Scalar, p521::ProjectivePoint, p521::AffinePoint, 66, b"6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449");
impl_curve_ops!(legacy, NistP224Engine, p224, p224::NistP224, p224::SecretKey, p224::Scalar, p224::ProjectivePoint, p224::AffinePoint, 28, b"26959946667150639794667015087019625940457807714424391721682722368061");

#[derive(Debug)]
pub enum ECDHPace {
    NistP256(NistP256Engine),
    BrainpoolP256r1(BrainpoolP256r1Engine),
    BrainpoolP256t1(BrainpoolP256t1Engine),
    NistP384(NistP384Engine),
    BrainpoolP384r1(BrainpoolP384r1Engine),
    BrainpoolP384t1(BrainpoolP384t1Engine),
    NistP521(NistP521Engine),
    NistP224(NistP224Engine),
}

impl ECDHPace {
    pub fn new(id: u32) -> Result<Self, ECDHPaceError> {
        if domain_parameter::get(id).is_none() {
            return Err(ECDHPaceError::UnknownId(id));
        }
        match id {
            10 => Ok(Self::NistP224(NistP224Engine::new())),
            12 => Ok(Self::NistP256(NistP256Engine::new())),
            13 => Ok(Self::BrainpoolP256r1(BrainpoolP256r1Engine::new())),
            15 => Ok(Self::NistP384(NistP384Engine::new())),
            16 => Ok(Self::BrainpoolP384r1(BrainpoolP384r1Engine::new())),
            18 => Ok(Self::NistP521(NistP521Engine::new())),
            23 => Ok(Self::BrainpoolP256t1(BrainpoolP256t1Engine::new())),
            26 => Ok(Self::BrainpoolP384t1(BrainpoolP384t1Engine::new())),
            _ => Err(ECDHPaceError::UnsupportedCurve(id)),
        }
    }

    pub fn generate_key_pair(&mut self, seed32: Option<&[u8]>) -> Result<(), ECDHPaceError> {
        match self {
            Self::NistP256(e) => e.generate_key_pair(seed32),
            Self::BrainpoolP256r1(e) => e.generate_key_pair(seed32),
            Self::BrainpoolP256t1(e) => e.generate_key_pair(seed32),
            Self::NistP384(e) => e.generate_key_pair(seed32),
            Self::BrainpoolP384r1(e) => e.generate_key_pair(seed32),
            Self::BrainpoolP384t1(e) => e.generate_key_pair(seed32),
            Self::NistP521(e) => e.generate_key_pair(seed32),
            Self::NistP224(e) => e.generate_key_pair(seed32),
        }
    }

    pub fn get_pub_key(&self) -> Result<PublicKeyPace, ECDHPaceError> {
        match self {
            Self::NistP256(e) => e.get_pub_key(),
            Self::BrainpoolP256r1(e) => e.get_pub_key(),
            Self::BrainpoolP256t1(e) => e.get_pub_key(),
            Self::NistP384(e) => e.get_pub_key(),
            Self::BrainpoolP384r1(e) => e.get_pub_key(),
            Self::BrainpoolP384t1(e) => e.get_pub_key(),
            Self::NistP521(e) => e.get_pub_key(),
            Self::NistP224(e) => e.get_pub_key(),
        }
    }

    pub fn get_pub_key_ephemeral(&self) -> Result<PublicKeyPace, ECDHPaceError> {
        match self {
            Self::NistP256(e) => e.get_pub_key_ephemeral(),
            Self::BrainpoolP256r1(e) => e.get_pub_key_ephemeral(),
            Self::BrainpoolP256t1(e) => e.get_pub_key_ephemeral(),
            Self::NistP384(e) => e.get_pub_key_ephemeral(),
            Self::BrainpoolP384r1(e) => e.get_pub_key_ephemeral(),
            Self::BrainpoolP384t1(e) => e.get_pub_key_ephemeral(),
            Self::NistP521(e) => e.get_pub_key_ephemeral(),
            Self::NistP224(e) => e.get_pub_key_ephemeral(),
        }
    }

    pub fn map_and_generate_ephemeral(
        &mut self,
        other_pub_key: &PublicKeyPace,
        nonce: &[u8],
        seed32: Option<&[u8]>,
    ) -> Result<(), ECDHPaceError> {
        match self {
            Self::NistP256(e) => e.map_and_generate_ephemeral(other_pub_key, nonce, seed32),
            Self::BrainpoolP256r1(e) => e.map_and_generate_ephemeral(other_pub_key, nonce, seed32),
            Self::BrainpoolP256t1(e) => e.map_and_generate_ephemeral(other_pub_key, nonce, seed32),
            Self::NistP384(e) => e.map_and_generate_ephemeral(other_pub_key, nonce, seed32),
            Self::BrainpoolP384r1(e) => e.map_and_generate_ephemeral(other_pub_key, nonce, seed32),
            Self::BrainpoolP384t1(e) => e.map_and_generate_ephemeral(other_pub_key, nonce, seed32),
            Self::NistP521(e) => e.map_and_generate_ephemeral(other_pub_key, nonce, seed32),
            Self::NistP224(e) => e.map_and_generate_ephemeral(other_pub_key, nonce, seed32),
        }
    }

    pub fn get_ephemeral_shared_seed(
        &self,
        other_ephemeral_pub_key: &PublicKeyPace,
    ) -> Result<Vec<u8>, ECDHPaceError> {
        match self {
            Self::NistP256(e) => e.get_ephemeral_shared_seed(other_ephemeral_pub_key),
            Self::BrainpoolP256r1(e) => e.get_ephemeral_shared_seed(other_ephemeral_pub_key),
            Self::BrainpoolP256t1(e) => e.get_ephemeral_shared_seed(other_ephemeral_pub_key),
            Self::NistP384(e) => e.get_ephemeral_shared_seed(other_ephemeral_pub_key),
            Self::BrainpoolP384r1(e) => e.get_ephemeral_shared_seed(other_ephemeral_pub_key),
            Self::BrainpoolP384t1(e) => e.get_ephemeral_shared_seed(other_ephemeral_pub_key),
            Self::NistP521(e) => e.get_ephemeral_shared_seed(other_ephemeral_pub_key),
            Self::NistP224(e) => e.get_ephemeral_shared_seed(other_ephemeral_pub_key),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_id_is_rejected() {
        assert_eq!(ECDHPace::new(99).unwrap_err(), ECDHPaceError::UnknownId(99));
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
    fn engine_constructs_for_all_supported_curves() {
        for id in &[10, 12, 13, 15, 16, 18, 23, 26] {
            let e = ECDHPace::new(*id).unwrap();
            assert_eq!(e.get_pub_key().unwrap_err(), ECDHPaceError::NoPublicKey);
        }
    }

    #[test]
    fn seeded_key_pair_is_deterministic() {
        let seed = [0x11u8; 32];
        for id in &[10, 12, 13, 15, 16, 18, 23, 26] {
            let mut a = ECDHPace::new(*id).unwrap();
            let mut b = ECDHPace::new(*id).unwrap();
            a.generate_key_pair(Some(&seed)).unwrap();
            b.generate_key_pair(Some(&seed)).unwrap();
            let pka = a.get_pub_key().unwrap().to_bytes();
            let pkb = b.get_pub_key().unwrap().to_bytes();
            assert_eq!(pka, pkb);
        }
    }

    #[test]
    fn seed_wrong_length_errors() {
        let mut e = ECDHPace::new(12).unwrap();
        let err = e.generate_key_pair(Some(&[0u8; 16])).unwrap_err();
        assert_eq!(err, ECDHPaceError::InvalidSeedLen);
    }

    #[test]
    fn shared_secret_is_symmetric_all_curves() {
        for id in &[10, 12, 13, 15, 16, 18, 23, 26] {
            let mut alice = ECDHPace::new(*id).unwrap();
            let mut bob = ECDHPace::new(*id).unwrap();
            alice.generate_key_pair(Some(&[0x01u8; 32])).unwrap();
            bob.generate_key_pair(Some(&[0x02u8; 32])).unwrap();

            let alice_pk = alice.get_pub_key().unwrap();
            let bob_pk = bob.get_pub_key().unwrap();

            // simulated map and ephemeral gen
            let nonce = [0xAAu8; 16];
            alice.map_and_generate_ephemeral(&bob_pk, &nonce, Some(&[0x03u8; 32])).unwrap();
            bob.map_and_generate_ephemeral(&alice_pk, &nonce, Some(&[0x04u8; 32])).unwrap();

            let alice_eph_pk = alice.get_pub_key_ephemeral().unwrap();
            let bob_eph_pk = bob.get_pub_key_ephemeral().unwrap();

            let seed_alice = alice.get_ephemeral_shared_seed(&bob_eph_pk).unwrap();
            let seed_bob = bob.get_ephemeral_shared_seed(&alice_eph_pk).unwrap();
            assert_eq!(seed_alice, seed_bob);
        }
    }
}
