//! PKCS#3 Diffie-Hellman engine.
//!
//! Implements the key-exchange primitives used by PACE:
//! - [`DhParameterSpec`] — group parameters `(p, g, length)`.
//! - [`DhKeyPair`] — `(public_key, private_key)` pair.
//! - [`DHpkcs3Engine`] — engine for generating key pairs, computing shared
//!   secrets, and deriving the ephemeral generator for PACE-GM.
//!
//! Arithmetic uses [`num_bigint::BigUint`] since DH operates on non-negative
//! integers modulo a prime `p`. Random private keys are drawn from
//! `[2^(length-1), 2^length)`.

use num_bigint::BigUint;
use num_traits::One;
use rand::{RngCore, SeedableRng, rngs::OsRng, rngs::StdRng};
use thiserror::Error;

/// Default private-key length (bits) when not specified on the
/// [`DhParameterSpec`].
pub const DEFAULT_PRIVATE_KEY_LENGTH: u32 = 256;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error returned by [`DHpkcs3Engine`] operations.
#[derive(Debug, Error)]
#[error("DHpkcs3EngineError: {0}")]
pub struct DhPkcs3EngineError(pub String);

// ---------------------------------------------------------------------------
// DhParameterSpec
// ---------------------------------------------------------------------------

/// Diffie-Hellman group parameters.
#[derive(Debug, Clone)]
pub struct DhParameterSpec {
    p: BigUint,
    g: BigUint,
    length: u32,
}

impl DhParameterSpec {
    /// Creates a new [`DhParameterSpec`] with the given prime `p`, generator
    /// `g`, and private-key bit `length`.
    pub fn new(p: BigUint, g: BigUint, length: u32) -> Self {
        Self { p, g, length }
    }

    /// Creates a new [`DhParameterSpec`] with [`DEFAULT_PRIVATE_KEY_LENGTH`].
    pub fn with_default_length(p: BigUint, g: BigUint) -> Self {
        Self::new(p, g, DEFAULT_PRIVATE_KEY_LENGTH)
    }

    /// Private-key bit length.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Generator `g`.
    pub fn g(&self) -> &BigUint {
        &self.g
    }

    /// Prime modulus `p`.
    pub fn p(&self) -> &BigUint {
        &self.p
    }
}

impl std::fmt::Display for DhParameterSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DhParameterSpec; p: {:?}, g: {:?}, length: {}",
            self.p.to_bytes_be(),
            self.g.to_bytes_be(),
            self.length,
        )
    }
}

// ---------------------------------------------------------------------------
// DhKeyPair
// ---------------------------------------------------------------------------

/// Diffie-Hellman key pair.
#[derive(Debug, Clone)]
pub struct DhKeyPair {
    public_key: BigUint,
    private_key: BigUint,
}

impl DhKeyPair {
    /// Creates a new [`DhKeyPair`].
    pub fn new(public_key: BigUint, private_key: BigUint) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Public key.
    pub fn public_key(&self) -> &BigUint {
        &self.public_key
    }

    /// Private key.
    pub fn private_key(&self) -> &BigUint {
        &self.private_key
    }

    /// Renders the private key in addition to the public key — debugging only.
    pub fn to_string_also_private(&self) -> String {
        format!(
            "DhKeyPair; PublicKey: {:?}, PrivateKey: {:?}",
            self.public_key.to_bytes_be(),
            self.private_key.to_bytes_be(),
        )
    }
}

impl std::fmt::Display for DhKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DhKeyPair; PublicKey: {:?} ",
            self.public_key.to_bytes_be()
        )
    }
}

// ---------------------------------------------------------------------------
// DHpkcs3Engine
// ---------------------------------------------------------------------------

/// PKCS#3 Diffie-Hellman engine. Holds a [`DhParameterSpec`] and a key pair;
/// derives shared secrets and the PACE-GM ephemeral generator.
#[derive(Debug, Clone)]
pub struct DHpkcs3Engine {
    parameter_spec: DhParameterSpec,
    public_key: BigUint,
    private_key: BigUint,
}

impl DHpkcs3Engine {
    /// Constructs an engine from a fixed `private_key`.
    pub fn from_private(
        private_key: BigUint,
        parameter_spec: DhParameterSpec,
    ) -> Result<Self, DhPkcs3EngineError> {
        Self::new(parameter_spec, Some(private_key), None)
    }

    /// Constructs an engine; if `private_key` is `None`, a new key pair is
    /// generated (optionally deterministic given `seed`).
    pub fn new(
        parameter_spec: DhParameterSpec,
        private_key: Option<BigUint>,
        seed: Option<u64>,
    ) -> Result<Self, DhPkcs3EngineError> {
        let priv_key = match private_key {
            Some(p) => p,
            None => Self::generate_private_key(parameter_spec.length, seed)?,
        };
        let pub_key = Self::generate_public_key(&priv_key, &parameter_spec);
        Ok(Self {
            parameter_spec,
            public_key: pub_key,
            private_key: priv_key,
        })
    }

    /// Parameters used by this engine.
    pub fn parameter_spec(&self) -> &DhParameterSpec {
        &self.parameter_spec
    }

    /// Public key.
    pub fn public_key(&self) -> &BigUint {
        &self.public_key
    }

    /// Private key.
    pub fn private_key(&self) -> &BigUint {
        &self.private_key
    }

    /// Returns a [`DhKeyPair`] snapshot of the engine's keys.
    pub fn key_pair(&self) -> DhKeyPair {
        DhKeyPair::new(self.public_key.clone(), self.private_key.clone())
    }

    /// Computes the shared secret `otherPublicKey^privateKey mod p`.
    pub fn compute_secret_key(&self, other_public_key: &BigUint) -> BigUint {
        other_public_key.modpow(&self.private_key, self.parameter_spec.p())
    }

    /// Computes the PACE-GM ephemeral generator:
    /// `G_ephemeral = (g^nonce mod p * H) mod p` where `H` is the shared
    /// secret derived from `other_public_key`.
    pub fn compute_generator(&self, other_public_key: &BigUint, nonce: &BigUint) -> BigUint {
        let h = self.compute_secret_key(other_public_key);
        let g_exp = self
            .parameter_spec
            .g()
            .modpow(nonce, self.parameter_spec.p());
        (g_exp * h) % self.parameter_spec.p()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn generate_private_key(length: u32, seed: Option<u64>) -> Result<BigUint, DhPkcs3EngineError> {
        if length == 0 || length % 8 != 0 {
            return Err(DhPkcs3EngineError(format!(
                "Invalid bitLength value - {length}"
            )));
        }
        let byte_len = (length / 8) as usize;
        let lower = BigUint::one() << (length - 1);
        let upper = BigUint::one() << length;
        let mut bytes = vec![0u8; byte_len];

        match seed {
            Some(s) => {
                let mut rng = StdRng::seed_from_u64(s);
                Ok(Self::draw_in_range(&mut rng, &mut bytes, &lower, &upper))
            }
            None => {
                let mut rng = OsRng;
                Ok(Self::draw_in_range(&mut rng, &mut bytes, &lower, &upper))
            }
        }
    }

    fn draw_in_range<R: RngCore>(
        rng: &mut R,
        buf: &mut [u8],
        lower: &BigUint,
        upper: &BigUint,
    ) -> BigUint {
        loop {
            rng.fill_bytes(buf);
            let n = BigUint::from_bytes_be(buf);
            if &n >= lower && &n < upper {
                return n;
            }
        }
    }

    fn generate_public_key(private_key: &BigUint, spec: &DhParameterSpec) -> BigUint {
        spec.g().modpow(private_key, spec.p())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Small test group: p = 23, g = 5. All values fit in a byte.
    // length=8 bits so private keys are drawn from [128, 256), but since p=23
    // these are reduced modulo p. This is *not* a secure group — just numeric
    // sanity.
    fn small_spec() -> DhParameterSpec {
        DhParameterSpec::new(BigUint::from(23u32), BigUint::from(5u32), 8)
    }

    #[test]
    fn key_pair_roundtrip_with_fixed_private() {
        let spec = small_spec();
        let engine =
            DHpkcs3Engine::from_private(BigUint::from(6u32), spec.clone()).unwrap();
        // 5^6 mod 23 = 15625 mod 23 = 8
        assert_eq!(engine.public_key(), &BigUint::from(8u32));
        assert_eq!(engine.private_key(), &BigUint::from(6u32));
    }

    #[test]
    fn shared_secret_symmetric() {
        let spec = small_spec();
        let alice = DHpkcs3Engine::from_private(BigUint::from(6u32), spec.clone()).unwrap();
        let bob = DHpkcs3Engine::from_private(BigUint::from(15u32), spec).unwrap();

        let s_ab = alice.compute_secret_key(bob.public_key());
        let s_ba = bob.compute_secret_key(alice.public_key());
        assert_eq!(s_ab, s_ba);
    }

    #[test]
    fn compute_generator_matches_definition() {
        let spec = small_spec();
        let nonce = BigUint::from(3u32);

        let alice = DHpkcs3Engine::from_private(BigUint::from(6u32), spec.clone()).unwrap();
        let bob = DHpkcs3Engine::from_private(BigUint::from(15u32), spec.clone()).unwrap();

        let h = alice.compute_secret_key(bob.public_key());
        let g_exp = spec.g().modpow(&nonce, spec.p());
        let expected = (&g_exp * &h) % spec.p();

        let got = alice.compute_generator(bob.public_key(), &nonce);
        assert_eq!(got, expected);
    }

    #[test]
    fn seeded_private_key_is_deterministic() {
        let spec = small_spec();
        let a = DHpkcs3Engine::new(spec.clone(), None, Some(42)).unwrap();
        let b = DHpkcs3Engine::new(spec, None, Some(42)).unwrap();
        assert_eq!(a.private_key(), b.private_key());
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn generated_private_key_is_within_range() {
        // Use length=16 so range is [2^15, 2^16) = [32768, 65536).
        let spec = DhParameterSpec::new(BigUint::from(2147483647u32), BigUint::from(5u32), 16);
        let engine = DHpkcs3Engine::new(spec, None, Some(1)).unwrap();
        let lower = BigUint::one() << 15;
        let upper = BigUint::one() << 16;
        assert!(engine.private_key() >= &lower);
        assert!(engine.private_key() < &upper);
    }

    #[test]
    fn non_multiple_of_8_bit_length_is_rejected() {
        let spec = DhParameterSpec::new(BigUint::from(23u32), BigUint::from(5u32), 7);
        let err = DHpkcs3Engine::new(spec, None, Some(0)).unwrap_err();
        assert!(err.0.contains("Invalid bitLength"));
    }

    #[test]
    fn zero_bit_length_is_rejected() {
        let spec = DhParameterSpec::new(BigUint::from(23u32), BigUint::from(5u32), 0);
        let err = DHpkcs3Engine::new(spec, None, Some(0)).unwrap_err();
        assert!(err.0.contains("Invalid bitLength"));
    }

    #[test]
    fn key_pair_snapshot_returns_both_keys() {
        let spec = small_spec();
        let engine = DHpkcs3Engine::from_private(BigUint::from(6u32), spec).unwrap();
        let kp = engine.key_pair();
        assert_eq!(kp.public_key(), engine.public_key());
        assert_eq!(kp.private_key(), engine.private_key());
    }
}
