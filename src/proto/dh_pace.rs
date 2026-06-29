//! Diffie-Hellman PACE engine.
//!
//! Wraps the generic [`DHpkcs3Engine`] with ICAO-specific helpers:
//! - named RFC 5114 groups (`RFC5114_1024_160`, `2048_224`, `2048_256`),
//! - `DomainParameterSelectorDH::get(id)` for id 0 / 1 / 2,
//! - ephemeral engine for the PACE-GM mapped generator,
//! - [`PublicKeyPace`] boundary conversions.

use num_bigint::BigUint;
use once_cell::sync::Lazy;
use thiserror::Error;

use crate::crypto::diffie_hellman::{DHpkcs3Engine, DhParameterSpec};
use crate::proto::domain_parameter;
use crate::proto::public_key_pace::PublicKeyPace;
use crate::utils::big_uint_to_bytes;

/// Error returned by [`DHPace`] operations.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("DHPaceError: {0}")]
pub struct DHPaceError(pub String);

// ---------------------------------------------------------------------------
// RFC 5114 groups (ICAO 9303 p11 §9.5.1 ids 0/1/2)
// ---------------------------------------------------------------------------

fn big_hex(h: &str) -> BigUint {
    let clean: String = h.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    BigUint::parse_bytes(clean.as_bytes(), 16).expect("valid hex")
}

/// RFC 5114 — 1024-bit MODP with 160-bit prime-order subgroup (ICAO id 0).
pub static RFC5114_1024_160: Lazy<DhParameterSpec> = Lazy::new(|| {
    DhParameterSpec::new(
        big_hex(concat!(
            "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6",
            "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0",
            "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70",
            "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0",
            "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708",
            "DF1FB2BC2E4A4371"
        )),
        big_hex(concat!(
            "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F",
            "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213",
            "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1",
            "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A",
            "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24",
            "855E6EEB22B3B2E5"
        )),
        160,
    )
    // RFC 5114 §2.1 — 160-bit prime-order subgroup order q.
    .with_subgroup_order(big_hex("F518AA8781A8DF278ABA4E7D64B7CB9D49462353"))
});

/// RFC 5114 — 2048-bit MODP with 224-bit prime-order subgroup (ICAO id 1).
pub static RFC5114_2048_224: Lazy<DhParameterSpec> = Lazy::new(|| {
    DhParameterSpec::new(
        big_hex(concat!(
            "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1",
            "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15",
            "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212",
            "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207",
            "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708",
            "B3BF8A317091883681286130BC8985DB1602E714415D9330",
            "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D",
            "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8",
            "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763",
            "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71",
            "CF9DE5384E71B81C0AC4DFFE0C10E64F"
        )),
        big_hex(concat!(
            "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF",
            "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA",
            "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7",
            "C17669101999024AF4D027275AC1348BB8A762D0521BC98A",
            "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE",
            "F180EB34118E98D119529A45D6F834566E3025E316A330EF",
            "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB",
            "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381",
            "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269",
            "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179",
            "81BC087F2A7065B384B890D3191F2BFA"
        )),
        224,
    )
    // RFC 5114 §2.2 — 224-bit prime-order subgroup order q.
    .with_subgroup_order(big_hex(concat!(
        "801C0D34C58D93FE997177101F80535A",
        "4738CEBCBF389A99B36371EB"
    )))
});

/// RFC 5114 — 2048-bit MODP with 256-bit prime-order subgroup (ICAO id 2).
pub static RFC5114_2048_256: Lazy<DhParameterSpec> = Lazy::new(|| {
    DhParameterSpec::new(
        big_hex(concat!(
            "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2",
            "5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30",
            "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD",
            "5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B",
            "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C",
            "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E",
            "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9",
            "67E144E5140564251CCACB83E6B486F6B3CA3F7971506026",
            "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3",
            "75F26375D7014103A4B54330C198AF126116D2276E11715F",
            "693877FAD7EF09CADB094AE91E1A1597"
        )),
        big_hex(concat!(
            "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF2054",
            "07F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555",
            "BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18",
            "A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B",
            "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83",
            "1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55",
            "A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14",
            "C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915",
            "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6",
            "184B523D1DB246C32F63078490F00EF8D647D148D4795451",
            "5E2327CFEF98C582664B4C0F6CC41659"
        )),
        256,
    )
    // RFC 5114 §2.3 — 256-bit prime-order subgroup order q.
    .with_subgroup_order(big_hex(concat!(
        "8CF83642A709A097B447997640129DA2",
        "99B1A47D1EB3750BA308B0FE64F5FBD3"
    )))
});

// ---------------------------------------------------------------------------
// DHPace engine
// ---------------------------------------------------------------------------

/// Diffie-Hellman PACE engine. Holds a main key pair plus an optional
/// ephemeral key pair (used during PACE-GM mapping).
#[derive(Debug)]
pub struct DHPace {
    domain_spec: DhParameterSpec,
    engine: Option<DHpkcs3Engine>,
    ephemeral: Option<DHpkcs3Engine>,
}

impl DHPace {
    /// Constructs a [`DHPace`] for the given ICAO domain parameter id, using
    /// a freshly-generated key pair with the provided spec.
    ///
    /// # Errors
    /// Returns [`DHPaceError`] when `id` is not in the ICAO table, or when
    /// engine construction fails.
    pub fn new(id: u32, spec: DhParameterSpec) -> Result<Self, DHPaceError> {
        if domain_parameter::get(id).is_none() {
            return Err(DHPaceError(format!(
                "DHPace; Domain parameter with id {id} does not exist."
            )));
        }
        let engine = DHpkcs3Engine::new(spec.clone(), None, None)
            .map_err(|e| DHPaceError(format!("DH engine: {}", e.0)))?;
        Ok(Self {
            domain_spec: spec,
            engine: Some(engine),
            ephemeral: None,
        })
    }

    pub fn public_key(&self) -> Result<&BigUint, DHPaceError> {
        self.engine
            .as_ref()
            .map(|e| e.public_key())
            .ok_or_else(|| DHPaceError("Public key is null. Generate key pair first.".into()))
    }

    /// Byte length of the group modulus `p` — i.e. the size of a full-width DH
    /// public key. 128 bytes for the 1024-bit group, 256 for the 2048-bit ones.
    pub fn modulus_byte_len(&self) -> usize {
        (self.domain_spec.p().bits() as usize).div_ceil(8)
    }

    pub fn ephemeral_public_key(&self) -> Result<&BigUint, DHPaceError> {
        self.ephemeral
            .as_ref()
            .map(|e| e.public_key())
            .ok_or_else(|| {
                DHPaceError(
                    "Ephemeral public key is null. Generate ephemeral key pair first.".into(),
                )
            })
    }

    /// Generates a new main key pair (optionally deterministic given `seed`).
    pub fn generate_key_pair(&mut self, seed: Option<u64>) -> Result<(), DHPaceError> {
        let engine = DHpkcs3Engine::new(self.domain_spec.clone(), None, seed)
            .map_err(|e| DHPaceError(e.0))?;
        self.engine = Some(engine);
        Ok(())
    }

    /// Builds an ephemeral engine whose generator is the mapped one.
    pub fn generate_ephemeral_with_custom_generator(
        &mut self,
        ephemeral_generator: BigUint,
        seed: Option<u64>,
    ) -> Result<(), DHPaceError> {
        let mut spec = DhParameterSpec::new(
            self.domain_spec.p().clone(),
            ephemeral_generator,
            self.domain_spec.length(),
        );
        // Preserve the subgroup order so ephemeral private keys are sampled
        // unbiased in [1, q-1] rather than from a raw length-bit range.
        if let Some(q) = self.domain_spec.q() {
            spec = spec.with_subgroup_order(q.clone());
        }
        let engine = DHpkcs3Engine::new(spec, None, seed).map_err(|e| DHPaceError(e.0))?;
        self.ephemeral = Some(engine);
        Ok(())
    }

    /// Returns the current public key wrapped in a [`PublicKeyPace::Dh`].
    pub fn get_pub_key(&self) -> Result<PublicKeyPace, DHPaceError> {
        let pk = self.public_key()?;
        Ok(PublicKeyPace::new_dh(big_uint_to_bytes(pk)))
    }

    /// Returns the ephemeral public key wrapped in a [`PublicKeyPace::Dh`].
    pub fn get_pub_key_ephemeral(&self) -> Result<PublicKeyPace, DHPaceError> {
        let pk = self.ephemeral_public_key()?;
        Ok(PublicKeyPace::new_dh(big_uint_to_bytes(pk)))
    }

    /// Computes the ephemeral shared secret with the other party's ephemeral
    /// public key.
    pub fn get_ephemeral_shared_secret(
        &self,
        other_ephemeral_pub_key: &[u8],
    ) -> Result<BigUint, DHPaceError> {
        let engine = self.ephemeral.as_ref().ok_or_else(|| {
            DHPaceError("Ephemeral engine is null. Generate ephemeral key pair first.".into())
        })?;
        let other = BigUint::from_bytes_be(other_ephemeral_pub_key);
        engine
            .compute_secret_key(&other)
            .map_err(|e| DHPaceError(e.0))
    }

    /// Computes the PACE-GM mapped generator:
    /// `G' = (g^nonce mod p) * H mod p`, where `H = other^priv mod p`.
    pub fn get_mapped_generator(
        &self,
        other_pub_key: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, DHPaceError> {
        let engine = self
            .engine
            .as_ref()
            .ok_or_else(|| DHPaceError("Engine is null. Generate key pair first.".into()))?;
        let other = BigUint::from_bytes_be(other_pub_key);
        let nonce_bn = BigUint::from_bytes_be(nonce);
        let generator = engine
            .compute_generator(&other, &nonce_bn)
            .map_err(|e| DHPaceError(e.0))?;
        Ok(big_uint_to_bytes(&generator))
    }
}

// ---------------------------------------------------------------------------
// Named curves (by ICAO id)
// ---------------------------------------------------------------------------

/// Convenience constructor for ICAO id 0 (RFC 5114 1024/160).
pub fn dh_pace_id0() -> Result<DHPace, DHPaceError> {
    DHPace::new(0, RFC5114_1024_160.clone())
}

/// Convenience constructor for ICAO id 1 (RFC 5114 2048/224).
pub fn dh_pace_id1() -> Result<DHPace, DHPaceError> {
    DHPace::new(1, RFC5114_2048_224.clone())
}

/// Convenience constructor for ICAO id 2 (RFC 5114 2048/256).
pub fn dh_pace_id2() -> Result<DHPace, DHPaceError> {
    DHPace::new(2, RFC5114_2048_256.clone())
}

/// Selector mirroring the `DomainParameterSelectorDH.getDomainParameter`.
pub fn get_domain_parameter(id: u32) -> Result<DHPace, DHPaceError> {
    match id {
        0 => dh_pace_id0(),
        1 => dh_pace_id1(),
        2 => dh_pace_id2(),
        _ => Err(DHPaceError(format!(
            "Domain parameter with id {id} is not supported."
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_rejects_unknown_id() {
        let err = get_domain_parameter(99).unwrap_err();
        assert!(err.0.contains("not supported"));
    }

    #[test]
    fn id0_has_correct_bit_length() {
        let dh = dh_pace_id0().unwrap();
        // 1024-bit MODP prime, 160-bit prime-order subgroup.
        assert_eq!(dh.domain_spec.p().bits(), 1024);
        assert_eq!(dh.domain_spec.length(), 160);
    }

    #[test]
    fn id2_has_correct_params() {
        let dh = dh_pace_id2().unwrap();
        // 2048-bit MODP prime, 256-bit prime-order subgroup.
        assert_eq!(dh.domain_spec.p().bits(), 2048);
        assert_eq!(dh.domain_spec.length(), 256);
    }

    // Use a tiny custom group for determinism + speed. The real RFC 5114
    // groups are too big for cheap unit tests. We need a *genuine* prime-order
    // subgroup so peer public keys pass the small-subgroup confinement check in
    // `compute_secret_key`: p = 467, p-1 = 2 * 233, and the order-233 subgroup
    // is exactly the quadratic residues, generated by g = 4 (= 2^2). q = 233
    // also keeps generated private keys in [1, q-1].
    fn small_spec() -> DhParameterSpec {
        DhParameterSpec::new(BigUint::from(467u32), BigUint::from(4u32), 8)
            .with_subgroup_order(BigUint::from(233u32))
    }

    fn build_small(priv_key: u32) -> DHPace {
        let spec = small_spec();
        let engine =
            DHpkcs3Engine::from_private(BigUint::from(priv_key), spec.clone()).unwrap();
        DHPace {
            domain_spec: spec,
            engine: Some(engine),
            ephemeral: None,
        }
    }

    #[test]
    fn ephemeral_shared_secret_is_symmetric_in_small_group() {
        // Symmetry of the agreed secret, exercised through the ephemeral
        // engines (the only shared-secret path the session uses). Using the
        // group's own generator makes them behave like plain DH key pairs.
        let mut alice = build_small(6);
        let mut bob = build_small(15);
        // Use a subgroup generator (g = 4, a quadratic residue) so the
        // ephemeral public keys stay inside the order-233 subgroup and pass
        // the small-subgroup confinement check during shared-secret agreement.
        alice
            .generate_ephemeral_with_custom_generator(BigUint::from(4u32), Some(6))
            .unwrap();
        bob.generate_ephemeral_with_custom_generator(BigUint::from(4u32), Some(15))
            .unwrap();

        let alice_pub = alice.get_pub_key_ephemeral().unwrap().to_relevant_bytes();
        let bob_pub = bob.get_pub_key_ephemeral().unwrap().to_relevant_bytes();

        let s_ab = alice.get_ephemeral_shared_secret(&bob_pub).unwrap();
        let s_ba = bob.get_ephemeral_shared_secret(&alice_pub).unwrap();
        assert_eq!(s_ab, s_ba);
    }

    #[test]
    fn get_pub_key_returns_wrapped_dh_pubkey() {
        let dh = build_small(6);
        let pk = dh.get_pub_key().unwrap();
        match pk {
            PublicKeyPace::Dh { pub_bytes } => {
                assert_eq!(pub_bytes, big_uint_to_bytes(dh.public_key().unwrap()));
            }
            _ => panic!("expected DH"),
        }
    }

    #[test]
    fn mapped_generator_matches_manual_computation() {
        let alice = build_small(6);
        let bob = build_small(15);
        let bob_pub = big_uint_to_bytes(bob.public_key().unwrap());
        let nonce = vec![0x03u8]; // small nonce

        // H = bob_pub^alice_priv mod p, with alice_priv = 6 (build_small(6)).
        let expected_h = BigUint::from_bytes_be(&bob_pub)
            .modpow(&BigUint::from(6u32), alice.domain_spec.p());
        let nonce_bn = BigUint::from_bytes_be(&nonce);
        let g_exp = alice
            .domain_spec
            .g()
            .modpow(&nonce_bn, alice.domain_spec.p());
        let expected = (&g_exp * &expected_h) % alice.domain_spec.p();

        let got = alice.get_mapped_generator(&bob_pub, &nonce).unwrap();
        assert_eq!(BigUint::from_bytes_be(&got), expected);
    }

    #[test]
    fn ephemeral_key_pair_flow() {
        let mut dh = build_small(6);
        // Use a bespoke ephemeral generator (any element of the group).
        dh.generate_ephemeral_with_custom_generator(BigUint::from(7u32), Some(1))
            .unwrap();
        let pk = dh.get_pub_key_ephemeral().unwrap();
        assert!(matches!(pk, PublicKeyPace::Dh { .. }));
    }
}
