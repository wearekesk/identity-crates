//! ICAO 9303 Part 11 domain parameter table.
//!
//! Lists every domain parameter ID defined in §9.5.1 of ICAO 9303 Part 11.
//! Each entry records the human-readable name, the bit size, whether the
//! parameter is GF(p) / EC(p), and whether this library currently supports it
//! (i.e. whether the underlying crypto backend can evaluate it).
//!
//! For the Rust port, the `is_supported` flag is `true` for NIST P-256
//! (secp256r1, id 12, via [`crate::proto::ecdh_pace`]) and the three RFC 5114
//! MODP/DH groups (ids 0/1/2, via [`crate::proto::dh_pace`]); additional
//! parameters can be enabled as the PACE backend gains broader curve support.

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Whether a given domain parameter describes a finite-field or elliptic-curve
/// group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainParameterType {
    /// Finite field `GF(p)` — classical Diffie-Hellman.
    Gfp,
    /// Elliptic curve over `F_p`.
    Ecp,
}

/// ICAO 9303 domain parameter entry. Equality is keyed on the `id`.
#[derive(Debug, Clone)]
pub struct DomainParameter {
    pub id: u32,
    pub name: &'static str,
    pub size: u32,
    pub kind: DomainParameterType,
    pub is_supported: bool,
}

impl PartialEq for DomainParameter {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for DomainParameter {}

impl std::hash::Hash for DomainParameter {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl std::fmt::Display for DomainParameter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DomainParameter(id: {}, name: {}, size: {}, type: {:?}, isSupported: {})",
            self.id, self.name, self.size, self.kind, self.is_supported,
        )
    }
}

/// ICAO 9303 Part 11 §9.5.1 domain parameter table.
pub static ICAO_DOMAIN_PARAMETERS: Lazy<HashMap<u32, DomainParameter>> = Lazy::new(|| {
    let entries = [
        DomainParameter { id:  0, name: "1024-bit MODP Group with 160-bit Prime Order Subgroup",  size: 1024, kind: DomainParameterType::Gfp, is_supported: true  },
        DomainParameter { id:  1, name: "2048-bit MODP Group with 224-bit Prime Order Subgroup",  size: 2048, kind: DomainParameterType::Gfp, is_supported: true  },
        DomainParameter { id:  2, name: "2048-bit MODP Group with 256-bit Prime Order Subgroup",  size: 2048, kind: DomainParameterType::Gfp, is_supported: true  },
        DomainParameter { id:  8, name: "NIST P-192 (secp192r1)",                                 size:  192, kind: DomainParameterType::Ecp, is_supported: false },
        DomainParameter { id:  9, name: "BrainpoolP192r1",                                        size:  192, kind: DomainParameterType::Ecp, is_supported: false },
        DomainParameter { id: 10, name: "NIST P-224 (secp224r1)",                                 size:  224, kind: DomainParameterType::Ecp, is_supported: false },
        DomainParameter { id: 11, name: "BrainpoolP224r1",                                        size:  224, kind: DomainParameterType::Ecp, is_supported: false },
        DomainParameter { id: 12, name: "NIST P-256 (secp256r1)",                                 size:  256, kind: DomainParameterType::Ecp, is_supported: true  },
        DomainParameter { id: 13, name: "BrainpoolP256r1",                                        size:  256, kind: DomainParameterType::Ecp, is_supported: false },
        DomainParameter { id: 14, name: "BrainpoolP320r1",                                        size:  320, kind: DomainParameterType::Ecp, is_supported: false },
        DomainParameter { id: 15, name: "NIST P-384 (secp384r1)",                                 size:  384, kind: DomainParameterType::Ecp, is_supported: false },
        DomainParameter { id: 16, name: "BrainpoolP384r1",                                        size:  384, kind: DomainParameterType::Ecp, is_supported: false },
        DomainParameter { id: 17, name: "BrainpoolP512r1",                                        size:  512, kind: DomainParameterType::Ecp, is_supported: false },
        DomainParameter { id: 18, name: "NIST P-521 (secp521r1)",                                 size:  521, kind: DomainParameterType::Ecp, is_supported: false },
    ];
    entries.into_iter().map(|p| (p.id, p)).collect()
});

/// Returns the domain parameter with the given ID, if present in the table.
pub fn get(id: u32) -> Option<&'static DomainParameter> {
    ICAO_DOMAIN_PARAMETERS.get(&id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_entries_are_p256_and_rfc5114_dh_groups() {
        let mut supported: Vec<u32> = ICAO_DOMAIN_PARAMETERS
            .values()
            .filter(|p| p.is_supported)
            .map(|p| p.id)
            .collect();
        supported.sort_unstable();
        // P-256 (12, ECDH) + RFC 5114 MODP/DH groups (0/1/2).
        assert_eq!(supported, vec![0, 1, 2, 12]);
    }

    #[test]
    fn table_has_14_entries() {
        assert_eq!(ICAO_DOMAIN_PARAMETERS.len(), 14);
    }

    #[test]
    fn lookup_known_id() {
        let p = get(12).unwrap();
        assert_eq!(p.name, "NIST P-256 (secp256r1)");
        assert_eq!(p.size, 256);
        assert_eq!(p.kind, DomainParameterType::Ecp);
        assert!(p.is_supported);
    }

    #[test]
    fn lookup_unknown_id_returns_none() {
        assert!(get(999).is_none());
        assert!(get(3).is_none()); // gap between 2 and 8
    }

    #[test]
    fn equality_by_id() {
        let a = DomainParameter {
            id: 12,
            name: "a",
            size: 0,
            kind: DomainParameterType::Gfp,
            is_supported: false,
        };
        let b = DomainParameter {
            id: 12,
            name: "b",
            size: 99,
            kind: DomainParameterType::Ecp,
            is_supported: true,
        };
        assert_eq!(a, b);
    }
}
