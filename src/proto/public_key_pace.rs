//! PACE public key holders.
//!
//! PACE exchanges public keys as either raw byte strings (DH) or affine
//! points (x, y) (ECDH). The [`PublicKeyPace`] enum wraps both.

use num_bigint::BigUint;

use crate::utils::big_uint_to_bytes;

/// PACE public key — either DH (raw bytes) or ECDH (affine `(x, y)` coordinates).
#[derive(Debug, Clone)]
pub enum PublicKeyPace {
    /// DH public key — raw big-endian bytes of the integer value.
    Dh { pub_bytes: Vec<u8> },
    /// ECDH public key — affine `(x, y)` coordinates.
    Ecdh { x: BigUint, y: BigUint },
}

impl PublicKeyPace {
    /// DH constructor.
    pub fn new_dh(pub_bytes: impl Into<Vec<u8>>) -> Self {
        Self::Dh {
            pub_bytes: pub_bytes.into(),
        }
    }

    /// ECDH constructor from `(x, y)` big-endian coordinates.
    pub fn new_ecdh(x: BigUint, y: BigUint) -> Self {
        Self::Ecdh { x, y }
    }

    /// ECDH constructor from the concatenated `x || y` byte form returned by
    /// most card implementations. The input must have even length.
    pub fn ecdh_from_hex(xy: &[u8]) -> Option<Self> {
        if xy.is_empty() || xy.len() % 2 != 0 {
            return None;
        }
        let half = xy.len() / 2;
        Some(Self::Ecdh {
            x: BigUint::from_bytes_be(&xy[..half]),
            y: BigUint::from_bytes_be(&xy[half..]),
        })
    }

    /// Serialises the full public key.
    ///
    /// - DH → raw pub bytes
    /// - ECDH → `x_bytes || y_bytes`
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Dh { pub_bytes } => pub_bytes.clone(),
            Self::Ecdh { x, y } => {
                let mut out = big_uint_to_bytes(x);
                out.extend_from_slice(&big_uint_to_bytes(y));
                out
            }
        }
    }

    /// Returns the bytes used to derive the shared secret.
    ///
    /// - DH → raw pub bytes (same as `to_bytes`)
    /// - ECDH → just the `x` coordinate bytes
    pub fn to_relevant_bytes(&self) -> Vec<u8> {
        match self {
            Self::Dh { pub_bytes } => pub_bytes.clone(),
            Self::Ecdh { x, .. } => big_uint_to_bytes(x),
        }
    }
}

impl std::fmt::Display for PublicKeyPace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dh { pub_bytes } => write!(f, "{}", hex::encode(pub_bytes)),
            Self::Ecdh { x, y } => write!(
                f,
                "X: {}\nY: {}",
                hex::encode(big_uint_to_bytes(x)),
                hex::encode(big_uint_to_bytes(y))
            ),
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
    fn dh_to_bytes_and_relevant_bytes() {
        let p = PublicKeyPace::new_dh(vec![0x01, 0x02]);
        assert_eq!(p.to_bytes(), vec![0x01, 0x02]);
        assert_eq!(p.to_relevant_bytes(), vec![0x01, 0x02]);
    }

    #[test]
    fn ecdh_to_bytes_concatenates_xy() {
        let p = PublicKeyPace::new_ecdh(BigUint::from(0xAAu32), BigUint::from(0xBBu32));
        assert_eq!(p.to_bytes(), vec![0xAA, 0xBB]);
        assert_eq!(p.to_relevant_bytes(), vec![0xAA]);
    }

    #[test]
    fn ecdh_from_hex_splits_in_half() {
        let p = PublicKeyPace::ecdh_from_hex(&[0x11, 0x22, 0x33, 0x44]).unwrap();
        match p {
            PublicKeyPace::Ecdh { x, y } => {
                assert_eq!(x, BigUint::from(0x1122u32));
                assert_eq!(y, BigUint::from(0x3344u32));
            }
            _ => panic!("expected ECDH"),
        }
    }

    #[test]
    fn ecdh_from_hex_rejects_odd_length() {
        assert!(PublicKeyPace::ecdh_from_hex(&[0x11, 0x22, 0x33]).is_none());
        assert!(PublicKeyPace::ecdh_from_hex(&[]).is_none());
    }

    #[test]
    fn display_dh_hex_encodes() {
        let p = PublicKeyPace::new_dh(vec![0xDE, 0xAD]);
        assert_eq!(p.to_string(), "dead");
    }
}
