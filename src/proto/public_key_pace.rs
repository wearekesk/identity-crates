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
    /// ECDH public key — affine `(x, y)` coordinates plus the curve's
    /// field-element width in bytes. The width is needed so each coordinate is
    /// emitted left-padded to the fixed length the `04 || X || Y` SEC1 form
    /// requires; emitting the minimal big-endian bytes would drop leading zero
    /// bytes and produce short, malformed coordinates for strict chips.
    Ecdh {
        x: BigUint,
        y: BigUint,
        coord_len: usize,
    },
}

impl PublicKeyPace {
    /// DH constructor.
    pub fn new_dh(pub_bytes: impl Into<Vec<u8>>) -> Self {
        Self::Dh {
            pub_bytes: pub_bytes.into(),
        }
    }

    /// ECDH constructor with an explicit fixed coordinate width (bytes).
    ///
    /// `coord_len` is the curve's field-element width (e.g. 32 for P-256) so
    /// that each coordinate is emitted left-padded to full width even when it
    /// has leading zero bytes.
    pub fn new_ecdh_fixed(x: BigUint, y: BigUint, coord_len: usize) -> Self {
        Self::Ecdh { x, y, coord_len }
    }

    /// ECDH constructor from the concatenated `x || y` byte form returned by
    /// most card implementations. The input must have even length; each half is
    /// the fixed coordinate width.
    pub fn ecdh_from_hex(xy: &[u8]) -> Option<Self> {
        if xy.is_empty() || xy.len() % 2 != 0 {
            return None;
        }
        let half = xy.len() / 2;
        Some(Self::Ecdh {
            x: BigUint::from_bytes_be(&xy[..half]),
            y: BigUint::from_bytes_be(&xy[half..]),
            coord_len: half,
        })
    }

    /// Serialises the full public key.
    ///
    /// - DH → raw pub bytes
    /// - ECDH → `x_bytes || y_bytes`, each left-padded to `coord_len`.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Dh { pub_bytes } => pub_bytes.clone(),
            Self::Ecdh { x, y, coord_len } => {
                let mut out = pad_be(x, *coord_len);
                out.extend_from_slice(&pad_be(y, *coord_len));
                out
            }
        }
    }

    /// Returns the bytes used to derive the shared secret.
    ///
    /// - DH → raw pub bytes (same as `to_bytes`)
    /// - ECDH → just the `x` coordinate bytes, left-padded to `coord_len`.
    pub fn to_relevant_bytes(&self) -> Vec<u8> {
        match self {
            Self::Dh { pub_bytes } => pub_bytes.clone(),
            Self::Ecdh { x, coord_len, .. } => pad_be(x, *coord_len),
        }
    }
}

/// Left-pads `value`'s big-endian bytes with `0x00` to exactly `len` bytes.
/// If the value is already wider than `len`, its natural bytes are returned.
fn pad_be(value: &BigUint, len: usize) -> Vec<u8> {
    let raw = big_uint_to_bytes(value);
    if raw.len() >= len {
        raw
    } else {
        let mut out = vec![0u8; len - raw.len()];
        out.extend_from_slice(&raw);
        out
    }
}

impl std::fmt::Display for PublicKeyPace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dh { pub_bytes } => write!(f, "{}", hex::encode(pub_bytes)),
            Self::Ecdh { x, y, coord_len } => write!(
                f,
                "X: {}\nY: {}",
                hex::encode(pad_be(x, *coord_len)),
                hex::encode(pad_be(y, *coord_len))
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
        let p = PublicKeyPace::new_ecdh_fixed(BigUint::from(0xAAu32), BigUint::from(0xBBu32), 1);
        assert_eq!(p.to_bytes(), vec![0xAA, 0xBB]);
        assert_eq!(p.to_relevant_bytes(), vec![0xAA]);
    }

    #[test]
    fn ecdh_from_hex_splits_in_half() {
        let p = PublicKeyPace::ecdh_from_hex(&[0x11, 0x22, 0x33, 0x44]).unwrap();
        match p {
            PublicKeyPace::Ecdh { x, y, coord_len } => {
                assert_eq!(x, BigUint::from(0x1122u32));
                assert_eq!(y, BigUint::from(0x3344u32));
                assert_eq!(coord_len, 2);
            }
            _ => panic!("expected ECDH"),
        }
    }

    #[test]
    fn ecdh_fixed_width_pads_leading_zero_coordinates() {
        // A coordinate with a leading zero byte must still be emitted at full
        // width so the X||Y form stays fixed-length for strict chips.
        let x = BigUint::from(0x00AABBu32); // natural 2 bytes (AA BB)
        let y = BigUint::from(0x010203u32); // natural 3 bytes
        let pk = PublicKeyPace::new_ecdh_fixed(x, y, 4);
        assert_eq!(
            pk.to_bytes(),
            vec![0x00, 0x00, 0xAA, 0xBB, 0x00, 0x01, 0x02, 0x03]
        );
        assert_eq!(pk.to_relevant_bytes(), vec![0x00, 0x00, 0xAA, 0xBB]);
        // ecdh_from_hex round-trips the same fixed width.
        let parsed = PublicKeyPace::ecdh_from_hex(&pk.to_bytes()).unwrap();
        assert_eq!(parsed.to_bytes(), pk.to_bytes());
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
