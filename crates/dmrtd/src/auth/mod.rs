//! Chip authentication — proving the chip is genuine, and proving its data is.
//!
//! Two different guarantees, and they are not interchangeable:
//!
//! - [`active`] — **Active Authentication (AA)**: the chip signs a challenge with a
//!   private key it cannot be made to reveal. This proves the chip is *not a clone*.
//!   It says nothing about whether the data on it is genuine — a forged chip carrying
//!   its own keypair passes AA.
//!
//! - [`passive`] — **Passive Authentication (PA)**: EF.SOD is a CMS `SignedData`
//!   signed by a Document Signer whose certificate chains to a country's CSCA. It
//!   carries a hash of every data group. This proves the data was *issued by that
//!   country and has not been modified*. It says nothing about whether the chip in
//!   front of you is the original — a byte-for-byte copy passes PA.
//!
//! A trustworthy read needs both: PA says the data is authentic, AA says this chip is
//! the one it was issued to.

pub mod active;
pub mod passive;

mod der;
mod rsa;

/// Hash algorithms an eMRTD may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgo {
    /// Digest `data` with this algorithm.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        use sha1::Digest as _;
        match self {
            HashAlgo::Sha1 => sha1::Sha1::digest(data).to_vec(),
            HashAlgo::Sha224 => sha2::Sha224::digest(data).to_vec(),
            HashAlgo::Sha256 => sha2::Sha256::digest(data).to_vec(),
            HashAlgo::Sha384 => sha2::Sha384::digest(data).to_vec(),
            HashAlgo::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    /// Digest length in bytes.
    pub fn digest_len(&self) -> usize {
        match self {
            HashAlgo::Sha1 => 20,
            HashAlgo::Sha224 => 28,
            HashAlgo::Sha256 => 32,
            HashAlgo::Sha384 => 48,
            HashAlgo::Sha512 => 64,
        }
    }

    /// From the X.509 / CMS algorithm OID.
    pub fn from_oid(oid: &[u64]) -> Option<Self> {
        match oid {
            [1, 3, 14, 3, 2, 26] => Some(HashAlgo::Sha1),
            [2, 16, 840, 1, 101, 3, 4, 2, 4] => Some(HashAlgo::Sha224),
            [2, 16, 840, 1, 101, 3, 4, 2, 1] => Some(HashAlgo::Sha256),
            [2, 16, 840, 1, 101, 3, 4, 2, 2] => Some(HashAlgo::Sha384),
            [2, 16, 840, 1, 101, 3, 4, 2, 3] => Some(HashAlgo::Sha512),
            _ => None,
        }
    }

    /// The DigestInfo prefix for RSA PKCS#1 v1.5 (RFC 8017 §9.2, notes 1).
    pub(crate) fn digest_info_prefix(&self) -> &'static [u8] {
        match self {
            HashAlgo::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            HashAlgo::Sha224 => &[
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x04, 0x05, 0x00, 0x04, 0x1c,
            ],
            HashAlgo::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            HashAlgo::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            HashAlgo::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    /// ISO/IEC 9796-2 hash identifier, used in an explicit (`0xCC`) trailer.
    pub(crate) fn from_iso9796_id(id: u8) -> Option<Self> {
        match id {
            0x33 => Some(HashAlgo::Sha1),
            0x34 => Some(HashAlgo::Sha256),
            0x35 => Some(HashAlgo::Sha512),
            0x36 => Some(HashAlgo::Sha384),
            0x38 => Some(HashAlgo::Sha224),
            _ => None,
        }
    }
}
