//! Enumerations describing the "Enhanced 2.0 Secure QR" wire format.
//!
//! Discriminant values are the on-the-wire codes parsed out of the QR payload,
//! so they are preserved exactly.

/// Control-unit kind found inside a Secure-QR block (`SecureCodeType`).
///
/// `control_type` is a 3-bit field, so only variants `0..=7` are reachable from
/// the wire; the remaining variants are retained for completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureCodeType {
    /// Heading level 1 text.
    ScTextH1 = 0,
    /// Heading level 2 text.
    ScTextH2 = 1,
    /// Caption text.
    ScTextCaption = 2,
    /// Normal body text.
    ScTextNormal = 3,
    /// Tabular data. (`SCTable` payloads are not parsed.)
    ScTable = 4,
    /// Binary blob (PII / image / mixed).
    ScBlob = 5,
    /// Placeholder element.
    ScPlaceHolder = 6,
    /// Identifier element.
    ScIdentifier = 7,
    /// Alignment directive.
    ScAlign = 8,
    /// Newline directive.
    ScNewLine = 9,
    /// Background directive.
    ScBackground = 10,
    /// Line directive.
    ScLIne = 11,
    /// Hyperlink element.
    ScHyperLink = 12,
}

impl SecureCodeType {
    /// Maps a raw control-type value to its [`SecureCodeType`], if known.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::ScTextH1,
            1 => Self::ScTextH2,
            2 => Self::ScTextCaption,
            3 => Self::ScTextNormal,
            4 => Self::ScTable,
            5 => Self::ScBlob,
            6 => Self::ScPlaceHolder,
            7 => Self::ScIdentifier,
            8 => Self::ScAlign,
            9 => Self::ScNewLine,
            10 => Self::ScBackground,
            11 => Self::ScLIne,
            12 => Self::ScHyperLink,
            _ => return None,
        })
    }
}

/// Top-level code type (`CodeType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeType {
    /// A single code.
    SingleCode = 3,
    /// A multi code.
    MultiCode = 6,
}

impl CodeType {
    /// Maps a raw code-type value to its [`CodeType`], if known.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            3 => Self::SingleCode,
            6 => Self::MultiCode,
            _ => return None,
        })
    }
}

/// Character-set selector for a block's payload (`CharacterSets`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharacterSets {
    /// `0123456789+-.%/*`
    Numeric1 = 0,
    /// `0123456789-.%<>/`
    Numeric2 = 1,
    /// No fixed alphabet.
    Text = 2,
    /// Upper-case alphanumerics.
    AlphaNumericUpperCase = 3,
    /// Lower-case alphanumerics.
    AlphaNumericLowerCase = 4,
    /// Mixed-case alphanumerics.
    AlphaNumeric = 5,
    /// Upper-case alphabet.
    AlphabetsUpperCase = 6,
    /// Lower-case alphabet.
    AlphabetsLowerCase = 7,
    /// Mixed-case alphabet.
    Alphabets = 8,
    /// Hexadecimal digits.
    HexaDecimal = 9,
}

impl CharacterSets {
    /// Maps a raw 4-bit character-set value to its [`CharacterSets`], if known.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Numeric1,
            1 => Self::Numeric2,
            2 => Self::Text,
            3 => Self::AlphaNumericUpperCase,
            4 => Self::AlphaNumericLowerCase,
            5 => Self::AlphaNumeric,
            6 => Self::AlphabetsUpperCase,
            7 => Self::AlphabetsLowerCase,
            8 => Self::Alphabets,
            9 => Self::HexaDecimal,
            _ => return None,
        })
    }
}

/// Signature scheme (`SignatureScheme`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// Elliptic-curve (ECDSA P-384 / SHA-384).
    Ecc = 0,
    /// RSA.
    Rsa = 1,
}

impl SignatureScheme {
    /// Maps a raw signature-scheme value to its [`SignatureScheme`], if known.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Ecc,
            1 => Self::Rsa,
            _ => return None,
        })
    }
}

/// Identifier of an `SCBlob`'s contents (`SCBlobIdentifier`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SCBlobIdentifier {
    /// Personally-identifiable information (zlib-compressed).
    Pii = 0x0302,
    /// Embedded WebP image.
    Image = 0x0102,
    /// Mixed contents (not parsed).
    Mixed = 0x0301,
}

impl SCBlobIdentifier {
    /// Maps a raw 16-bit identifier to its [`SCBlobIdentifier`], if known.
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            0x0302 => Self::Pii,
            0x0102 => Self::Image,
            0x0301 => Self::Mixed,
            _ => return None,
        })
    }
}

/// Alignment position for a `SCAlign` directive (`AlignPosition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignPosition {
    /// Left / top.
    LeftTop = 0,
    /// Left / center.
    LeftCenter = 1,
    /// Left / bottom.
    LeftBottom = 2,
    /// Center / top.
    CenterTop = 3,
    /// Center / center.
    CenterCenter = 4,
    /// Center / bottom.
    CenterBottom = 5,
    /// Right / top.
    RightTop = 6,
    /// Right / center.
    RightCenter = 7,
    /// Right / bottom.
    RightBottom = 8,
}

impl AlignPosition {
    /// Maps a raw alignment value to its [`AlignPosition`], if known.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::LeftTop,
            1 => Self::LeftCenter,
            2 => Self::LeftBottom,
            3 => Self::CenterTop,
            4 => Self::CenterCenter,
            5 => Self::CenterBottom,
            6 => Self::RightTop,
            7 => Self::RightCenter,
            8 => Self::RightBottom,
            _ => return None,
        })
    }
}

/// Placeholder element type (`PlaceHolderTypes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceHolderTypes {
    /// Heading level 1.
    H1 = 0,
    /// Heading level 2.
    H2 = 1,
    /// Caption.
    Caption = 2,
    /// Normal text.
    Normal = 3,
    /// Image.
    Image = 4,
}

impl PlaceHolderTypes {
    /// Maps a raw placeholder-type value to its [`PlaceHolderTypes`], if known.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::H1,
            1 => Self::H2,
            2 => Self::Caption,
            3 => Self::Normal,
            4 => Self::Image,
            _ => return None,
        })
    }
}
