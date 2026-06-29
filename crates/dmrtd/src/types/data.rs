//! DMRTD data row and data set types.
//!
//! A [`DataRow`] represents a single `[Tag, Length, Value]` entry.
//! A [`DataSet`] is an ordered collection of [`DataRow`] entries whose
//! serialised form is the concatenation of all `[Tag, Length, Value]` triples.

use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error type for [`DataRow`] operations.
#[derive(Debug, Error)]
#[error("DataRowException: {message}")]
pub struct DataRowException {
    pub message: String,
}

impl DataRowException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// DataRow
// ---------------------------------------------------------------------------

/// Represents one Data Row in a Data Field.
///
/// MRTD additional data is stored in communication messages in the form:
/// ```text
/// [Tag (1 byte)] [Length (1 byte)] [Value (Length bytes)]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRow {
    /// Single-byte tag identifier.
    pub tag: u8,
    /// Byte length of `value` (computed automatically on construction).
    pub length: usize,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

impl DataRow {
    /// Constructs a [`DataRow`] from a `tag` and `value` bytes.
    /// `length` is derived from `value.len()`.
    pub fn new(tag: u8, value: Vec<u8>) -> Self {
        let length = value.len();
        Self { tag, length, value }
    }

    /// Serialises the row as `[tag, length_byte, ...value]`.
    ///
    /// The length byte is derived from `value.len()`, not the public `length`
    /// field, so a caller mutating `length` independently cannot emit a length
    /// that disagrees with the actual value.
    ///
    /// # Panics
    /// Panics if `value.len() > 255` (length field is a single byte).
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.value.len();
        assert!(
            len <= 0xFF,
            "DataRow value length {len} exceeds maximum single-byte length (255)"
        );
        let mut bytes = Vec::with_capacity(2 + len);
        bytes.push(self.tag);
        bytes.push(len as u8);
        bytes.extend_from_slice(&self.value);
        bytes
    }

    /// Returns a hex-dump string of the serialised row.
    ///
    /// Each byte is formatted as `0xNN ` (uppercase hex, space-separated).
    pub fn print_hex(&self) -> String {
        self.to_bytes()
            .iter()
            .map(|b| format!("0x{:02X} ", b))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// DataSet
// ---------------------------------------------------------------------------

/// Represents an entire data set composed of multiple [`DataRow`] entries.
///
/// [`DataSet::to_bytes`] returns the concatenation of all rows serialised as
/// `[Tag, Length, Value]` triples.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DataSet {
    pub rows: Vec<DataRow>,
}

impl DataSet {
    /// Creates an empty [`DataSet`].
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Appends a new row built from raw `tag` and `value` bytes.
    pub fn add_raw_row(&mut self, tag: u8, value: Vec<u8>) {
        self.rows.push(DataRow::new(tag, value));
    }

    /// Appends an already-constructed [`DataRow`].
    pub fn add_row(&mut self, row: DataRow) {
        self.rows.push(row);
    }

    /// Serialises the entire data set by concatenating every row's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.rows.iter().flat_map(|r| r.to_bytes()).collect()
    }

    /// Removes all rows from the data set.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Returns the number of rows in the data set.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Returns `true` if the data set contains no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_row_to_bytes_basic() {
        let row = DataRow::new(0x5A, vec![0x01, 0x02, 0x03]);
        let bytes = row.to_bytes();
        assert_eq!(bytes, vec![0x5A, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn data_row_length_is_derived() {
        let row = DataRow::new(0x01, vec![0xAA, 0xBB]);
        assert_eq!(row.length, 2);
    }

    #[test]
    fn data_row_to_bytes_uses_value_len_not_stored_length() {
        // A desynced `length` field must not affect serialisation.
        let mut row = DataRow::new(0x5A, vec![0x01, 0x02, 0x03]);
        row.length = 99; // tampered, diverges from value.len()
        assert_eq!(row.to_bytes(), vec![0x5A, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn data_row_empty_value() {
        let row = DataRow::new(0xFF, vec![]);
        assert_eq!(row.to_bytes(), vec![0xFF, 0x00]);
    }

    #[test]
    fn data_set_to_bytes_multiple_rows() {
        let mut ds = DataSet::new();
        ds.add_raw_row(0x01, vec![0xAA]);
        ds.add_raw_row(0x02, vec![0xBB, 0xCC]);
        // Expected: [01 01 AA] + [02 02 BB CC]
        assert_eq!(
            ds.to_bytes(),
            vec![0x01, 0x01, 0xAA, 0x02, 0x02, 0xBB, 0xCC]
        );
    }

    #[test]
    fn data_set_clear() {
        let mut ds = DataSet::new();
        ds.add_raw_row(0x10, vec![0x00]);
        assert!(!ds.is_empty());
        ds.clear();
        assert!(ds.is_empty());
    }

    #[test]
    fn data_row_print_hex() {
        let row = DataRow::new(0x5A, vec![0xFF]);
        // [0x5A, 0x01, 0xFF]
        let hex = row.print_hex();
        assert!(hex.contains("0x5A"));
        assert!(hex.contains("0x01"));
        assert!(hex.contains("0xFF"));
    }

    #[test]
    fn pair_conversion() {
        // Smoke test: DataSet add_row
        let row = DataRow::new(0xAB, vec![1, 2, 3]);
        let mut ds = DataSet::new();
        ds.add_row(row.clone());
        assert_eq!(ds.rows[0], row);
    }
}
