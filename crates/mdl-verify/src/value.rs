use std::collections::BTreeMap;

use crate::MdlError;

/// A disclosed data element value.
///
/// mdoc element values are arbitrary CBOR: `family_name` is a text string, `portrait`
/// is a byte string holding a JPEG, `age_over_21` is a bool, `driving_privileges` is
/// an array of maps. This is a small, CBOR-shaped tree so callers do not have to take
/// a dependency on the underlying CBOR crate to read them.
#[derive(Debug, Clone, PartialEq)]
pub enum MdlValue {
    Text(String),
    Bytes(Vec<u8>),
    Int(i128),
    Float(f64),
    Bool(bool),
    Null,
    /// A CBOR-tagged date: `full-date` (tag 1004, e.g. `"1980-01-01"`) or `tdate`
    /// (tag 0, an RFC 3339 timestamp). ISO/IEC 18013-5 uses both — `birth_date` and
    /// `expiry_date` are `full-date`, `portrait_capture_date` is a `tdate`.
    Date(String),
    Array(Vec<MdlValue>),
    Map(BTreeMap<String, MdlValue>),
}

impl MdlValue {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    /// The value as a date string — either a [`MdlValue::Date`] or a plain
    /// [`MdlValue::Text`], since not every issuer tags its dates.
    pub fn as_date(&self) -> Option<&str> {
        match self {
            Self::Date(s) | Self::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[MdlValue]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, MdlValue>> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }
}

/// CBOR tag 0 — `tdate`, an RFC 3339 timestamp.
const TAG_TDATE: u64 = 0;
/// CBOR tag 1004 — `full-date`, an RFC 3339 `full-date` string.
const TAG_FULL_DATE: u64 = 1004;

impl TryFrom<&ciborium::Value> for MdlValue {
    type Error = MdlError;

    fn try_from(value: &ciborium::Value) -> Result<Self, MdlError> {
        Ok(match value {
            ciborium::Value::Text(s) => Self::Text(s.clone()),
            ciborium::Value::Bytes(b) => Self::Bytes(b.clone()),
            ciborium::Value::Integer(i) => Self::Int((*i).into()),
            ciborium::Value::Float(f) => Self::Float(*f),
            ciborium::Value::Bool(b) => Self::Bool(*b),
            ciborium::Value::Null => Self::Null,
            ciborium::Value::Tag(tag, inner) => match (*tag, inner.as_ref()) {
                (TAG_TDATE | TAG_FULL_DATE, ciborium::Value::Text(s)) => Self::Date(s.clone()),
                // Any other tag: keep the value, drop the tag. Tags in mdoc element
                // values are date hints; an unknown one should not fail the whole
                // verification, and the untagged value is still faithful.
                _ => Self::try_from(inner.as_ref())?,
            },
            ciborium::Value::Array(items) => Self::Array(
                items
                    .iter()
                    .map(Self::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ciborium::Value::Map(entries) => {
                let mut map = BTreeMap::new();
                for (key, value) in entries {
                    let key = key.as_text().ok_or_else(|| {
                        MdlError::Unreadable(format!(
                            "element value contains a map with a non-text key: {key:?}"
                        ))
                    })?;
                    map.insert(key.to_string(), Self::try_from(value)?);
                }
                Self::Map(map)
            }
            other => {
                return Err(MdlError::Unreadable(format!(
                    "unsupported CBOR in element value: {other:?}"
                )))
            }
        })
    }
}
