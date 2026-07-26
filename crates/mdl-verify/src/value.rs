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
    /// Any other CBOR tag, kept rather than dropped: an issuer-defined extension may
    /// carry semantics in the tag, and this crate is not in a position to decide the
    /// tag was unimportant.
    Tagged {
        tag: u64,
        value: Box<MdlValue>,
    },
    Array(Vec<MdlValue>),
    /// A CBOR map, as an ordered list of pairs.
    ///
    /// Not a `BTreeMap<String, _>`: CBOR keys are arbitrary values, and issuers do use
    /// integer keys. Projecting into a string map would mean either rejecting a
    /// perfectly valid, issuer-signed element or silently dropping duplicate keys —
    /// both worse than handing back what was actually signed. Use
    /// [`get`](Self::get) for the common text-keyed lookup.
    Map(Vec<(MdlValue, MdlValue)>),
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

    pub fn as_map(&self) -> Option<&[(MdlValue, MdlValue)]> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Look up a text key in a [`MdlValue::Map`] — the common case, e.g. reading
    /// `vehicle_category_code` out of an entry in `driving_privileges`.
    ///
    /// Returns the first match; a map with duplicate keys is malformed, but it is
    /// preserved rather than silently collapsed, so
    /// [`as_map`](Self::as_map) can still see both.
    pub fn get(&self, key: &str) -> Option<&MdlValue> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, value)| value)
    }

    /// Strip a [`MdlValue::Tagged`] wrapper, if there is one.
    pub fn untagged(&self) -> &MdlValue {
        match self {
            Self::Tagged { value, .. } => value.untagged(),
            other => other,
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
                // Any other tag is kept. Dropping it would quietly change the meaning
                // of an issuer-signed extension value.
                _ => Self::Tagged {
                    tag: *tag,
                    value: Box::new(Self::try_from(inner.as_ref())?),
                },
            },
            ciborium::Value::Array(items) => Self::Array(
                items
                    .iter()
                    .map(Self::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ciborium::Value::Map(entries) => Self::Map(
                entries
                    .iter()
                    .map(|(key, value)| Ok((Self::try_from(key)?, Self::try_from(value)?)))
                    .collect::<Result<Vec<_>, MdlError>>()?,
            ),
            other => {
                return Err(MdlError::Unreadable(format!(
                    "unsupported CBOR in element value: {other:?}"
                )))
            }
        })
    }
}
