//! AAMVA DL / ID payload parser.
//!
//! The payload layout (AAMVA Card Design Standard, v01 onwards) is:
//!
//! ```text
//!   @\n\x1E\r  ANSI   IIN(6)  v(2)  jv(2)  nbSub(2)
//!   { subfileType(2) offset(4) length(4) } × nbSub
//!   { subfileType(2) { elementCode(3) value \n } ... \r } × nbSub
//! ```

use chrono::NaiveDate;
use std::collections::BTreeMap;
use std::str::FromStr;

use super::data::{
    AamvaHeader, AamvaLicense, Compliance, Country, EyeColor, HairColor, Height, Sex,
    SubfileDesignator, Truncation,
};
use super::error::AamvaError;

/// ASCII compliance indicator (`@`).
const COMPLIANCE: u8 = 0x40;
/// AAMVA element separator — `\n`.
const DATA_ELEMENT_SEP: u8 = 0x0A;
/// Record separator — `\x1E`.
const RECORD_SEP: u8 = 0x1E;
/// Segment terminator — `\r`.
const SEGMENT_TERM: u8 = 0x0D;
/// Header tag preceding the IIN.
const ANSI_TAG: &[u8] = b"ANSI ";
/// Minimum well-formed header length:
/// `@\n\x1E\r` (4) + `ANSI ` (5) + IIN (6) + version (2) + jurisdiction version (2)
/// + entry count (2) + at least one 10-byte subfile designator.
const MIN_HEADER_LEN: usize = 4 + 5 + 6 + 2 + 2 + 2 + 10;

/// Parses a raw AAMVA payload (UTF-8 text from the PDF417 barcode) into an
/// [`AamvaLicense`].
pub fn parse(payload: &[u8]) -> Result<AamvaLicense, AamvaError> {
    if payload.len() < MIN_HEADER_LEN {
        return Err(AamvaError::PayloadTooShort {
            len: payload.len(),
            min: MIN_HEADER_LEN,
        });
    }

    // --- header magic (`@\n\x1E\r`) ---
    if payload[0] != COMPLIANCE {
        return Err(AamvaError::MissingComplianceIndicator);
    }
    if payload[1..4] != [DATA_ELEMENT_SEP, RECORD_SEP, SEGMENT_TERM] {
        return Err(AamvaError::MalformedHeader(
            "expected header magic `@\\n\\x1E\\r`".into(),
        ));
    }
    if &payload[4..9] != ANSI_TAG {
        return Err(AamvaError::MissingAnsiHeader);
    }

    // --- fixed-width fields ---
    let iin = ascii_str(&payload[9..15], "IIN")?.to_string();
    let aamva_version = ascii_digits(&payload[15..17], "AAMVA version")?;
    let jurisdiction_version = ascii_digits(&payload[17..19], "jurisdiction version")?;
    let entry_count = ascii_digits(&payload[19..21], "entry count")?;

    // --- subfile designators ---
    let mut cursor = 21usize;
    let mut designators = Vec::with_capacity(entry_count as usize);
    for index in 0..entry_count as usize {
        if cursor + 10 > payload.len() {
            return Err(AamvaError::MalformedSubfileDesignator { index });
        }
        let subfile_type = ascii_str(&payload[cursor..cursor + 2], "subfile type")?.to_string();
        let offset = ascii_digits_u32(&payload[cursor + 2..cursor + 6], "subfile offset")? as usize;
        let length =
            ascii_digits_u32(&payload[cursor + 6..cursor + 10], "subfile length")? as usize;
        designators.push(SubfileDesignator {
            subfile_type,
            offset,
            length,
        });
        cursor += 10;
    }

    // --- parse every subfile ---
    let mut elements = BTreeMap::<String, String>::new();
    for designator in &designators {
        let end = designator
            .offset
            .checked_add(designator.length)
            .ok_or_else(|| AamvaError::SubfileOutOfBounds {
                subfile: designator.subfile_type.clone(),
                offset: designator.offset,
                length: designator.length,
                payload_len: payload.len(),
            })?;
        if end > payload.len() {
            return Err(AamvaError::SubfileOutOfBounds {
                subfile: designator.subfile_type.clone(),
                offset: designator.offset,
                length: designator.length,
                payload_len: payload.len(),
            });
        }

        let subfile = &payload[designator.offset..end];
        if subfile.len() < 2 || &subfile[..2] != designator.subfile_type.as_bytes() {
            return Err(AamvaError::SubfileTypeMismatch {
                expected: designator.subfile_type.clone(),
            });
        }

        parse_subfile_elements(&subfile[2..], &mut elements)?;
    }

    let license = build_license(
        elements,
        designators,
        iin,
        aamva_version,
        jurisdiction_version,
        entry_count,
    )?;
    Ok(license)
}

/// Splits the body of one subfile on `\n` / `\r` and stores each
/// `code(3)` → `value` pair in `elements`.
fn parse_subfile_elements(
    body: &[u8],
    elements: &mut BTreeMap<String, String>,
) -> Result<(), AamvaError> {
    for raw in body.split(|b| *b == DATA_ELEMENT_SEP || *b == SEGMENT_TERM) {
        if raw.is_empty() {
            continue;
        }
        if raw.len() < 3 {
            // Extraneous bytes between elements — skip.
            continue;
        }
        let code = std::str::from_utf8(&raw[..3])
            .map_err(|_| AamvaError::MalformedHeader("non-UTF8 element code".into()))?
            .to_string();
        let value = std::str::from_utf8(&raw[3..])
            .map_err(|_| AamvaError::MalformedHeader(format!("non-UTF8 value for {code}")))?
            .trim_end_matches(['\r', '\n'])
            .to_string();
        // Later subfiles may re-declare elements; last write wins.
        elements.insert(code, value);
    }
    Ok(())
}

fn build_license(
    elements: BTreeMap<String, String>,
    subfiles: Vec<SubfileDesignator>,
    iin: String,
    aamva_version: u8,
    jurisdiction_version: u8,
    entry_count: u8,
) -> Result<AamvaLicense, AamvaError> {
    let get = |code: &str| {
        elements
            .get(code)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let get_date = |code: &'static str| -> Result<Option<NaiveDate>, AamvaError> {
        match elements.get(code) {
            Some(raw) if !raw.trim().is_empty() => Ok(Some(parse_date(raw, code)?)),
            _ => Ok(None),
        }
    };

    let parse_enum = |code: &str| -> Option<String> { get(code) };

    Ok(AamvaLicense {
        header: Some(AamvaHeader {
            iin,
            aamva_version,
            jurisdiction_version,
            entry_count,
            subfiles,
        }),

        family_name: get("DCS"),
        first_name: get("DAC"),
        middle_name: get("DAD"),
        name_suffix: get("DCU"),
        family_name_truncation: parse_enum("DDE").and_then(|s| Truncation::from_str(&s).ok()),
        first_name_truncation: parse_enum("DDF").and_then(|s| Truncation::from_str(&s).ok()),
        middle_name_truncation: parse_enum("DDG").and_then(|s| Truncation::from_str(&s).ok()),

        document_number: get("DAQ"),
        document_discriminator: get("DCF"),
        country: parse_enum("DCG").and_then(|s| Country::from_str(&s).ok()),
        jurisdiction: get("DAJ"),

        date_of_birth: get_date("DBB")?,
        issue_date: get_date("DBD")?,
        expiry_date: get_date("DBA")?,
        card_revision_date: get_date("DDB")?,
        under_18_until: get_date("DDH")?,
        under_19_until: get_date("DDI")?,
        under_21_until: get_date("DDJ")?,

        sex: parse_enum("DBC").and_then(|s| Sex::from_str(&s).ok()),
        eye_color: parse_enum("DAY").and_then(|s| EyeColor::from_str(&s).ok()),
        hair_color: parse_enum("DAZ").and_then(|s| HairColor::from_str(&s).ok()),
        height: get("DAU").as_deref().and_then(Height::parse),
        weight_lb: get("DAW").as_deref().and_then(|s| s.parse().ok()),
        weight_kg: get("DAX").as_deref().and_then(|s| s.parse().ok()),
        weight_range: get("DCE").as_deref().and_then(|s| s.parse().ok()),

        address_street_1: get("DAG"),
        address_street_2: get("DAH"),
        city: get("DAI"),
        postal_code: get("DAK"),

        vehicle_class: get("DCA"),
        restrictions: get("DCB"),
        endorsements: get("DCD"),

        organ_donor: get("DDK").as_deref().map(|s| s == "1"),
        veteran: get("DDL").as_deref().map(|s| s == "1"),
        compliance: parse_enum("DDA").and_then(|s| Compliance::from_str(&s).ok()),

        elements,
    })
}

/// Parses an AAMVA date — `MMDDCCYY` for USA IINs, `CCYYMMDD` for Canadian
/// ones. Accepts both forms as a fallback so the parser stays jurisdiction-
/// agnostic.
pub(crate) fn parse_date(raw: &str, element: &'static str) -> Result<NaiveDate, AamvaError> {
    let s = raw.trim();
    // MMDDCCYY (USA default)
    if let Ok(d) = NaiveDate::parse_from_str(s, "%m%d%Y") {
        return Ok(d);
    }
    // CCYYMMDD (Canadian jurisdictions)
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y%m%d") {
        return Ok(d);
    }
    Err(AamvaError::InvalidDate {
        element,
        raw: s.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ascii_str<'a>(bytes: &'a [u8], field: &str) -> Result<&'a str, AamvaError> {
    std::str::from_utf8(bytes)
        .map_err(|_| AamvaError::MalformedHeader(format!("non-ASCII {field}")))
}

fn ascii_digits(bytes: &[u8], field: &str) -> Result<u8, AamvaError> {
    ascii_str(bytes, field)?
        .parse::<u8>()
        .map_err(|_| AamvaError::MalformedHeader(format!("non-numeric {field}")))
}

fn ascii_digits_u32(bytes: &[u8], field: &str) -> Result<u32, AamvaError> {
    ascii_str(bytes, field)?
        .parse::<u32>()
        .map_err(|_| AamvaError::MalformedHeader(format!("non-numeric {field}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a small synthetic AAMVA DL payload. Values are fixed so the
    /// tests can assert exact output.
    fn fixture_payload() -> Vec<u8> {
        // Subfile content — the 2-char type tag is re-emitted at the start
        // of the subfile per the spec.
        let dl_body = [
            "DAQD12345678",
            "DCSDOE",
            "DACJOHN",
            "DADQUINCY",
            "DBB01151990",
            "DBD06012022",
            "DBA06012030",
            "DBC1",
            "DAU070 in",
            "DAW180",
            "DAYBRO",
            "DAZBLN",
            "DAGMAIN ST 123",
            "DAHAPT 4",
            "DAIANYTOWN",
            "DAJCA",
            "DAK902100000",
            "DCAA",
            "DCBA",
            "DCDA",
            "DCGUSA",
            "DCFABC12345",
            "DDEN",
            "DDFN",
            "DDGN",
            "DDAF",
            "DDK1",
            "DDL0",
        ]
        .join("\n");
        let mut subfile = Vec::new();
        subfile.extend_from_slice(b"DL");
        subfile.extend_from_slice(dl_body.as_bytes());
        subfile.push(SEGMENT_TERM);

        // Header is: `@\n\x1E\r` + `ANSI ` + IIN + versions + counts + designators
        let iin = b"636014";
        let version = b"09";
        let jversion = b"00";
        let entries = b"01";

        // Build header + designator, filling in the offset once we know it.
        let designator_len = 10usize;
        let header_prefix_len = 4 + 5 + iin.len() + version.len() + jversion.len() + entries.len();
        let subfile_offset = header_prefix_len + designator_len;
        let subfile_len = subfile.len();

        let designator = format!("DL{:04}{:04}", subfile_offset, subfile_len);
        let mut payload = Vec::new();
        payload.push(COMPLIANCE);
        payload.push(DATA_ELEMENT_SEP);
        payload.push(RECORD_SEP);
        payload.push(SEGMENT_TERM);
        payload.extend_from_slice(ANSI_TAG);
        payload.extend_from_slice(iin);
        payload.extend_from_slice(version);
        payload.extend_from_slice(jversion);
        payload.extend_from_slice(entries);
        payload.extend_from_slice(designator.as_bytes());
        debug_assert_eq!(payload.len(), subfile_offset);
        payload.extend_from_slice(&subfile);
        payload
    }

    #[test]
    fn parses_fixture() {
        let payload = fixture_payload();
        let license = parse(&payload).unwrap();

        let header = license.header.as_ref().unwrap();
        assert_eq!(header.iin, "636014");
        assert_eq!(header.aamva_version, 9);
        assert_eq!(header.jurisdiction_version, 0);
        assert_eq!(header.entry_count, 1);
        assert_eq!(header.subfiles[0].subfile_type, "DL");

        assert_eq!(license.document_number.as_deref(), Some("D12345678"));
        assert_eq!(license.family_name.as_deref(), Some("DOE"));
        assert_eq!(license.first_name.as_deref(), Some("JOHN"));
        assert_eq!(license.middle_name.as_deref(), Some("QUINCY"));
        assert_eq!(
            license.date_of_birth,
            Some(NaiveDate::from_ymd_opt(1990, 1, 15).unwrap())
        );
        assert_eq!(
            license.expiry_date,
            Some(NaiveDate::from_ymd_opt(2030, 6, 1).unwrap())
        );
        assert_eq!(
            license.issue_date,
            Some(NaiveDate::from_ymd_opt(2022, 6, 1).unwrap())
        );
        assert_eq!(license.sex, Some(Sex::Male));
        assert_eq!(license.height, Some(Height::Inches(70)));
        assert_eq!(license.weight_lb, Some(180));
        assert_eq!(license.eye_color, Some(EyeColor::Brown));
        assert_eq!(license.hair_color, Some(HairColor::Blond));
        assert_eq!(license.address_street_1.as_deref(), Some("MAIN ST 123"));
        assert_eq!(license.address_street_2.as_deref(), Some("APT 4"));
        assert_eq!(license.city.as_deref(), Some("ANYTOWN"));
        assert_eq!(license.jurisdiction.as_deref(), Some("CA"));
        assert_eq!(license.postal_code.as_deref(), Some("902100000"));
        assert_eq!(license.country, Some(Country::Usa));
        assert_eq!(license.document_discriminator.as_deref(), Some("ABC12345"));
        assert_eq!(license.compliance, Some(Compliance::Compliant));
        assert_eq!(license.organ_donor, Some(true));
        assert_eq!(license.veteran, Some(false));
        assert_eq!(
            license.family_name_truncation,
            Some(Truncation::NotTruncated)
        );
    }

    #[test]
    fn raw_elements_map_is_populated() {
        let license = parse(&fixture_payload()).unwrap();
        // Every declared code should be present in the flat map.
        assert_eq!(
            license.elements.get("DAQ").map(String::as_str),
            Some("D12345678")
        );
        assert_eq!(license.elements.get("DCS").map(String::as_str), Some("DOE"));
        assert_eq!(
            license.elements.get("DBB").map(String::as_str),
            Some("01151990")
        );
        assert!(license.elements.contains_key("DCG"));
    }

    #[test]
    fn rejects_missing_compliance() {
        let mut payload = fixture_payload();
        payload[0] = b'X';
        assert!(matches!(
            parse(&payload).unwrap_err(),
            AamvaError::MissingComplianceIndicator
        ));
    }

    #[test]
    fn rejects_missing_ansi_tag() {
        let mut payload = fixture_payload();
        payload[4] = b'x'; // replaces 'A' of "ANSI "
        assert!(matches!(
            parse(&payload).unwrap_err(),
            AamvaError::MissingAnsiHeader
        ));
    }

    #[test]
    fn rejects_short_payload() {
        let err = parse(b"@\n").unwrap_err();
        assert!(matches!(err, AamvaError::PayloadTooShort { .. }));
    }

    #[test]
    fn rejects_non_numeric_version() {
        let mut payload = fixture_payload();
        payload[15] = b'X'; // first char of AAMVA version
        let err = parse(&payload).unwrap_err();
        assert!(matches!(err, AamvaError::MalformedHeader(_)));
    }

    #[test]
    fn canadian_date_format_parses() {
        let d = parse_date("19900115", "DBB").unwrap();
        assert_eq!(d, NaiveDate::from_ymd_opt(1990, 1, 15).unwrap());
    }

    #[test]
    fn us_date_format_parses() {
        let d = parse_date("01151990", "DBB").unwrap();
        assert_eq!(d, NaiveDate::from_ymd_opt(1990, 1, 15).unwrap());
    }

    #[test]
    fn height_with_cm_unit_parses() {
        assert_eq!(Height::parse("178 cm"), Some(Height::Centimetres(178)));
    }

    #[test]
    fn height_without_unit_defaults_to_inches() {
        assert_eq!(Height::parse("070"), Some(Height::Inches(70)));
    }

    #[test]
    fn eye_color_aliases() {
        assert_eq!(EyeColor::from_str("BRO").unwrap(), EyeColor::Brown);
        assert_eq!(EyeColor::from_str("BRN").unwrap(), EyeColor::Brown);
        // Unrecognised codes fall into the `Other` variant via #[strum(default)].
        assert_eq!(
            EyeColor::from_str("ZZZ").unwrap(),
            EyeColor::Other("ZZZ".into())
        );
    }

    #[test]
    fn sex_codes_parse() {
        assert_eq!(Sex::from_str("1").unwrap(), Sex::Male);
        assert_eq!(Sex::from_str("2").unwrap(), Sex::Female);
        assert_eq!(Sex::from_str("9").unwrap(), Sex::NotSpecified);
        assert!(Sex::from_str("3").is_err());
    }

    #[test]
    fn truncation_codes_parse() {
        assert_eq!(Truncation::from_str("T").unwrap(), Truncation::Truncated);
        assert_eq!(Truncation::from_str("N").unwrap(), Truncation::NotTruncated);
        assert_eq!(Truncation::from_str("U").unwrap(), Truncation::Unknown);
    }

    #[test]
    fn enum_display_roundtrips() {
        // Display mirrors the primary serialize tag.
        assert_eq!(Sex::Male.to_string(), "1");
        assert_eq!(Compliance::Compliant.to_string(), "F");
        assert_eq!(Country::Usa.to_string(), "USA");
        assert_eq!(Truncation::Truncated.to_string(), "T");
    }
}
