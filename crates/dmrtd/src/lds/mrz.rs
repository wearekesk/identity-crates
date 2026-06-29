//! Machine Readable Zone parsing for DMRTD.
//!
//! Parses the three MRZ formats defined in ICAO 9303:
//! - **TD1** — 90 bytes (3 lines × 30)
//! - **TD2** — 72 bytes (2 lines × 36)
//! - **TD3** — 88 bytes (2 lines × 44)
//!
//! Decoding validates every check digit present in the document (document
//! number, date of birth, date of expiry, optional data where applicable, and
//! the composite) and returns [`MrzParseError`] on mismatch.

use chrono::NaiveDate;
use thiserror::Error;

use crate::extension::datetime::DateTimeFormatExt;
use crate::extension::string::StringDateExt;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// MRZ format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MrzVersion {
    Td1,
    Td2,
    Td3,
}

/// Error returned by [`Mrz::from_bytes`].
#[derive(Debug, Error, PartialEq, Eq)]
#[error("MRZParseError: {0}")]
pub struct MrzParseError(pub String);

/// Parsed Machine Readable Zone.
#[derive(Debug, Clone)]
pub struct Mrz {
    pub country: String,
    pub date_of_birth: NaiveDate,
    pub date_of_expiry: NaiveDate,
    pub document_code: String,
    pub first_name: String,
    pub last_name: String,
    pub nationality: String,
    pub gender: String,
    pub version: MrzVersion,
    doc_num: String,
    opt_data: String,
    opt_data2: Option<String>,
    encoded: Vec<u8>,
}

impl Mrz {
    /// Parses an MRZ from its raw bytes (as read from EF.DG1 / stored on chip).
    pub fn from_bytes(encoded: impl Into<Vec<u8>>) -> Result<Self, MrzParseError> {
        let encoded = encoded.into();
        let (version, parsed) = match encoded.len() {
            90 => (MrzVersion::Td1, Self::parse_td1(&encoded)?),
            72 => (MrzVersion::Td2, Self::parse_td2(&encoded)?),
            88 => (MrzVersion::Td3, Self::parse_td3(&encoded)?),
            _ => return Err(MrzParseError("Invalid MRZ data".into())),
        };
        Ok(Self {
            version,
            encoded,
            ..parsed
        })
    }

    /// Returns the original encoded bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns the document number (possibly extended for TD1/TD2).
    pub fn document_number(&self) -> &str {
        &self.doc_num
    }

    /// Returns the first optional-data field.
    pub fn optional_data(&self) -> &str {
        &self.opt_data
    }

    /// Returns the second optional-data field (TD1 only, unless the extended
    /// document number consumed it).
    pub fn optional_data2(&self) -> Option<&str> {
        self.opt_data2.as_deref()
    }

    // -----------------------------------------------------------------------
    // Check digit
    // -----------------------------------------------------------------------

    /// Calculates the ICAO 9303 MRZ check digit over `check_string`.
    ///
    /// Returns `None` if the input contains an unrecognised character.
    /// Coercing such inputs to `0` (as the reference does) would let malformed
    /// MRZ data slip through whenever the stored check digit happens to be `0`,
    /// so unsupported characters are rejected instead.
    pub fn calculate_check_digit(check_string: &str) -> Option<u32> {
        const MULTIPLIERS: [u32; 3] = [7, 3, 1];
        let mut sum: u32 = 0;
        let mut m = 0;
        for c in check_string.chars() {
            let value = match c {
                '0'..='9' => (c as u32) - ('0' as u32),
                'A'..='Z' => (c as u32) - ('A' as u32) + 10,
                '<' | ' ' => 0,
                _ => return None,
            };
            sum += value * MULTIPLIERS[m];
            m = (m + 1) % MULTIPLIERS.len();
        }
        Some(sum % 10)
    }

    // -----------------------------------------------------------------------
    // TD1 / TD2 / TD3 parsing
    // -----------------------------------------------------------------------

    fn parse_td1(data: &[u8]) -> Result<Mrz, MrzParseError> {
        let mut r = Reader::new(data);

        let document_code = read(&mut r, 2)?;
        let country = read(&mut r, 3)?;
        let mut doc_num = read(&mut r, 9)?;
        let cd_doc_num = read_with_pad(&mut r, 1)?;
        let mut opt_data = read(&mut r, 15)?;
        let date_of_birth = read_date(&mut r, false)?;
        assert_check_digit(&date_of_birth.format_yymmdd(), read_cd(&mut r)?, "Data of Birth check digit mismatch")?;

        let gender = read(&mut r, 1)?;
        let date_of_expiry = read_date(&mut r, true)?;
        assert_check_digit(&date_of_expiry.format_yymmdd(), read_cd(&mut r)?, "Data of Expiry check digit mismatch")?;

        let nationality = read(&mut r, 3)?;
        let mut opt_data2: Option<String> = Some(read(&mut r, 11)?);

        parse_extended_document_number(&mut doc_num, &cd_doc_num, &mut opt_data, &mut opt_data2)?;

        let cd_composite = read_cd(&mut r)?;
        let (last_name, first_name) = read_name_identifiers(&mut r, 30)?;

        // Extract composite and calculate/verify its CD.
        r.reset();
        r.skip(5);
        let mut composite = read_with_pad(&mut r, 25)?;
        composite.push_str(&read_with_pad(&mut r, 7)?);
        r.skip(1);
        composite.push_str(&read_with_pad(&mut r, 7)?);
        r.skip(3);
        composite.push_str(&read_with_pad(&mut r, 11)?);
        assert_check_digit(&composite, cd_composite, "Composite check digit mismatch")?;

        Ok(Mrz {
            country,
            date_of_birth,
            date_of_expiry,
            document_code,
            first_name,
            last_name,
            nationality,
            gender,
            version: MrzVersion::Td1,
            doc_num,
            opt_data,
            opt_data2,
            encoded: Vec::new(),
        })
    }

    fn parse_td2(data: &[u8]) -> Result<Mrz, MrzParseError> {
        let mut r = Reader::new(data);

        let document_code = read(&mut r, 2)?;
        let country = read(&mut r, 3)?;
        let (last_name, first_name) = read_name_identifiers(&mut r, 31)?;

        let mut doc_num = read(&mut r, 9)?;
        let cd_doc_num = read_with_pad(&mut r, 1)?;

        let nationality = read(&mut r, 3)?;
        let date_of_birth = read_date(&mut r, false)?;
        assert_check_digit(&date_of_birth.format_yymmdd(), read_cd(&mut r)?, "Data of Birth check digit mismatch")?;

        let gender = read(&mut r, 1)?;
        let date_of_expiry = read_date(&mut r, true)?;
        assert_check_digit(&date_of_expiry.format_yymmdd(), read_cd(&mut r)?, "Data of Expiry check digit mismatch")?;

        let mut opt_data = read(&mut r, 7)?;
        let mut opt_data2: Option<String> = None;
        parse_extended_document_number(&mut doc_num, &cd_doc_num, &mut opt_data, &mut opt_data2)?;

        let cd_composite = read_cd(&mut r)?;

        // Extract composite and calculate/verify its CD.
        r.rewind(36);
        let mut composite = read_with_pad(&mut r, 10)?;
        r.skip(3);
        composite.push_str(&read_with_pad(&mut r, 7)?);
        r.skip(1);
        composite.push_str(&read_with_pad(&mut r, 14)?);
        assert_check_digit(&composite, cd_composite, "Composite check digit mismatch")?;

        Ok(Mrz {
            country,
            date_of_birth,
            date_of_expiry,
            document_code,
            first_name,
            last_name,
            nationality,
            gender,
            version: MrzVersion::Td2,
            doc_num,
            opt_data,
            opt_data2,
            encoded: Vec::new(),
        })
    }

    fn parse_td3(data: &[u8]) -> Result<Mrz, MrzParseError> {
        let mut r = Reader::new(data);

        let document_code = read(&mut r, 2)?;
        let country = read(&mut r, 3)?;
        let (last_name, first_name) = read_name_identifiers(&mut r, 39)?;

        let doc_num = read(&mut r, 9)?;
        assert_check_digit(&doc_num, read_cd(&mut r)?, "Document Number check digit mismatch")?;

        let nationality = read(&mut r, 3)?;
        let date_of_birth = read_date(&mut r, false)?;
        assert_check_digit(&date_of_birth.format_yymmdd(), read_cd(&mut r)?, "Data of Birth check digit mismatch")?;

        let gender = read(&mut r, 1)?;
        let date_of_expiry = read_date(&mut r, true)?;
        assert_check_digit(&date_of_expiry.format_yymmdd(), read_cd(&mut r)?, "Data of Expiry check digit mismatch")?;

        let opt_data = read(&mut r, 14)?;
        assert_check_digit(&opt_data, read_cd(&mut r)?, "Optional data check digit mismatch")?;

        let cd_composite = read_cd(&mut r)?;

        // Extract composite and calculate/verify its CD.
        r.rewind(44);
        let mut composite = read_with_pad(&mut r, 10)?;
        r.skip(3);
        composite.push_str(&read_with_pad(&mut r, 7)?);
        r.skip(1);
        composite.push_str(&read_with_pad(&mut r, 22)?);
        assert_check_digit(&composite, cd_composite, "Composite check digit mismatch")?;

        Ok(Mrz {
            country,
            date_of_birth,
            date_of_expiry,
            document_code,
            first_name,
            last_name,
            nationality,
            gender,
            version: MrzVersion::Td3,
            doc_num,
            opt_data,
            opt_data2: None,
            encoded: Vec::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Byte-stream reader & shared helpers
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn reset(&mut self) {
        self.pos = 0;
    }
    fn skip(&mut self, n: usize) {
        self.pos += n;
    }
    fn rewind(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }
}

fn read_with_pad(r: &mut Reader<'_>, size: usize) -> Result<String, MrzParseError> {
    if r.pos + size > r.buf.len() {
        return Err(MrzParseError(format!(
            "Unexpected end of MRZ data (pos={}, needed={})",
            r.pos, size
        )));
    }
    let slice = &r.buf[r.pos..r.pos + size];
    r.pos += size;
    // MRZ is ASCII — each byte maps directly to a char.
    Ok(slice.iter().map(|&b| b as char).collect())
}

fn read(r: &mut Reader<'_>, size: usize) -> Result<String, MrzParseError> {
    let s = read_with_pad(r, size)?;
    Ok(s.trim_end_matches('<').to_string())
}

fn read_date(r: &mut Reader<'_>, future_date: bool) -> Result<NaiveDate, MrzParseError> {
    let yymmdd = read(r, 6)?;
    yymmdd
        .parse_date_yymmdd(future_date)
        .map_err(|e| MrzParseError(format!("Invalid date in MRZ: {e}")))
}

fn read_cd(r: &mut Reader<'_>) -> Result<u32, MrzParseError> {
    let s = read_with_pad(r, 1)?;
    if s == "<" {
        return Ok(0);
    }
    s.parse::<u32>()
        .map_err(|_| MrzParseError("Invalid check digit character in MRZ".into()))
}

fn read_name_identifiers(
    r: &mut Reader<'_>,
    size: usize,
) -> Result<(String, String), MrzParseError> {
    let name_field = read(r, size)?;
    let ids: Vec<String> = name_field.split("<<").map(|s| s.replace('<', " ")).collect();
    let last = ids.first().cloned().unwrap_or_default();
    let first = if ids.len() > 1 {
        ids[1..].join(" ")
    } else {
        String::new()
    };
    Ok((last, first))
}

fn assert_check_digit(value: &str, cdigit: u32, err_msg: &str) -> Result<(), MrzParseError> {
    // `None` (unsupported character) is treated as a mismatch and rejected.
    if Mrz::calculate_check_digit(value) != Some(cdigit) {
        return Err(MrzParseError(err_msg.into()));
    }
    Ok(())
}

/// Handles TD1/TD2 extended document numbers: if the document-number check
/// digit field is `<`, the first part of `opt_data` (before the next `<`) is
/// appended to `doc_num`, and the real check digit is taken from the last
/// character of that segment. `opt_data` and `opt_data2` are shifted
/// accordingly (TD1 moves `opt_data2` into `opt_data`; TD2 just clears the
/// consumed portion of `opt_data`).
fn parse_extended_document_number(
    doc_num: &mut String,
    str_cd_doc_num: &str,
    opt_data: &mut String,
    opt_data2: &mut Option<String>,
) -> Result<(), MrzParseError> {
    let cd_doc_num: u32;
    if str_cd_doc_num == "<" && opt_data.len() > 2 {
        let dn_second_part = opt_data.split('<').next().unwrap_or("");
        if dn_second_part.is_empty() {
            return Err(MrzParseError(
                "Document Number extension is empty".into(),
            ));
        }
        // Operate on characters, not bytes: MRZ bytes are mapped 1:1 to chars,
        // so bytes >= 0x80 become multi-byte UTF-8 and byte-indexed slicing
        // would panic on a char boundary. Split off the trailing check digit.
        let mut chars: Vec<char> = dn_second_part.chars().collect();
        let last_char = chars
            .pop()
            .ok_or_else(|| MrzParseError("Document Number extension is empty".into()))?;
        let body: String = chars.into_iter().collect();
        doc_num.push_str(&body);
        cd_doc_num = last_char
            .to_digit(10)
            .ok_or_else(|| MrzParseError("Invalid extended document number check digit".into()))?;
        *opt_data = opt_data2.take().unwrap_or_default();
    } else {
        cd_doc_num = str_cd_doc_num
            .parse::<u32>()
            .map_err(|_| MrzParseError("Invalid document number check digit".into()))?;
    }

    assert_check_digit(doc_num, cd_doc_num, "Document Number check digit mismatch")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ICAO 9303 Appendix A to Part 3 check-digit examples.
    #[test]
    fn check_digit_examples() {
        assert_eq!(Mrz::calculate_check_digit("520727"), Some(3));
        assert_eq!(Mrz::calculate_check_digit("AB2134<<<"), Some(5));
        assert_eq!(
            Mrz::calculate_check_digit("HA672242<658022549601086<<<<<<<<<<<<<<0"),
            Some(8)
        );
        assert_eq!(
            Mrz::calculate_check_digit("D231458907<<<<<<<<<<<<<<<34071279507122<<<<<<<<<<<"),
            Some(2)
        );
        assert_eq!(
            Mrz::calculate_check_digit("HA672242<658022549601086<<<<<<<0"),
            Some(8)
        );
    }

    #[test]
    fn check_digit_rejects_unsupported_character() {
        // '*' is not in the MRZ alphabet → rejected rather than coerced to 0.
        assert_eq!(Mrz::calculate_check_digit("12*456"), None);
    }

    #[test]
    fn parse_td1_sample() {
        let mrz_str = "I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<";
        let mrz = Mrz::from_bytes(mrz_str.as_bytes().to_vec()).unwrap();
        assert_eq!(mrz.version, MrzVersion::Td1);
        assert_eq!(mrz.document_code, "I");
        assert_eq!(mrz.document_number(), "D23145890");
        assert_eq!(mrz.country, "UTO");
        assert_eq!(mrz.nationality, "UTO");
        assert_eq!(mrz.first_name, "ANNA MARIA");
        assert_eq!(mrz.last_name, "ERIKSSON");
        assert_eq!(mrz.gender, "F");
        assert_eq!(mrz.date_of_birth, NaiveDate::from_ymd_opt(1974, 8, 12).unwrap());
        assert_eq!(mrz.date_of_expiry, NaiveDate::from_ymd_opt(2012, 4, 15).unwrap());
        assert_eq!(mrz.optional_data(), "");
        assert_eq!(mrz.optional_data2(), Some(""));
    }

    #[test]
    fn parse_td1_extended_document_number() {
        let mrz_str = "I<UTOD23145890<7349<<<<<<<<<<<3407127M9507122UTO<<<<<<<<<<<2STEVENSON<<PETER<JOHN<<<<<<<<<";
        let mrz = Mrz::from_bytes(mrz_str.as_bytes().to_vec()).unwrap();
        assert_eq!(mrz.version, MrzVersion::Td1);
        assert_eq!(mrz.document_number(), "D23145890734");
        assert_eq!(mrz.first_name, "PETER JOHN");
        assert_eq!(mrz.last_name, "STEVENSON");
        assert_eq!(mrz.gender, "M");
        assert_eq!(mrz.date_of_birth, NaiveDate::from_ymd_opt(1934, 7, 12).unwrap());
        assert_eq!(mrz.date_of_expiry, NaiveDate::from_ymd_opt(1995, 7, 12).unwrap());
        assert_eq!(mrz.optional_data(), "");
        assert_eq!(mrz.optional_data2(), None);
    }

    #[test]
    fn parse_td2_sample() {
        let mrz_str = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6";
        let mrz = Mrz::from_bytes(mrz_str.as_bytes().to_vec()).unwrap();
        assert_eq!(mrz.version, MrzVersion::Td2);
        assert_eq!(mrz.document_number(), "D23145890");
        assert_eq!(mrz.first_name, "ANNA MARIA");
        assert_eq!(mrz.last_name, "ERIKSSON");
        assert_eq!(mrz.gender, "F");
        assert_eq!(mrz.date_of_birth, NaiveDate::from_ymd_opt(1974, 8, 12).unwrap());
        assert_eq!(mrz.date_of_expiry, NaiveDate::from_ymd_opt(2012, 4, 15).unwrap());
        assert_eq!(mrz.optional_data(), "");
        assert_eq!(mrz.optional_data2(), None);
    }

    #[test]
    fn parse_td2_extended_document_number() {
        let mrz_str = "I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8";
        let mrz = Mrz::from_bytes(mrz_str.as_bytes().to_vec()).unwrap();
        assert_eq!(mrz.version, MrzVersion::Td2);
        assert_eq!(mrz.document_number(), "D23145890734");
        assert_eq!(mrz.date_of_birth, NaiveDate::from_ymd_opt(1934, 7, 12).unwrap());
        assert_eq!(mrz.date_of_expiry, NaiveDate::from_ymd_opt(1995, 7, 12).unwrap());
        assert_eq!(mrz.optional_data(), "");
        assert_eq!(mrz.optional_data2(), None);
    }

    #[test]
    fn parse_td3_sample() {
        let mrz_str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
        let mrz = Mrz::from_bytes(mrz_str.as_bytes().to_vec()).unwrap();
        assert_eq!(mrz.version, MrzVersion::Td3);
        assert_eq!(mrz.document_code, "P");
        assert_eq!(mrz.document_number(), "L898902C3");
        assert_eq!(mrz.country, "UTO");
        assert_eq!(mrz.nationality, "UTO");
        assert_eq!(mrz.first_name, "ANNA MARIA");
        assert_eq!(mrz.last_name, "ERIKSSON");
        assert_eq!(mrz.gender, "F");
        assert_eq!(mrz.date_of_birth, NaiveDate::from_ymd_opt(1974, 8, 12).unwrap());
        assert_eq!(mrz.date_of_expiry, NaiveDate::from_ymd_opt(2012, 4, 15).unwrap());
        assert_eq!(mrz.optional_data(), "ZE184226B");
        assert_eq!(mrz.optional_data2(), None);
    }

    #[test]
    fn parse_td3_single_letter_country() {
        let mrz_str = "P<D<<SCHMIDT<<FINN<<<<<<<<<<<<<<<<<<<<<<<<<<AA89BXHZ56D<<7503201M2511188<<<<<<<<<<<<<<<8";
        let mrz = Mrz::from_bytes(mrz_str.as_bytes().to_vec()).unwrap();
        assert_eq!(mrz.document_number(), "AA89BXHZ5");
        assert_eq!(mrz.country, "D");
        assert_eq!(mrz.nationality, "D");
        assert_eq!(mrz.last_name, "SCHMIDT");
        assert_eq!(mrz.first_name, "FINN");
        assert_eq!(mrz.date_of_birth, NaiveDate::from_ymd_opt(1975, 3, 20).unwrap());
        assert_eq!(mrz.date_of_expiry, NaiveDate::from_ymd_opt(2025, 11, 18).unwrap());
    }

    #[test]
    fn invalid_length_rejected() {
        let err = Mrz::from_bytes(Vec::<u8>::new()).unwrap_err();
        assert_eq!(err.0, "Invalid MRZ data");
    }

    // -----------------------------------------------------------------------
    // Fuzz tests — ICAO check-digit mismatch vectors.
    // -----------------------------------------------------------------------

    #[test]
    fn td1_doc_num_mismatch() {
        let m = "I<UTOD231458902<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<";
        let err = Mrz::from_bytes(m.as_bytes().to_vec()).unwrap_err();
        assert!(err.0.contains("Document Number check digit"));
    }

    #[test]
    fn td1_birth_mismatch() {
        let m = "I<UTOD231458907<<<<<<<<<<<<<<<7408123F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<";
        let err = Mrz::from_bytes(m.as_bytes().to_vec()).unwrap_err();
        assert!(err.0.contains("Data of Birth"));
    }

    #[test]
    fn td1_expiry_mismatch() {
        let m = "I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204158UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<";
        let err = Mrz::from_bytes(m.as_bytes().to_vec()).unwrap_err();
        assert!(err.0.contains("Data of Expiry"));
    }

    #[test]
    fn td2_composite_mismatch() {
        let m = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<7";
        let err = Mrz::from_bytes(m.as_bytes().to_vec()).unwrap_err();
        assert!(err.0.contains("Composite check digit"));
    }

    #[test]
    fn td3_optional_data_mismatch() {
        let m = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<20";
        let err = Mrz::from_bytes(m.as_bytes().to_vec()).unwrap_err();
        assert!(err.0.contains("Optional data check digit"));
    }

    #[test]
    fn to_bytes_roundtrip() {
        let src = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
        let mrz = Mrz::from_bytes(src.as_bytes().to_vec()).unwrap();
        assert_eq!(mrz.to_bytes(), src.as_bytes());
    }
}
