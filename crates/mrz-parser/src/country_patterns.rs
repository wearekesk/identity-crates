use once_cell::sync::Lazy;
use regex::Regex;

/// Pattern information for a specific country to help extract document numbers
/// from MRZ first-line content.
#[derive(Debug)]
pub struct MRZCountryPattern {
    pub country_code: &'static str,
    pub id_prefix: &'static str,
    pub document_number_pattern: Regex,
    pub document_number_start_index: usize,
}

/// Static list of country patterns, held in a lazily-initialized `Vec` so the
/// contained `Regex` instances are compiled once at runtime.
static PATTERNS: Lazy<Vec<MRZCountryPattern>> = Lazy::new(|| {
    vec![
        MRZCountryPattern {
            country_code: "AUT",
            id_prefix: "IDAUT",
            document_number_pattern: Regex::new(r"([0-9]{10})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "BEL",
            id_prefix: "IDBEL",
            document_number_pattern: Regex::new(r"([A-Z][0-9]{3}[A-Z][0-9]{6})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "BGR",
            id_prefix: "IDBGR",
            document_number_pattern: Regex::new(r"([0-9]{10})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "CYP",
            id_prefix: "IDCYP",
            document_number_pattern: Regex::new(r"([0-9]{9})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "CZE",
            id_prefix: "IDCZE",
            document_number_pattern: Regex::new(r"([A-Z]?[0-9]{8,9})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "DEU",
            id_prefix: "IDDEU",
            document_number_pattern: Regex::new(r"([A-Z0-9]{9})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "DNK",
            id_prefix: "IDDNK",
            document_number_pattern: Regex::new(r"([0-9]{9})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "ESP",
            id_prefix: "IDESP",
            document_number_pattern: Regex::new(r"(\d{8}[A-Z])").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "EST",
            id_prefix: "IDEST",
            document_number_pattern: Regex::new(r"([A-Z]{0,2}[0-9]{8})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "FIN",
            id_prefix: "IDFIN",
            document_number_pattern: Regex::new(r"([0-9]{14})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "FRA",
            id_prefix: "IDFRA",
            document_number_pattern: Regex::new(r"([A-Z0-9]{12})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "GBR",
            id_prefix: "IDGBR",
            document_number_pattern: Regex::new(r"([0-9]{13})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "GRC",
            id_prefix: "IDGRC",
            document_number_pattern: Regex::new(r"([A-Z]{0,2}[0-9]{8,10})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "HRV",
            id_prefix: "IDHRV",
            document_number_pattern: Regex::new(r"([0-9]{11})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "HUN",
            id_prefix: "IDHUN",
            document_number_pattern: Regex::new(r"([0-9]{6}[A-Z]{2})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "IRL",
            id_prefix: "IDIRL",
            document_number_pattern: Regex::new(r"([A-Z0-9]{12})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "ITA",
            id_prefix: "IDIT",
            document_number_pattern: Regex::new(r"([A-Z0-9]{10})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "LTU",
            id_prefix: "IDLTU",
            document_number_pattern: Regex::new(r"([0-9]{8})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "LUX",
            id_prefix: "IDLUX",
            document_number_pattern: Regex::new(r"([A-Z]{0,2}[0-9]{8,10})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "LVA",
            id_prefix: "IDLVA",
            document_number_pattern: Regex::new(r"([A-Z]?[0-9]{8,9})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "MLT",
            id_prefix: "IDMLT",
            document_number_pattern: Regex::new(r"([A-Z]?[0-9]{8,9})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "NLD",
            id_prefix: "IDNLD",
            document_number_pattern: Regex::new(r"([A-Z]{2}[0-9]{7})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "POL",
            id_prefix: "IDPOL",
            document_number_pattern: Regex::new(r"([A-Z]{0,3}[0-9]{8,9})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "PRT",
            id_prefix: "IDPRT",
            document_number_pattern: Regex::new(r"([A-Z]{0,2}[0-9]{8})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "ROU",
            id_prefix: "IDROU",
            document_number_pattern: Regex::new(r"([A-Z]{2}[0-9]{8,9})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "SVK",
            id_prefix: "IDSVK",
            document_number_pattern: Regex::new(r"([0-9]{6}[A-Z][0-9]{3})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "SVN",
            id_prefix: "IDSVN",
            document_number_pattern: Regex::new(r"([A-Z]?[0-9]{9,10})").unwrap(),
            document_number_start_index: 5,
        },
        MRZCountryPattern {
            country_code: "SWE",
            id_prefix: "IDSWE",
            document_number_pattern: Regex::new(r"([A-Z]?[0-9]{8,9})").unwrap(),
            document_number_start_index: 5,
        },
    ]
});

/// Return a reference to the first matching country pattern for `first_line`,
/// based on whether `first_line` starts with the pattern's `id_prefix`.
pub fn get_country_pattern(first_line: &str) -> Option<&'static MRZCountryPattern> {
    PATTERNS
        .iter()
        .find(|p| first_line.starts_with(p.id_prefix))
}

/// Return all available patterns as a slice.
pub fn patterns() -> &'static [MRZCountryPattern] {
    PATTERNS.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_known_prefix() {
        let first = "IDGBR123456789012";
        let p = get_country_pattern(first).expect("pattern found");
        assert_eq!(p.country_code, "GBR");
    }

    #[test]
    fn no_match_returns_none() {
        let first = "UNKNOWNPREFIX";
        assert!(get_country_pattern(first).is_none());
    }
}
