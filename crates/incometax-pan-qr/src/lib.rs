//! Indian Income-Tax PAN (Permanent Account Number) validation.
//!
//! A PAN is a 10-character code `AAAAA9999A`:
//! - chars 1–3: alphabetic series,
//! - char 4: entity type (`P C H F A T B L J G`),
//! - char 5: alphabetic (first letter of surname / entity name),
//! - chars 6–9: numeric,
//! - char 10: alphabetic check character.
//!
//! [`check_pan_details`] validates the structure and classifies the holder by
//! the 4th-character entity code. This is a *structural* check only — it does
//! not confirm the PAN was issued.

/// Entity type encoded by the 4th character of a PAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanType {
    /// `P` — an individual.
    Individual,
    /// `C` — a company.
    Company,
    /// `H` — a Hindu Undivided Family (HUF).
    HinduUndividedFamily,
    /// `F` — a firm / limited liability partnership.
    Firm,
    /// `A` — an Association of Persons (AOP).
    AssociationOfPersons,
    /// `T` — a trust.
    Trust,
    /// `B` — a Body of Individuals (BOI).
    BodyOfIndividuals,
    /// `L` — a local authority.
    LocalAuthority,
    /// `J` — an artificial juridical person.
    ArtificialJuridicalPerson,
    /// `G` — a government agency.
    GovernmentAgency,
    /// Input is non-empty but not a structurally valid PAN.
    InvalidFormat,
    /// Input was empty / absent.
    Unknown,
}

impl PanType {
    /// Maps a PAN 4th-character entity code to its [`PanType`].
    fn from_entity_code(code: u8) -> Option<Self> {
        Some(match code {
            b'P' => PanType::Individual,
            b'C' => PanType::Company,
            b'H' => PanType::HinduUndividedFamily,
            b'F' => PanType::Firm,
            b'A' => PanType::AssociationOfPersons,
            b'T' => PanType::Trust,
            b'B' => PanType::BodyOfIndividuals,
            b'L' => PanType::LocalAuthority,
            b'J' => PanType::ArtificialJuridicalPerson,
            b'G' => PanType::GovernmentAgency,
            _ => return None,
        })
    }

    /// Human-readable description, matching the canonical Income-Tax labels.
    pub fn description(&self) -> &'static str {
        match self {
            PanType::Individual => "Individual",
            PanType::Company => "Company",
            PanType::HinduUndividedFamily => "Hindu Undivided Family (HUF)",
            PanType::Firm => "Firm",
            PanType::AssociationOfPersons => "Association of Persons (AOP)",
            PanType::Trust => "Trust",
            PanType::BodyOfIndividuals => "Body of Individuals (BOI)",
            PanType::LocalAuthority => "Local Authority",
            PanType::ArtificialJuridicalPerson => "Artificial Juridical Person",
            PanType::GovernmentAgency => "Government Agency",
            PanType::InvalidFormat => "Invalid Format",
            PanType::Unknown => "Unknown",
        }
    }
}

/// Result of inspecting a PAN string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanDetails {
    /// The normalized (uppercased, trimmed) PAN, or `None` if the input was empty.
    pub pan_number: Option<String>,
    /// Whether `pan_number` is structurally valid.
    pub is_valid: bool,
    /// The entity type implied by the 4th character (or `Unknown`/`InvalidFormat`).
    pub pan_type: PanType,
}

/// Structurally validates a PAN and classifies its entity type.
///
/// The input is trimmed and upper-cased before checking. Empty input yields
/// `is_valid == false`, `pan_type == Unknown`, and `pan_number == None`.
pub fn check_pan_details(pan: &str) -> PanDetails {
    let normalized = pan.trim().to_uppercase();
    if normalized.is_empty() {
        return PanDetails {
            pan_number: None,
            is_valid: false,
            pan_type: PanType::Unknown,
        };
    }

    let valid_structure = is_valid_pan(normalized.as_bytes());
    let pan_type = if valid_structure {
        // 4th character is the entity code; structure guarantees it is one of
        // the accepted codes, so the map always succeeds here.
        PanType::from_entity_code(normalized.as_bytes()[3]).unwrap_or(PanType::InvalidFormat)
    } else {
        PanType::InvalidFormat
    };

    PanDetails {
        pan_number: Some(normalized),
        is_valid: valid_structure,
        pan_type,
    }
}

/// `^[A-Z]{3}[PCHFATBLJG][A-Z][0-9]{4}[A-Z]$` without a regex dependency.
fn is_valid_pan(b: &[u8]) -> bool {
    b.len() == 10
        && b[0..3].iter().all(u8::is_ascii_uppercase)
        && matches!(
            b[3],
            b'P' | b'C' | b'H' | b'F' | b'A' | b'T' | b'B' | b'L' | b'J' | b'G'
        )
        && b[4].is_ascii_uppercase()
        && b[5..9].iter().all(u8::is_ascii_digit)
        && b[9].is_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_individual_pan() {
        let d = check_pan_details("ABCPK1234L");
        assert!(d.is_valid);
        assert_eq!(d.pan_type, PanType::Individual);
        assert_eq!(d.pan_type.description(), "Individual");
        assert_eq!(d.pan_number.as_deref(), Some("ABCPK1234L"));
    }

    #[test]
    fn trims_and_uppercases() {
        let d = check_pan_details("  abcca1234l  ");
        assert!(d.is_valid);
        assert_eq!(d.pan_number.as_deref(), Some("ABCCA1234L"));
        assert_eq!(d.pan_type, PanType::Company);
    }

    #[test]
    fn classifies_every_entity_code() {
        for (code, ty) in [
            ('P', PanType::Individual),
            ('C', PanType::Company),
            ('H', PanType::HinduUndividedFamily),
            ('F', PanType::Firm),
            ('A', PanType::AssociationOfPersons),
            ('T', PanType::Trust),
            ('B', PanType::BodyOfIndividuals),
            ('L', PanType::LocalAuthority),
            ('J', PanType::ArtificialJuridicalPerson),
            ('G', PanType::GovernmentAgency),
        ] {
            let pan = format!("ABC{code}K1234L");
            let d = check_pan_details(&pan);
            assert!(d.is_valid, "{pan} should be valid");
            assert_eq!(d.pan_type, ty, "{pan} entity type");
        }
    }

    #[test]
    fn empty_input_is_unknown() {
        let d = check_pan_details("   ");
        assert!(!d.is_valid);
        assert_eq!(d.pan_type, PanType::Unknown);
        assert_eq!(d.pan_number, None);
    }

    #[test]
    fn rejects_bad_structure() {
        // bad 4th char (entity code), wrong lengths, misplaced digits/letters
        for bad in [
            "ABCDE1234L",  // 4th char 'D' not an entity code
            "ABCP12345L",  // 5th char must be a letter
            "ABCPK123L",   // too short
            "ABCPK1234LL", // too long
            "ABCPKX234L",  // 6th char must be a digit
            "12CPK1234L",  // first three must be letters
            "ABCPK1234_",  // last char must be a letter
        ] {
            let d = check_pan_details(bad);
            assert!(!d.is_valid, "{bad} should be invalid");
            assert_eq!(d.pan_type, PanType::InvalidFormat, "{bad}");
        }
    }
}
