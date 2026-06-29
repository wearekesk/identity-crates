//! PACE-related constants.

/// PACE mapping type. The closely related
/// [`MappingType`](crate::lds::asn1_object_identifiers::MappingType)
/// uses the same three variants (`Gm` / `Im` / `Cam`); this enum is kept
/// separately for the PACE substructure namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaceMappingType {
    /// Generic Mapping.
    Gm,
    /// Integrated Mapping.
    Im,
    /// Chip Authentication Mapping.
    Cam,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_variants_are_distinct() {
        assert_ne!(PaceMappingType::Gm, PaceMappingType::Im);
        assert_ne!(PaceMappingType::Im, PaceMappingType::Cam);
        assert_ne!(PaceMappingType::Gm, PaceMappingType::Cam);
    }
}
