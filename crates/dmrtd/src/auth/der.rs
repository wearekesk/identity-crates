//! A small, strict DER reader.
//!
//! Only what the authentication paths need: walk a structure, pull a primitive, read
//! an OID. Everything is bounds-checked and returns `None` rather than panicking —
//! this parses attacker-supplied bytes off a chip, so a malformed length must be a
//! clean failure, never an index out of range.

pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// Split `input` into (tag, contents, rest).
pub fn next(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = input.split_first()?;
    let (&first_len, after_first) = after_tag.split_first()?;

    let (len, body) = if first_len & 0x80 == 0 {
        // short form: the length is the byte itself
        (first_len as usize, after_first)
    } else {
        // long form: low 7 bits say how many bytes the length occupies
        let n = (first_len & 0x7f) as usize;
        // 0x80 is the indefinite form — not legal in DER
        if n == 0 || n > 4 || after_first.len() < n {
            return None;
        }
        let mut len = 0usize;
        for &b in &after_first[..n] {
            len = len.checked_mul(256)?.checked_add(b as usize)?;
        }
        (len, &after_first[n..])
    };

    if body.len() < len {
        return None;
    }
    Some((tag, &body[..len], &body[len..]))
}

/// Contents of the next element, which must carry `tag`, plus what follows it.
pub fn take(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (t, contents, rest) = next(input)?;
    (t == tag).then_some((contents, rest))
}

/// Contents of a single element of type `tag` that spans the whole input.
pub fn expect(input: &[u8], tag: u8) -> Option<&[u8]> {
    let (t, contents, _rest) = next(input)?;
    (t == tag).then_some(contents)
}

/// Decode an OID's contents into its arcs.
pub fn oid_arcs(contents: &[u8]) -> Option<Vec<u64>> {
    let (&first, rest) = contents.split_first()?;
    // the first byte packs two arcs: 40 * arc1 + arc2
    let mut arcs = vec![(first / 40) as u64, (first % 40) as u64];

    let mut value: u64 = 0;
    let mut pending = false;
    for &b in rest {
        value = value.checked_mul(128)?.checked_add((b & 0x7f) as u64)?;
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
            pending = false;
        } else {
            pending = true;
        }
    }
    // a trailing continuation byte means the encoding was truncated
    (!pending).then_some(arcs)
}

/// A BIT STRING's payload, minus the "unused bits" prefix byte.
pub fn bit_string_bytes(contents: &[u8]) -> Option<&[u8]> {
    let (&unused, bits) = contents.split_first()?;
    // keys and signatures are whole bytes; anything else is malformed here
    (unused == 0).then_some(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_form() {
        let (tag, contents, rest) = next(&[0x02, 0x02, 0x00, 0xca, 0xff]).unwrap();
        assert_eq!(tag, INTEGER);
        assert_eq!(contents, &[0x00, 0xca]);
        assert_eq!(rest, &[0xff]);
    }

    #[test]
    fn reads_long_form() {
        let mut input = vec![SEQUENCE, 0x82, 0x01, 0x00]; // length 256
        input.extend(std::iter::repeat_n(0xAA, 256));
        let (tag, contents, rest) = next(&input).unwrap();
        assert_eq!(tag, SEQUENCE);
        assert_eq!(contents.len(), 256);
        assert!(rest.is_empty());
    }

    #[test]
    fn a_length_running_past_the_buffer_is_rejected_not_panicked() {
        assert!(next(&[0x30, 0x7f, 0x01]).is_none()); // claims 127 bytes, has 1
        assert!(next(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none()); // absurd length
        assert!(next(&[0x30]).is_none()); // truncated
        assert!(next(&[]).is_none());
        assert!(next(&[0x30, 0x80]).is_none()); // indefinite: not DER
    }

    #[test]
    fn decodes_oids() {
        // 2.16.840.1.101.3.4.2.1 — SHA-256
        let sha256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        assert_eq!(
            oid_arcs(&sha256).unwrap(),
            vec![2, 16, 840, 1, 101, 3, 4, 2, 1]
        );
        // 1.3.14.3.2.26 — SHA-1
        let sha1 = [0x2b, 0x0e, 0x03, 0x02, 0x1a];
        assert_eq!(oid_arcs(&sha1).unwrap(), vec![1, 3, 14, 3, 2, 26]);
        // truncated continuation
        assert!(oid_arcs(&[0x2b, 0x80]).is_none());
    }

    #[test]
    fn unwraps_bit_strings() {
        assert_eq!(
            bit_string_bytes(&[0x00, 0xde, 0xad]).unwrap(),
            &[0xde, 0xad]
        );
        assert!(bit_string_bytes(&[0x03, 0xde]).is_none()); // unused bits: not a key
        assert!(bit_string_bytes(&[]).is_none());
    }
}
