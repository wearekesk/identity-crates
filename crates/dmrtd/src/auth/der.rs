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
        let len_bytes = &after_first[..n];
        // DER requires the *minimal* encoding: no leading zero byte, and long form
        // is only legal when the value doesn't fit in short form (< 0x80). Rejecting
        // non-minimal lengths keeps a BER-style encoding from slipping through this
        // reader, which is documented as strict DER.
        if len_bytes[0] == 0 {
            return None;
        }
        let mut len = 0usize;
        for &b in len_bytes {
            len = len.checked_mul(256)?.checked_add(b as usize)?;
        }
        if len < 0x80 {
            return None;
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

/// Contents of a single element of type `tag` that spans the *entire* input —
/// nothing may follow it. Trailing bytes after the element mean the value wasn't the
/// whole thing it was taken for (an appended TLV on a cert / SOD / key), so reject it.
pub fn expect(input: &[u8], tag: u8) -> Option<&[u8]> {
    let (t, contents, rest) = next(input)?;
    (t == tag && rest.is_empty()).then_some(contents)
}

/// Decode an OID's contents into its arcs.
pub fn oid_arcs(contents: &[u8]) -> Option<Vec<u64>> {
    // Every subidentifier, including the first, is base-128. Decode them all, then
    // split the first: it packs arc1·40 + arc2, and for arc1 = 2 the second arc can
    // be arbitrarily large (so the first subidentifier may span several bytes — the
    // old `first / 40` on a single byte got those wrong).
    let mut subids = Vec::new();
    let mut value: u64 = 0;
    let mut pending = false;
    let mut fresh = true; // are we on the first byte of a subidentifier?
    for &b in contents {
        // A subidentifier that opens with 0x80 has a zero high group — a leading-zero
        // base-128 encoding, which DER forbids. Reject it so a BER OID can't slip past
        // this strict reader.
        if fresh && b == 0x80 {
            return None;
        }
        fresh = b & 0x80 == 0;
        value = value.checked_mul(128)?.checked_add((b & 0x7f) as u64)?;
        if b & 0x80 == 0 {
            subids.push(value);
            value = 0;
            pending = false;
        } else {
            pending = true;
        }
    }
    // a trailing continuation byte means the encoding was truncated
    if pending {
        return None;
    }

    let first = *subids.first()?;
    let (arc1, arc2) = if first < 80 {
        (first / 40, first % 40)
    } else {
        // 40·arc1 + arc2 with arc1 capped at 2, so anything ≥ 80 is arc1 = 2
        (2, first - 80)
    };
    let mut arcs = vec![arc1, arc2];
    arcs.extend_from_slice(&subids[1..]);
    Some(arcs)
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
    fn non_minimal_lengths_are_rejected_as_ber_not_der() {
        // long form for a value that fits in short form (len 1 as 0x81 0x01)
        assert!(next(&[0x04, 0x81, 0x01, 0xAA]).is_none());
        // leading zero length octet (0x82 0x00 0x80 ...)
        let mut ber = vec![0x04, 0x82, 0x00, 0x80];
        ber.extend(std::iter::repeat_n(0xAA, 0x80));
        assert!(next(&ber).is_none());
        // the minimal short form of the same value is fine
        let mut der = vec![0x04, 0x7f];
        der.extend(std::iter::repeat_n(0xAA, 0x7f));
        assert!(next(&der).is_some());
    }

    #[test]
    fn expect_rejects_trailing_bytes() {
        // one INTEGER that spans the whole input — accepted
        assert!(expect(&[0x02, 0x01, 0x05], INTEGER).is_some());
        // the same INTEGER with an appended TLV — rejected, it isn't the whole value
        assert!(expect(&[0x02, 0x01, 0x05, 0x02, 0x01, 0x06], INTEGER).is_none());
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
    fn decodes_a_multi_byte_first_subidentifier() {
        // 2.100.3 — first subidentifier is 40·2 + 100 = 180, which needs two base-128
        // bytes (0x81 0x34). The old single-byte `first / 40` couldn't represent it.
        let oid = [0x81, 0x34, 0x03];
        assert_eq!(oid_arcs(&oid).unwrap(), vec![2, 100, 3]);
    }

    #[test]
    fn non_minimal_base128_oid_subidentifiers_are_rejected() {
        // a subidentifier opening with 0x80 has a leading-zero high group — non-minimal
        // BER; a strict-DER reader must reject it. (0x80 0x01 is a padded encoding of 1.)
        assert!(oid_arcs(&[0x80, 0x01]).is_none());
        // padding a later subidentifier is equally invalid: 2.5.<0x80 0x03>
        assert!(oid_arcs(&[0x55, 0x80, 0x03]).is_none());
        // the minimal form of the same OID is fine
        assert_eq!(oid_arcs(&[0x55, 0x03]).unwrap(), vec![2, 5, 3]);
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
