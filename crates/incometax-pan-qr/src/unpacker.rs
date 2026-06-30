//! The non-standard bit-unpacking routine used by PAN Secure QRs.
//!
//! A 1:1 port of `utils/unpacker.py` (`BitUnpacker`), which the upstream notes
//! was itself ported directly from the app's baksmali. The carry-bit state
//! machine in [`BitUnpacker::bit_unpack`] is reproduced exactly.

use crate::error::PanQrError;

/// Streaming bit-unpacker. Bytes are accumulated into [`BitUnpacker::output`]
/// as whole bytes become available.
#[derive(Debug, Default)]
pub struct BitUnpacker {
    /// Decoded output bytes written so far.
    pub output: Vec<u8>,
    /// Partially-assembled current byte (`a` in the Python).
    a: u8,
    /// Number of valid low bits currently held in `a` (`b` in the Python).
    b: u32,
}

impl BitUnpacker {
    /// Creates an empty unpacker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds `v1` bits of `v` (low bits first) into the stream, emitting whole
    /// bytes to [`BitUnpacker::output`].
    ///
    /// Faithfully mirrors the Python `bit_unpack(v, v1)`: the `a`/`b` carry
    /// state, the `1..=32` bounds check, the `>> 8` draining loop, and the
    /// final partial-byte accumulation.
    pub fn bit_unpack(&mut self, v: u32, v1: u32) -> Result<(), PanQrError> {
        if v1 > 0x20 || v1 < 1 {
            return Err(PanQrError::InvalidBitCount(v1 as i64));
        }

        // Work in wider, signed arithmetic so the running value and bit count
        // can be shifted/decremented exactly as the unbounded-int Python does.
        let mut v: u64 = v as u64;
        let mut v1: i64 = v1 as i64;

        let v2 = self.b;
        if v2 > 0 && (v2 as i64) + v1 >= 8 {
            let v3 = ((self.a as u64) | (v << v2)) & 0xFF;
            self.a = v3 as u8;
            v >>= 8 - v2;
            v1 -= (8 - v2) as i64;
            self.output.push(v3 as u8);
            self.a = 0;
            self.b = 0;
        }

        while v1 / 8 > 0 {
            self.output.push((v & 0xFF) as u8);
            v >>= 8;
            v1 -= 8;
        }

        if v1 > 0 {
            self.a = (((v << self.b) | (self.a as u64)) & 0xFF) as u8;
            self.b += v1 as u32;
        }

        Ok(())
    }
}

/// Decodes a scanned PAN-QR string into the packed byte stream.
///
/// Ports the top-level `unpack()` from `main.py`: the string is split into
/// 4-character chunks, each parsed as a decimal integer and fed to
/// `bit_unpack(int, 13)`.
pub fn unpack_scanned_string(scanned: &str) -> Result<Vec<u8>, PanQrError> {
    let chars: Vec<char> = scanned.chars().collect();
    let mut unpacker = BitUnpacker::new();

    for chunk in chars.chunks(4) {
        let chunk_str: String = chunk.iter().collect();
        let value: u32 = chunk_str
            .parse()
            .map_err(|_| PanQrError::InvalidChunk(chunk_str.clone()))?;
        unpacker.bit_unpack(value, 13)?;
    }

    Ok(unpacker.output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference implementation, transcribed straight from the Python, used to
    /// cross-check the production routine on small inputs.
    fn py_bit_unpack(out: &mut Vec<u8>, a: &mut i64, b: &mut i64, v_in: i64, v1_in: i64) {
        let mut v = v_in;
        let mut v1 = v1_in;
        let v2 = *b;
        if v2 > 0 && v2 + v1 >= 8 {
            let v3 = (*a | (v << v2)) & 0xFF;
            *a = v3;
            v >>= 8 - v2;
            v1 -= 8 - v2;
            out.push(v3 as u8);
            *a = 0;
            *b = 0;
        }
        while v1 / 8 > 0 {
            out.push((v & 0xFF) as u8);
            v >>= 8;
            v1 -= 8;
        }
        if v1 > 0 {
            *a = ((v << *b) | *a) & 0xFF;
            *b += v1;
        }
    }

    #[test]
    fn single_call_13_bits() {
        // 0b1_0110_0111_0101 = 0x1675 = 5749. Low 8 bits 0x75 are emitted, the
        // top 5 bits (0b10110 = 0x16) remain held in `a`.
        let mut u = BitUnpacker::new();
        u.bit_unpack(5749, 13).unwrap();
        assert_eq!(u.output, vec![0x75]);
    }

    #[test]
    fn carry_across_two_calls() {
        let mut u = BitUnpacker::new();
        u.bit_unpack(5749, 13).unwrap(); // holds 5 bits (0x16)
        u.bit_unpack(5749, 13).unwrap(); // combines carry, emits more bytes
        let mut a = 0i64;
        let mut b = 0i64;
        let mut expected = Vec::new();
        py_bit_unpack(&mut expected, &mut a, &mut b, 5749, 13);
        py_bit_unpack(&mut expected, &mut a, &mut b, 5749, 13);
        assert_eq!(u.output, expected);
    }

    #[test]
    fn matches_reference_over_a_sequence() {
        let inputs = [0u32, 1, 7, 255, 256, 4095, 8191, 1234, 9999, 42];
        let mut u = BitUnpacker::new();
        for &x in &inputs {
            u.bit_unpack(x, 13).unwrap();
        }
        let mut a = 0i64;
        let mut b = 0i64;
        let mut expected = Vec::new();
        for &x in &inputs {
            py_bit_unpack(&mut expected, &mut a, &mut b, x as i64, 13);
        }
        assert_eq!(u.output, expected);
    }

    #[test]
    fn rejects_bad_bit_count() {
        let mut u = BitUnpacker::new();
        assert!(u.bit_unpack(1, 0).is_err());
        assert!(u.bit_unpack(1, 33).is_err());
    }

    #[test]
    fn unpack_scanned_string_rejects_non_numeric() {
        assert!(unpack_scanned_string("abcd").is_err());
    }

    #[test]
    fn unpack_scanned_string_matches_manual() {
        // Two chunks "5749" and "0042".
        let out = unpack_scanned_string("57490042").unwrap();
        let mut u = BitUnpacker::new();
        u.bit_unpack(5749, 13).unwrap();
        u.bit_unpack(42, 13).unwrap();
        assert_eq!(out, u.output);
    }
}
