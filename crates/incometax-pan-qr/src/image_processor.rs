//! WebP header reconstruction for embedded PAN photos.
//!
//! A 1:1 port of `utils/image.py` (`ImageProcessor`). The QR stores the image
//! with a stripped container header; [`ImageProcessor::fix_header`] rebuilds a
//! valid WebP (RIFF) header in front of the payload.

use crate::values::{IMAGE_HEADER_RIFF, IMAGE_HEADER_VP8, IMAGE_HEADER_WEBP};

/// Reconstructs the WebP header of an embedded image.
pub struct ImageProcessor<'a> {
    image_bytes: &'a [u8],
}

impl<'a> ImageProcessor<'a> {
    /// Wraps the raw (header-stripped) image bytes.
    pub fn new(image_bytes: &'a [u8]) -> Self {
        Self { image_bytes }
    }

    /// The RIFF chunk-length field, taken from `image_bytes[2..6]`.
    fn retrieve_length(&self) -> &[u8] {
        self.image_bytes.get(2..6).unwrap_or(&[])
    }

    /// Rebuilds the header: `RIFF`, length (`bytes[2..6]`), `WEBP`, `VP8 `,
    /// then the original payload from `bytes[16..]`.
    pub fn fix_header(&self) -> Vec<u8> {
        let tail = self.image_bytes.get(16..).unwrap_or(&[]);
        let mut fixed = Vec::with_capacity(16 + tail.len());
        fixed.extend_from_slice(IMAGE_HEADER_RIFF);
        fixed.extend_from_slice(self.retrieve_length());
        fixed.extend_from_slice(IMAGE_HEADER_WEBP);
        fixed.extend_from_slice(IMAGE_HEADER_VP8);
        fixed.extend_from_slice(tail);
        fixed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuilds_header() {
        // 16-byte (garbage) original header + 4 payload bytes.
        let mut input = vec![0u8; 16];
        input[2] = 0x10;
        input[3] = 0x20;
        input[4] = 0x30;
        input[5] = 0x40;
        input.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let out = ImageProcessor::new(&input).fix_header();
        assert_eq!(&out[0..4], b"RIFF");
        assert_eq!(&out[4..8], &[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(&out[8..12], b"WEBP");
        assert_eq!(&out[12..16], b"VP8 ");
        assert_eq!(&out[16..], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
