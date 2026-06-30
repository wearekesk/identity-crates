//! WebP header reconstruction for embedded PAN photos.
//!
//! The QR stores the image with a stripped container header;
//! [`ImageProcessor::fix_header`] rebuilds a valid WebP (RIFF) header in front
//! of the payload.

use crate::error::PanQrError;
use crate::values::{IMAGE_HEADER_RIFF, IMAGE_HEADER_VP8, IMAGE_HEADER_WEBP};

/// Number of leading bytes the stripped image must carry: a 4-byte length field
/// lives at `[2..6]` and the original payload begins at `[16..]`.
const MIN_IMAGE_HEADER_LEN: usize = 16;

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
    ///
    /// Errors with [`PanQrError::ImageTooSmall`] when there are fewer than
    /// [`MIN_IMAGE_HEADER_LEN`] bytes, since the length field and payload offset
    /// would otherwise read off the end and yield a malformed image.
    pub fn fix_header(&self) -> Result<Vec<u8>, PanQrError> {
        if self.image_bytes.len() < MIN_IMAGE_HEADER_LEN {
            return Err(PanQrError::ImageTooSmall(self.image_bytes.len()));
        }
        let tail = &self.image_bytes[MIN_IMAGE_HEADER_LEN..];
        let mut fixed = Vec::with_capacity(MIN_IMAGE_HEADER_LEN + tail.len());
        fixed.extend_from_slice(IMAGE_HEADER_RIFF);
        fixed.extend_from_slice(self.retrieve_length());
        fixed.extend_from_slice(IMAGE_HEADER_WEBP);
        fixed.extend_from_slice(IMAGE_HEADER_VP8);
        fixed.extend_from_slice(tail);
        Ok(fixed)
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

        let out = ImageProcessor::new(&input).fix_header().unwrap();
        assert_eq!(&out[0..4], b"RIFF");
        assert_eq!(&out[4..8], &[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(&out[8..12], b"WEBP");
        assert_eq!(&out[12..16], b"VP8 ");
        assert_eq!(&out[16..], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn rejects_short_input() {
        // Fewer than 16 bytes cannot carry the length field + payload offset.
        let input = vec![0u8; 15];
        assert!(matches!(
            ImageProcessor::new(&input).fix_header(),
            Err(PanQrError::ImageTooSmall(15))
        ));
        // The boundary at exactly 16 bytes is accepted.
        let ok = vec![0u8; 16];
        assert!(ImageProcessor::new(&ok).fix_header().is_ok());
    }
}
