//! PDF417 barcode detection via the `rxing` crate.
//!
//! Two entry points mirror the Aadhaar QR module:
//! - [`decode_pdf417_from_image_bytes`] — PNG/JPEG bytes.
//! - [`decode_pdf417_from_luma8`] — raw 8-bit grayscale buffer.

use rxing::{BarcodeFormat, DecodeHints};

use super::error::AamvaError;

/// Decodes a PDF417 barcode from PNG/JPEG image bytes and returns the raw
/// text content.
pub fn decode_pdf417_from_image_bytes(bytes: &[u8]) -> Result<String, AamvaError> {
    let luma = image::load_from_memory(bytes)
        .map_err(|e| AamvaError::ImageDecode(e.to_string()))?
        .to_luma8();
    let (width, height) = (luma.width(), luma.height());
    decode_pdf417_from_luma8(width, height, luma.into_raw())
}

/// Decodes a PDF417 barcode from a raw luma8 buffer (`width × height` bytes).
pub fn decode_pdf417_from_luma8(
    width: u32,
    height: u32,
    luma: Vec<u8>,
) -> Result<String, AamvaError> {
    let expected = (width as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| AamvaError::ImageDecode(format!("dimensions {width}x{height} overflow")))?;
    if luma.len() != expected {
        return Err(AamvaError::PdfDecode(format!(
            "luma buffer length {} does not match width*height={}",
            luma.len(),
            expected
        )));
    }
    let mut hints = DecodeHints::default();
    hints.TryHarder = Some(true);
    let result = rxing::helpers::detect_in_luma_with_hints(
        luma,
        width,
        height,
        Some(BarcodeFormat::PDF_417),
        &mut hints,
    )
    .map_err(map_rxing_err)?;
    Ok(result.getText().to_string())
}

fn map_rxing_err(e: rxing::Exceptions) -> AamvaError {
    // Classify by the concrete `rxing::Exceptions` variant rather than by
    // matching substrings of the formatted message.
    match e {
        rxing::Exceptions::NotFoundException(_) => AamvaError::BarcodeNotFound,
        other => AamvaError::PdfDecode(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GrayImage, ImageFormat, Luma};
    use rxing::pdf417::PDF417Writer;
    use rxing::{EncodeHints, Writer};
    use std::io::Cursor;

    /// Renders a PDF417 of `text` into a luma8 buffer.
    fn encode_pdf417_to_luma(text: &str, width: i32, height: i32) -> (u32, u32, Vec<u8>) {
        let writer = PDF417Writer::default();
        let matrix = writer
            .encode_with_hints(
                text,
                &BarcodeFormat::PDF_417,
                width,
                height,
                &EncodeHints::default(),
            )
            .expect("PDF417 encode");
        let w = matrix.getWidth();
        let h = matrix.getHeight();
        let mut img = GrayImage::from_pixel(w, h, Luma([255u8]));
        for y in 0..h {
            for x in 0..w {
                if matrix.get(x, y) {
                    img.put_pixel(x, y, Luma([0u8]));
                }
            }
        }
        (w, h, img.into_raw())
    }

    #[test]
    fn roundtrip_simple_text_via_luma8() {
        let original = "HELLO PDF417";
        let (w, h, buf) = encode_pdf417_to_luma(original, 400, 120);
        let decoded = decode_pdf417_from_luma8(w, h, buf).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn roundtrip_via_png_bytes() {
        let original = "AAMVA-TEST";
        let (w, h, buf) = encode_pdf417_to_luma(original, 400, 120);
        let img = GrayImage::from_raw(w, h, buf).unwrap();
        let mut png_bytes = Cursor::new(Vec::new());
        img.write_to(&mut png_bytes, ImageFormat::Png).unwrap();
        let decoded = decode_pdf417_from_image_bytes(png_bytes.get_ref()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn luma_dimensions_mismatch_is_rejected() {
        let err = decode_pdf417_from_luma8(10, 10, vec![0u8; 50]).unwrap_err();
        assert!(matches!(err, AamvaError::PdfDecode(_)));
    }
}
