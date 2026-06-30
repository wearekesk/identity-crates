//! QR code detection via the `rxing` crate.
//!
//! Two entry points:
//! - [`decode_pan_qr_text_from_image_bytes`] — accepts PNG/JPEG bytes.
//! - [`decode_pan_qr_from_luma8`] — accepts a raw 8-bit grayscale buffer (pairs
//!   naturally with camera pipelines on mobile, no image-format dependency).

use rxing::{BarcodeFormat, DecodeHints};

use crate::error::PanQrError;

/// Decodes a PAN QR code from PNG/JPEG image bytes and returns the embedded
/// numeric text.
pub fn decode_pan_qr_text_from_image_bytes(bytes: &[u8]) -> Result<String, PanQrError> {
    let luma = image::load_from_memory(bytes)
        .map_err(|e| PanQrError::ImageDecode(e.to_string()))?
        .to_luma8();
    let (width, height) = (luma.width(), luma.height());
    decode_pan_qr_from_luma8(width, height, luma.into_raw())
}

/// Decodes a PAN QR code from a raw 8-bit luma buffer (`width × height` bytes)
/// and returns the embedded numeric text.
pub fn decode_pan_qr_from_luma8(
    width: u32,
    height: u32,
    luma: Vec<u8>,
) -> Result<String, PanQrError> {
    let expected = (width as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| PanQrError::ImageDecode(format!("dimensions {width}x{height} overflow")))?;
    if luma.len() != expected {
        return Err(PanQrError::QrDecode(format!(
            "luma buffer length {} does not match width*height={}",
            luma.len(),
            expected
        )));
    }
    let mut hints = DecodeHints {
        TryHarder: Some(true),
        ..Default::default()
    };
    let result = rxing::helpers::detect_in_luma_with_hints(
        luma,
        width,
        height,
        Some(BarcodeFormat::QR_CODE),
        &mut hints,
    )
    .map_err(map_rxing_err)?;
    Ok(result.getText().to_string())
}

fn map_rxing_err(e: rxing::Exceptions) -> PanQrError {
    // Classify by the concrete `rxing::Exceptions` variant rather than by
    // matching substrings of the formatted message.
    match e {
        rxing::Exceptions::NotFoundException(_) => PanQrError::BarcodeNotFound,
        other => PanQrError::QrDecode(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GrayImage, ImageFormat, Luma};
    use rxing::qrcode::decoder::ErrorCorrectionLevel;
    use rxing::qrcode::encoder::qrcode_encoder::encode as qr_encode;
    use std::io::Cursor;

    /// Renders a QR code containing `text` as a luma8 image. Each QR module
    /// is drawn at `scale` pixels square with a `quiet_zone_modules` border.
    fn encode_qr_to_luma(text: &str, scale: u32, quiet_zone_modules: u32) -> (u32, u32, Vec<u8>) {
        let qr = qr_encode(text, ErrorCorrectionLevel::L).unwrap();
        let matrix = qr.getMatrix().as_ref().expect("QR matrix present");
        let m_width = matrix.getWidth();
        let m_height = matrix.getHeight();
        let total_w = (m_width + quiet_zone_modules * 2) * scale;
        let total_h = (m_height + quiet_zone_modules * 2) * scale;

        let mut img = GrayImage::from_pixel(total_w, total_h, Luma([255u8]));
        for y in 0..m_height {
            for x in 0..m_width {
                if matrix.get(x, y) == 1 {
                    let px = (x + quiet_zone_modules) * scale;
                    let py = (y + quiet_zone_modules) * scale;
                    for dy in 0..scale {
                        for dx in 0..scale {
                            img.put_pixel(px + dx, py + dy, Luma([0u8]));
                        }
                    }
                }
            }
        }
        (total_w, total_h, img.into_raw())
    }

    #[test]
    fn roundtrip_numeric_text_via_luma8() {
        let original = "123456789012";
        let (w, h, buf) = encode_qr_to_luma(original, 4, 4);
        let decoded = decode_pan_qr_from_luma8(w, h, buf).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn roundtrip_via_png_bytes() {
        let original = "987654321098";
        let (w, h, buf) = encode_qr_to_luma(original, 4, 4);
        let img = GrayImage::from_raw(w, h, buf).unwrap();
        let mut png_bytes = Cursor::new(Vec::new());
        img.write_to(&mut png_bytes, ImageFormat::Png).unwrap();
        let decoded = decode_pan_qr_text_from_image_bytes(png_bytes.get_ref()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn luma_dimensions_mismatch_is_rejected() {
        let err = decode_pan_qr_from_luma8(10, 10, vec![0u8; 50]).unwrap_err();
        assert!(matches!(err, PanQrError::QrDecode(_)));
    }

    #[test]
    fn blank_image_reports_not_found() {
        let (w, h) = (64u32, 64u32);
        let buf = vec![255u8; (w * h) as usize];
        let err = decode_pan_qr_from_luma8(w, h, buf).unwrap_err();
        assert!(matches!(
            err,
            PanQrError::BarcodeNotFound | PanQrError::QrDecode(_)
        ));
    }

    #[test]
    fn bad_image_bytes_report_image_decode() {
        let err = decode_pan_qr_text_from_image_bytes(&[0u8, 1, 2, 3]).unwrap_err();
        assert!(matches!(err, PanQrError::ImageDecode(_)));
    }
}
