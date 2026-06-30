//! zlib inflation of PII blobs.
//!
//! Decompresses zlib streams using [`flate2`]'s `ZlibDecoder`.

use crate::error::PanQrError;
use flate2::read::ZlibDecoder;
use std::io::Read;

/// Inflates zlib-compressed data.
pub fn inflate(compressed: &[u8]) -> Result<Vec<u8>, PanQrError> {
    let mut decoder = ZlibDecoder::new(compressed);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| PanQrError::Inflate(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn roundtrip() {
        let data = b"hello PAN QR";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(inflate(&compressed).unwrap(), data);
    }

    #[test]
    fn rejects_garbage() {
        assert!(inflate(&[0x00, 0x01, 0x02, 0x03]).is_err());
    }
}
