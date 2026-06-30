//! zlib inflation of PII blobs.
//!
//! Decompresses zlib streams using [`flate2`]'s `ZlibDecoder`.

use crate::error::PanQrError;
use flate2::read::ZlibDecoder;
use std::io::Read;

/// Maximum number of bytes we will inflate from a PII blob. A genuine PII blob is
/// tiny; the cap guards against a crafted "zlib bomb" that would exhaust memory.
const MAX_DECOMPRESSED_SIZE: usize = 32 * 1024 * 1024;

/// Inflates zlib-compressed data, capping the output at [`MAX_DECOMPRESSED_SIZE`].
pub fn inflate(compressed: &[u8]) -> Result<Vec<u8>, PanQrError> {
    inflate_capped(compressed, MAX_DECOMPRESSED_SIZE)
}

/// Inflates a zlib stream, refusing to produce more than `limit` bytes. Reading
/// through `take(limit + 1)` lets us reject an over-limit (bomb) payload without
/// first allocating it in full.
fn inflate_capped(compressed: &[u8], limit: usize) -> Result<Vec<u8>, PanQrError> {
    let decoder = ZlibDecoder::new(compressed);
    let mut out = Vec::new();
    decoder
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| PanQrError::Inflate(e.to_string()))?;
    if out.len() > limit {
        return Err(PanQrError::DecompressionLimitExceeded(limit));
    }
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

    #[test]
    fn rejects_decompression_bomb() {
        // 1000 highly-compressible bytes shrink to a small stream but inflate
        // back past a tiny limit, so the cap must reject them.
        let data = vec![0u8; 1000];
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&data).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(matches!(
            inflate_capped(&compressed, 10),
            Err(PanQrError::DecompressionLimitExceeded(10))
        ));
        // A limit large enough for the real output inflates normally.
        assert_eq!(inflate_capped(&compressed, 1000).unwrap(), data);
    }
}
