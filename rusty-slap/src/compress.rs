use std::io::Read;

use flate2::read::{GzDecoder, ZlibDecoder, ZlibEncoder};
use flate2::Compression;

/// Zlib (RFC 1950) inflate: 2-byte header + deflate + adler32 checksum.
pub fn zlib_inflate(src: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = ZlibDecoder::new(src);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| format!("zlib inflate: {e}"))?;
    Ok(out)
}

/// Zlib (RFC 1950) deflate.  `level` 0–9 (6 = default).
pub fn zlib_deflate(src: &[u8], level: u32) -> Result<Vec<u8>, String> {
    let mut encoder = ZlibEncoder::new(src, Compression::new(level));
    let mut out = Vec::new();
    encoder
        .read_to_end(&mut out)
        .map_err(|e| format!("zlib deflate: {e}"))?;
    Ok(out)
}

/// Gzip (RFC 1952) inflate.
pub fn gzip_inflate(src: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = GzDecoder::new(src);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| format!("gzip inflate: {e}"))?;
    Ok(out)
}

/// Bzip2 decompress.
pub fn bz2_decompress(src: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = bzip2_rs::DecoderReader::new(src);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| format!("bzip2 decompress: {e}"))?;
    Ok(out)
}
