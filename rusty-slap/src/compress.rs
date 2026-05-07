//! Decompression and compression entry points used over the FFI seam.
//!
//! Each public function takes input bytes and returns either the
//! produced bytes or the underlying library's diagnostic verbatim. The
//! cause string is intentionally unprefixed: the Haskell side wraps
//! every failure as a typed 'Slap.Error.DecompressionFailure' that
//! already names the site (NINJA1 zlib payload, BSDiff diff bzip2
//! section, etc.), so a Rust-side prefix would only double-label the
//! rendered message.

use std::io::Read;

use flate2::read::{GzDecoder, ZlibDecoder, ZlibEncoder};
use flate2::Compression;

/// Drain a `Read` to a fresh `Vec<u8>`, surfacing any I/O failure as the
/// underlying library's diagnostic verbatim. The four streaming entry
/// points below differ only in which decoder/encoder they construct;
/// this helper keeps that single shared shape in one place.
fn drain_to_vec<R: Read>(mut reader: R) -> Result<Vec<u8>, String> {
    let mut output_bytes = Vec::new();
    reader
        .read_to_end(&mut output_bytes)
        .map_err(|cause| cause.to_string())?;
    Ok(output_bytes)
}

/// Zlib (RFC 1950) inflate: 2-byte header + deflate + adler32 checksum.
pub fn zlib_inflate(input: &[u8]) -> Result<Vec<u8>, String> {
    drain_to_vec(ZlibDecoder::new(input))
}

/// Zlib (RFC 1950) deflate at the library's default compression level.
/// The NINJA1 spec is mute on level — any zlib-deflate output round-trips
/// through any decoder regardless of level — so slap pins the default
/// rather than exposing a knob no caller currently turns.
pub fn zlib_deflate(input: &[u8]) -> Result<Vec<u8>, String> {
    drain_to_vec(ZlibEncoder::new(input, Compression::default()))
}

/// Gzip (RFC 1952) inflate.
pub fn gzip_inflate(input: &[u8]) -> Result<Vec<u8>, String> {
    drain_to_vec(GzDecoder::new(input))
}

/// Bzip2 decompress.
pub fn bzip2_decompress(input: &[u8]) -> Result<Vec<u8>, String> {
    drain_to_vec(bzip2_rs::DecoderReader::new(input))
}
