//! Decompression and compression entry points used over the FFI seam.
//!
//! Each public function takes input bytes and returns either the
//! produced bytes or the underlying library's diagnostic verbatim. The
//! cause string is intentionally unprefixed: the Haskell side wraps
//! every failure as a typed 'Slap.Status.DecompressionFailure' that
//! already names the site (NINJA1 zlib payload, BSDiff diff bzip2
//! section, etc.), so a Rust-side prefix would only double-label the
//! rendered message.

use std::io::{Read, Write};

use bzip2::bufread::BzDecoder;
use bzip2::read::BzEncoder;
use flate2::bufread::GzDecoder;
use flate2::read::ZlibEncoder;
use flate2::{Compression, Decompress, FlushDecompress, GzBuilder, Status};

/// Drain a `Read` to a fresh `Vec<u8>`, surfacing any I/O failure as
/// the underlying library's diagnostic verbatim — the one drain every
/// streaming entry point below shares.
fn drain_to_vec<R: Read>(mut reader: R) -> Result<Vec<u8>, String> {
    let mut output_bytes = Vec::new();
    reader
        .read_to_end(&mut output_bytes)
        .map_err(|cause| cause.to_string())?;
    Ok(output_bytes)
}

/// Zlib (RFC 1950) inflate: 2-byte header + deflate + adler32 checksum.
/// The stream must account for the whole input and reach its own end:
/// the callers hand exactly the bytes their wire container delimits as
/// the stream, so a stream ending before the input (trailing bytes) or
/// an input ending before the stream (truncation) is container
/// corruption. Both verdicts are judged on the raw `Decompress` state
/// machine, whose consumption count answers them exactly;
/// [`gzip_inflate`] and [`bzip2_decompress`] hold the same line through
/// their `bufread` decoders' unconsumed remainder.
pub fn zlib_inflate(input: &[u8]) -> Result<Vec<u8>, String> {
    // A chunk at a time; the vector grows as output lands, not pre-sized.
    const OUTPUT_RESERVE_CHUNK: usize = 32 * 1024;
    let mut decompressor = Decompress::new(true);
    let mut output_bytes: Vec<u8> = Vec::new();
    loop {
        let consumed_before = decompressor.total_in() as usize;
        let produced_before = decompressor.total_out();
        output_bytes.reserve(OUTPUT_RESERVE_CHUNK);
        let status = decompressor
            .decompress_vec(&input[consumed_before..], &mut output_bytes, FlushDecompress::None)
            .map_err(|cause| cause.to_string())?;
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                let stalled = decompressor.total_in() as usize == consumed_before
                    && decompressor.total_out() == produced_before;
                if stalled {
                    return Err(format!(
                        "the stream is incomplete: decoding stalled after {} of {} input bytes without reaching the stream's end",
                        decompressor.total_in(),
                        input.len()
                    ));
                }
            }
        }
    }
    let consumed = decompressor.total_in() as usize;
    if consumed != input.len() {
        return Err(format!(
            "the stream ended after {consumed} of {} input bytes; the remainder is not part of the stream",
            input.len()
        ));
    }
    Ok(output_bytes)
}

/// Zlib (RFC 1950) deflate at the library's default compression level.
/// The NINJA1 spec is mute on level — any zlib-deflate output round-trips
/// through any decoder regardless of level — so slap pins the default
/// rather than exposing a knob no caller currently turns. The `expect`
/// holds for the reason `gzip_deflate` spells out.
pub fn zlib_deflate(input: &[u8]) -> Vec<u8> {
    drain_to_vec(ZlibEncoder::new(input, Compression::default()))
        .expect("in-memory zlib deflate yields no error; allocation failure aborts")
}

/// Gzip (RFC 1952) inflate, held to [`zlib_inflate`]'s completeness
/// contract: bytes past the member's end — junk or a second member —
/// are container corruption and refused, never quietly ignored.
pub fn gzip_inflate(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = GzDecoder::new(input);
    let decoded = drain_to_vec(&mut decoder)?;
    refuse_unconsumed_remainder(decoder.into_inner(), input.len())?;
    Ok(decoded)
}

/// Gzip (RFC 1952) deflate at the library's default compression level
/// with `mtime = 0` pinned in the gzip header — locks output
/// determinism so the same input bytes produce the same compressed
/// bytes. In-memory deflate is total at the algorithm level; the
/// `expect`s below document that the only fail-shaped event is
/// allocation failure, which Rust's default allocator handles by
/// aborting before any error value reaches the caller.
pub fn gzip_deflate(input: &[u8]) -> Vec<u8> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    encoder.write_all(input).expect("in-memory gzip deflate yields no error; allocation failure aborts");
    encoder.finish().expect("in-memory gzip deflate yields no error; allocation failure aborts")
}

/// Bzip2 decompress, held to [`zlib_inflate`]'s completeness contract:
/// bytes past the stream's end are container corruption and refused.
pub fn bzip2_decompress(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = BzDecoder::new(input);
    let decoded = drain_to_vec(&mut decoder)?;
    refuse_unconsumed_remainder(decoder.into_inner(), input.len())?;
    Ok(decoded)
}

/// The completeness verdict shared by the streaming inflaters: a
/// `bufread` decoder consumes exactly its stream's bytes, so whatever
/// it leaves behind is not part of the stream. The message matches
/// [`zlib_inflate`]'s, whose raw state machine reaches the same verdict
/// through its consumption count.
fn refuse_unconsumed_remainder(remainder: &[u8], input_length: usize) -> Result<(), String> {
    if remainder.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the stream ended after {} of {input_length} input bytes; the remainder is not part of the stream",
        input_length - remainder.len()
    ))
}

/// Bzip2 compress at level 9, the maximum block size — the setting the
/// reference bsdiff tooling compresses its three sections with
/// (`kCompressionLevel` in the endorsed source's bz2_compressor.cc),
/// pinned rather than exposed as a knob no caller currently turns. The
/// `expect` holds for the reason `gzip_deflate` spells out.
pub fn bzip2_compress(input: &[u8]) -> Vec<u8> {
    drain_to_vec(BzEncoder::new(input, bzip2::Compression::best()))
        .expect("in-memory bzip2 compress yields no error; allocation failure aborts")
}

#[cfg(test)]
mod tests {
    use super::{bzip2_compress, bzip2_decompress, gzip_deflate, gzip_inflate, zlib_deflate, zlib_inflate};

    #[test]
    fn bzip2_round_trips() {
        let inputs: [&[u8]; 3] = [b"", b"slap", &[0u8; 100_000]];
        for input in inputs {
            let compressed = bzip2_compress(input);
            assert!(!compressed.is_empty(), "even empty input owes framing bytes");
            assert_eq!(bzip2_decompress(&compressed).as_deref(), Ok(input));
        }
    }

    #[test]
    fn zlib_round_trips() {
        let inputs: [&[u8]; 3] = [b"", b"slap", &[0u8; 100_000]];
        for input in inputs {
            assert_eq!(zlib_inflate(&zlib_deflate(input)).as_deref(), Ok(input));
        }
    }

    /// A stream cut short is refused, never returned as partial output.
    #[test]
    fn zlib_truncated_stream_is_refused() {
        let compressed =
            zlib_deflate(b"a body long enough that cutting five bytes lands mid-stream");
        let truncated = &compressed[..compressed.len() - 5];
        assert!(zlib_inflate(truncated).is_err(), "a truncated stream must not decode");
    }

    /// Bytes past the stream's end are container corruption, not padding.
    #[test]
    fn zlib_trailing_bytes_are_refused() {
        let mut padded = zlib_deflate(b"slap");
        padded.extend_from_slice(&[0x00, 0x51]);
        assert!(zlib_inflate(&padded).is_err(), "trailing bytes must be refused");
    }

    #[test]
    fn gzip_round_trips() {
        let inputs: [&[u8]; 3] = [b"", b"slap", &[0u8; 100_000]];
        for input in inputs {
            assert_eq!(gzip_inflate(&gzip_deflate(input)).as_deref(), Ok(input));
        }
    }

    #[test]
    fn gzip_truncated_stream_is_refused() {
        let compressed =
            gzip_deflate(b"a body long enough that cutting five bytes lands mid-stream");
        let truncated = &compressed[..compressed.len() - 5];
        assert!(gzip_inflate(truncated).is_err(), "a truncated stream must not decode");
    }

    #[test]
    fn gzip_trailing_bytes_are_refused() {
        let mut padded = gzip_deflate(b"slap");
        padded.extend_from_slice(&[0x00, 0x51]);
        assert!(gzip_inflate(&padded).is_err(), "trailing bytes must be refused");
    }

    /// A second gzip member is bytes past the stream's end like any
    /// other: the wire containers each delimit exactly one stream.
    #[test]
    fn gzip_second_member_is_refused() {
        let mut two_members = gzip_deflate(b"slap");
        two_members.extend_from_slice(&gzip_deflate(b"slap again"));
        assert!(gzip_inflate(&two_members).is_err(), "a second member must be refused");
    }

    #[test]
    fn bzip2_truncated_stream_is_refused() {
        let compressed =
            bzip2_compress(b"a body long enough that cutting five bytes lands mid-stream");
        let truncated = &compressed[..compressed.len() - 5];
        assert!(bzip2_decompress(truncated).is_err(), "a truncated stream must not decode");
    }

    #[test]
    fn bzip2_trailing_bytes_are_refused() {
        let mut padded = bzip2_compress(b"slap");
        padded.extend_from_slice(&[0x00, 0x51]);
        assert!(bzip2_decompress(&padded).is_err(), "trailing bytes must be refused");
    }
}
