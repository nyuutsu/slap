//! LZMA decompression for the streams xdelta3 emits.
//!
//! xdelta3's LZMA secondary compressor is liblzma writing an xz/LZMA2
//! stream (`LZMA_FILTER_LZMA2`, check=none) that it never finishes:
//! the bytes begin with an ordinary xz stream header and block header,
//! continue as raw LZMA2 chunks, and then simply stop — no end-of-
//! stream chunk marker, no index, no stream footer, because the
//! encoder keeps the stream open across the patch's windows and dies
//! with it unfinished. The caller hands this module one such stream,
//! gathered whole; this module owns the two adaptations that shape
//! demands:
//!
//!   * the xz stream header and block header are walked past, exposing
//!     the raw LZMA2 chunk sequence `lzma-rs` decodes (its one-shot
//!     `xz_decompress` front door expects the complete, properly-closed
//!     file these streams never are);
//!
//!   * a synthetic end-of-stream marker is chained after the input, so
//!     the chunk decoder ends cleanly at the input's end instead of
//!     erroring on the marker the encoder never wrote. A stream that
//!     carries a real marker stops there, and the bytes after it
//!     surface as unconsumed input.
//!
//! What comes back is bytes and facts: the decoded output, plus how
//! many input bytes the decoder consumed. Whether those facts honor
//! the framing the stream was carried under is the caller's judgment,
//! not this module's.

use std::io::{Cursor, Read};

/// The xz stream header: the 6-byte magic, 2 bytes of stream flags,
/// and a 4-byte CRC32 of the flags. The flags only name the block
/// check type, and a check never arrives in an unfinished stream, so
/// nothing past the magic needs reading — the header is verified by
/// its magic and walked past whole.
const XZ_STREAM_HEADER_LENGTH: usize = 12;

/// The xz magic: `0xFD` followed by ASCII `7zXZ` and a zero byte.
const XZ_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];

/// The LZMA2 end-of-stream chunk marker this module chains after the
/// input (a single zero control byte).
const LZMA2_END_OF_STREAM: [u8; 1] = [0x00];

/// What one decompression produced: the decoded bytes, and how many
/// bytes of the caller's input the decoder consumed before it
/// finished. Consumption counts the xz framing as consumed; a
/// shortfall against the input length means the decoder stopped — at
/// a premature end-of-stream marker — with input left over.
pub struct LzmaDecodeOutcome {
    pub decoded_bytes: Vec<u8>,
    pub consumed_input_length: usize,
}

/// Decompress one xdelta3-flavored LZMA stream. On failure the
/// returned message carries the underlying cause verbatim — either
/// this module's own framing complaint or `lzma-rs`'s diagnostic —
/// for the caller to wrap as it sees fit.
pub fn lzma_decompress(input: &[u8]) -> Result<LzmaDecodeOutcome, String> {
    let framing_length = xz_framing_length(input)?;
    let chunk_bytes = &input[framing_length..];

    // Chain the synthetic end-of-stream marker after the real chunks.
    // The chain leaves the cursor inspectable afterwards: its position
    // is how far into the real chunks the decoder read, capped at the
    // chunk length when the decoder ran through to the synthetic
    // marker.
    let mut chunk_reader = Cursor::new(chunk_bytes).chain(&LZMA2_END_OF_STREAM[..]);
    let mut decoded_bytes = Vec::new();
    lzma_rs::lzma2_decompress(&mut chunk_reader, &mut decoded_bytes)
        .map_err(|cause| cause.to_string())?;
    let consumed_chunk_bytes = chunk_reader.get_ref().0.position() as usize;

    Ok(LzmaDecodeOutcome {
        decoded_bytes,
        consumed_input_length: framing_length + consumed_chunk_bytes,
    })
}

/// The byte count of the xz framing at the head of the stream: the
/// stream header plus the block header, whose first byte encodes its
/// own size as `(byte + 1) * 4`. Everything after is LZMA2 chunk data.
fn xz_framing_length(input: &[u8]) -> Result<usize, String> {
    if input.len() < XZ_STREAM_HEADER_LENGTH || input[..XZ_MAGIC.len()] != XZ_MAGIC {
        return Err("stream does not begin with an xz stream header".to_string());
    }
    let block_header_size_byte = *input
        .get(XZ_STREAM_HEADER_LENGTH)
        .ok_or_else(|| "stream ends inside its xz block header".to_string())?;
    let block_header_length = (block_header_size_byte as usize + 1) * 4;
    let framing_length = XZ_STREAM_HEADER_LENGTH + block_header_length;
    if input.len() < framing_length {
        return Err("stream ends inside its xz block header".to_string());
    }
    Ok(framing_length)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Both fixtures are unmodified xdelta3 output: the data-kind
    // stream of a one-window `-S lzma` patch, paired with the same
    // window's data section from the patch's `-S none` twin. The plain
    // section is the expected decode; the round-trip tests below check
    // they match.
    //
    // The first carries a single LZMA2 *uncompressed* chunk — control
    // byte 0x01, the literal bytes in the clear — which is what
    // liblzma emits when compression would not have paid.
    const XD3_UNCOMPRESSED_CHUNK_STREAM: [u8; 56] = [
        0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x00, 0xFF, 0x12, 0xD9, 0x41,
        0x02, 0x00, 0x21, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x8F, 0x98, 0x41, 0x9C,
        0x01, 0x00, 0x1C, 0x63, 0x6F, 0x72, 0x72, 0x65, 0x63, 0x74, 0x20, 0x68,
        0x6F, 0x72, 0x73, 0x65, 0x20, 0x62, 0x61, 0x74, 0x74, 0x65, 0x72, 0x79,
        0x20, 0x73, 0x74, 0x61, 0x70, 0x6C, 0x65, 0x20,
    ];
    const XD3_UNCOMPRESSED_CHUNK_PLAIN: &[u8] = b"correct horse battery staple ";

    // The second carries a real compressed chunk (control byte 0xE0):
    // 256 plain bytes carried as 233 stream bytes.
    const XD3_COMPRESSED_CHUNK_STREAM: [u8; 233] = [
        0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x00, 0xFF, 0x12, 0xD9, 0x41,
        0x02, 0x00, 0x21, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x8F, 0x98, 0x41, 0x9C,
        0xE0, 0x00, 0xFF, 0x00, 0xCA, 0x5D, 0x00, 0x21, 0x90, 0x04, 0x52, 0x59,
        0xF2, 0xD9, 0x13, 0x94, 0x15, 0x72, 0x05, 0x0B, 0xC8, 0x98, 0xDB, 0x60,
        0x4B, 0xBD, 0xFA, 0xAC, 0x39, 0xBF, 0x24, 0xEC, 0xAC, 0x55, 0xF8, 0x14,
        0xBB, 0x9C, 0xBA, 0xBD, 0x43, 0x73, 0x3E, 0x4E, 0x95, 0x63, 0x89, 0x84,
        0x67, 0xB8, 0x32, 0xC2, 0x95, 0xDD, 0x4E, 0xF9, 0x19, 0xB7, 0xC5, 0x83,
        0x05, 0xB1, 0xB9, 0x92, 0x7E, 0x63, 0x36, 0xF9, 0x72, 0x90, 0x75, 0x48,
        0xBB, 0x98, 0xF1, 0x70, 0x0B, 0x47, 0x2C, 0xEF, 0x3A, 0x2A, 0x59, 0xFD,
        0x9E, 0xB4, 0x7E, 0x7F, 0x41, 0x8E, 0x64, 0x7A, 0xB0, 0x9D, 0x95, 0x5F,
        0x48, 0x71, 0x74, 0x3B, 0x38, 0xD6, 0xD4, 0xE8, 0x1D, 0x09, 0x31, 0x19,
        0x9D, 0xE8, 0x7E, 0x9A, 0x84, 0xC7, 0xA8, 0xF1, 0xC6, 0x61, 0xAE, 0x88,
        0x17, 0x6B, 0x0C, 0x19, 0x91, 0x3E, 0x88, 0xEC, 0x57, 0x67, 0x57, 0x97,
        0x85, 0x6C, 0xD2, 0x08, 0x93, 0x74, 0xBC, 0x6B, 0x5F, 0xFC, 0x05, 0xF6,
        0x36, 0x55, 0x80, 0x76, 0x99, 0xE4, 0x05, 0x75, 0x48, 0x10, 0xB4, 0xE7,
        0x0E, 0x98, 0x59, 0x68, 0xC6, 0x37, 0x99, 0xF3, 0x34, 0xB3, 0x9B, 0xA2,
        0xC2, 0x46, 0x76, 0xAD, 0x1F, 0x9D, 0x77, 0x42, 0xA0, 0xD2, 0x70, 0x1B,
        0x4C, 0x6F, 0xB7, 0xA0, 0x1B, 0x01, 0xA1, 0xD2, 0xCB, 0x88, 0xD9, 0x21,
        0x2F, 0x7A, 0xDE, 0x84, 0x0D, 0x55, 0xF6, 0x8C, 0xAE, 0xE8, 0x39, 0xED,
        0xEF, 0x6E, 0x6E, 0x7A, 0x36,
    ];
    const XD3_COMPRESSED_CHUNK_PLAIN: [u8; 256] = [
        0x43, 0x40, 0x42, 0x43, 0x44, 0x4D, 0x40, 0x46, 0x43, 0x49, 0x4A, 0x46,
        0x4F, 0x45, 0x4B, 0x45, 0x49, 0x41, 0x40, 0x46, 0x45, 0x42, 0x4B, 0x4D,
        0x47, 0x47, 0x44, 0x42, 0x42, 0x41, 0x4A, 0x42, 0x44, 0x45, 0x42, 0x44,
        0x4A, 0x41, 0x43, 0x4F, 0x4C, 0x45, 0x45, 0x42, 0x49, 0x41, 0x40, 0x4A,
        0x45, 0x4D, 0x4E, 0x43, 0x48, 0x4E, 0x4C, 0x4A, 0x4F, 0x41, 0x4F, 0x48,
        0x4C, 0x41, 0x44, 0x4D, 0x44, 0x41, 0x43, 0x41, 0x43, 0x4D, 0x47, 0x48,
        0x48, 0x46, 0x41, 0x44, 0x42, 0x40, 0x47, 0x41, 0x4F, 0x44, 0x4E, 0x44,
        0x46, 0x48, 0x41, 0x4F, 0x47, 0x41, 0x4B, 0x4F, 0x41, 0x46, 0x4B, 0x49,
        0x43, 0x4F, 0x48, 0x4B, 0x4D, 0x47, 0x45, 0x46, 0x46, 0x4E, 0x4F, 0x4C,
        0x4D, 0x4C, 0x4E, 0x47, 0x43, 0x4F, 0x42, 0x49, 0x4D, 0x45, 0x49, 0x42,
        0x40, 0x46, 0x4A, 0x48, 0x4A, 0x4C, 0x43, 0x43, 0x47, 0x4E, 0x49, 0x42,
        0x41, 0x4B, 0x42, 0x40, 0x46, 0x44, 0x4F, 0x46, 0x49, 0x45, 0x4F, 0x4C,
        0x45, 0x41, 0x47, 0x4F, 0x4A, 0x4D, 0x4B, 0x46, 0x4A, 0x43, 0x49, 0x46,
        0x4C, 0x4F, 0x4B, 0x42, 0x4F, 0x4D, 0x4C, 0x4A, 0x48, 0x4B, 0x45, 0x44,
        0x4E, 0x45, 0x40, 0x4D, 0x4E, 0x40, 0x4B, 0x47, 0x47, 0x43, 0x4B, 0x48,
        0x49, 0x49, 0x4B, 0x46, 0x40, 0x46, 0x4A, 0x4F, 0x47, 0x46, 0x4A, 0x4E,
        0x4E, 0x42, 0x46, 0x4F, 0x48, 0x4E, 0x43, 0x44, 0x45, 0x44, 0x47, 0x41,
        0x46, 0x49, 0x43, 0x48, 0x4B, 0x4D, 0x49, 0x47, 0x4A, 0x49, 0x46, 0x4D,
        0x4D, 0x4E, 0x46, 0x40, 0x44, 0x42, 0x4F, 0x44, 0x41, 0x47, 0x4F, 0x40,
        0x46, 0x4F, 0x4D, 0x4F, 0x43, 0x42, 0x40, 0x4F, 0x49, 0x4C, 0x44, 0x49,
        0x4C, 0x42, 0x4D, 0x45, 0x4B, 0x4B, 0x4C, 0x43, 0x46, 0x4F, 0x49, 0x49,
        0x45, 0x4D, 0x40, 0x47,
    ];

    #[test]
    fn uncompressed_chunk_stream_round_trips() {
        let outcome = lzma_decompress(&XD3_UNCOMPRESSED_CHUNK_STREAM).expect("decodes");
        assert_eq!(outcome.decoded_bytes, XD3_UNCOMPRESSED_CHUNK_PLAIN);
        assert_eq!(outcome.consumed_input_length, XD3_UNCOMPRESSED_CHUNK_STREAM.len());
    }

    #[test]
    fn compressed_chunk_stream_round_trips() {
        let outcome = lzma_decompress(&XD3_COMPRESSED_CHUNK_STREAM).expect("decodes");
        assert_eq!(outcome.decoded_bytes, XD3_COMPRESSED_CHUNK_PLAIN);
        assert_eq!(outcome.consumed_input_length, XD3_COMPRESSED_CHUNK_STREAM.len());
    }

    #[test]
    fn premature_end_marker_surfaces_unconsumed_input() {
        // A real end-of-stream marker mid-input stops the decoder; the
        // trailing bytes register as unconsumed rather than decoded.
        let mut stream = XD3_UNCOMPRESSED_CHUNK_STREAM.to_vec();
        stream.push(0x00);
        stream.extend_from_slice(b"trailing");
        let outcome = lzma_decompress(&stream).expect("decodes up to the marker");
        assert_eq!(outcome.decoded_bytes, XD3_UNCOMPRESSED_CHUNK_PLAIN);
        assert_eq!(
            outcome.consumed_input_length,
            XD3_UNCOMPRESSED_CHUNK_STREAM.len() + 1
        );
    }

    #[test]
    fn truncated_chunk_errors() {
        let truncated = &XD3_COMPRESSED_CHUNK_STREAM[..XD3_COMPRESSED_CHUNK_STREAM.len() - 40];
        assert!(lzma_decompress(truncated).is_err());
    }

    #[test]
    fn missing_xz_header_errors() {
        assert!(lzma_decompress(b"").is_err());
        assert!(lzma_decompress(b"not an xz stream at all").is_err());
    }

    #[test]
    fn truncated_block_header_errors() {
        // A valid stream header whose block header claims more bytes
        // than the stream holds.
        let mut stream = XD3_UNCOMPRESSED_CHUNK_STREAM[..13].to_vec();
        stream[12] = 0xFF;
        assert!(lzma_decompress(&stream).is_err());
    }
}
