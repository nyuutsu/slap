//! The LZMA streams xdelta3 carries: reading the shape xd3 emits, and
//! writing that same shape back.
//!
//! xdelta3's LZMA secondary compressor is liblzma writing an xz/LZMA2
//! stream (`LZMA_FILTER_LZMA2`, check=none) that it never finishes:
//! the bytes begin with an ordinary xz stream header and block header,
//! continue as raw LZMA2 chunks, and then simply stop — no end-of-
//! stream chunk marker, no index, no stream footer, because the
//! encoder keeps the stream open across the patch's windows and dies
//! with it unfinished. The unfinished shape is load-bearing, not a
//! habit: both framings a section decode is held to (xd3's
//! `xd3_decode_secondary` and slap's own) demand the whole stream
//! consumed and exactly the declared size produced, and a finished
//! stream's closing structures would sit past that stop as unconsumed
//! input. So [`lzma_compress`] emits exactly this shape, ending on a
//! sync flush.
//!
//! For reading, the caller hands this module one such stream, gathered
//! whole; this module owns the two adaptations the shape demands:
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
//! not this module's. The one exception sits before the decode: the
//! chunk headers' declared sizes are held to the caller's ceiling
//! ([`hold_chunk_declarations_to_ceiling`]), so a stream declaring
//! more output than its framing never decompresses at all.

use std::io::{Cursor, Read};

// ── Decompression ──────────────────────────────────────────────────────

/// The xz stream header: the 6-byte magic, 2 bytes of stream flags,
/// and a 4-byte CRC32 of the flags. The flags only name the block
/// check type, and a check never arrives in an unfinished stream, so
/// nothing past the magic needs reading — the header is verified by
/// its magic and walked past whole.
const XZ_STREAM_HEADER_LENGTH: usize = 12;

/// The xz stream magic.
const XZ_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];

/// The LZMA2 end-of-stream chunk marker this module chains after the
/// input (a single zero control byte).
const LZMA2_END_OF_STREAM: [u8; 1] = [0x00];

/// What one decompression produced: the decoded bytes, and how many
/// bytes of the caller's input the decoder consumed before it
/// finished. Consumption counts the xz framing as consumed; a
/// shortfall against the input length means the decoder stopped — at
/// a premature end-of-stream marker — with input left over.
#[derive(Debug)]
pub struct LzmaDecodeOutcome {
    pub decoded_bytes: Vec<u8>,
    pub consumed_input_length: usize,
}

/// Decompress one xdelta3-flavored LZMA stream. `declared_output_length`
/// is the output total the carrying framing declared: not the decode's
/// terminus — the chunk headers declare their own sizes — but the ceiling
/// those declarations are held to before any chunk decodes. On failure
/// the returned message carries the underlying cause verbatim — either
/// this module's own complaint or `lzma-rs`'s diagnostic — for the
/// caller to wrap as it sees fit.
pub fn lzma_decompress(
    input: &[u8],
    declared_output_length: usize,
) -> Result<LzmaDecodeOutcome, String> {
    let framing_length = xz_framing_length(input)?;
    let chunk_bytes = &input[framing_length..];
    hold_chunk_declarations_to_ceiling(chunk_bytes, declared_output_length)?;

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

/// Hold the chunk headers' declared unpacked sizes to the output total
/// the carrying framing declared. The chunk framing is readable without
/// decoding anything, and a chunk decodes to at most the size its header
/// declares, so the running sum bounds the whole decode's output — and a
/// high-ratio stream declaring more than its framing does is refused
/// before a byte of it decompresses. No write-side bound could do the
/// same: `lzma-rs` buffers the entire output before its sink sees any
/// of it. The walk judges nothing else — a malformed status byte, a
/// truncated header, or a chunk running off the input's end all stop it
/// early, leaving the decoder's own diagnostics to speak.
fn hold_chunk_declarations_to_ceiling(
    chunk_bytes: &[u8],
    declared_output_length: usize,
) -> Result<(), String> {
    // The sum runs in u64: on a 32-bit target the declarations can
    // outgrow a usize before the ceiling check fires.
    let mut declared_total: u64 = 0;
    let mut position: usize = 0;
    loop {
        let Some(&status_byte) = chunk_bytes.get(position) else { return Ok(()) };
        let (unpacked_size, chunk_stride) = match status_byte {
            // The end-of-stream marker.
            0x00 => return Ok(()),
            // An uncompressed chunk: u16 BE `size - 1`, then the bytes in the clear.
            0x01 | 0x02 => {
                let Some(header) = chunk_bytes.get(position + 1..position + 3) else { return Ok(()) };
                let unpacked_size = u16::from_be_bytes([header[0], header[1]]) as u64 + 1;
                (unpacked_size, 3 + unpacked_size as usize)
            }
            // No chunk starts with 0x03..=0x7F.
            0x03..=0x7F => return Ok(()),
            // A compressed chunk: the status byte's low five bits extend the u16 BE unpacked size,
            // then a u16 BE packed size, then a properties byte when bits 5–6 say properties reset.
            _ => {
                let Some(header) = chunk_bytes.get(position + 1..position + 5) else { return Ok(()) };
                let unpacked_size = ((u64::from(status_byte) & 0x1F) << 16
                    | u16::from_be_bytes([header[0], header[1]]) as u64) + 1;
                let packed_size = u16::from_be_bytes([header[2], header[3]]) as usize + 1;
                let properties_byte_length = usize::from((status_byte >> 5) & 0x3 >= 2);
                (unpacked_size, 5 + properties_byte_length + packed_size)
            }
        };
        declared_total += unpacked_size;
        if declared_total > declared_output_length as u64 {
            return Err(format!(
                "the chunks declare {declared_total} or more output bytes where the framing declares {declared_output_length}"
            ));
        }
        position += chunk_stride;
    }
}

// ── Compression ────────────────────────────────────────────────────────

/// The LZMA2 preset the encoder runs at: the middle of the range and
/// xz's own default level. Fixed here rather than exposed — no caller
/// turns a level knob today.
const ENCODING_PRESET: u32 = 6;

/// One kind's sections compressed as the continuous stream
/// [`lzma_decompress`] reads back, with the cut positions that split
/// it into per-section pieces. The first piece begins at offset 0 and
/// carries the xz framing; every later piece is a bare continuation
/// slice, exactly the carriage the decode side gathers back together.
pub struct LzmaSectionStream {
    pub stream_bytes: Vec<u8>,
    /// End offset of each section's piece within `stream_bytes`, one
    /// per section, ascending; the last equals the stream's length.
    pub piece_end_offsets: Vec<usize>,
}

/// Compress a kind's sections, in window order, into one
/// xdelta3-flavored stream: the xz stream and block headers, then
/// LZMA2 chunks sync-flushed at every section boundary and never
/// finished (see the module header for why the end-of-stream marker
/// must not be written). One encoder runs the whole stream, so the
/// dictionary persists across sections — a later window's section
/// compresses against everything before it, which is most of why the
/// gathered stream beats per-section streams.
///
/// Total: any sections compress, the empty list included (its stream
/// is the bare framing, with no pieces to cut). The writer sinks into
/// a `Vec`, which cannot raise an I/O error, so an `Err` from the
/// encoder would mean an encoder bug; the `expect`s die loudly on one.
pub fn lzma_compress_sections(sections: &[&[u8]]) -> LzmaSectionStream {
    use std::io::Write;

    let total_length: usize = sections.iter().map(|section| section.len()).sum();
    let mut options = lzma_rust2::Lzma2Options::with_preset(ENCODING_PRESET);
    // A dictionary reaching past the whole stream's input buys nothing,
    // so it shrinks to the sections' combined length (floored at the
    // format's minimum) and the decoder's allocation shrinks with it.
    // The block header rounds back up to the nearest encodable size, so
    // the decoder always allocates at least what the encoder used.
    options.lzma_options.dict_size = (total_length as u64)
        .clamp(
            u64::from(lzma_rust2::DICT_SIZE_MIN),
            u64::from(options.lzma_options.dict_size),
        ) as u32;
    let dictionary_size = options.lzma_options.dict_size;

    // The sink starts as the framing bytes, so chunk output appends
    // straight after them and every cut offset is already
    // stream-absolute.
    let mut writer = lzma_rust2::Lzma2Writer::new(xz_framing(dictionary_size), options);
    let mut piece_end_offsets = Vec::with_capacity(sections.len());
    for section in sections {
        writer
            .write_all(section)
            .expect("xdelta3_lzma: LZMA2 encoder failed on an in-memory sink");
        writer
            .flush()
            .expect("xdelta3_lzma: LZMA2 encoder failed to flush on an in-memory sink");
        piece_end_offsets.push(writer.inner().len());
    }
    LzmaSectionStream {
        stream_bytes: writer.into_inner(),
        piece_end_offsets,
    }
}

/// Compress one plain buffer into a stream of its own: the one-section
/// reading of [`lzma_compress_sections`].
pub fn lzma_compress(plain: &[u8]) -> Vec<u8> {
    lzma_compress_sections(&[plain]).stream_bytes
}

/// The xz stream header and block header that open a stream: the same
/// 24 bytes `xz_framing_length` walks past on the way in. The stream
/// flags declare check=none — xd3's own choice, and an unfinished
/// stream never reaches where a check would live — and the block
/// header names the single LZMA2 filter with the dictionary's
/// property byte.
fn xz_framing(dictionary_size: u32) -> Vec<u8> {
    let stream_flags = [0x00, 0x00]; // second byte 0x00: check = none
    let block_header = [
        0x02, // block header size: (0x02 + 1) * 4 = 12 bytes, itself included
        0x00, // block flags: one filter, no optional size fields
        0x21, // filter id: LZMA2
        0x01, // filter properties length
        dictionary_property_byte(dictionary_size),
        0x00, // header padding
        0x00,
        0x00,
    ];

    let mut framing = Vec::with_capacity(XZ_STREAM_HEADER_LENGTH + block_header.len() + 4);
    framing.extend_from_slice(&XZ_MAGIC);
    framing.extend_from_slice(&stream_flags);
    framing.extend_from_slice(&crate::crc32::crc32(&stream_flags).to_le_bytes());
    framing.extend_from_slice(&block_header);
    framing.extend_from_slice(&crate::crc32::crc32(&block_header).to_le_bytes());
    framing
}

/// The xz one-byte dictionary-size encoding: the smallest property
/// value whose decoded size holds at least `dictionary_size`, so a
/// decoder sizing its dictionary from the header never allocates less
/// than the encoder used. Property values 0–39 decode as
/// `(2 | (v & 1)) << (v / 2 + 11)`; 40, the encoding's ceiling, names
/// 4 GiB − 1 and is unreachable here (`lzma_compress` caps the
/// dictionary at the preset's 8 MiB).
fn dictionary_property_byte(dictionary_size: u32) -> u8 {
    (0..=39)
        .find(|&property| decoded_dictionary_size(property) >= dictionary_size)
        .unwrap_or(40)
}

/// The dictionary size an xz property byte in 0–39 decodes to.
fn decoded_dictionary_size(property: u8) -> u32 {
    (2 | u32::from(property & 1)) << (property / 2 + 11)
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
        let outcome = lzma_decompress(&XD3_UNCOMPRESSED_CHUNK_STREAM, XD3_UNCOMPRESSED_CHUNK_PLAIN.len()).expect("decodes");
        assert_eq!(outcome.decoded_bytes, XD3_UNCOMPRESSED_CHUNK_PLAIN);
        assert_eq!(outcome.consumed_input_length, XD3_UNCOMPRESSED_CHUNK_STREAM.len());
    }

    #[test]
    fn compressed_chunk_stream_round_trips() {
        let outcome = lzma_decompress(&XD3_COMPRESSED_CHUNK_STREAM, XD3_COMPRESSED_CHUNK_PLAIN.len()).expect("decodes");
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
        let outcome = lzma_decompress(&stream, XD3_UNCOMPRESSED_CHUNK_PLAIN.len()).expect("decodes up to the marker");
        assert_eq!(outcome.decoded_bytes, XD3_UNCOMPRESSED_CHUNK_PLAIN);
        assert_eq!(
            outcome.consumed_input_length,
            XD3_UNCOMPRESSED_CHUNK_STREAM.len() + 1
        );
    }

    #[test]
    fn truncated_chunk_errors() {
        let truncated = &XD3_COMPRESSED_CHUNK_STREAM[..XD3_COMPRESSED_CHUNK_STREAM.len() - 40];
        assert!(lzma_decompress(truncated, XD3_COMPRESSED_CHUNK_PLAIN.len()).is_err());
    }

    #[test]
    fn missing_xz_header_errors() {
        assert!(lzma_decompress(b"", 0).is_err());
        assert!(lzma_decompress(b"not an xz stream at all", 0).is_err());
    }

    #[test]
    fn truncated_block_header_errors() {
        // A valid stream header whose block header claims more bytes
        // than the stream holds.
        let mut stream = XD3_UNCOMPRESSED_CHUNK_STREAM[..13].to_vec();
        stream[12] = 0xFF;
        assert!(lzma_decompress(&stream, XD3_UNCOMPRESSED_CHUNK_PLAIN.len()).is_err());
    }

    #[test]
    fn chunks_declaring_past_the_framing_are_refused_undecoded() {
        // A megabyte of one byte compresses to a handful of chunks whose
        // headers still declare the megabyte; a framing declaring one
        // byte less must be refused by the header walk, before any
        // chunk decodes.
        let plain = vec![0x42u8; 1 << 20];
        let stream = lzma_compress(&plain);
        let refusal = lzma_decompress(&stream, plain.len() - 1).unwrap_err();
        assert!(
            refusal.contains("where the framing declares"),
            "unexpected error: {refusal}",
        );
    }

    // ── The compression half ──────────────────────────────────────────

    /// SplitMix64, matching the house pseudo-random helper.
    fn pseudo_random_bytes(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state.wrapping_add(0x9e3779b97f4a7c15);
                let mut mixed = state;
                mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d049bb133111eb);
                mixed ^= mixed >> 31;
                mixed as u8
            })
            .collect()
    }

    /// Round-trip pins the whole contract at once: the decoded bytes
    /// match, and the decoder consumes the entire stream — the two
    /// verdicts every section framing (xd3's and slap's) holds a
    /// decode to. Lengths span a single chunk up to well past the
    /// 64 KiB compressed-chunk ceiling, and alphabets span
    /// tightly-compressible to incompressible.
    #[test]
    fn compressed_streams_round_trip_fully_consumed() {
        let cases: &[(u64, usize, u8)] = &[
            (0x01, 1, 4),            // single byte
            (0x02, 29, 255),         // short and incompressible
            (0x03, 4 << 10, 3),      // a few KiB, tiny alphabet
            (0x04, 300 << 10, 16),   // hundreds of KiB: several chunks
            (0x05, 1 << 20, 64),     // a MiB of middling entropy
        ];
        for &(seed, length, alphabet) in cases {
            let plain: Vec<u8> = pseudo_random_bytes(seed, length)
                .into_iter()
                .map(|byte| byte % alphabet)
                .collect();
            let stream = lzma_compress(&plain);
            let outcome = lzma_decompress(&stream, plain.len()).expect("compressed stream decodes");
            assert_eq!(outcome.decoded_bytes, plain, "seed {seed:#x}");
            assert_eq!(
                outcome.consumed_input_length,
                stream.len(),
                "seed {seed:#x}: the stream must decode with nothing left over",
            );
        }
    }

    /// Every stream prefix ending at a cut decodes to exactly the
    /// sections written up to that cut, fully consumed: the cuts land
    /// on chunk boundaries, and the dictionary carries across them.
    /// This is the same walk the window emitter's pieces take through
    /// a decoder, prefix by prefix.
    #[test]
    fn section_stream_prefixes_decode_to_their_sections() {
        let sections: Vec<Vec<u8>> = vec![
            pseudo_random_bytes(0xA1, 30_000).into_iter().map(|byte| byte % 8).collect(),
            pseudo_random_bytes(0xA2, 10),
            pseudo_random_bytes(0xA3, 80_000).into_iter().map(|byte| byte % 8).collect(),
        ];
        let section_slices: Vec<&[u8]> = sections.iter().map(Vec::as_slice).collect();
        let outcome = lzma_compress_sections(&section_slices);
        assert_eq!(outcome.piece_end_offsets.len(), sections.len());
        assert_eq!(
            *outcome.piece_end_offsets.last().expect("three pieces"),
            outcome.stream_bytes.len(),
        );
        let mut expected = Vec::new();
        for (index, section) in sections.iter().enumerate() {
            expected.extend_from_slice(section);
            let prefix = &outcome.stream_bytes[..outcome.piece_end_offsets[index]];
            let decoded = lzma_decompress(prefix, expected.len()).expect("a cut prefix decodes");
            assert_eq!(decoded.decoded_bytes, expected, "prefix {index}");
            assert_eq!(
                decoded.consumed_input_length,
                prefix.len(),
                "prefix {index} must decode with nothing left over",
            );
        }
    }

    /// The chunk region must stop at a sync flush, not an end-of-stream
    /// marker: decoding it raw — without the synthetic marker
    /// `lzma_decompress` chains on — must therefore fail at end of
    /// input. A finished stream would decode cleanly here, and its
    /// marker would strand every byte after it as unconsumed input on
    /// the reading side.
    #[test]
    fn compressed_chunks_end_unterminated() {
        let plain = pseudo_random_bytes(0xF105, 2048);
        let stream = lzma_compress(&plain);
        let framing_length = xz_framing_length(&stream).expect("framing walks");
        let mut chunk_reader = Cursor::new(&stream[framing_length..]);
        let mut decoded = Vec::new();
        assert!(
            lzma_rs::lzma2_decompress(&mut chunk_reader, &mut decoded).is_err(),
            "the chunk region carried an end-of-stream marker",
        );
    }

    /// The empty buffer compresses to the bare framing and reads back
    /// empty: the function is total, though slap never compresses an
    /// empty section (a compressed section must declare a positive
    /// decompressed size).
    #[test]
    fn empty_input_round_trips_as_bare_framing() {
        let stream = lzma_compress(b"");
        assert_eq!(stream.len(), XZ_STREAM_HEADER_LENGTH + 12);
        let outcome = lzma_decompress(&stream, 0).expect("bare framing decodes");
        assert!(outcome.decoded_bytes.is_empty());
        assert_eq!(outcome.consumed_input_length, stream.len());
    }

    /// The property byte always rounds up: the decoded size holds at
    /// least the requested dictionary, and the next-smaller property
    /// (where one exists) does not.
    #[test]
    fn dictionary_property_byte_rounds_up_minimally() {
        for dict_size in [4096, 4097, 65536, 100_000, 1 << 20, 8 << 20] {
            let property = dictionary_property_byte(dict_size);
            assert!(decoded_dictionary_size(property) >= dict_size, "{dict_size}");
            if property > 0 {
                assert!(
                    decoded_dictionary_size(property - 1) < dict_size,
                    "{dict_size}: property {property} is not minimal",
                );
            }
        }
    }

    /// Many small, low-entropy sections, flushed apart, must
    /// round-trip byte-for-byte: the gathered stream shares one
    /// dictionary across sync flushes, and what it emits must decode
    /// back exactly.
    #[test]
    fn low_entropy_sections_round_trip_across_flushes() {
        for seed in 1..=5u64 {
            let whole: Vec<u8> = pseudo_random_bytes(seed, 99_000)
                .into_iter()
                .map(|byte| byte % 4)
                .collect();
            let sections: Vec<&[u8]> = whole.chunks(3_000).collect();
            let outcome = lzma_compress_sections(&sections);
            let decoded = lzma_decompress(&outcome.stream_bytes, whole.len())
                .expect("the gathered stream decodes");
            assert_eq!(
                decoded.decoded_bytes, whole,
                "seed {seed}: decoded bytes must match the input across flushes",
            );
            assert_eq!(
                decoded.consumed_input_length,
                outcome.stream_bytes.len(),
                "seed {seed}: the stream must decode with nothing left over",
            );
        }
    }
}
