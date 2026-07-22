//! Yay0 (Nintendo LZSS) decompression.
//!
//! Wire format (16-byte header followed by three interleaved streams):
//!   0x00..0x04 : "Yay0" magic
//!   0x04..0x08 : decompressed size      (u32 BE)
//!   0x08..0x0C : link table offset      (u32 BE)
//!   0x0C..0x10 : chunk data offset      (u32 BE)
//!   0x10..     : command bitstream
//!   link  ..   : link table (u16 BE entries)
//!   chunk ..   : literal / extended-count byte stream
//!
//! Each command bit (MSB first within each byte) is read in turn:
//!   bit = 1 : copy one literal byte from the chunk stream to output
//!   bit = 0 : read a u16 BE link entry; top nibble is the raw count
//!             field, low 12 bits are `distance - 1`. A count field of
//!             0 takes an additional byte from the chunk stream and
//!             yields `chunk_byte + 0x12`; any other value yields
//!             `count_field + 2`. The matched run is copied
//!             byte-by-byte out of the already-written output, since
//!             source and destination can overlap (RLE-style).
//!
//! The three streams advance independently: the algorithm treats the
//! header's link and chunk offsets as starting positions only and
//! places no upper bound on how far each cursor can travel into the
//! input. Each stream is therefore exhaustible on its own — a
//! malformed file can run any one of them off the end of the buffer
//! before the loop reaches the declared decompressed size. The
//! cursors below carry their stream's name so the resulting
//! diagnostic identifies which stream came up short.

// ── Public surface ─────────────────────────────────────────────────────

/// Yay0-decompress `input`. On success, the returned `Vec<u8>` has
/// length equal to the declared decompressed size from the header. On
/// failure, the returned message is the underlying cause verbatim —
/// the Haskell side wraps it as a typed `DecompressionCause`.
pub fn yay0_decompress(input: &[u8]) -> Result<Vec<u8>, String> {
    let header               = Yay0Header::parse(input)?;
    let mut command_bitstream = CommandBitstream::starting_at(input, 0x10);
    let mut chunk_stream     = ByteStreamCursor::new(input, header.chunk_offset, "chunk");
    let mut link_stream      = ByteStreamCursor::new(input, header.link_offset,  "link");
    // The header's decompressed size bounds the loop and the overflow
    // check below, but it is a declaration, not a measurement, and does
    // not earn an up-front allocation; the vector grows as bytes land.
    let mut decoded_output   = Vec::new();

    while decoded_output.len() < header.decompressed_size {
        if command_bitstream.pop_bit()? {
            decoded_output.push(chunk_stream.pop_byte()?);
        } else {
            let link_entry = LinkEntry(link_stream.pop_big_endian_u16()?);
            let copy_count = match link_entry.count_field() {
                0           => chunk_stream.pop_byte()? as usize + 0x12,
                count_field => count_field + 2,
            };
            if decoded_output.len() + copy_count > header.decompressed_size {
                return Err("output overflowed declared size".to_string());
            }
            back_copy_byte_by_byte(&mut decoded_output, link_entry.distance(), copy_count)?;
        }
    }

    Ok(decoded_output)
}

// ── Header ─────────────────────────────────────────────────────────────

/// Decoded and validated Yay0 header. Its three fields are all the
/// caller of [`yay0_decompress`] needs to drive the main loop; parsing
/// is split out so header errors are produced by a single function
/// with a single concern.
struct Yay0Header {
    decompressed_size: usize,
    link_offset:       usize,
    chunk_offset:      usize,
}

impl Yay0Header {
    fn parse(input: &[u8]) -> Result<Self, String> {
        if input.len() < 16 {
            return Err("truncated header".to_string());
        }
        if &input[0..4] != b"Yay0" {
            return Err("bad magic".to_string());
        }
        let header = Yay0Header {
            decompressed_size: read_big_endian_u32_at(input,  4) as usize,
            link_offset:       read_big_endian_u32_at(input,  8) as usize,
            chunk_offset:      read_big_endian_u32_at(input, 12) as usize,
        };
        if header.decompressed_size == 0 {
            return Err("invalid decompressed size: 0".to_string());
        }
        if header.link_offset > input.len() {
            return Err(format!(
                "the compressed data is corrupt: it points past the end of the file (link offset 0x{:x}, file {} bytes)",
                header.link_offset, input.len()
            ));
        }
        if header.chunk_offset > input.len() {
            return Err(format!(
                "the compressed data is corrupt: it points past the end of the file (chunk offset 0x{:x}, file {} bytes)",
                header.chunk_offset, input.len()
            ));
        }
        Ok(header)
    }
}

fn read_big_endian_u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

// ── Stream cursors ─────────────────────────────────────────────────────

/// A cursor over one of Yay0's byte-oriented input streams (link
/// table or chunk data). Carries `stream_name` so an exhaustion error
/// reads as "link stream exhausted ..." or "chunk stream exhausted
/// ..." — the diagnostic names which of the three concurrent streams
/// ran dry first.
struct ByteStreamCursor<'input> {
    bytes:       &'input [u8],
    position:    usize,
    stream_name: &'static str,
}

impl<'input> ByteStreamCursor<'input> {
    fn new(bytes: &'input [u8], starting_position: usize, stream_name: &'static str) -> Self {
        ByteStreamCursor { bytes, position: starting_position, stream_name }
    }

    fn pop_byte(&mut self) -> Result<u8, String> {
        let byte = *self.bytes.get(self.position).ok_or_else(|| self.exhausted_error())?;
        self.position += 1;
        Ok(byte)
    }

    fn pop_big_endian_u16(&mut self) -> Result<u16, String> {
        if self.position + 2 > self.bytes.len() {
            return Err(self.exhausted_error());
        }
        let value = u16::from_be_bytes([self.bytes[self.position], self.bytes[self.position + 1]]);
        self.position += 2;
        Ok(value)
    }

    fn exhausted_error(&self) -> String {
        format!("{} stream exhausted before output buffer filled", self.stream_name)
    }
}

/// A cursor over the command bitstream, which sits at byte 0x10 of
/// the input and is consumed MSB-first within each byte. Layered over
/// a byte cursor so the underlying out-of-bounds diagnostic flows
/// through the same channel as the link/chunk streams.
struct CommandBitstream<'input> {
    underlying_bytes: ByteStreamCursor<'input>,
    bit_index:        u32,
}

impl<'input> CommandBitstream<'input> {
    fn starting_at(bytes: &'input [u8], starting_position: usize) -> Self {
        CommandBitstream {
            underlying_bytes: ByteStreamCursor::new(bytes, starting_position, "command"),
            bit_index:        7,
        }
    }

    fn pop_bit(&mut self) -> Result<bool, String> {
        let command_byte = *self.underlying_bytes.bytes
            .get(self.underlying_bytes.position)
            .ok_or_else(|| self.underlying_bytes.exhausted_error())?;
        let bit_value = (command_byte >> self.bit_index) & 1 != 0;
        if self.bit_index == 0 {
            self.underlying_bytes.position += 1;
            self.bit_index                  = 7;
        } else {
            self.bit_index -= 1;
        }
        Ok(bit_value)
    }
}

// ── Link entry ─────────────────────────────────────────────────────────

/// A raw u16 link entry pulled from the link table, with the wire
/// vocabulary surfaced as accessors. A `count_field` of 0 signals to
/// the caller that an additional byte must be taken from the chunk
/// stream to determine the true run length.
struct LinkEntry(u16);

impl LinkEntry {
    fn count_field(&self) -> usize { (self.0 >> 12) as usize }
    fn distance(&self)    -> usize { ((self.0 & 0xFFF) + 1) as usize }
}

// ── Back-copy ──────────────────────────────────────────────────────────

/// Copy `count` bytes out of the live output buffer at offset
/// `output.len() - distance`, one byte at a time. Byte-by-byte is
/// not an optimization deficit — it's load-bearing: when the run
/// extends past the original write head, later reads see bytes that
/// were pushed during this very call, producing the RLE behavior the
/// format relies on (e.g., distance=1, count=N fills N copies of the
/// previous byte).
fn back_copy_byte_by_byte(output: &mut Vec<u8>, distance: usize, count: usize) -> Result<(), String> {
    if distance > output.len() {
        return Err(format!(
            "back-reference distance {} exceeds written {}",
            distance, output.len()
        ));
    }
    let read_base = output.len() - distance;
    for offset_within_run in 0..count {
        let byte = output[read_base + offset_within_run];
        output.push(byte);
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Yay0 blob: 16-byte header + caller-supplied tail.
    fn yay0_blob(
        decompressed_size: u32,
        link_offset:       u32,
        chunk_offset:      u32,
        tail:              &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16 + tail.len());
        bytes.extend_from_slice(b"Yay0");
        bytes.extend_from_slice(&decompressed_size.to_be_bytes());
        bytes.extend_from_slice(&link_offset.to_be_bytes());
        bytes.extend_from_slice(&chunk_offset.to_be_bytes());
        bytes.extend_from_slice(tail);
        bytes
    }

    #[test]
    fn five_literals_round_trip() {
        // Command 0b11111000 — five 1-bits drive five literal copies;
        // the remaining bits never get consumed because the loop exits
        // as soon as five bytes have been written.
        let blob = yay0_blob(
            5, 0x11, 0x11,
            &[0xF8,  b'H', b'e', b'l', b'l', b'o'],
        );
        assert_eq!(yay0_decompress(&blob).unwrap(), b"Hello");
    }

    #[test]
    fn back_reference_round_trip() {
        // Output "ABABAB": two literals 'A','B', then a back-reference
        // with count_field=2 (raw count 4) and distance 2 that copies
        // "ABAB" byte-by-byte from the live output buffer.
        let link_high   = 0x20u8;
        let link_low    = 0x01u8;
        let command     = 0b11000000u8;
        let blob = yay0_blob(
            6, 0x11, 0x13,
            &[command,  link_high, link_low,  b'A', b'B'],
        );
        assert_eq!(yay0_decompress(&blob).unwrap(), b"ABABAB");
    }

    #[test]
    fn extended_count_back_reference() {
        // count_field=0 takes an extra byte from the chunk stream:
        // extra=0 → count=0x12 (18). One literal 'A' seeds the buffer,
        // then 18 back-copies at distance 1 produce a run of 19 'A's.
        let link_high = 0x00u8;
        let link_low  = 0x00u8;
        let command   = 0b10000000u8;
        let blob = yay0_blob(
            19, 0x11, 0x13,
            &[command,  link_high, link_low,  b'A', 0x00],
        );
        assert_eq!(yay0_decompress(&blob).unwrap(), vec![b'A'; 19]);
    }

    #[test]
    fn truncated_header_errors() {
        assert_eq!(yay0_decompress(&[]).unwrap_err(), "truncated header");
        assert_eq!(yay0_decompress(&[0u8; 15]).unwrap_err(), "truncated header");
    }

    #[test]
    fn bad_magic_errors() {
        let mut blob = yay0_blob(5, 0x11, 0x11, &[0u8; 8]);
        blob[3] = b'1';
        assert_eq!(yay0_decompress(&blob).unwrap_err(), "bad magic");
    }

    #[test]
    fn zero_decompressed_size_errors() {
        let blob = yay0_blob(0, 0x10, 0x10, &[]);
        assert_eq!(yay0_decompress(&blob).unwrap_err(), "invalid decompressed size: 0");
    }

    #[test]
    fn link_offset_beyond_file_errors() {
        let blob = yay0_blob(1, 0xFFFF_FFFF, 0x10, &[0u8; 4]);
        assert!(yay0_decompress(&blob).unwrap_err().contains("link offset"));
    }

    #[test]
    fn chunk_offset_beyond_file_errors() {
        let blob = yay0_blob(1, 0x10, 0xFFFF_FFFF, &[0u8; 4]);
        assert!(yay0_decompress(&blob).unwrap_err().contains("chunk offset"));
    }

    #[test]
    fn back_reference_with_nothing_written_errors() {
        // First command bit is 0 → immediately tries a back-reference
        // before any bytes have been written. Distance 1, but output
        // is empty, so the distance > output.len() guard fires.
        let blob = yay0_blob(
            4, 0x11, 0x13,
            &[0b00000000u8,  0x10, 0x00,  0xAA, 0xBB],
        );
        let err = yay0_decompress(&blob).unwrap_err();
        assert!(err.starts_with("back-reference distance"),
                "unexpected error: {err}");
    }

    #[test]
    fn back_reference_overshooting_declared_size_errors() {
        // Declared size 3: literal 'A', then a back-ref with raw count
        // 4 (count_field=2) — overruns the declared output.
        let blob = yay0_blob(
            3, 0x11, 0x13,
            &[0b10000000u8,  0x20, 0x00,  b'A'],
        );
        assert_eq!(
            yay0_decompress(&blob).unwrap_err(),
            "output overflowed declared size",
        );
    }

    #[test]
    fn command_stream_exhausted_from_header_only_input() {
        // Header-only input with nonzero declared size: validation
        // passes (link/chunk offsets are inside the file), the loop
        // starts, and the very first command-byte read at 0x10 finds
        // input.len() == 16. Smallest input that reaches the guard.
        let blob = yay0_blob(1, 0, 0, &[]);
        assert_eq!(
            yay0_decompress(&blob).unwrap_err(),
            "command stream exhausted before output buffer filled",
        );
    }

    #[test]
    fn command_stream_exhausted_from_overlapping_sections() {
        // Adversarial 17-byte input: one command byte (0xFF) tells the
        // decoder to take eight literals. chunk_offset = 0 sends those
        // reads into the header itself — legal per the algorithm,
        // which gives the chunk stream no upper bound. After eight
        // ops, command_position == 0x11 == input.len(), and the ninth
        // iteration's command-byte read fires the exhaustion guard
        // ahead of any other stream.
        let blob = yay0_blob(9, 0x10, 0, &[0xFF]);
        assert_eq!(
            yay0_decompress(&blob).unwrap_err(),
            "command stream exhausted before output buffer filled",
        );
    }
}
