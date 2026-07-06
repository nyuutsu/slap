//! FFI surface for slap. Each public function is a thin pipe over the
//! corresponding pure-Rust module: parse the caller's buffer pointers
//! into a slice, run the algorithm, surface the result back through the
//! caller's out-pointers. The two helpers [`view_caller_buffer`] and
//! [`surface_outcome_to_caller`] keep that shape uniform across the
//! decompression seam so each FFI body reads as one sentence.

mod bps_diff;
mod bps_hash_chain;
mod compress;
mod crc32;
mod vcdiff_diff;
mod vcdiff_hash_chain;
mod xdelta1_diff;
mod xdelta1_hash_chain;
mod xdelta3_djw;
mod xdelta3_fgk;
mod xdelta3_lzma;
mod yay0;
mod zip;

// ── Boundary helpers ──────────────────────────────────────────────────

/// View a caller-provided buffer as a Rust slice. The empty case is
/// handled explicitly so a null pointer with `length == 0` is legal —
/// matching Haskell's `ByteString.empty`, whose pointer is unspecified.
///
/// # Safety
/// `address` must point to `length` readable bytes, or `length` must be 0.
unsafe fn view_caller_buffer<'a>(address: *const u8, length: usize) -> &'a [u8] {
    if length == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(address, length) }
    }
}

/// Hand a Rust-owned `Vec<u8>` across the FFI seam. The buffer's heap
/// allocation is forgotten on the Rust side; the caller becomes its
/// owner and must free it via [`rusty_free`] with the matching length.
/// An empty `Vec` writes a null address and zero length — the canonical
/// "no buffer" pair on the receiving side.
///
/// # Safety
/// `address_pointer` and `length_pointer` must be valid, aligned,
/// writable pointers.
unsafe fn surface_buffer_to_caller(
    buffer_contents: Vec<u8>,
    address_pointer: *mut *mut u8,
    length_pointer: *mut usize,
) {
    let byte_count = buffer_contents.len();
    if byte_count == 0 {
        unsafe {
            *address_pointer = std::ptr::null_mut();
            *length_pointer  = 0;
        }
        return;
    }
    let mut owned_buffer = buffer_contents.into_boxed_slice();
    let buffer_address   = owned_buffer.as_mut_ptr();
    std::mem::forget(owned_buffer);
    unsafe {
        *address_pointer = buffer_address;
        *length_pointer  = byte_count;
    }
}

/// Package a `Result<Vec<u8>, String>` from a decompression or
/// compression entry point into the caller's two channels: bytes flow
/// through `output_*` on success, the underlying library's diagnostic
/// flows through `error_*` on failure, and the unused channel is
/// written empty for tidiness either way. Returns 0 on success, -1 on
/// failure — the FFI status-code convention shared across the seam.
///
/// # Safety
/// All four pointers must be valid, aligned, and writable.
unsafe fn surface_outcome_to_caller(
    outcome: Result<Vec<u8>, String>,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
    error_address_pointer:  *mut *mut u8,
    error_length_pointer:   *mut usize,
) -> i32 {
    match outcome {
        Ok(output_bytes) => {
            unsafe {
                surface_buffer_to_caller(output_bytes, output_address_pointer, output_length_pointer);
                surface_buffer_to_caller(Vec::new(),   error_address_pointer,  error_length_pointer);
            }
            0
        }
        Err(cause_message) => {
            unsafe {
                surface_buffer_to_caller(Vec::new(),                output_address_pointer, output_length_pointer);
                surface_buffer_to_caller(cause_message.into_bytes(), error_address_pointer,  error_length_pointer);
            }
            -1
        }
    }
}

// ── Checksum FFI ──────────────────────────────────────────────────────

/// CRC-32 (CRC-32/ISO-HDLC variant — the zlib / PNG / PKZIP / gzip
/// flavor). See [`crc32::crc32`] for the variant rationale.
///
/// # Safety
/// `input_address` must point to `input_length` readable bytes (or may
/// be null when `input_length == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_crc32(input_address: *const u8, input_length: usize) -> u32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    crc32::crc32(input)
}

/// Adler-32 checksum per RFC 1950. Folds the byte stream through the
/// two running sums named in the spec: `byte_sum` (the byte-modular
/// running total) and `cumulative_sum` (the running total of every
/// `byte_sum` value). The packed wire form is `cumulative_sum << 16 |
/// byte_sum`.
///
/// # Safety
/// `input_address` must point to `input_length` readable bytes (or may
/// be null when `input_length == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_adler32(input_address: *const u8, input_length: usize) -> u32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    let (byte_sum, cumulative_sum) = input.iter().fold((1u32, 0u32), |(byte_sum, cumulative_sum), &byte| {
        let next_byte_sum       = (byte_sum + byte as u32) % 65521;
        let next_cumulative_sum = (cumulative_sum + next_byte_sum) % 65521;
        (next_byte_sum, next_cumulative_sum)
    });
    (cumulative_sum << 16) | byte_sum
}

// ── BPS diff FFI ──────────────────────────────────────────────────────

/// Compute the BPS action stream for a (source, target) pair. Rust
/// allocates the output; caller frees with [`rusty_free`].
///
/// Returns 0 unconditionally — the BPS diff itself is total. The `i32`
/// slot mirrors the FFI status-code shape used by every other rusty
/// function; keeping it uniform means the Haskell side imports every
/// FFI export with the same return-type discipline.
///
/// # Safety
/// - `source_address` must point to `source_length` readable bytes (or
///   may be null when `source_length == 0`).
/// - `target_address` must point to `target_length` readable bytes (or
///   may be null when `target_length == 0`).
/// - `output_address_pointer` and `output_length_pointer` must be
///   valid, aligned, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_bps_diff(
    source_address:         *const u8,
    source_length:          usize,
    target_address:         *const u8,
    target_length:          usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
) -> i32 {
    let source = unsafe { view_caller_buffer(source_address, source_length) };
    let target = unsafe { view_caller_buffer(target_address, target_length) };
    let action_stream = bps_diff::bps_diff(source, target);
    unsafe { surface_buffer_to_caller(action_stream, output_address_pointer, output_length_pointer) };
    0
}

// ── xdelta1 diff FFI ──────────────────────────────────────────────────

/// Compute an xdelta1 diff. Returns 0 on success (all six output
/// buffers + one offset-mode byte populated; `error_cause` null).
/// Returns -1 on failure (all output buffers null; `error_cause`
/// carries the cause string). All caller-owned buffers must be
/// freed via [`rusty_free`].
///
/// The instruction stream is returned as three parallel homogeneous
/// arrays — one byte per `instruction_target` (0 = data source, 1 =
/// file source); one `u64` LE per `instruction_source_offset`; one
/// `u64` LE per `instruction_length`. The three arrays share length
/// N (= the instruction count); the byte counts on the offset and
/// length buffers are 8N.
///
/// The `file_source_offset_mode` byte encodes the differ's choice
/// for the file-source's per-instruction-offset encoding: 0 =
/// absolute, 1 = sequential. The Haskell side decodes the byte
/// into `Slap.XDelta1.Types.XDelta1OffsetMode` directly.
///
/// # Safety
/// All buffer pointers follow rusty-slap's existing convention (see
/// [`view_caller_buffer`] / [`surface_buffer_to_caller`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_xdelta1_diff(
    source_address:                              *const u8,
    source_length:                               usize,
    target_address:                              *const u8,
    target_length:                               usize,
    instruction_targets_address_pointer:         *mut *mut u8,
    instruction_targets_length_pointer:          *mut usize,
    instruction_source_offsets_address_pointer:  *mut *mut u8,
    instruction_source_offsets_length_pointer:   *mut usize,
    instruction_lengths_address_pointer:         *mut *mut u8,
    instruction_lengths_length_pointer:          *mut usize,
    data_segment_address_pointer:                *mut *mut u8,
    data_segment_length_pointer:                 *mut usize,
    file_source_offset_mode_pointer:             *mut u8,
    error_cause_address_pointer:                 *mut *mut u8,
    error_cause_length_pointer:                  *mut usize,
) -> i32 {
    let source = unsafe { view_caller_buffer(source_address, source_length) };
    let target = unsafe { view_caller_buffer(target_address, target_length) };
    match xdelta1_diff::xdelta1_diff(source, target) {
        Ok(diff) => {
            let (targets, source_offsets, lengths) = split_to_parallel_arrays(&diff.instructions);
            unsafe {
                surface_buffer_to_caller(targets,           instruction_targets_address_pointer,        instruction_targets_length_pointer);
                surface_buffer_to_caller(source_offsets,    instruction_source_offsets_address_pointer, instruction_source_offsets_length_pointer);
                surface_buffer_to_caller(lengths,           instruction_lengths_address_pointer,        instruction_lengths_length_pointer);
                surface_buffer_to_caller(diff.data_segment, data_segment_address_pointer,               data_segment_length_pointer);
                *file_source_offset_mode_pointer = match diff.file_source_offset_mode {
                    xdelta1_diff::FileSourceOffsetMode::Absolute   => 0,
                    xdelta1_diff::FileSourceOffsetMode::Sequential => 1,
                };
                surface_buffer_to_caller(Vec::new(), error_cause_address_pointer, error_cause_length_pointer);
            }
            0
        }
        Err(cause_message) => {
            unsafe {
                surface_buffer_to_caller(Vec::new(), instruction_targets_address_pointer,        instruction_targets_length_pointer);
                surface_buffer_to_caller(Vec::new(), instruction_source_offsets_address_pointer, instruction_source_offsets_length_pointer);
                surface_buffer_to_caller(Vec::new(), instruction_lengths_address_pointer,        instruction_lengths_length_pointer);
                surface_buffer_to_caller(Vec::new(), data_segment_address_pointer,               data_segment_length_pointer);
                *file_source_offset_mode_pointer = 0;
                surface_buffer_to_caller(cause_message.into_bytes(), error_cause_address_pointer, error_cause_length_pointer);
            }
            -1
        }
    }
}

/// Project an [`xdelta1_diff::XDelta1DiffOutput`]'s instruction vec
/// into three parallel homogeneous byte buffers — one per field. The
/// inverse split happens on the Haskell side in `Slap.XDelta1.FFI`.
fn split_to_parallel_arrays(
    instructions: &[xdelta1_diff::Instruction],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let instruction_count    = instructions.len();
    let mut targets          = Vec::with_capacity(instruction_count);
    let mut source_offsets   = Vec::with_capacity(instruction_count * 8);
    let mut lengths          = Vec::with_capacity(instruction_count * 8);
    for instruction in instructions {
        targets.push(match instruction.target {
            xdelta1_diff::InstructionTarget::DataSource => 0,
            xdelta1_diff::InstructionTarget::FileSource => 1,
        });
        source_offsets.extend_from_slice(&instruction.source_offset.to_le_bytes());
        lengths.extend_from_slice(&instruction.length.to_le_bytes());
    }
    (targets, source_offsets, lengths)
}

// ── VCDIFF cover FFI ──────────────────────────────────────────────────

/// Compute the per-window VCDIFF covers for a (source, target) pair —
/// the greedy segmentation of each `window_length`-byte slice of the
/// target (final slice the remainder; the empty target one empty
/// window) into copies and literals. `window_length` must be positive;
/// a caller wanting one window over everything passes the target's
/// length (or more). Rust allocates the four output arrays; the caller
/// frees each with [`rusty_free`].
///
/// Returns 0 unconditionally — the covers are total (every input
/// yields them). The `i32` slot keeps the FFI return-type discipline
/// uniform with [`rusty_bps_diff`].
///
/// The covers cross as three parallel homogeneous arrays sharing the
/// total segment count N — one `kind` byte per segment (0 = literal,
/// 1 = copy); one `u64` LE `offset` per segment (window-relative: a
/// copy's offset into `source ++ that window's slice`, a literal's
/// offset into the slice); one `u64` LE `length` per segment — plus a
/// fourth array of one `u64` LE segment count per window, in window
/// order, which is how the caller splits the flat stream back into
/// covers. The offset and length buffers are 8N bytes.
///
/// # Safety
/// Buffer pointers follow rusty-slap's existing convention (see
/// [`view_caller_buffer`] / [`surface_buffer_to_caller`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_vcdiff_cover(
    source_address:                *const u8,
    source_length:                 usize,
    target_address:                *const u8,
    target_length:                 usize,
    window_length:                 usize,
    kinds_address_pointer:         *mut *mut u8,
    kinds_length_pointer:          *mut usize,
    offsets_address_pointer:       *mut *mut u8,
    offsets_length_pointer:        *mut usize,
    lengths_address_pointer:       *mut *mut u8,
    lengths_length_pointer:        *mut usize,
    window_counts_address_pointer: *mut *mut u8,
    window_counts_length_pointer:  *mut usize,
) -> i32 {
    let source = unsafe { view_caller_buffer(source_address, source_length) };
    let target = unsafe { view_caller_buffer(target_address, target_length) };
    let covers = vcdiff_diff::vcdiff_windowed_covers(source, target, window_length);
    let (kinds, offsets, lengths, window_counts) = split_covers_to_parallel_arrays(&covers);
    unsafe {
        surface_buffer_to_caller(kinds,         kinds_address_pointer,         kinds_length_pointer);
        surface_buffer_to_caller(offsets,       offsets_address_pointer,       offsets_length_pointer);
        surface_buffer_to_caller(lengths,       lengths_address_pointer,       lengths_length_pointer);
        surface_buffer_to_caller(window_counts, window_counts_address_pointer, window_counts_length_pointer);
    }
    0
}

/// Project per-window covers into three parallel homogeneous byte
/// buffers — one `kind` byte, one LE `u64` offset, and one LE `u64`
/// length per segment, all windows concatenated in order — plus the
/// per-window segment counts (one LE `u64` each) the flat stream is
/// split back by. The inverse happens on the Haskell side in
/// `Slap.VCDIFF.FFI`. Sibling to [`split_to_parallel_arrays`].
fn split_covers_to_parallel_arrays(
    covers: &[Vec<vcdiff_diff::CoverSegment>],
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let segment_count: usize = covers.iter().map(Vec::len).sum();
    let mut kinds         = Vec::with_capacity(segment_count);
    let mut offsets       = Vec::with_capacity(segment_count * 8);
    let mut lengths       = Vec::with_capacity(segment_count * 8);
    let mut window_counts = Vec::with_capacity(covers.len() * 8);
    for cover in covers {
        window_counts.extend_from_slice(&(cover.len() as u64).to_le_bytes());
        for segment in cover {
            kinds.push(match segment.kind {
                vcdiff_diff::SegmentKind::Literal => 0,
                vcdiff_diff::SegmentKind::Copy    => 1,
            });
            offsets.extend_from_slice(&segment.offset.to_le_bytes());
            lengths.extend_from_slice(&segment.length.to_le_bytes());
        }
    }
    (kinds, offsets, lengths, window_counts)
}

// ── Free ──────────────────────────────────────────────────────────────

/// Free a buffer previously surfaced by a rusty-slap function.
///
/// # Safety
/// `buffer_address` must have been returned by a rusty-slap function
/// with the matching `buffer_length`, or be null (in which case this
/// is a no-op).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_free(buffer_address: *mut u8, buffer_length: usize) {
    if !buffer_address.is_null() && buffer_length > 0 {
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(buffer_address, buffer_length)));
        }
    }
}

// ── Compression FFI ───────────────────────────────────────────────────

/// Zlib (RFC 1950) inflate. Rust allocates the output; caller frees
/// with [`rusty_free`]. Returns 0 on success, -1 on decompression
/// error — the cause message flows through the error channel.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes.
/// - All four out-pointers must be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_zlib_inflate(
    input_address:          *const u8,
    input_length:           usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
    error_address_pointer:  *mut *mut u8,
    error_length_pointer:   *mut usize,
) -> i32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    unsafe {
        surface_outcome_to_caller(
            compress::zlib_inflate(input),
            output_address_pointer, output_length_pointer,
            error_address_pointer,  error_length_pointer,
        )
    }
}

/// Zlib (RFC 1950) deflate at the library default level. Rust
/// allocates the output; caller frees with [`rusty_free`]. No error
/// channel: zlib-deflate of in-memory bytes is total at the algorithm
/// level (mirror of [`rusty_gzip_deflate`]), and allocation failure
/// aborts the process before any value reaches the caller.
///
/// The level isn't exposed because no caller currently chooses one —
/// see [`compress::zlib_deflate`] for the spec rationale.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes.
/// - `output_address_pointer` and `output_length_pointer` must be
///   valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_zlib_deflate(
    input_address:          *const u8,
    input_length:           usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
) {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    let compressed = compress::zlib_deflate(input);
    unsafe { surface_buffer_to_caller(compressed, output_address_pointer, output_length_pointer) };
}

/// Gzip (RFC 1952) inflate. Rust allocates the output; caller frees
/// with [`rusty_free`]. Returns 0 on success, -1 on decompression
/// error.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes.
/// - All four out-pointers must be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_gzip_inflate(
    input_address:          *const u8,
    input_length:           usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
    error_address_pointer:  *mut *mut u8,
    error_length_pointer:   *mut usize,
) -> i32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    unsafe {
        surface_outcome_to_caller(
            compress::gzip_inflate(input),
            output_address_pointer, output_length_pointer,
            error_address_pointer,  error_length_pointer,
        )
    }
}

/// Gzip (RFC 1952) deflate at the library default level. Rust
/// allocates the output; caller frees with [`rusty_free`]. No error
/// channel: gzip-deflate of in-memory bytes is total at the
/// algorithm level, and allocation failure aborts the process before
/// any value reaches the caller.
///
/// `mtime` in the gzip header is pinned to 0 (see
/// [`compress::gzip_deflate`]) so the same input bytes always
/// produce the same compressed bytes — required for the round-trip
/// re-emit identity property in 'Slap.XDelta1.Create'.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes.
/// - `output_address_pointer` and `output_length_pointer` must be
///   valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_gzip_deflate(
    input_address:          *const u8,
    input_length:           usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
) {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    let compressed = compress::gzip_deflate(input);
    unsafe { surface_buffer_to_caller(compressed, output_address_pointer, output_length_pointer) };
}

/// Bzip2 decompress. Rust allocates the output; caller frees with
/// [`rusty_free`]. Returns 0 on success, -1 on decompression error.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes.
/// - All four out-pointers must be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_bzip2_decompress(
    input_address:          *const u8,
    input_length:           usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
    error_address_pointer:  *mut *mut u8,
    error_length_pointer:   *mut usize,
) -> i32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    unsafe {
        surface_outcome_to_caller(
            compress::bzip2_decompress(input),
            output_address_pointer, output_length_pointer,
            error_address_pointer,  error_length_pointer,
        )
    }
}

/// LZMA decompression of one xdelta3-flavored stream (xz header, raw
/// LZMA2 chunks, no closing footer — see [`xdelta3_lzma`]). Rust allocates
/// the output; caller frees with [`rusty_free`]. Returns 0 on success
/// (output and consumed-input-length populated; error channel empty),
/// -1 on decoder fault (output empty, consumed 0, cause message in
/// the error channel). The consumed length is a fact only the decoder
/// can know — whether it honors the framing the stream was carried
/// under is the caller's judgment, made on the other side of the seam.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes (or
///   may be null when `input_length == 0`).
/// - `consumed_length_pointer` and the four buffer out-pointers must
///   be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_lzma_decompress(
    input_address:           *const u8,
    input_length:            usize,
    output_address_pointer:  *mut *mut u8,
    output_length_pointer:   *mut usize,
    consumed_length_pointer: *mut usize,
    error_address_pointer:   *mut *mut u8,
    error_length_pointer:    *mut usize,
) -> i32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    match xdelta3_lzma::lzma_decompress(input) {
        Ok(outcome) => {
            unsafe {
                surface_buffer_to_caller(outcome.decoded_bytes, output_address_pointer, output_length_pointer);
                *consumed_length_pointer = outcome.consumed_input_length;
                surface_buffer_to_caller(Vec::new(), error_address_pointer, error_length_pointer);
            }
            0
        }
        Err(cause_message) => {
            unsafe {
                surface_buffer_to_caller(Vec::new(), output_address_pointer, output_length_pointer);
                *consumed_length_pointer = 0;
                surface_buffer_to_caller(cause_message.into_bytes(), error_address_pointer, error_length_pointer);
            }
            -1
        }
    }
}

/// LZMA compression of one buffer into one xdelta3-flavored stream
/// (xz header, sync-flushed LZMA2 chunks, no closing marker — see
/// [`xdelta3_lzma`]): the write-side partner of
/// [`rusty_lzma_decompress`]. Rust allocates the output; caller frees
/// with [`rusty_free`]. No error channel: compression of in-memory
/// bytes is total at the algorithm level (mirror of
/// [`rusty_gzip_deflate`]), and allocation failure aborts the process
/// before any value reaches the caller.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes (or
///   may be null when `input_length == 0`).
/// - `output_address_pointer` and `output_length_pointer` must be
///   valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_lzma_compress(
    input_address:          *const u8,
    input_length:           usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
) {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    let compressed = xdelta3_lzma::lzma_compress(input);
    unsafe { surface_buffer_to_caller(compressed, output_address_pointer, output_length_pointer) };
}

/// LZMA compression of one kind's sections into one continuous
/// xdelta3-flavored stream, sync-flushed at every section boundary and
/// never finished (see [`xdelta3_lzma::lzma_compress_sections`]): the
/// write-side seam the multi-window emitter drives. Sections cross as
/// a concatenated buffer plus `section_count` per-section lengths (the
/// [`rusty_fgk_decompress`] convention); back come the stream bytes
/// and one `u64` LE piece-end offset per section, which is how the
/// caller slices the stream into per-window pieces. Rust allocates
/// both outputs; caller frees each with [`rusty_free`]. No error
/// channel: compression of in-memory bytes is total at the algorithm
/// level (mirror of [`rusty_lzma_compress`]).
///
/// # Safety
/// - `sections_address` must point to `sections_length` readable bytes
///   (or may be null when `sections_length == 0`).
/// - `section_lengths_address` must point to `section_count` readable
///   `usize` values (or may be null when `section_count == 0`), and
///   they must sum to `sections_length`.
/// - The four out-pointers must be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_lzma_compress_sections(
    sections_address:        *const u8,
    sections_length:         usize,
    section_lengths_address: *const usize,
    section_count:           usize,
    stream_address_pointer:  *mut *mut u8,
    stream_length_pointer:   *mut usize,
    cuts_address_pointer:    *mut *mut u8,
    cuts_length_pointer:     *mut usize,
) {
    let concatenated = unsafe { view_caller_buffer(sections_address, sections_length) };
    let section_lengths = if section_count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(section_lengths_address, section_count) }
    };
    let mut sections = Vec::with_capacity(section_count);
    let mut consumed = 0;
    for &section_length in section_lengths {
        sections.push(&concatenated[consumed..consumed + section_length]);
        consumed += section_length;
    }
    let outcome = xdelta3_lzma::lzma_compress_sections(&sections);
    let mut cut_bytes = Vec::with_capacity(outcome.piece_end_offsets.len() * 8);
    for piece_end in &outcome.piece_end_offsets {
        cut_bytes.extend_from_slice(&(*piece_end as u64).to_le_bytes());
    }
    unsafe {
        surface_buffer_to_caller(outcome.stream_bytes, stream_address_pointer, stream_length_pointer);
        surface_buffer_to_caller(cut_bytes,            cuts_address_pointer,   cuts_length_pointer);
    }
}

/// DJW decompression of one xdelta3 secondary-compressed section
/// (xdelta3's own static multi-table Huffman — see [`xdelta3_djw`]). The
/// expected output length crosses as an argument: it is the decode
/// loop's terminus, not a framing fact. Rust allocates the output;
/// caller frees with [`rusty_free`]. Returns 0 on success (output and
/// consumed-input-length populated; error channel empty), -1 on
/// decoder fault (output empty, consumed 0, cause message in the
/// error channel).
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes (or
///   may be null when `input_length == 0`).
/// - `consumed_length_pointer` and the four buffer out-pointers must
///   be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_djw_decompress(
    input_address:           *const u8,
    input_length:            usize,
    expected_output_length:  usize,
    output_address_pointer:  *mut *mut u8,
    output_length_pointer:   *mut usize,
    consumed_length_pointer: *mut usize,
    error_address_pointer:   *mut *mut u8,
    error_length_pointer:    *mut usize,
) -> i32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    match xdelta3_djw::djw_decompress(input, expected_output_length) {
        Ok(outcome) => {
            unsafe {
                surface_buffer_to_caller(outcome.decoded_bytes, output_address_pointer, output_length_pointer);
                *consumed_length_pointer = outcome.consumed_input_length;
                surface_buffer_to_caller(Vec::new(), error_address_pointer, error_length_pointer);
            }
            0
        }
        Err(cause_message) => {
            unsafe {
                surface_buffer_to_caller(Vec::new(), output_address_pointer, output_length_pointer);
                *consumed_length_pointer = 0;
                surface_buffer_to_caller(cause_message.into_bytes(), error_address_pointer, error_length_pointer);
            }
            -1
        }
    }
}

/// DJW compression of one section (xdelta3's static multi-table
/// Huffman — see [`xdelta3_djw`]): the write-side partner of
/// [`rusty_djw_decompress`]. Rust allocates the output; caller frees
/// with [`rusty_free`]. No error channel: compression of in-memory
/// bytes is total at the algorithm level (mirror of
/// [`rusty_lzma_compress`]), and allocation failure aborts the process
/// before any value reaches the caller.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes (or
///   may be null when `input_length == 0`).
/// - `output_address_pointer` and `output_length_pointer` must be
///   valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_djw_compress(
    input_address:          *const u8,
    input_length:           usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
) {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    let compressed = xdelta3_djw::djw_compress(input);
    unsafe { surface_buffer_to_caller(compressed, output_address_pointer, output_length_pointer) };
}

/// FGK decompression of one kind's gathered secondary-compressed
/// sections (xdelta3's adaptive Huffman, "for demonstration purposes
/// only" — see [`xdelta3_fgk`]). Unlike DJW, the sections share one
/// tree: `input` is the kind's section streams concatenated in order,
/// and `section_output_lengths_address` points to `section_count`
/// declared output sizes, one per section, that bound each section's
/// decode and realign the reader between them. Rust allocates the
/// output (all sections' decoded bytes concatenated); caller frees with
/// [`rusty_free`]. Returns 0 on success (output and consumed-input-
/// length populated; error channel empty), -1 on decoder fault (output
/// empty, consumed 0, cause message in the error channel). Named for
/// its possible sibling `rusty_fgk_compress`.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes (or
///   may be null when `input_length == 0`).
/// - `section_output_lengths_address` must point to `section_count`
///   readable `usize` values (or may be null when `section_count == 0`).
/// - `consumed_length_pointer` and the four buffer out-pointers must
///   be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_fgk_decompress(
    input_address:                   *const u8,
    input_length:                    usize,
    section_output_lengths_address:  *const usize,
    section_count:                   usize,
    output_address_pointer:          *mut *mut u8,
    output_length_pointer:           *mut usize,
    consumed_length_pointer:         *mut usize,
    error_address_pointer:           *mut *mut u8,
    error_length_pointer:            *mut usize,
) -> i32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    let section_output_lengths = if section_count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(section_output_lengths_address, section_count) }
    };
    match xdelta3_fgk::fgk_decompress_sections(input, section_output_lengths) {
        Ok(outcome) => {
            unsafe {
                surface_buffer_to_caller(outcome.decoded_bytes, output_address_pointer, output_length_pointer);
                *consumed_length_pointer = outcome.consumed_input_length;
                surface_buffer_to_caller(Vec::new(), error_address_pointer, error_length_pointer);
            }
            0
        }
        Err(cause_message) => {
            unsafe {
                surface_buffer_to_caller(Vec::new(), output_address_pointer, output_length_pointer);
                *consumed_length_pointer = 0;
                surface_buffer_to_caller(cause_message.into_bytes(), error_address_pointer, error_length_pointer);
            }
            -1
        }
    }
}

/// Yay0 (Nintendo LZSS) decompression. Rust allocates the output;
/// caller frees with [`rusty_free`]. Returns 0 on success, -1 on
/// decompression error — the cause message flows through the error
/// channel.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes.
/// - All four out-pointers must be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_yay0_decompress(
    input_address:          *const u8,
    input_length:           usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
    error_address_pointer:  *mut *mut u8,
    error_length_pointer:   *mut usize,
) -> i32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    unsafe {
        surface_outcome_to_caller(
            yay0::yay0_decompress(input),
            output_address_pointer, output_length_pointer,
            error_address_pointer,  error_length_pointer,
        )
    }
}

/// List a ZIP's entry names, NUL-terminated. Rust allocates the output;
/// caller frees with [`rusty_free`]. Returns 0 on success, -1 on failure —
/// the cause flows through the error channel.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes.
/// - All four out-pointers must be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_zip_entry_names(
    input_address:          *const u8,
    input_length:           usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
    error_address_pointer:  *mut *mut u8,
    error_length_pointer:   *mut usize,
) -> i32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    unsafe {
        surface_outcome_to_caller(
            zip::zip_entry_names(input),
            output_address_pointer, output_length_pointer,
            error_address_pointer,  error_length_pointer,
        )
    }
}

/// Extract one named entry's decompressed bytes from a ZIP. The name is a
/// UTF-8 byte range. Rust allocates the output; caller frees with
/// [`rusty_free`]. Returns 0 on success, -1 on failure — the cause flows
/// through the error channel.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes.
/// - `name_address` must point to `name_length` readable bytes.
/// - All four out-pointers must be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_zip_extract_entry(
    input_address:          *const u8,
    input_length:           usize,
    name_address:           *const u8,
    name_length:            usize,
    output_address_pointer: *mut *mut u8,
    output_length_pointer:  *mut usize,
    error_address_pointer:  *mut *mut u8,
    error_length_pointer:   *mut usize,
) -> i32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    let name_bytes = unsafe { view_caller_buffer(name_address, name_length) };
    let outcome = match std::str::from_utf8(name_bytes) {
        Ok(entry_name) => zip::zip_extract_entry(input, entry_name),
        Err(_) => Err("the requested entry name was not valid UTF-8".to_string()),
    };
    unsafe {
        surface_outcome_to_caller(
            outcome,
            output_address_pointer, output_length_pointer,
            error_address_pointer,  error_length_pointer,
        )
    }
}
