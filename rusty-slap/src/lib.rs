//! FFI surface for slap. Each public function is a thin pipe over the
//! corresponding pure-Rust module: parse the caller's buffer pointers
//! into a slice, run the algorithm, surface the result back through the
//! caller's out-pointers. The two helpers [`view_caller_buffer`] and
//! [`surface_outcome_to_caller`] keep that shape uniform across the
//! decompression seam so each FFI body reads as one sentence.

mod bps_diff;
mod bps_suffix_sort;
mod compress;
mod crc32;
mod xdelta1_diff;
mod xdelta1_suffix_array;
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
/// `input_address` must point to `input_length` readable bytes (or be
/// non-null when `input_length == 0`).
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
/// `input_address` must point to `input_length` readable bytes (or be
/// non-null when `input_length == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_adler32(input_address: *const u8, input_length: usize) -> u32 {
    let input = unsafe { view_caller_buffer(input_address, input_length) };
    let (byte_sum, cumulative_sum) = input.iter().fold((1u32, 0u32), |(byte_sum, cumulative_sum), &byte| {
        let byte_sum       = (byte_sum + byte as u32) % 65521;
        let cumulative_sum = (cumulative_sum + byte_sum) % 65521;
        (byte_sum, cumulative_sum)
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
///   be non-null when `source_length == 0`).
/// - `target_address` must point to `target_length` readable bytes (or
///   be non-null when `target_length == 0`).
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
