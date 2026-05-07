//! FFI surface for slap. Each public function is a thin pipe over the
//! corresponding pure-Rust module: parse the caller's buffer pointers
//! into a slice, run the algorithm, surface the result back through the
//! caller's out-pointers. The two helpers [`view_caller_buffer`] and
//! [`surface_outcome_to_caller`] keep that shape uniform across the
//! decompression seam so each FFI body reads as one sentence.

mod bps_diff;
mod compress;
mod crc32;
mod suffix_sort;

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
/// allocates the output; caller frees with [`rusty_free`]. Returns 0
/// on success, -1 on compression error.
///
/// The level isn't exposed because no caller currently chooses one —
/// see [`compress::zlib_deflate`] for the spec rationale.
///
/// # Safety
/// - `input_address` must point to `input_length` readable bytes.
/// - All four out-pointers must be valid, aligned, and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_zlib_deflate(
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
            compress::zlib_deflate(input),
            output_address_pointer, output_length_pointer,
            error_address_pointer,  error_length_pointer,
        )
    }
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
