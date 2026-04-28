mod bps_diff;
mod compress;
mod crc32;
mod suffix_sort;

/// CRC-32 with hardware acceleration via crc32fast.
///
/// # Safety
/// `data` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_crc32(data: *const u8, len: usize) -> u32 {
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    crc32::crc32(slice)
}

/// Compute BPS diff (action byte stream).
///
/// Rust allocates the output buffer.  On success, writes the pointer and
/// length into `out_ptr` / `out_len` and returns 0.  Caller frees with
/// `rusty_free`.
///
/// # Safety
/// - `source` must point to `source_len` readable bytes (or be non-null when `source_len == 0`).
/// - `target` must point to `target_len` readable bytes (or be non-null when `target_len == 0`).
/// - `out_ptr` and `out_len` must be valid, aligned, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_bps_diff(
    source: *const u8,
    source_len: usize,
    target: *const u8,
    target_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let src = if source_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(source, source_len) }
    };
    let tgt = if target_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(target, target_len) }
    };
    let result = bps_diff::bps_diff(src, tgt);
    unsafe { write_vec_to_ffi(result, out_ptr, out_len) };
    0
}

/// Free a buffer previously allocated by rusty-slap.
///
/// # Safety
/// `ptr` must have been returned by a rusty-slap function with the matching
/// `len`, or be null (in which case this is a no-op).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
        }
    }
}

/// Write a `Vec<u8>` into FFI output pointers.  Caller frees with `rusty_free`.
///
/// # Safety
/// `out_ptr` and `out_len` must be valid, aligned, writable pointers.
unsafe fn write_vec_to_ffi(v: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) {
    let len = v.len();
    if len == 0 {
        unsafe {
            *out_ptr = std::ptr::null_mut();
            *out_len = 0;
        }
        return;
    }
    let mut boxed = v.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
}

// ── Adler-32 FFI ───────────────────────────────────────────────────

/// Adler-32 checksum per RFC 1950.
///
/// # Safety
/// `data` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_adler32(data: *const u8, len: usize) -> u32 {
    let slice = if len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(data, len) } };
    let (a, b) = slice.iter().fold((1u32, 0u32), |(a, b), &byte| {
        let a = (a + byte as u32) % 65521;
        let b = (b + a) % 65521;
        (a, b)
    });
    (b << 16) | a
}

// ── Compression FFI ─────────────────────────────────────────────────

/// Zlib (RFC 1950) inflate.  Rust allocates the output; free with `rusty_free`.
/// Returns 0 on success, -1 on decompression error.
///
/// # Safety
/// - `src` must point to `src_len` readable bytes.
/// - `out_ptr` and `out_len` must be valid, aligned, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_zlib_inflate(
    src: *const u8,
    src_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let slice = if src_len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(src, src_len) } };
    match compress::zlib_inflate(slice) {
        Ok(v) => { unsafe { write_vec_to_ffi(v, out_ptr, out_len) }; 0 }
        Err(_) => -1,
    }
}

/// Zlib (RFC 1950) deflate.  Rust allocates the output; free with `rusty_free`.
/// Returns 0 on success, -1 on compression error.
///
/// # Safety
/// - `src` must point to `src_len` readable bytes.
/// - `out_ptr` and `out_len` must be valid, aligned, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_zlib_deflate(
    src: *const u8,
    src_len: usize,
    level: i32,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let slice = if src_len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(src, src_len) } };
    match compress::zlib_deflate(slice, level as u32) {
        Ok(v) => { unsafe { write_vec_to_ffi(v, out_ptr, out_len) }; 0 }
        Err(_) => -1,
    }
}

/// Gzip (RFC 1952) inflate.  Rust allocates the output; free with `rusty_free`.
/// Returns 0 on success, -1 on decompression error.
///
/// # Safety
/// - `src` must point to `src_len` readable bytes.
/// - `out_ptr` and `out_len` must be valid, aligned, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_gzip_inflate(
    src: *const u8,
    src_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let slice = if src_len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(src, src_len) } };
    match compress::gzip_inflate(slice) {
        Ok(v) => { unsafe { write_vec_to_ffi(v, out_ptr, out_len) }; 0 }
        Err(_) => -1,
    }
}

/// Bzip2 decompress.  Rust allocates the output; free with `rusty_free`.
/// Returns 0 on success, -1 on decompression error.
///
/// # Safety
/// - `src` must point to `src_len` readable bytes.
/// - `out_ptr` and `out_len` must be valid, aligned, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusty_bz2_decompress(
    src: *const u8,
    src_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let slice = if src_len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(src, src_len) } };
    match compress::bz2_decompress(slice) {
        Ok(v) => { unsafe { write_vec_to_ffi(v, out_ptr, out_len) }; 0 }
        Err(_) => -1,
    }
}
