//! Reading ZIP archives with the `zip` crate: list entry names, then
//! extract one entry by its central-directory index. Store and Deflate only,
//! the crate pinned to those to keep C codecs out.

use std::io::{Cursor, Read};

use zip::ZipArchive;
use zip::result::ZipError;

/// Entry names in central-directory order, each prefixed by its little-endian u32 byte length.
/// Length-prefixed rather than separated, so a NUL byte in a name is carried through, not mistaken for a boundary.
pub fn zip_entry_names(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut archive = ZipArchive::new(Cursor::new(input)).map_err(describe_zip_error)?;
    let mut joined = Vec::new();
    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index).map_err(describe_zip_error)?;
        let name = entry.name().as_bytes();
        joined.extend_from_slice(&(name.len() as u32).to_le_bytes());
        joined.extend_from_slice(name);
    }
    Ok(joined)
}

/// The decompressed bytes of the entry at the given central-directory index.
/// This matches the order 'zip_entry_names' returns, so the caller extracts by position and never round-trips a name.
pub fn zip_extract_entry_by_index(input: &[u8], index: usize) -> Result<Vec<u8>, String> {
    let mut archive = ZipArchive::new(Cursor::new(input)).map_err(describe_zip_error)?;
    let mut entry = archive.by_index(index).map_err(describe_zip_error)?;
    if entry.encrypted() {
        return Err("this entry is password-protected; slap cannot read encrypted archives".to_string());
    }
    // The central directory's size field is a declaration, not a
    // measurement; the vector grows as decompression produces bytes.
    let mut output = Vec::new();
    entry
        .read_to_end(&mut output)
        .map_err(|cause| format!("could not decompress the entry: {cause}"))?;
    Ok(output)
}

/// A reason that keeps encrypted and unsupported distinct from corrupt.
fn describe_zip_error(error: ZipError) -> String {
    match error {
        ZipError::InvalidArchive(message) => format!("not a valid ZIP archive: {message}"),
        ZipError::UnsupportedArchive(message) => {
            format!("this ZIP uses something slap does not support: {message}")
        }
        ZipError::FileNotFound => "the named entry is not present in the archive".to_string(),
        ZipError::Io(cause) => format!("error reading the archive: {cause}"),
        other => format!("{other}"),
    }
}
