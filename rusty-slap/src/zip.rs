//! Reading ZIP archives: list entry names, then extract one entry.

use std::io::{Cursor, Read};

use zip::ZipArchive;
use zip::result::ZipError;

/// Entry names, NUL-terminated, read from the central directory.
pub fn zip_entry_names(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut archive = ZipArchive::new(Cursor::new(input)).map_err(describe)?;
    let mut joined = Vec::new();
    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index).map_err(describe)?;
        joined.extend_from_slice(entry.name().as_bytes());
        joined.push(0);
    }
    Ok(joined)
}

/// The decompressed bytes of the named entry.
pub fn zip_extract_entry(input: &[u8], entry_name: &str) -> Result<Vec<u8>, String> {
    let mut archive = ZipArchive::new(Cursor::new(input)).map_err(describe)?;
    let mut entry = archive.by_name(entry_name).map_err(describe)?;
    if entry.encrypted() {
        return Err(format!(
            "the entry \"{entry_name}\" is password-protected; slap cannot read encrypted archives"
        ));
    }
    let mut output = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut output)
        .map_err(|cause| format!("could not decompress the entry \"{entry_name}\": {cause}"))?;
    Ok(output)
}

/// A reason that keeps encrypted and unsupported distinct from corrupt.
fn describe(error: ZipError) -> String {
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
