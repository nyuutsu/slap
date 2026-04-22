// CRC-32 variant: CRC-32/ISO-HDLC — the zlib / PNG / PKZIP / gzip flavor,
// check value 0xCBF43926 against the input b"123456789". This is what every
// BPS tool in the ecosystem produces, including byuu's `beat` reference
// implementation, despite the BPS spec naming only "CRC32" without
// disambiguating the variant.
//
// We deliberately do not trial-fit other CRC-32 variants when a declared
// checksum fails to match. Unlike expanding accepted EBP JSON flavors —
// where being permissive costs nothing — CRC variant trial-fitting would
// muddy the one question the checksum exists to answer: is this patch
// corrupt, or not. See docs/bps/questions.md → "Which CRC-32 variant does
// BPS actually use?" for the long-form reasoning.

/// Compute CRC-32 via crc32fast (which uses hardware acceleration when available).
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}
