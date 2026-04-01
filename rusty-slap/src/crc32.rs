/// Compute CRC-32 via crc32fast (which uses hardware acceleration when available).
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}
