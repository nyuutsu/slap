/// Compute CRC-32 (standard reflected polynomial) using hardware acceleration
/// when available (CLMUL on x86, NEON on ARM).
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}
