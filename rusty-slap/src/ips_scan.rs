//! IPS's diff-region finder: the two questions the region scan in
//! `Slap.IPS.Optimize` asks — from here, where do source and target next
//! differ, and where do they next agree?
//!
//! Positions run over the shared prefix alone: the files are compared only
//! where both have bytes, and target bytes past the source's end are the
//! caller's tail-extension region, never this module's business. Both
//! answers return the shared length when no such position exists.
//! Sibling of `ups_scan`, whose walk instead zero-pads past the source's
//! end — the one rule the two formats do not share.

/// The first position at or after `from`, within the shared prefix, where
/// source and target disagree.
pub fn next_difference(source: &[u8], target: &[u8], from: usize) -> usize {
    let shared_length = source.len().min(target.len());
    source[from..shared_length]
        .iter()
        .zip(&target[from..shared_length])
        .position(|(source_byte, target_byte)| source_byte != target_byte)
        .map_or(shared_length, |offset| from + offset)
}

/// The first position at or after `from`, within the shared prefix, where
/// source and target agree.
pub fn next_agreement(source: &[u8], target: &[u8], from: usize) -> usize {
    let shared_length = source.len().min(target.len());
    source[from..shared_length]
        .iter()
        .zip(&target[from..shared_length])
        .position(|(source_byte, target_byte)| source_byte == target_byte)
        .map_or(shared_length, |offset| from + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_are_found_and_bounded() {
        let source = [1u8, 2, 3, 4, 5];
        let target = [1u8, 9, 9, 4, 5];
        assert_eq!(next_difference(&source, &target, 0), 1);
        assert_eq!(next_agreement(&source, &target, 1), 3);
        assert_eq!(next_difference(&source, &target, 3), 5);
    }

    #[test]
    fn the_shared_prefix_is_the_whole_world() {
        let source = [7u8];
        let target = [7u8, 8, 9];
        assert_eq!(next_difference(&source, &target, 0), 1);
        assert_eq!(next_agreement(&source, &target, 1), 1);
    }
}
