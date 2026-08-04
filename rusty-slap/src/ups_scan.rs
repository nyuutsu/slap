//! UPS's run finder: the two questions the block walk in `Slap.UPS.Create`
//! asks at every turn — from here, where do source and target next differ,
//! and where do they next agree?
//!
//! Positions run over the target alone. A source byte past the source's own
//! end reads as zero — the same virtual padding the format's XOR stream
//! assumes — so past the shared prefix a difference is any non-zero target
//! byte, and an agreement is any zero. Both answers return `target.len()`
//! when no such position exists: the walk's natural end sentinel, and the
//! "phantom terminator" position the Haskell side already documents.

/// The first position at or after `from` where source and target disagree.
pub fn next_difference(source: &[u8], target: &[u8], from: usize) -> usize {
    let shared_length = source.len().min(target.len());
    if from < shared_length {
        if let Some(offset) = source[from..shared_length]
            .iter()
            .zip(&target[from..shared_length])
            .position(|(source_byte, target_byte)| source_byte != target_byte)
        {
            return from + offset;
        }
    }
    let beyond_source = from.max(shared_length);
    match target[beyond_source..].iter().position(|&target_byte| target_byte != 0) {
        Some(offset) => beyond_source + offset,
        None => target.len(),
    }
}

/// The first position at or after `from` where source and target agree.
pub fn next_agreement(source: &[u8], target: &[u8], from: usize) -> usize {
    let shared_length = source.len().min(target.len());
    if from < shared_length {
        if let Some(offset) = source[from..shared_length]
            .iter()
            .zip(&target[from..shared_length])
            .position(|(source_byte, target_byte)| source_byte == target_byte)
        {
            return from + offset;
        }
    }
    let beyond_source = from.max(shared_length);
    match target[beyond_source..].iter().position(|&target_byte| target_byte == 0) {
        Some(offset) => beyond_source + offset,
        None => target.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_are_found_and_bounded() {
        let source = [1u8, 2, 3, 4, 5];
        let target = [1u8, 9, 9, 4, 5];
        assert_eq!(next_difference(&source, &target, 0), 1);
        assert_eq!(next_agreement(&source, &target, 1), 3);
        assert_eq!(next_difference(&source, &target, 3), 5);
    }

    #[test]
    fn past_the_source_zero_is_agreement() {
        let source = [7u8];
        let target = [7u8, 0, 8, 0];
        assert_eq!(next_difference(&source, &target, 0), 2);
        assert_eq!(next_agreement(&source, &target, 2), 3);
    }

    #[test]
    fn a_tail_run_ends_at_the_phantom_position() {
        let source = [1u8, 2];
        let target = [1u8, 9];
        assert_eq!(next_difference(&source, &target, 0), 1);
        assert_eq!(next_agreement(&source, &target, 1), 2);
    }
}
