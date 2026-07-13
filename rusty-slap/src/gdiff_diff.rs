//! GDIFF differ. Takes source bytes and target bytes; produces a
//! [`GDiffDiffOutput`] containing the commands and data segment that,
//! applied to the source, reproduce the target. Emits
//! [`CommandKind::Copy`] for spans of target that match some region of
//! source and [`CommandKind::Data`] for bytes that didn't match
//! (accumulated into the data segment).
//!
//! The matcher is a source hash-chain finder (see
//! [`crate::gdiff_hash_chain`]) queried once per target position. The
//! walk is greedy: at each position, take the match the finder offers,
//! otherwise accumulate one literal byte and advance. The finder owns
//! the shortest-match floor, the wire-cost gate, and the
//! pursuit/discovery choice, so this walk holds no matching policy of
//! its own.
//!
//! Crosses the FFI seam as parallel homogeneous buffers; the Haskell
//! side in `Slap.GDIFF.FFI` slices the data segment back into
//! per-command payloads.

use crate::gdiff_hash_chain::{SourceHashChainMatcher, SourceMatch};

// ── Public surface ─────────────────────────────────────────────────────

/// One command emitted by the differ. Vec order in [`GDiffDiffOutput`]
/// is emission order; the FFI bridge serializes positionally and
/// Haskell consumes in the same order.
pub struct Command {
    pub kind:          CommandKind,
    pub source_offset: u64,
    pub length:        u64,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum CommandKind {
    /// DATA — bytes accumulated from target positions that didn't
    /// match any source span; `source_offset` points into the data
    /// segment.
    Data,
    /// COPY — bytes the differ matched to a source span;
    /// `source_offset` is the position in the old file.
    Copy,
}

pub struct GDiffDiffOutput {
    pub commands:     Vec<Command>,
    pub data_segment: Vec<u8>,
}

/// Compute a GDIFF diff. The one failure is an internal-invariant
/// violation: cumulative emit length != target length at end of walk.
pub fn gdiff_diff(source: &[u8], target: &[u8]) -> Result<GDiffDiffOutput, String> {
    if target.is_empty() {
        return Ok(GDiffDiffOutput {
            commands:     Vec::new(),
            data_segment: Vec::new(),
        });
    }

    let mut matcher = SourceHashChainMatcher::build(source);
    let mut state   = EncoderState::initial();
    while state.target_position < target.len() {
        match matcher.match_at(target, state.target_position, state.pending_literal_floor()) {
            Some(found) => state.emit_copy(target, found),
            None        => state.accumulate_literal_byte(),
        }
    }
    state.flush_pending_literal(target);
    state.into_output_checked(target.len())
}

// ── Encoder state ──────────────────────────────────────────────────────

/// Mutable state threaded through the target walk.
/// `literal_run_start` tracks an in-progress run of bytes destined for
/// the data segment so consecutive non-match positions accumulate into
/// one DATA command rather than one per byte.
struct EncoderState {
    commands:          Vec<Command>,
    data_segment:      Vec<u8>,
    target_position:   usize,
    literal_run_start: Option<usize>,
}

impl EncoderState {
    fn initial() -> Self {
        EncoderState {
            commands:          Vec::new(),
            data_segment:      Vec::new(),
            target_position:   0,
            literal_run_start: None,
        }
    }

    fn accumulate_literal_byte(&mut self) {
        if self.literal_run_start.is_none() {
            self.literal_run_start = Some(self.target_position);
        }
        self.target_position += 1;
    }

    /// Where the pending literal run began, or the current position when
    /// none is pending — the floor an accepted match may reach back to.
    fn pending_literal_floor(&self) -> usize {
        self.literal_run_start.unwrap_or(self.target_position)
    }

    /// Record a copy. Any pending literal run is flushed first —
    /// shortened by the bytes the match reached back to absorb, and
    /// dropped whole when it absorbed them all — so the DATA command
    /// lands before the copy in emission order.
    fn emit_copy(&mut self, target: &[u8], found: SourceMatch) {
        let match_start = self.target_position - found.starts_earlier_by;
        if let Some(literal_run_start) = self.literal_run_start.take() {
            if match_start > literal_run_start {
                self.flush_literal_run(&target[literal_run_start..match_start]);
            }
        }
        self.commands.push(Command {
            kind:          CommandKind::Copy,
            source_offset: found.source_offset as u64,
            length:        found.length as u64,
        });
        self.target_position = match_start + found.length;
    }

    /// Append `literal_bytes` to the data segment and emit one DATA
    /// command covering it, its offset the segment position where the
    /// bytes land.
    fn flush_literal_run(&mut self, literal_bytes: &[u8]) {
        let data_segment_start = self.data_segment.len() as u64;
        let literal_length     = literal_bytes.len() as u64;
        self.data_segment.extend_from_slice(literal_bytes);
        self.commands.push(Command {
            kind:          CommandKind::Data,
            source_offset: data_segment_start,
            length:        literal_length,
        });
    }

    /// Emit any pending literal as one trailing DATA — called once at
    /// end of walk for the tail flush.
    fn flush_pending_literal(&mut self, target: &[u8]) {
        if let Some(literal_run_start) = self.literal_run_start.take() {
            if self.target_position > literal_run_start {
                let literal_bytes = &target[literal_run_start..self.target_position];
                self.flush_literal_run(literal_bytes);
            }
        }
    }

    /// Surface the final structured output, checking the cumulative-
    /// emit-length invariant. Catches a class of "differ silently
    /// dropped or duplicated bytes" bugs before they reach the wire
    /// encoder.
    fn into_output_checked(self, target_length: usize) -> Result<GDiffDiffOutput, String> {
        let cumulative_emitted_length: u64 =
            self.commands.iter().map(|command| command.length).sum();
        if cumulative_emitted_length != target_length as u64 {
            return Err(format!(
                "gdiff differ: cumulative emit length {cumulative_emitted_length} != \
                 target length {target_length} (internal invariant violation)"
            ));
        }
        Ok(GDiffDiffOutput {
            commands:     self.commands,
            data_segment: self.data_segment,
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_roundtrip(source: &[u8], target: &[u8]) {
        let diff = gdiff_diff(source, target).expect("differ should succeed");
        let mut reconstructed = Vec::with_capacity(target.len());
        for command in &diff.commands {
            let offset = command.source_offset as usize;
            let length = command.length        as usize;
            match command.kind {
                CommandKind::Data => {
                    reconstructed.extend_from_slice(&diff.data_segment[offset..offset + length])
                }
                CommandKind::Copy => {
                    reconstructed.extend_from_slice(&source[offset..offset + length])
                }
            }
        }
        assert_eq!(reconstructed, target, "reconstructed target differs");
    }

    #[test]
    fn empty_target() {
        let diff = gdiff_diff(&[1, 2, 3, 4, 5], &[]).expect("differ should succeed");
        assert!(diff.commands.is_empty());
        assert!(diff.data_segment.is_empty());
    }

    #[test]
    fn empty_source_means_all_literal() {
        let target: Vec<u8> = (0..100u8).collect();
        let diff = gdiff_diff(&[], &target).expect("differ should succeed");
        assert!(diff.commands.iter().all(|command| command.kind == CommandKind::Data));
        assert_eq!(diff.data_segment, target);
        assert_roundtrip(&[], &target);
    }

    #[test]
    fn source_shorter_than_min_match_is_all_literal() {
        let source: Vec<u8> = (0..3u8).collect(); // length 3, under the finder's 8-byte floor
        let target: Vec<u8> = (0..10u8).collect();
        let diff = gdiff_diff(&source, &target).expect("differ should succeed");
        assert_eq!(diff.commands.len(), 1);
        assert_eq!(diff.commands[0].kind, CommandKind::Data);
        assert_eq!(diff.commands[0].length, 10);
        assert_eq!(diff.data_segment, target);
        assert_roundtrip(&source, &target);
    }

    #[test]
    fn identical_buffers_match_entirely_from_source() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let diff = gdiff_diff(&data, &data).expect("differ should succeed");
        assert_eq!(diff.data_segment.len(), 0);
        assert!(diff.commands.iter().any(|command| command.kind == CommandKind::Copy));
        assert_roundtrip(&data, &data);
    }

    #[test]
    fn block_move_compresses_well() {
        let source: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut target = source.clone();
        target[0x800..0x900].copy_from_slice(&source[0x100..0x200]);
        let diff = gdiff_diff(&source, &target).expect("differ should succeed");
        assert!(
            diff.data_segment.len() < target.len() / 4,
            "data segment {} bytes vs target {} bytes",
            diff.data_segment.len(),
            target.len()
        );
        assert_roundtrip(&source, &target);
    }

    #[test]
    fn target_unrelated_to_source_is_all_literal() {
        let source: Vec<u8> = b"the quick brown fox jumps over the lazy dog".to_vec();
        let target: Vec<u8> = (0..16u8).cycle().take(64).collect();
        let diff = gdiff_diff(&source, &target).expect("differ should succeed");
        // No copies when no match reaches the floor. (Cycling bytes
        // 0..16 shares no floor-length substring with English text.)
        let copy_count = diff
            .commands
            .iter()
            .filter(|command| command.kind == CommandKind::Copy)
            .count();
        assert_eq!(copy_count, 0);
        assert_roundtrip(&source, &target);
    }

    #[test]
    fn round_trip_random_inputs() {
        // Light fuzz across a few sizes to exercise the walk.
        let mut state = 0x1234_5678_9abc_def0u64;
        for &(source_length, target_length) in
            &[(0usize, 32usize), (4, 0), (3, 100), (256, 256), (1024, 2048)]
        {
            let mut next_byte = || -> u8 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (state >> 33) as u8
            };
            let source: Vec<u8> = (0..source_length).map(|_| next_byte()).collect();
            let target: Vec<u8> = (0..target_length).map(|_| next_byte()).collect();
            assert_roundtrip(&source, &target);
        }
    }
}
