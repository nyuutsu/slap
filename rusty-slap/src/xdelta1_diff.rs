//! xdelta1 differ. Takes source bytes and target bytes; produces an
//! [`XDelta1DiffOutput`] containing the instructions and data segment
//! that, applied to the source, reproduce the target. Emits
//! [`InstructionTarget::FileSource`] for spans of target that match
//! some region of source and [`InstructionTarget::DataSource`] for
//! bytes that didn't match (accumulated into the inline data
//! segment).
//!
//! The matcher is a suffix-array index over source (see
//! [`crate::xdelta1_suffix_array`]) queried once per target position.
//! The walk is greedy: at each position, take the longest match the
//! SA reports if it reaches [`MIN_MATCH_LENGTH`], otherwise
//! accumulate one literal byte and advance.
//!
//! Crosses the FFI seam as parallel homogeneous buffers. The Haskell
//! side in `Slap.XDelta1.FFI` reassembles the output and feeds it to
//! `Slap.XDelta1.Create.assemblePatch`.

use crate::xdelta1_suffix_array::SourceSuffixArrayIndex;

/// Shortest match length the differ will emit as a file-source
/// instruction. Matches the canonical xdelta1 setting; an empirical
/// choice in this range trades a few bytes of literal-segment growth
/// for many fewer fragmented short instructions, which dominate
/// total wire size under the greedy walk (which has no lookahead
/// and so commits to every match it sees). Below 8, short
/// coincidental matches splinter what would otherwise be one long
/// run of literals or one long file-source match into multiple
/// records with their own per-instruction varint overhead.
const MIN_MATCH_LENGTH: usize = 8;

// ── Public surface ─────────────────────────────────────────────────────

/// One instruction emitted by the differ. Vec order in
/// [`XDelta1DiffOutput`] is emission order; the FFI bridge serializes
/// positionally and Haskell consumes in the same order.
pub struct Instruction {
    pub target:        InstructionTarget,
    pub source_offset: u64,
    pub length:        u64,
}

/// Which of the patch's two sources an instruction references.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum InstructionTarget {
    /// The patch's inline data segment — bytes accumulated from
    /// target positions that didn't match any source span.
    DataSource,
    /// The user's external source ROM — bytes the differ matched
    /// against the source suffix-array index.
    FileSource,
}

/// How file-source instruction offsets should be encoded on the wire.
/// Crosses the FFI seam as a single byte (0 = `Absolute`, 1 =
/// `Sequential`); the Haskell side decodes it directly into
/// `Slap.XDelta1.Types.XDelta1OffsetMode`.
///
/// The choice is observed end-of-walk by [`observe_file_source_offset_mode`]:
/// if every file-source instruction's offset equals the cumulative
/// length of file-source instructions emitted before it, the patch
/// can encode under `Sequential` (writing 0 for every per-instruction
/// offset varint, reconstructing on parse from the cumulative sum)
/// and the wire bytes shrink. Otherwise it must encode under
/// `Absolute`, writing each offset verbatim.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum FileSourceOffsetMode {
    Absolute,
    Sequential,
}

/// The differ's structured output. Crosses the FFI seam as parallel
/// homogeneous buffers (one per instruction field, plus the data
/// segment and the file-source offset-mode byte); this struct is the
/// pre-serialization in-Rust shape.
pub struct XDelta1DiffOutput {
    pub instructions:             Vec<Instruction>,
    pub data_segment:             Vec<u8>,
    pub file_source_offset_mode:  FileSourceOffsetMode,
}

/// Compute an xdelta1 diff. Returns the pre-serialization structured
/// output for the FFI bridge.
///
/// Failures: sources too large for the `u32`-indexed suffix array
/// (surfaced by [`SourceSuffixArrayIndex::build`]) and internal-
/// invariant violations (cumulative emit length != target length at
/// end). All return `Err(cause)` rather than `panic!` /
/// `unreachable!()` into the process-abort path established by
/// `panic = "abort"`.
pub fn xdelta1_diff(source: &[u8], target: &[u8]) -> Result<XDelta1DiffOutput, String> {
    if target.is_empty() {
        return Ok(XDelta1DiffOutput {
            instructions:            Vec::new(),
            data_segment:            Vec::new(),
            file_source_offset_mode: FileSourceOffsetMode::Sequential,
        });
    }

    let suffix_array_index = SourceSuffixArrayIndex::build(source)?;
    let mut state          = EncoderState::initial();
    while state.target_position < target.len() {
        let target_suffix = &target[state.target_position..];
        let match_candidate =
            suffix_array_index.longest_match_for_target_suffix(source, target_suffix);
        match match_candidate {
            Some(accepted_match) if (accepted_match.match_length as usize) >= MIN_MATCH_LENGTH =>
                state.emit_file_match(
                    target,
                    accepted_match.source_offset as u64,
                    accepted_match.match_length as u64,
                ),
            _ =>
                state.accumulate_literal_byte(),
        }
    }
    state.flush_pending_literal(target);

    let file_source_offset_mode = observe_file_source_offset_mode(&state.instructions);
    state.into_output_checked(target.len(), file_source_offset_mode)
}

/// End-of-walk observation: did the differ produce file-source
/// instructions whose offsets form a monotone-cumulative sequence?
/// If so, the patch can encode under `Sequential` (writing 0 for
/// every per-instruction offset varint); otherwise it must encode
/// under `Absolute`.
///
/// Vacuous case (no file-source instructions): pick `Sequential`.
/// Sequential's wire shape is the natural compact default and the
/// choice doesn't affect emitted bytes when there's nothing to
/// encode an offset for.
fn observe_file_source_offset_mode(instructions: &[Instruction]) -> FileSourceOffsetMode {
    let mut next_expected_offset_under_sequential: u64 = 0;
    for instruction in instructions {
        if instruction.target != InstructionTarget::FileSource {
            continue;
        }
        if instruction.source_offset != next_expected_offset_under_sequential {
            return FileSourceOffsetMode::Absolute;
        }
        next_expected_offset_under_sequential += instruction.length;
    }
    FileSourceOffsetMode::Sequential
}

// ── Encoder state ──────────────────────────────────────────────────────

/// Mutable state threaded through the target walk.
/// `literal_run_start` tracks an in-progress run of bytes destined
/// for the data segment so consecutive non-match positions accumulate
/// into one `FromDataSource` instruction rather than one per byte.
/// File-source sequential-mode tracking lives in the post-pass
/// (`observe_file_source_offset_mode`) rather than in this state —
/// the differ records absolute source offsets unconditionally and
/// the mode is observed end-of-walk.
struct EncoderState {
    instructions:        Vec<Instruction>,
    data_segment:        Vec<u8>,
    target_position:     usize,
    literal_run_start:   Option<usize>,
}

impl EncoderState {
    fn initial() -> Self {
        EncoderState {
            instructions:      Vec::new(),
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

    /// Record a file-source match. Any pending literal run is flushed
    /// first so the data-source instruction lands before the match
    /// in emission order.
    fn emit_file_match(&mut self, target: &[u8], source_offset: u64, match_length: u64) {
        if let Some(literal_run_start) = self.literal_run_start.take() {
            if self.target_position > literal_run_start {
                self.flush_literal_run(&target[literal_run_start..self.target_position]);
            }
        }
        self.record_emit(InstructionTarget::FileSource, source_offset, match_length);
        self.target_position += match_length as usize;
    }

    /// Append `literal_bytes` to the data segment and emit one
    /// `FromDataSource` instruction covering it. The source offset
    /// is the current data-segment end position; the call site has
    /// already extracted the byte slice from target.
    fn flush_literal_run(&mut self, literal_bytes: &[u8]) {
        let data_segment_start = self.data_segment.len() as u64;
        let literal_length     = literal_bytes.len() as u64;
        self.data_segment.extend_from_slice(literal_bytes);
        self.record_emit(InstructionTarget::DataSource, data_segment_start, literal_length);
    }

    /// Emit any pending literal as one trailing `FromDataSource` —
    /// called once at end of walk for the tail flush.
    fn flush_pending_literal(&mut self, target: &[u8]) {
        if let Some(literal_run_start) = self.literal_run_start.take() {
            if self.target_position > literal_run_start {
                let literal_bytes = &target[literal_run_start..self.target_position];
                self.flush_literal_run(literal_bytes);
            }
        }
    }

    fn record_emit(
        &mut self,
        instruction_target: InstructionTarget,
        source_offset:      u64,
        length:             u64,
    ) {
        self.instructions.push(Instruction {
            target: instruction_target,
            source_offset,
            length,
        });
    }

    /// Surface the final structured output, checking the cumulative-
    /// emit-length invariant. Catches a class of "differ silently
    /// dropped or duplicated bytes" bugs before they reach the wire
    /// encoder. The mode is decided by the caller's end-of-walk
    /// observation pass and flowed in by parameter so all three
    /// output fields are set in one constructor.
    fn into_output_checked(
        self,
        target_length:           usize,
        file_source_offset_mode: FileSourceOffsetMode,
    ) -> Result<XDelta1DiffOutput, String> {
        let cumulative_emitted_length: u64 = self.instructions.iter().map(|i| i.length).sum();
        if cumulative_emitted_length != target_length as u64 {
            return Err(format!(
                "xdelta1 differ: cumulative emit length {cumulative_emitted_length} != \
                 target length {target_length} (internal invariant violation)"
            ));
        }
        Ok(XDelta1DiffOutput {
            instructions: self.instructions,
            data_segment: self.data_segment,
            file_source_offset_mode,
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_roundtrip(source: &[u8], target: &[u8]) {
        let diff = xdelta1_diff(source, target).expect("differ should succeed");
        let mut reconstructed = Vec::with_capacity(target.len());
        for instruction in &diff.instructions {
            let offset = instruction.source_offset as usize;
            let length = instruction.length        as usize;
            match instruction.target {
                InstructionTarget::DataSource => {
                    reconstructed.extend_from_slice(&diff.data_segment[offset..offset + length])
                }
                InstructionTarget::FileSource => {
                    reconstructed.extend_from_slice(&source[offset..offset + length])
                }
            }
        }
        assert_eq!(reconstructed, target, "reconstructed target differs");
    }

    #[test]
    fn empty_target() {
        let diff = xdelta1_diff(&[1, 2, 3, 4, 5], &[]).expect("differ should succeed");
        assert!(diff.instructions.is_empty());
        assert!(diff.data_segment.is_empty());
        assert_eq!(diff.file_source_offset_mode, FileSourceOffsetMode::Sequential);
    }

    #[test]
    fn empty_source_means_all_literal() {
        let target: Vec<u8> = (0..100u8).collect();
        let diff = xdelta1_diff(&[], &target).expect("differ should succeed");
        assert!(diff
            .instructions
            .iter()
            .all(|i| i.target == InstructionTarget::DataSource));
        assert_eq!(diff.data_segment, target);
        assert_roundtrip(&[], &target);
    }

    #[test]
    fn source_shorter_than_min_match_is_all_literal() {
        let source: Vec<u8> = (0..3u8).collect(); // length 3 < MIN_MATCH_LENGTH
        let target: Vec<u8> = (0..10u8).collect();
        let diff = xdelta1_diff(&source, &target).expect("differ should succeed");
        assert_eq!(diff.instructions.len(), 1);
        assert_eq!(diff.instructions[0].target, InstructionTarget::DataSource);
        assert_eq!(diff.instructions[0].length, 10);
        assert_eq!(diff.data_segment, target);
        assert_roundtrip(&source, &target);
    }

    #[test]
    fn identical_buffers_match_entirely_from_source() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let diff = xdelta1_diff(&data, &data).expect("differ should succeed");
        assert_eq!(diff.data_segment.len(), 0);
        assert!(diff.instructions.iter().any(|i| i.target == InstructionTarget::FileSource));
        assert_roundtrip(&data, &data);
    }

    #[test]
    fn block_move_compresses_well() {
        let source: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut target = source.clone();
        target[0x800..0x900].copy_from_slice(&source[0x100..0x200]);
        let diff = xdelta1_diff(&source, &target).expect("differ should succeed");
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
        let diff = xdelta1_diff(&source, &target).expect("differ should succeed");
        // No file-source instructions when no match reaches MIN_MATCH.
        // (Cycling bytes 0..16 shares no MIN_MATCH-length substring
        // with English text.)
        let file_source_count = diff
            .instructions
            .iter()
            .filter(|i| i.target == InstructionTarget::FileSource)
            .count();
        assert_eq!(file_source_count, 0);
        assert_roundtrip(&source, &target);
    }

    #[test]
    fn observe_sequential_mode_on_in_order_emit() {
        // Target = source[0..32] ++ source[32..64] would emit two
        // file matches at offsets 0 and 32; both monotone-cumulative.
        let source: Vec<u8> = (0..=255u8).collect();
        let target           = source.clone();
        let diff = xdelta1_diff(&source, &target).expect("differ should succeed");
        assert_eq!(diff.file_source_offset_mode, FileSourceOffsetMode::Sequential);
    }

    #[test]
    fn observe_absolute_mode_on_out_of_order_emit() {
        // Target reorders two source halves — emit order will not
        // be monotone-cumulative.
        let source: Vec<u8> = (0..200u8).collect();
        let target: Vec<u8> = source[100..200]
            .iter()
            .chain(source[0..100].iter())
            .copied()
            .collect();
        let diff = xdelta1_diff(&source, &target).expect("differ should succeed");
        assert_eq!(diff.file_source_offset_mode, FileSourceOffsetMode::Absolute);
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
