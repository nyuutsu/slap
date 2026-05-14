//! xdelta1 differ. Takes source bytes and target bytes; produces an
//! [`XDelta1DiffOutput`] containing the instructions and data segment
//! that, applied to the source, reproduce the target. Emits
//! [`InstructionTarget::FileSource`] for spans of target that match
//! some region of source and [`InstructionTarget::DataSource`] for
//! bytes that didn't match (accumulated into the inline data
//! segment).
//!
//! Crosses the FFI seam as parallel homogeneous buffers. The Haskell
//! side in `Slap.XDelta1.FFI` reassembles the output and feeds it to
//! `Slap.XDelta1.Create.assemblePatch`.

/// Anchor granularity for the rolling-checksum index. Matches
/// canonical's `QUERY_SIZE_POW = 1 << 4` default (`xdelta.h:78`) and
/// is also the minimum match length the differ will emit. A patcher
/// implementation detail; no CLI surface.
const BLOCK_SIZE: usize = 16;

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
    /// target positions that didn't match any source block.
    DataSource,
    /// The user's external source ROM — bytes the differ matched
    /// against the source index.
    FileSource,
}

/// The differ's structured output. Crosses the FFI seam as parallel
/// homogeneous buffers (one per instruction field, plus the data
/// segment and the per-source sequential flag); this struct is the
/// pre-serialization in-Rust shape.
pub struct XDelta1DiffOutput {
    pub instructions:              Vec<Instruction>,
    pub data_segment:              Vec<u8>,
    pub file_source_is_sequential: bool,
}

/// Compute an xdelta1 diff. Returns the pre-serialization structured
/// output for the FFI bridge.
///
/// Failures: at minimum, allocation refusals when building the source
/// index on memory-constrained hosts. Also internal-invariant
/// violations (cumulative emit length != target length at end) which
/// return `Err(cause)` rather than `panic!` / `unreachable!()` into
/// the process-abort path established by `panic = "abort"`.
pub fn xdelta1_diff(source: &[u8], target: &[u8]) -> Result<XDelta1DiffOutput, String> {
    let source_index = SourceIndex::build(source)?;
    let mut state = EncoderState::initial();

    // Degenerate target shorter than the anchor granularity: no hash
    // window forms, every byte flows through the data segment.
    if target.len() < BLOCK_SIZE {
        if !target.is_empty() {
            state.flush_literal_run(target);
        }
        return state.into_output_checked(target.len());
    }

    let mut rolling_checksum = RollingChecksum::over_block(&target[0..BLOCK_SIZE]);

    while state.target_position + BLOCK_SIZE <= target.len() {
        let step = decide_step(&source_index, source, target, &state, rolling_checksum);
        match step {
            Step::EmitFileMatch(matched) => {
                state.emit_file_match(target, matched);
                if state.target_position + BLOCK_SIZE <= target.len() {
                    rolling_checksum = RollingChecksum::over_block(
                        &target[state.target_position..state.target_position + BLOCK_SIZE],
                    );
                }
            }
            Step::AccumulateLiteral => {
                state.accumulate_literal_byte();
                if state.target_position + BLOCK_SIZE <= target.len() {
                    let byte_leaving_window  = target[state.target_position - 1];
                    let byte_entering_window = target[state.target_position + BLOCK_SIZE - 1];
                    rolling_checksum.slide_window(byte_leaving_window, byte_entering_window);
                }
            }
        }
    }

    // Anything between the last anchor-able position and target's end
    // joins the pending literal run (no hash window covers it).
    if state.target_position < target.len() {
        if state.literal_run_start.is_none() {
            state.literal_run_start = Some(state.target_position);
        }
        state.target_position = target.len();
    }

    state.flush_pending_literal(target);
    state.into_output_checked(target.len())
}

// ── Rolling checksum ───────────────────────────────────────────────────

/// A `u16` × `u16` rolling pair over a 16-byte window. `byte_sum` is
/// the modular sum of the bytes in the window; `weighted_byte_sum`
/// weights byte position so window permutations don't collide. The
/// packed 32-bit form `(weighted << 16) | byte_sum` is the hash key
/// indexed by [`SourceIndex`].
///
/// All arithmetic is `u16` wraparound. Verified against canonical
/// (`xdelta.c:812-819`): after sliding by one byte, the new weighted
/// sum equals `16·b[1] + 15·b[2] + … + 1·b[16]`, which decomposes to
/// `weighted_byte_sum − BLOCK_SIZE · byte_leaving + new_byte_sum`.
#[derive(Copy, Clone)]
struct RollingChecksum {
    byte_sum:          u16,
    weighted_byte_sum: u16,
}

impl RollingChecksum {
    /// Initialize over a 16-byte block. Used at index-build for every
    /// source block, and once for the first 16 bytes of target.
    fn over_block(block: &[u8]) -> Self {
        debug_assert_eq!(block.len(), BLOCK_SIZE);
        let mut byte_sum:          u16 = 0;
        let mut weighted_byte_sum: u16 = 0;
        for &byte_in_block in block {
            byte_sum          = byte_sum.wrapping_add(byte_in_block as u16);
            weighted_byte_sum = weighted_byte_sum.wrapping_add(byte_sum);
        }
        RollingChecksum { byte_sum, weighted_byte_sum }
    }

    /// Slide the 16-byte window by one byte. Called per-byte during
    /// the target walk.
    fn slide_window(&mut self, byte_leaving_window: u8, byte_entering_window: u8) {
        let leaving  = byte_leaving_window  as u16;
        let entering = byte_entering_window as u16;
        let new_byte_sum = self.byte_sum.wrapping_sub(leaving).wrapping_add(entering);
        let new_weighted_byte_sum = self
            .weighted_byte_sum
            .wrapping_sub(leaving.wrapping_mul(BLOCK_SIZE as u16))
            .wrapping_add(new_byte_sum);
        self.byte_sum          = new_byte_sum;
        self.weighted_byte_sum = new_weighted_byte_sum;
    }

    /// Pack the two halves into the 32-bit hash key indexed by
    /// [`SourceIndex`].
    fn hash_key(self) -> u32 {
        ((self.weighted_byte_sum as u32) << 16) | (self.byte_sum as u32)
    }
}

// ── Source index ───────────────────────────────────────────────────────

/// Open-addressed, no-probing table mapping rolling-checksum hash
/// keys to the byte offset of the source block they cover. Bucket =
/// `hash_key & (table_size − 1)`; on insert, the last block with this
/// bucket wins. The hash key is stored alongside the offset so that
/// lookups whose keys differ from the stored key — bucket collisions —
/// register as misses rather than false hits.
struct SourceIndex {
    buckets:    Vec<Option<IndexEntry>>,
    table_mask: usize,
}

#[derive(Copy, Clone)]
struct IndexEntry {
    hash_key:                 u32,
    source_block_byte_offset: usize,
}

impl SourceIndex {
    /// Walk source in non-overlapping 16-byte blocks; for each, insert
    /// (hash_key → block_byte_offset). The tail under 16 bytes is not
    /// indexed (can't anchor a ≥ 16-byte match).
    ///
    /// Table size: next power of two ≥ `source_block_count · 2`. The
    /// load-factor-0.5 ceiling keeps bucket collisions rare and the
    /// no-probing lookup honest.
    fn build(source: &[u8]) -> Result<Self, String> {
        let source_block_count = source.len() / BLOCK_SIZE;
        let table_size = if source_block_count == 0 {
            1
        } else {
            (source_block_count.saturating_mul(2))
                .checked_next_power_of_two()
                .ok_or_else(|| format!(
                    "xdelta1 differ: source block count {source_block_count} overflows table sizing"
                ))?
        };

        let mut buckets: Vec<Option<IndexEntry>> = Vec::new();
        buckets
            .try_reserve_exact(table_size)
            .map_err(|err| format!(
                "xdelta1 differ: failed to allocate source index of {table_size} buckets ({err})"
            ))?;
        buckets.resize(table_size, None);
        let table_mask = table_size - 1;

        for source_block_index in 0..source_block_count {
            let block_start = source_block_index * BLOCK_SIZE;
            let block       = &source[block_start..block_start + BLOCK_SIZE];
            let hash_key    = RollingChecksum::over_block(block).hash_key();
            let bucket      = (hash_key as usize) & table_mask;
            buckets[bucket] = Some(IndexEntry {
                hash_key,
                source_block_byte_offset: block_start,
            });
        }

        Ok(SourceIndex { buckets, table_mask })
    }

    /// Look up a hash key. Returns `Some(offset)` only when the stored
    /// bucket entry's key matches — bucket collisions register as
    /// misses, not false hits.
    fn lookup(&self, hash_key: u32) -> Option<usize> {
        let bucket = (hash_key as usize) & self.table_mask;
        match self.buckets[bucket] {
            Some(entry) if entry.hash_key == hash_key => Some(entry.source_block_byte_offset),
            _ => None,
        }
    }
}

// ── Encoder state ──────────────────────────────────────────────────────

/// Mutable state threaded through the target walk. `literal_run_start`
/// tracks an in-progress run of bytes destined for the data segment so
/// consecutive non-match positions accumulate into one
/// `FromDataSource` instruction rather than one per byte.
/// `file_source_position_after_last_emit` backs the file-source
/// sequential-offset-mode tracking — the flag starts true and flips
/// on the first non-contiguous file-source emit. The data source is
/// always sequential by construction (literals append in order, so
/// each `FromDataSource` emit's `source_offset` equals the running
/// data-segment length) so it carries no flag of its own.
struct EncoderState {
    instructions:                          Vec<Instruction>,
    data_segment:                          Vec<u8>,
    target_position:                       usize,
    literal_run_start:                     Option<usize>,
    file_source_position_after_last_emit:  u64,
    file_source_is_sequential:             bool,
}

impl EncoderState {
    fn initial() -> Self {
        EncoderState {
            instructions:                         Vec::new(),
            data_segment:                         Vec::new(),
            target_position:                      0,
            literal_run_start:                    None,
            file_source_position_after_last_emit: 0,
            file_source_is_sequential:            true,
        }
    }

    fn accumulate_literal_byte(&mut self) {
        if self.literal_run_start.is_none() {
            self.literal_run_start = Some(self.target_position);
        }
        self.target_position += 1;
    }

    /// Apply a [`Step::EmitFileMatch`] decision. The backward
    /// extension may have absorbed some bytes from a pending literal
    /// run, so we flush the literal up to the match's actual start
    /// before recording the file-source emit.
    fn emit_file_match(&mut self, target: &[u8], matched: ExtendedMatch) {
        let match_target_start = matched.target_start;
        let match_length       = matched.match_length;

        if let Some(literal_run_start) = self.literal_run_start.take() {
            if match_target_start > literal_run_start {
                self.flush_literal_run(&target[literal_run_start..match_target_start]);
            }
            // else: backward extension absorbed the entire literal
            // run; no literal bytes remain to flush.
        }

        self.record_emit(
            InstructionTarget::FileSource,
            matched.source_offset_in_match,
            match_length,
        );
        self.target_position = match_target_start + match_length as usize;
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
    /// called once at end of walk for the tail flush. The mid-walk
    /// partial flush inside [`Self::emit_file_match`] computes its
    /// slice directly and calls [`Self::flush_literal_run`].
    fn flush_pending_literal(&mut self, target: &[u8]) {
        if let Some(literal_run_start) = self.literal_run_start.take() {
            if self.target_position > literal_run_start {
                let literal_bytes = &target[literal_run_start..self.target_position];
                self.flush_literal_run(literal_bytes);
            }
        }
    }

    /// Record an emit. For file-source emits, also tracks sequential
    /// mode: a non-contiguous `source_offset` permanently flips
    /// `file_source_is_sequential` to false. Data-source emits don't
    /// need tracking — the data source is always sequential by
    /// construction (literals append in order, so `source_offset` is
    /// always the running data-segment length).
    fn record_emit(
        &mut self,
        instruction_target: InstructionTarget,
        source_offset:      u64,
        length:             u64,
    ) {
        if let InstructionTarget::FileSource = instruction_target {
            if source_offset != self.file_source_position_after_last_emit {
                self.file_source_is_sequential = false;
            }
            self.file_source_position_after_last_emit = source_offset + length;
        }
        self.instructions.push(Instruction {
            target: instruction_target,
            source_offset,
            length,
        });
    }

    /// Surface the final structured output, checking the cumulative-
    /// emit-length invariant. Catches a class of "differ silently
    /// dropped or duplicated bytes" bugs before they reach the wire
    /// encoder.
    fn into_output_checked(self, target_length: usize) -> Result<XDelta1DiffOutput, String> {
        let cumulative_emitted_length: u64 = self.instructions.iter().map(|i| i.length).sum();
        if cumulative_emitted_length != target_length as u64 {
            return Err(format!(
                "xdelta1 differ: cumulative emit length {cumulative_emitted_length} != \
                 target length {target_length} (internal invariant violation)"
            ));
        }
        Ok(XDelta1DiffOutput {
            instructions:              self.instructions,
            data_segment:              self.data_segment,
            file_source_is_sequential: self.file_source_is_sequential,
        })
    }
}

// ── Step decision ──────────────────────────────────────────────────────

/// What the differ decided to do at the current target position. The
/// imperative loop body applies the decision in one place rather than
/// scattering mutation across the matcher.
enum Step {
    /// Flush any pending literal, then record a `FromFileSource`
    /// instruction covering the extended match.
    EmitFileMatch(ExtendedMatch),
    /// No match worth emitting at this position; the byte at
    /// `target_position` joins the pending literal run.
    AccumulateLiteral,
}

/// A hash hit's full extent after bidirectional extension. The match
/// spans `target[target_start .. target_start + match_length]` and
/// the source side starts at `source_offset_in_match`.
#[derive(Copy, Clone)]
struct ExtendedMatch {
    target_start:           usize,
    source_offset_in_match: u64,
    match_length:           u64,
}

/// Classify the current target position into a [`Step`]. Misses,
/// false-positive hash hits (the 16-byte window doesn't actually
/// match), and matches that fail to reach the BLOCK_SIZE threshold
/// all fall through to `AccumulateLiteral`.
fn decide_step(
    source_index:     &SourceIndex,
    source:           &[u8],
    target:           &[u8],
    state:            &EncoderState,
    rolling_checksum: RollingChecksum,
) -> Step {
    let Some(source_anchor) = source_index.lookup(rolling_checksum.hash_key()) else {
        return Step::AccumulateLiteral;
    };

    let target_window = &target[state.target_position..state.target_position + BLOCK_SIZE];
    let source_window = &source[source_anchor..source_anchor + BLOCK_SIZE];
    if target_window != source_window {
        // False positive: the weak checksum collided but bytes differ.
        return Step::AccumulateLiteral;
    }

    let backward_floor = state.literal_run_start.unwrap_or(state.target_position);
    let extended = extend_match_bidirectionally(
        source,
        target,
        source_anchor,
        state.target_position,
        backward_floor,
    );

    Step::EmitFileMatch(extended)
}

/// Walk the match forward past the 16-byte anchor and backward into
/// already-covered target. Forward extension is bounded by both
/// buffers' ends; backward extension is bounded by `backward_floor`
/// (the earliest target position the match may absorb — typically the
/// pending literal run's start) and by `source[0]`.
fn extend_match_bidirectionally(
    source:          &[u8],
    target:          &[u8],
    source_anchor:   usize,
    target_position: usize,
    backward_floor:  usize,
) -> ExtendedMatch {
    let mut forward_extension = 0usize;
    let target_forward_capacity = target.len() - (target_position + BLOCK_SIZE);
    let source_forward_capacity = source.len() - (source_anchor + BLOCK_SIZE);
    let forward_capacity = target_forward_capacity.min(source_forward_capacity);
    while forward_extension < forward_capacity
        && target[target_position  + BLOCK_SIZE + forward_extension]
        == source[source_anchor    + BLOCK_SIZE + forward_extension]
    {
        forward_extension += 1;
    }

    let mut backward_extension = 0usize;
    let target_backward_capacity = target_position - backward_floor;
    let source_backward_capacity = source_anchor;
    let backward_capacity = target_backward_capacity.min(source_backward_capacity);
    while backward_extension < backward_capacity
        && target[target_position - 1 - backward_extension]
        == source[source_anchor   - 1 - backward_extension]
    {
        backward_extension += 1;
    }

    ExtendedMatch {
        target_start:           target_position - backward_extension,
        source_offset_in_match: (source_anchor - backward_extension) as u64,
        match_length:           (BLOCK_SIZE + backward_extension + forward_extension) as u64,
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
        let diff = xdelta1_diff(&[1, 2, 3], &[]).expect("differ should succeed");
        assert!(diff.instructions.is_empty());
        assert!(diff.data_segment.is_empty());
        assert!(diff.file_source_is_sequential);
    }

    #[test]
    fn empty_source_means_all_literal() {
        let target: Vec<u8> = (0..100u8).collect();
        let diff = xdelta1_diff(&[], &target).expect("differ should succeed");
        // No file-source instructions possible without an index.
        assert!(diff
            .instructions
            .iter()
            .all(|i| i.target == InstructionTarget::DataSource));
        assert_eq!(diff.data_segment, target);
        assert_roundtrip(&[], &target);
    }

    #[test]
    fn target_smaller_than_block_size_is_all_literal() {
        let source: Vec<u8> = (0..64u8).collect();
        let target: Vec<u8> = source[..10].to_vec();
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
    fn rolling_slide_matches_recompute() {
        // Stochastic verification of the slide formula: pick 32 random
        // bytes, init over [0..16], slide one byte at a time across
        // the buffer, and assert each slide agrees with a fresh
        // initialization over the corresponding window.
        let buffer: Vec<u8> = (0u8..32).map(|n| n.wrapping_mul(37).wrapping_add(11)).collect();
        let mut rolling = RollingChecksum::over_block(&buffer[0..BLOCK_SIZE]);
        for window_start in 1..(32 - BLOCK_SIZE + 1) {
            rolling.slide_window(buffer[window_start - 1], buffer[window_start + BLOCK_SIZE - 1]);
            let recomputed = RollingChecksum::over_block(&buffer[window_start..window_start + BLOCK_SIZE]);
            assert_eq!(rolling.hash_key(), recomputed.hash_key());
        }
    }
}
