//! BPS diff engine. Walks the target buffer left-to-right, choosing the
//! cheapest BPS action at each output position from a suffix-sorted
//! concatenation of `target[..sorted_window_size]` and `source`.
//!
//! Algorithm provenance: Alcaro's `libbps-suf.cpp` from Flips. The
//! cost-vs-literal heuristic and the progressive-sorting growth strategy
//! follow that implementation; the typed surface, decision-as-data
//! shape, and the split between deciding what to emit and executing the
//! emit are slap's.
//!
//! The loop body reads as: ask the SA for the best match candidate,
//! classify it into a [`BpsAction`] and decide whether emitting beats
//! accumulating a literal byte ([`LoopStep`]), then apply the decision.
//! Mutation lives entirely on the [`EncoderState`] struct and the output
//! buffer; no implicit state machine in parallel locals.
//!
//! The four BPS actions and what they encode:
//!
//! * [`BpsAction::SourceRead`] — copy `length` bytes from source at the
//!   current output offset (no offset payload).
//! * [`BpsAction::TargetRead`] — embed `length` literal bytes (payload
//!   is the bytes themselves).
//! * [`BpsAction::SourceCopy`] — copy `length` bytes from source at an
//!   arbitrary offset (payload is a signed delta from the previous
//!   `SourceCopy`'s end).
//! * [`BpsAction::TargetCopy`] — copy `length` bytes from already-written
//!   target at an arbitrary offset (payload is a signed delta from the
//!   previous `TargetCopy`'s end).

use crate::suffix_sort::{self, SuffixArray};

// ── Tuning constants ───────────────────────────────────────────────────

/// How far ahead of the current output position the sorted window must
/// extend. Match-finding compares the suffix at `output_position` against
/// neighbors in the SA; without runway past `output_position`, every
/// match would be capped by the not-yet-sorted boundary.
const REQUIRED_LOOKAHEAD: usize = 256;

/// Multiplier applied to the sorted window when growth is required. The
/// same factor governs the initial-window shrink loop, so initial-shrink
/// and grow-back stay geometrically in lockstep — a window shrunk by k
/// halvings is rebuilt by at most k regrowths over the encoding walk.
const WINDOW_GROWTH_MULTIPLIER: usize = 4;

/// Floor on the sorted window during initial shrink. The progressive
/// strategy shrinks the initial window so the first sort is cheap on
/// patches where source is much smaller than target; the floor prevents
/// over-shrinking on tiny inputs where the per-grow rebuild cost would
/// dominate the savings.
const MINIMUM_INITIAL_WINDOW: usize = 1024;

/// Number of low bits in a BPS action header reserved for the action
/// tag. The remaining bits carry `length - 1`. Two bits because BPS
/// has exactly four actions.
const ACTION_TAG_BIT_WIDTH: u32 = 2;

// ── Types ──────────────────────────────────────────────────────────────

/// One of the four BPS action types. Each is encoded on the wire as the
/// low [`ACTION_TAG_BIT_WIDTH`] bits of an action's byuu-varint header;
/// the upper bits carry length-minus-one.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum BpsAction {
    /// Copy `length` bytes from source at the current output offset. No
    /// offset payload — the offset is implicitly `output_position`.
    SourceRead,
    /// Embed `length` literal bytes; payload is the bytes themselves.
    /// Used as the encoder's fallback when no match is worth emitting.
    TargetRead,
    /// Copy `length` bytes from source at an arbitrary offset. Payload
    /// is the signed delta from the previous `SourceCopy`'s end.
    SourceCopy,
    /// Copy `length` bytes from already-written target at an arbitrary
    /// offset. Payload is the signed delta from the previous
    /// `TargetCopy`'s end.
    TargetCopy,
}

impl BpsAction {
    /// The two-bit wire tag, as used in the byuu-varint action header.
    fn wire_tag(self) -> u64 {
        match self {
            BpsAction::SourceRead => 0,
            BpsAction::TargetRead => 1,
            BpsAction::SourceCopy => 2,
            BpsAction::TargetCopy => 3,
        }
    }
}

/// Encoder state threaded through the main loop. The two `_end` fields
/// track the previous `SourceCopy`/`TargetCopy` end-positions so the
/// next copy's offset can be encoded as a signed delta from the previous;
/// `pending_target_read_start` tracks the start of an in-progress
/// `TargetRead` so consecutive non-emitted positions accumulate into one
/// `TargetRead` rather than one per byte.
struct EncoderState {
    /// Position into the target buffer where the next action will be
    /// written. Advances by `length` on emit, by 1 on no-match.
    output_position: usize,
    /// End position of the previous `SourceCopy` action's read region in
    /// source. Starts at 0; the next `SourceCopy`'s offset is encoded as
    /// a signed delta from this.
    last_source_copy_end: usize,
    /// End position of the previous `TargetCopy` action's read region in
    /// target. Starts at 0; the next `TargetCopy`'s offset is encoded as
    /// a signed delta from this.
    last_target_copy_end: usize,
    /// Start of an in-progress `TargetRead` (literal byte sequence), if
    /// any. None when no literal accumulation is in progress.
    pending_target_read_start: Option<usize>,
}

impl EncoderState {
    fn initial() -> Self {
        EncoderState {
            output_position: 0,
            last_source_copy_end: 0,
            last_target_copy_end: 0,
            pending_target_read_start: None,
        }
    }

    /// Defer this position to a (new or growing) pending `TargetRead`
    /// and step to the next output position.
    fn advance_with_pending_target_read(&mut self) {
        if self.pending_target_read_start.is_none() {
            self.pending_target_read_start = Some(self.output_position);
        }
        self.output_position += 1;
    }
}

/// Suffix-sorted concatenation of a target window and the source buffer,
/// with a reverse rank index for O(1) rank lookup at any position.
struct SortedConcat {
    /// The bytes that were sorted: `target[..sorted_window_size] ++ source`.
    bytes: Vec<u8>,
    /// The suffix array of `bytes`.
    suffix_array: SuffixArray,
    /// Inverse of `suffix_array`: `rank_at_position[position]` is the
    /// rank in the SA at which `position` appears.
    rank_at_position: Vec<usize>,
    /// How many bytes of target are included in `bytes`. Source occupies
    /// indices `[sorted_window_size, sorted_window_size + source_len)`.
    sorted_window_size: usize,
}

/// A match found by walking the SA from the current output position's
/// rank. `position_in_concat` indexes into the [`SortedConcat`]'s bytes;
/// `length` is how many bytes match the target starting at the current
/// output position.
#[derive(Copy, Clone)]
struct MatchCandidate {
    position_in_concat: usize,
    length: usize,
}

/// A match candidate that has been classified into a concrete BPS
/// action and resolved to a file-relative position. Carrying the
/// resolved file position (rather than the raw position-in-concat) lets
/// the emit step run without re-classifying.
#[derive(Copy, Clone)]
struct MatchEmission {
    action: BpsAction,
    /// File-relative position. For `SourceRead` this equals the current
    /// `output_position`. For `SourceCopy`/`TargetCopy` it is the read
    /// offset into source/target. `TargetRead` does not appear here —
    /// it is the literal-byte fallback, never classified as a match.
    file_position: usize,
    length: usize,
}

/// What the encoder decided to do at the current output position.
/// Returned as data by [`classify_and_decide`] so the imperative loop
/// body applies the decision in one place rather than scattering it
/// across the mutation.
enum LoopStep {
    /// Emit a match action; flush any pending `TargetRead` first.
    EmitMatch(MatchEmission),
    /// No match was worth emitting at this position; the byte at
    /// `state.output_position` joins the pending `TargetRead`.
    AccumulateLiteralByte,
}

// ── Public surface ─────────────────────────────────────────────────────

/// Compute a BPS diff between `source` and `target`. Returns the
/// byuu-varint-encoded BPS action stream — the bytes that splice
/// between the metadata block and the CRC footer in a BPS file.
#[must_use]
pub fn bps_diff(source: &[u8], target: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if target.is_empty() {
        return out;
    }

    let initial_window_size = compute_initial_window_size(target.len(), source.len());
    let mut sorted_concat = build_sorted_concat(target, source, initial_window_size);
    let mut state = EncoderState::initial();

    while state.output_position < target.len() {
        if needs_window_growth(&state, &sorted_concat, target.len()) {
            sorted_concat = grow_sorted_concat(
                target,
                source,
                sorted_concat.sorted_window_size,
                state.output_position,
            );
        }

        let step = match find_match_candidate(&sorted_concat, target, &state) {
            Some(candidate) => {
                classify_and_decide(candidate, &state, sorted_concat.sorted_window_size)
            }
            None => LoopStep::AccumulateLiteralByte,
        };

        match step {
            LoopStep::EmitMatch(emission) => emit_match(&mut out, &mut state, target, emission),
            LoopStep::AccumulateLiteralByte => state.advance_with_pending_target_read(),
        }
    }

    flush_pending_target_read(&mut out, &mut state, target);
    out
}

// ── Initial sort and progressive growth ────────────────────────────────

/// Pick the initial window size for the very first sort. The strategy
/// shrinks geometrically while the source is small relative to a
/// quarter of the target — every shrink halves the first-sort cost
/// without losing reachability, since the window will grow back at the
/// matching geometric rate as the encoder walks forward.
fn compute_initial_window_size(target_len: usize, source_len: usize) -> usize {
    let mut window_size = target_len;
    while window_size / WINDOW_GROWTH_MULTIPLIER > source_len
        && window_size > MINIMUM_INITIAL_WINDOW
    {
        window_size /= WINDOW_GROWTH_MULTIPLIER;
    }
    window_size
}

/// Build a [`SortedConcat`] over the first `sorted_window_size` bytes of
/// target followed by the entire source.
fn build_sorted_concat(target: &[u8], source: &[u8], sorted_window_size: usize) -> SortedConcat {
    let mut bytes = Vec::with_capacity(sorted_window_size + source.len());
    bytes.extend_from_slice(&target[..sorted_window_size]);
    bytes.extend_from_slice(source);
    let suffix_array = suffix_sort::suffix_sort(&bytes);
    let mut rank_at_position = vec![0usize; bytes.len()];
    for (rank, position) in suffix_array.iter_positions().enumerate() {
        rank_at_position[position] = rank;
    }
    SortedConcat {
        bytes,
        suffix_array,
        rank_at_position,
        sorted_window_size,
    }
}

/// Whether the encoder has walked close enough to the sorted boundary
/// that the next iteration would lack the required lookahead.
fn needs_window_growth(
    state: &EncoderState,
    sorted_concat: &SortedConcat,
    target_len: usize,
) -> bool {
    state.output_position + REQUIRED_LOOKAHEAD >= sorted_concat.sorted_window_size
        && sorted_concat.sorted_window_size < target_len
}

/// Build a fresh [`SortedConcat`] with a window grown to give the
/// encoder room to keep walking. Multiple growth steps may compound
/// inside a single call when one round of geometric expansion is not
/// enough to clear the lookahead requirement.
fn grow_sorted_concat(
    target: &[u8],
    source: &[u8],
    current_window_size: usize,
    output_position: usize,
) -> SortedConcat {
    let target_len = target.len();
    let mut grown_window_size = current_window_size;
    while output_position + REQUIRED_LOOKAHEAD >= grown_window_size
        && grown_window_size < target_len
    {
        grown_window_size = (grown_window_size * WINDOW_GROWTH_MULTIPLIER).min(target_len);
    }
    build_sorted_concat(target, source, grown_window_size)
}

// ── Match search ───────────────────────────────────────────────────────

/// Find the best match at the current output position by walking the SA
/// outward from that position's rank. Returns `None` when no neighbor
/// outside the not-yet-written zone exists or when the best neighbor's
/// match length is zero.
fn find_match_candidate(
    sorted_concat: &SortedConcat,
    target: &[u8],
    state: &EncoderState,
) -> Option<MatchCandidate> {
    let search_string = &target[state.output_position..sorted_concat.sorted_window_size];
    let starting_rank = sorted_concat.rank_at_position[state.output_position];

    let upward_neighbor =
        walk_up_for_valid_neighbor(sorted_concat, starting_rank, state.output_position);
    let downward_neighbor =
        walk_down_for_valid_neighbor(sorted_concat, starting_rank, state.output_position);

    let candidate = match (upward_neighbor, downward_neighbor) {
        (None, None) => return None,
        (Some(only), None) | (None, Some(only)) => MatchCandidate {
            position_in_concat: only,
            length: match_len(&sorted_concat.bytes[only..], search_string),
        },
        (Some(upward), Some(downward)) => {
            pick_longer_match(&sorted_concat.bytes, search_string, upward, downward)
        }
    };

    if candidate.length == 0 {
        None
    } else {
        Some(candidate)
    }
}

/// Walk the SA upward from `starting_rank` for the first neighbor whose
/// concat position lies outside the not-yet-written zone.
fn walk_up_for_valid_neighbor(
    sorted_concat: &SortedConcat,
    starting_rank: usize,
    output_position: usize,
) -> Option<usize> {
    let mut current_rank = starting_rank;
    while current_rank > 0 {
        current_rank -= 1;
        let candidate_position = sorted_concat.suffix_array.position_at_rank(current_rank);
        if is_outside_not_yet_written_zone(
            candidate_position,
            output_position,
            sorted_concat.sorted_window_size,
        ) {
            return Some(candidate_position);
        }
    }
    None
}

/// Walk the SA downward from `starting_rank + 1` for the first neighbor
/// whose concat position lies outside the not-yet-written zone.
fn walk_down_for_valid_neighbor(
    sorted_concat: &SortedConcat,
    starting_rank: usize,
    output_position: usize,
) -> Option<usize> {
    let sa_len = sorted_concat.suffix_array.len();
    let mut current_rank = starting_rank + 1;
    while current_rank < sa_len {
        let candidate_position = sorted_concat.suffix_array.position_at_rank(current_rank);
        if is_outside_not_yet_written_zone(
            candidate_position,
            output_position,
            sorted_concat.sorted_window_size,
        ) {
            return Some(candidate_position);
        }
        current_rank += 1;
    }
    None
}

/// True iff `position` lies outside the not-yet-written zone
/// `[output_position, sorted_window_size)`. The not-yet-written zone is
/// the range of target bytes the encoder has not emitted yet — matching
/// against them would mean copying from where we have not finished yet,
/// which the wire format cannot promise.
fn is_outside_not_yet_written_zone(
    position: usize,
    output_position: usize,
    sorted_window_size: usize,
) -> bool {
    position < output_position || position >= sorted_window_size
}

/// Given two SA neighbors of the search string, pick the one whose
/// match against `search_string` is longer. The two neighbors are
/// adjacent on the SA so they share a common prefix; the comparison
/// only diverges at the byte past their LCP. The candidate whose
/// divergence-point byte equals `search_string[lcp]` extends further;
/// the remaining match length is then measured directly.
fn pick_longer_match(
    bytes: &[u8],
    search_string: &[u8],
    first_position: usize,
    second_position: usize,
) -> MatchCandidate {
    let common_prefix_length = match_len(&bytes[first_position..], &bytes[second_position..]);
    if common_prefix_length >= search_string.len() {
        return MatchCandidate {
            position_in_concat: first_position,
            length: search_string.len(),
        };
    }
    let first_extends_into_search = first_position + common_prefix_length < bytes.len()
        && bytes[first_position + common_prefix_length] == search_string[common_prefix_length];
    let winning_position = if first_extends_into_search {
        first_position
    } else {
        second_position
    };
    let extra_match_length = match_len(
        &bytes[winning_position + common_prefix_length..],
        &search_string[common_prefix_length..],
    );
    MatchCandidate {
        position_in_concat: winning_position,
        length: common_prefix_length + extra_match_length,
    }
}

/// Length of the common prefix between two byte slices.
fn match_len(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right)
        .take_while(|(left_byte, right_byte)| left_byte == right_byte)
        .count()
}

// ── Classify and decide ────────────────────────────────────────────────

/// Classify a match candidate into a concrete [`MatchEmission`] and
/// decide whether emitting it beats accumulating a literal byte.
fn classify_and_decide(
    candidate: MatchCandidate,
    state: &EncoderState,
    sorted_window_size: usize,
) -> LoopStep {
    let emission = classify_match(candidate, state.output_position, sorted_window_size);
    if match_beats_literal(&emission, state) {
        LoopStep::EmitMatch(emission)
    } else {
        LoopStep::AccumulateLiteralByte
    }
}

/// Resolve a candidate's position-in-concat into a file-relative
/// position and the BPS action that would carry it. The split is
/// structural: positions below `sorted_window_size` index into the
/// already-written target half of the concat (`TargetCopy`); positions
/// at or above it index into source (`SourceCopy`, or `SourceRead` for
/// the no-offset special case).
fn classify_match(
    candidate: MatchCandidate,
    output_position: usize,
    sorted_window_size: usize,
) -> MatchEmission {
    if candidate.position_in_concat < sorted_window_size {
        MatchEmission {
            action: BpsAction::TargetCopy,
            file_position: candidate.position_in_concat,
            length: candidate.length,
        }
    } else {
        let file_position = candidate.position_in_concat - sorted_window_size;
        let action = if file_position == output_position {
            BpsAction::SourceRead
        } else {
            BpsAction::SourceCopy
        };
        MatchEmission {
            action,
            file_position,
            length: candidate.length,
        }
    }
}

/// Byte cost of emitting `action` at this output position. The action
/// header byte is counted as a flat 1 (the true varint width depends on
/// `length` and is approximated here); the offset payload, present only
/// for the copy actions, is sized by [`varint_cost`] over the encoded
/// signed delta.
fn match_byte_cost(action: BpsAction, file_position: usize, state: &EncoderState) -> usize {
    let action_header_byte = 1;
    let offset_payload_cost = match action {
        BpsAction::SourceRead | BpsAction::TargetRead => 0,
        BpsAction::SourceCopy => {
            varint_cost(encode_delta(state.last_source_copy_end, file_position))
        }
        BpsAction::TargetCopy => {
            varint_cost(encode_delta(state.last_target_copy_end, file_position))
        }
    };
    action_header_byte + offset_payload_cost
}

/// Whether `emission` is worth emitting versus extending the pending
/// `TargetRead`. The threshold is empirical, traced from Alcaro's
/// `use_match` in `libbps-suf.cpp` — heuristic rather than derived,
/// hence the trial-and-error shape:
///
/// * `1 + action_byte_cost` covers the action header byte plus the
///   offset payload (zero for `SourceRead`).
/// * `pending_flush_cost` (0 or 1) pays for the `TargetRead` flush
///   varint that emitting would force.
/// * `single_byte_tiebreaker` (0 or 1) adds one when `length == 1`,
///   breaking ties against emitting the smallest possible action.
fn match_beats_literal(emission: &MatchEmission, state: &EncoderState) -> bool {
    let action_byte_cost = match_byte_cost(emission.action, emission.file_position, state);
    let pending_flush_cost = usize::from(state.pending_target_read_start.is_some());
    let single_byte_tiebreaker = usize::from(emission.length == 1);
    let break_even_length = 1 + action_byte_cost + pending_flush_cost + single_byte_tiebreaker;
    emission.length >= break_even_length
}

// ── Emission ───────────────────────────────────────────────────────────

/// Emit a classified match: flush any pending `TargetRead`, write the
/// action header and (for copy actions) the offset payload, advance the
/// encoder state to the next output position, and update the relevant
/// last-copy-end cursor.
fn emit_match(
    out: &mut Vec<u8>,
    state: &mut EncoderState,
    target: &[u8],
    emission: MatchEmission,
) {
    flush_pending_target_read(out, state, target);
    let offset_payload = match emission.action {
        BpsAction::SourceRead | BpsAction::TargetRead => None,
        BpsAction::SourceCopy => Some(encode_delta(
            state.last_source_copy_end,
            emission.file_position,
        )),
        BpsAction::TargetCopy => Some(encode_delta(
            state.last_target_copy_end,
            emission.file_position,
        )),
    };
    emit_action(out, emission.action, emission.length, offset_payload);
    match emission.action {
        BpsAction::SourceCopy => {
            state.last_source_copy_end = emission.file_position + emission.length;
        }
        BpsAction::TargetCopy => {
            state.last_target_copy_end = emission.file_position + emission.length;
        }
        BpsAction::SourceRead | BpsAction::TargetRead => {}
    }
    state.output_position += emission.length;
}

/// Emit the byuu-varint header for `action` of `length` bytes, then the
/// offset-delta varint when one is provided. `SourceRead` has no
/// payload; `TargetRead`'s literal bytes are emitted by the caller
/// after this returns (the literal bytes are not a varint).
fn emit_action(out: &mut Vec<u8>, action: BpsAction, length: usize, offset_payload: Option<u64>) {
    encode_varint(out, encode_action_header(action, length));
    if let Some(delta) = offset_payload {
        encode_varint(out, delta);
    }
}

/// Pack an action's two-bit wire tag and length-minus-one into a single
/// `u64`, ready to be byuu-varint encoded.
fn encode_action_header(action: BpsAction, length: usize) -> u64 {
    ((length as u64 - 1) << ACTION_TAG_BIT_WIDTH) | action.wire_tag()
}

/// If a pending `TargetRead` is in progress, emit it and clear the
/// pending start. A no-op when nothing is pending. Called before any
/// non-`TargetRead` emission and once at the end of the main loop.
fn flush_pending_target_read(out: &mut Vec<u8>, state: &mut EncoderState, target: &[u8]) {
    if let Some(literal_run_start) = state.pending_target_read_start.take() {
        let literal_run_length = state.output_position - literal_run_start;
        emit_action(out, BpsAction::TargetRead, literal_run_length, None);
        out.extend_from_slice(&target[literal_run_start..state.output_position]);
    }
}

// ── Varint encoding ────────────────────────────────────────────────────
//
// BPS uses byuu's varint encoding: bit 7 of each byte signals whether
// it is the final byte of a value (1 means final, 0 means more
// follows). Between bytes, 1 is subtracted from the remaining value so
// that each width has a unique range (no aliased "leading zeros" across
// widths). Not LEB128 — encoder, decoder, and round-trip tests all
// live in this module to keep the convention contained.

fn encode_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value & 0x7F) as u8);
        value >>= 7;
        value -= 1;
    }
    out.push((value | 0x80) as u8);
}

/// Number of bytes a value would occupy when byuu-varint encoded.
fn varint_cost(mut value: u64) -> usize {
    let mut byte_count = 1;
    while value >= 0x80 {
        value >>= 7;
        value -= 1;
        byte_count += 1;
    }
    byte_count
}

/// Zigzag-encode the signed delta `next - previous`: bit 0 carries the
/// sign, bits 1+ carry the magnitude.
fn encode_delta(previous: usize, next: usize) -> u64 {
    if next >= previous {
        ((next - previous) as u64) << 1
    } else {
        (((previous - next) as u64) << 1) | 1
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic PRNG (SplitMix64).
    fn pseudo_random(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state.wrapping_add(0x9e3779b97f4a7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
                z ^= z >> 31;
                z as u8
            })
            .collect()
    }

    fn decode_varint(data: &[u8], cursor: &mut usize) -> u64 {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = data[*cursor];
            *cursor += 1;
            value += u64::from(byte & 0x7F) << shift;
            if byte & 0x80 != 0 {
                return value;
            }
            shift += 7;
            value += 1u64 << shift;
        }
    }

    #[test]
    fn empty_target() {
        assert!(bps_diff(&[1, 2, 3], &[]).is_empty());
        assert!(bps_diff(&[], &[]).is_empty());
    }

    #[test]
    fn identical() {
        let data = pseudo_random(0x1234, 256);
        let out = bps_diff(&data, &data);
        // Single SourceRead covering all 256 bytes.
        let mut cursor = 0;
        let header = decode_varint(&out, &mut cursor);
        assert_eq!(cursor, out.len(), "expected exactly one action");
        assert_eq!(header & 3, BpsAction::SourceRead.wire_tag());
        assert_eq!((header >> 2) + 1, 256);
    }

    #[test]
    fn empty_source() {
        let target = vec![10, 20, 30];
        let out = bps_diff(&[], &target);
        // Single TargetRead with the three literal bytes.
        let mut cursor = 0;
        let header = decode_varint(&out, &mut cursor);
        assert_eq!(header & 3, BpsAction::TargetRead.wire_tag());
        assert_eq!((header >> 2) + 1, 3);
        assert_eq!(&out[cursor..], &[10, 20, 30]);
    }

    #[test]
    fn varint_encoding() {
        let mut buf = Vec::new();

        // 0 → [0x80]
        encode_varint(&mut buf, 0);
        assert_eq!(buf, [0x80]);

        // 0x7F → [0xFF]
        buf.clear();
        encode_varint(&mut buf, 0x7F);
        assert_eq!(buf, [0xFF]);

        // 0x80 → [0x00, 0x80]
        buf.clear();
        encode_varint(&mut buf, 0x80);
        assert_eq!(buf, [0x00, 0x80]);

        // Round-trip through decode.
        for value in [0u64, 0x7F, 0x80, 0x3FFF, 0x4000, 12345678] {
            buf.clear();
            encode_varint(&mut buf, value);
            let mut cursor = 0;
            assert_eq!(
                decode_varint(&buf, &mut cursor),
                value,
                "round-trip failed for {value}"
            );
            assert_eq!(cursor, buf.len());
        }
    }

    #[test]
    fn block_move() {
        let source = pseudo_random(0xbeef, 4096);
        let mut target = source.clone();
        // Overwrite target[0x800..0x900] with source[0x100..0x200].
        target[0x800..0x900].copy_from_slice(&source[0x100..0x200]);
        let out = bps_diff(&source, &target);
        // Mostly SourceRead with one SourceCopy — patch is very small.
        assert!(
            out.len() < 100,
            "expected compact patch, got {} bytes",
            out.len()
        );
    }
}
