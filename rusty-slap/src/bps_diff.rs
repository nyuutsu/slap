//! BPS diff engine. Walks the target buffer left-to-right, choosing the
//! cheapest BPS action at each output position from the candidates the
//! hash-chain finder surfaces (`bps_hash_chain.rs`).
//!
//! Algorithm provenance: the cost-vs-literal heuristic is Alcaro's,
//! from `libbps-suf.cpp` in Flips. The typed surface, the
//! decision-as-data shape, and the split between finding, pricing, and
//! emitting are slap's.
//!
//! The loop body reads as: ask the finder for the best candidate at the
//! output position, classify it into a [`BpsAction`] and decide whether
//! emitting beats accumulating a literal byte ([`LoopStep`]), then apply
//! the decision. Mutation lives entirely on the [`EncoderState`] struct
//! and the output buffer; no implicit state machine in parallel locals.

use crate::bps_hash_chain::{FoundMatch, HashChainMatcher, MatchSide};

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

/// Encoder state threaded through the main loop.
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
    /// Start of an in-progress `TargetRead` (literal byte sequence), or `None`.
    /// Consecutive non-emitted positions accumulate into one `TargetRead` rather than one per byte.
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

/// A finder candidate classified into a concrete BPS action and carried
/// with the file-relative position the finder resolved, so the emit
/// step runs without re-classifying.
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

    let mut matcher = HashChainMatcher::build(source, target);
    let mut state = EncoderState::initial();

    while state.output_position < target.len() {
        let step = match matcher.match_at(
            state.output_position,
            state.last_source_copy_end,
            state.last_target_copy_end,
        ) {
            Some(found) => classify_and_decide(found, &state),
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

// ── Classify and decide ────────────────────────────────────────────────

/// Classify a finder candidate into a concrete [`MatchEmission`] and
/// decide whether emitting it beats accumulating a literal byte.
fn classify_and_decide(found: FoundMatch, state: &EncoderState) -> LoopStep {
    let emission = classify_match(found, state.output_position);
    if match_beats_literal(&emission, state) {
        LoopStep::EmitMatch(emission)
    } else {
        LoopStep::AccumulateLiteralByte
    }
}

/// Name the BPS action a candidate would ride out as: a written-target
/// candidate is a `TargetCopy`; a source candidate at exactly the
/// output position is the offset-free `SourceRead`, and anywhere else a
/// `SourceCopy`.
fn classify_match(found: FoundMatch, output_position: usize) -> MatchEmission {
    let action = match found.side {
        MatchSide::FromWrittenTarget => BpsAction::TargetCopy,
        MatchSide::FromSource if found.file_position == output_position => BpsAction::SourceRead,
        MatchSide::FromSource => BpsAction::SourceCopy,
    };
    MatchEmission {
        action,
        file_position: found.file_position,
        length: found.length,
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
/// * `action_byte_cost` covers the action header byte plus the
///   offset payload (zero for `SourceRead`); see [`match_byte_cost`].
/// * `pending_flush_cost` (0 or 1) pays for the `TargetRead` flush
///   varint that emitting would force.
/// * `single_byte_tiebreaker` (0 or 1) adds one when `length == 1`,
///   breaking ties against emitting the smallest possible action.
/// * The leading `+ 1`, combined with the `>=` comparison, makes
///   the threshold a strict-improvement margin: we emit only when
///   the match strictly saves bytes, never when it merely ties.
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
// live in this module to keep the convention contained. The finder
// imports [`varint_cost`] and [`encode_delta`] to rank candidates in
// the same bytes the emitter will spend.

fn encode_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value & 0x7F) as u8);
        value >>= 7;
        value -= 1;
    }
    out.push((value | 0x80) as u8);
}

/// Number of bytes a value would occupy when byuu-varint encoded.
pub(crate) fn varint_cost(mut value: u64) -> usize {
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
pub(crate) fn encode_delta(previous: usize, next: usize) -> u64 {
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
                let mut mixed = state;
                mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d049bb133111eb);
                mixed ^= mixed >> 31;
                mixed as u8
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
        // Mostly SourceRead with one copy action — patch is very small.
        assert!(
            out.len() < 100,
            "expected compact patch, got {} bytes",
            out.len()
        );
    }

    #[test]
    fn scattered_edits_emit_only_aligned_actions() {
        // One byte flipped every 4 KiB: the shape of a typical ROM edit.
        // Every flip is a one-byte TargetRead and everything between is
        // the offset-free SourceRead — no copy action ever spends a
        // delta, however tempting a far coincidence might look.
        let source = pseudo_random(0x99, 1 << 18);
        let flip_stride = 4096;
        let mut target = source.clone();
        for spot in (0..target.len()).step_by(flip_stride) {
            target[spot] ^= 0x5a;
        }
        let out = bps_diff(&source, &target);
        let mut cursor = 0;
        let mut action_count = 0;
        while cursor < out.len() {
            let header = decode_varint(&out, &mut cursor);
            let tag = header & 3;
            let length = (header >> 2) + 1;
            if tag == BpsAction::TargetRead.wire_tag() {
                assert_eq!(length, 1, "every literal is a single flipped byte");
                cursor += length as usize;
            } else {
                assert_eq!(tag, BpsAction::SourceRead.wire_tag(), "no copy action spends a delta");
                assert_eq!(length, (flip_stride - 1) as u64);
            }
            action_count += 1;
        }
        assert_eq!(action_count, 2 * (target.len() / flip_stride));
    }
}
