//! A deliberately naive VCDIFF cover matcher.
//!
//! It segments the target into copies and literals against the
//! superstring `U = source ++ produced-target`, by the simplest correct
//! technique: a greedy longest-match scan with no lookahead. At each
//! target position it finds the longest run that recurs earlier in `U`,
//! takes it when it clears [`MIN_MATCH`], and otherwise grows the
//! current literal run by one byte.
//!
//! This is the placeholder the suffix-array matcher (a later stage)
//! replaces, and the trustworthy reference that one is then
//! differentially tested against — so it is written for obvious
//! correctness, not speed. The scan is quadratic and that is fine:
//! there is no input it must be fast on yet.

/// Shortest run the matcher emits as a COPY. Four is the natural floor:
/// it is the smallest size the default code table's COPY rows encode,
/// and below it a COPY (opcode + coded size + address) does not beat
/// writing the bytes literally.
const MIN_MATCH: usize = 4;

/// Whether a cover segment copies earlier bytes or carries literal
/// target bytes. Crosses the FFI seam as a single tag byte
/// (0 = `Literal`, 1 = `Copy`).
pub enum SegmentKind {
    Literal,
    Copy,
}

/// One segment of a cover. A copy reproduces `length` bytes from the
/// absolute `offset` in `U = source ++ target`; a literal carries
/// `length` bytes beginning at the `offset` into the target. The two
/// share the (offset, length) shape, so the cover crosses the FFI seam
/// as one uniform triple stream tagged by `kind`.
pub struct CoverSegment {
    pub kind: SegmentKind,
    pub offset: u64,
    pub length: u64,
}

/// Segment a target into a cover against a source. Total: every input
/// yields a cover, the empty target included (the empty cover). When
/// nothing recurs, the whole target comes back as a single literal.
pub fn vcdiff_cover(source: &[u8], target: &[u8]) -> Vec<CoverSegment> {
    let mut segments = Vec::new();
    let mut literal_start = 0; // start, in the target, of the pending literal run
    let mut position = 0;
    while position < target.len() {
        match longest_match_at(source, target, position) {
            Some(found) if found.length >= MIN_MATCH => {
                flush_literal(&mut segments, literal_start, position);
                segments.push(CoverSegment {
                    kind: SegmentKind::Copy,
                    offset: found.u_offset as u64,
                    length: found.length as u64,
                });
                position += found.length;
                literal_start = position;
            }
            // No match, or one too short to be worth a COPY: this byte
            // extends the pending literal run.
            _ => position += 1,
        }
    }
    flush_literal(&mut segments, literal_start, target.len());
    segments
}

/// Emit the pending literal run `[start, end)` as a literal segment,
/// when it holds at least one byte. An empty run — a copy following
/// straight after another, or a copy at the very start — produces
/// nothing.
fn flush_literal(segments: &mut Vec<CoverSegment>, start: usize, end: usize) {
    if end > start {
        segments.push(CoverSegment {
            kind: SegmentKind::Literal,
            offset: start as u64,
            length: (end - start) as u64,
        });
    }
}

/// A match found in the superstring: its absolute `U` offset and the
/// number of bytes that matched.
struct Match {
    u_offset: usize,
    length: usize,
}

/// The longest run of target bytes beginning at `position` that also
/// occurs earlier in `U` — at a `U` offset strictly before the write
/// head (`source.len() + position`). Ties break to the earliest (lowest)
/// offset, so the matcher's output is deterministic. `None` only when no
/// candidate matches even one byte; the caller applies the [`MIN_MATCH`]
/// floor.
fn longest_match_at(source: &[u8], target: &[u8], position: usize) -> Option<Match> {
    let write_head = source.len() + position;
    let mut best: Option<Match> = None;
    for candidate in 0..write_head {
        let length = extend_match(source, target, candidate, position);
        if length > 0 && best.as_ref().is_none_or(|found| length > found.length) {
            best = Some(Match { u_offset: candidate, length });
        }
    }
    best
}

/// Match the target at `position` against the superstring at `candidate`,
/// returning the matched length. Bounded by [`match_reach`], so a
/// source-segment match never crosses into the target region and no
/// match runs past the target's end. Reads `U` through
/// [`byte_in_superstring`], so a match that overruns the write head —
/// copying bytes it is itself producing, the run-length case — is found
/// naturally; Apply reproduces it the same way.
fn extend_match(source: &[u8], target: &[u8], candidate: usize, position: usize) -> usize {
    let reach = match_reach(source, target, candidate, position);
    let mut length = 0;
    while length < reach
        && byte_in_superstring(source, target, candidate + length) == target[position + length]
    {
        length += 1;
    }
    length
}

/// How far a match anchored at `candidate` may run, before any byte
/// comparison. A source-region candidate is capped at the source's end:
/// a COPY that begins in the source segment may not cross into the
/// target region (the core "copies stay within their segment"
/// invariant). Both regions are capped at the target bytes still to be
/// produced.
fn match_reach(source: &[u8], target: &[u8], candidate: usize, position: usize) -> usize {
    let remaining_target = target.len() - position;
    if candidate < source.len() {
        (source.len() - candidate).min(remaining_target)
    } else {
        remaining_target
    }
}

/// The byte at absolute offset `u_offset` in `U = source ++ target`.
fn byte_in_superstring(source: &[u8], target: &[u8], u_offset: usize) -> u8 {
    if u_offset < source.len() {
        source[u_offset]
    } else {
        target[u_offset - source.len()]
    }
}
