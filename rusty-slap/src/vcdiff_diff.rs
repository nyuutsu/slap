//! VCDIFF cover construction: the segmentation of a target into copies
//! and literals that reconstruct it against a source.
//!
//! The cover is the seam between matching and emission — the matcher
//! segments the target, `Slap.VCDIFF.Create` serializes the segments to
//! wire bytes. This module owns the cover's shape (the [`CoverSegment`]
//! vocabulary and the greedy parse that lays segments down) and drives a
//! longest-match engine to fill it. That engine is the suffix-array
//! matcher in [`crate::vcdiff_suffix_sort`]: at each target position the
//! parse asks it for the longest run that recurs earlier in the
//! superstring `U = source ++ target`, takes it when it clears
//! [`MIN_MATCH`], and otherwise grows the current literal run by a byte.
//!
//! The naive quadratic scan that once answered that query lives on in
//! this module's tests as the differential oracle: exhaustively correct,
//! unusably slow, and the reference the suffix-array engine is held
//! against.

use crate::vcdiff_suffix_sort::{Match, SuperstringMatcher};

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
///
/// The longest-match engine is the suffix-array matcher built once here;
/// [`greedy_cover`] drives it. The naive scan this engine replaces lives
/// on as the differential oracle in this module's tests.
pub fn vcdiff_cover(source: &[u8], target: &[u8]) -> Vec<CoverSegment> {
    let matcher = SuperstringMatcher::build(source, target);
    greedy_cover(target.len(), |position| matcher.longest_match_at(position))
}

/// Greedily parse a target of `target_length` bytes into a cover: at
/// each position take the longest match the engine reports when it
/// clears [`MIN_MATCH`], otherwise extend the pending literal run by one
/// byte. The match engine is a parameter, so the production suffix-array
/// matcher and the test oracle drive this identical parse — the cover's
/// shape is decided here, once, and the engine only answers the longest-
/// match query.
fn greedy_cover(
    target_length: usize,
    mut longest_match_at: impl FnMut(usize) -> Option<Match>,
) -> Vec<CoverSegment> {
    let mut segments = Vec::new();
    let mut literal_start = 0; // start, in the target, of the pending literal run
    let mut position = 0;
    while position < target_length {
        match longest_match_at(position) {
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
    flush_literal(&mut segments, literal_start, target_length);
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

// ── Differential oracle and tests ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{greedy_cover, vcdiff_cover, CoverSegment, SegmentKind};
    use crate::vcdiff_suffix_sort::{Match, SuperstringMatcher};

    // ── The naive quadratic matcher, retained as the oracle ──────────

    /// The longest run of target bytes beginning at `position` that also
    /// occurs earlier in `U` — at a `U` offset strictly before the write
    /// head (`source.len() + position`). `None` only when no candidate
    /// matches even one byte; the caller applies the [`super::MIN_MATCH`]
    /// floor. The quadratic scan the suffix-array engine replaced, kept
    /// as the exhaustively-correct reference.
    fn naive_longest_match_at(source: &[u8], target: &[u8], position: usize) -> Option<Match> {
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

    /// Match the target at `position` against the superstring at
    /// `candidate`, returning the matched length. Bounded by
    /// [`match_reach`], so a source-segment match never crosses into the
    /// target region and no match runs past the target's end. Reads `U`
    /// through [`byte_in_superstring`], so a match that overruns the
    /// write head — the run-length case — is found naturally.
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

    /// How far a match anchored at `candidate` may run. A source-region
    /// candidate is capped at the source's end (a COPY beginning in the
    /// source segment may not cross into the target region); both regions
    /// are capped at the target bytes still to be produced.
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

    // ── Random inputs and cover utilities ────────────────────────────

    /// SplitMix64, matching the house pseudo-random helper.
    fn pseudo_random_bytes(seed: u64, length: usize) -> Vec<u8> {
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

    /// Bytes from a deliberately small alphabet, to force the long
    /// repeats and self-referential overlaps that exercise the cover's
    /// COPY and run-length paths.
    fn pseudo_random_low_alphabet(seed: u64, length: usize, alphabet: u8) -> Vec<u8> {
        pseudo_random_bytes(seed, length)
            .into_iter()
            .map(|byte| byte % alphabet)
            .collect()
    }

    /// The cover's structure with offsets deliberately dropped: each
    /// segment as `(kind tag, length)`. Offsets are excluded because any
    /// valid longest-match occurrence is correct, so two engines may pick
    /// different-but-equally-valid offsets; the structure must still
    /// agree.
    fn cover_structure(cover: &[CoverSegment]) -> Vec<(u8, u64)> {
        cover
            .iter()
            .map(|segment| {
                let tag = match segment.kind {
                    SegmentKind::Literal => 0,
                    SegmentKind::Copy => 1,
                };
                (tag, segment.length)
            })
            .collect()
    }

    /// Rebuild the target from a cover, reading copies out of
    /// `source ++ produced-so-far` byte by byte (so a self-referential
    /// overlap resolves) and literals out of the target. A wrong copy
    /// offset reproduces wrong bytes here even when the structure agrees,
    /// so this validates the offsets the structure check leaves free.
    fn reconstruct_from_cover(source: &[u8], target: &[u8], cover: &[CoverSegment]) -> Vec<u8> {
        let mut produced: Vec<u8> = Vec::with_capacity(target.len());
        for segment in cover {
            let offset = segment.offset as usize;
            let length = segment.length as usize;
            match segment.kind {
                SegmentKind::Literal => produced.extend_from_slice(&target[offset..offset + length]),
                SegmentKind::Copy => {
                    for step in 0..length {
                        let index = offset + step;
                        let byte = if index < source.len() {
                            source[index]
                        } else {
                            produced[index - source.len()]
                        };
                        produced.push(byte);
                    }
                }
            }
        }
        produced
    }

    /// `(seed, source length, target length, alphabet size)` — spanning
    /// empty sides, unrelated and related pairs, heavy repetition, and
    /// both size orderings.
    const CASES: &[(u64, usize, usize, u8)] = &[
        (0x01, 0, 0, 2),     // both empty
        (0x02, 0, 64, 3),    // empty source: pure self-reference
        (0x03, 64, 0, 3),    // empty target
        (0x04, 50, 50, 2),   // tiny alphabet, heavy overlap
        (0x05, 80, 80, 4),
        (0x06, 200, 137, 6), // source longer than target
        (0x07, 60, 240, 5),  // target longer than source
        (0x08, 300, 300, 255), // full alphabet: few coincidental matches
        (0x09, 1, 1, 2),     // single bytes
        (0x0a, 512, 512, 16),
    ];

    fn case_inputs(seed: u64, source_len: usize, target_len: usize, alphabet: u8) -> (Vec<u8>, Vec<u8>) {
        let source = pseudo_random_low_alphabet(seed, source_len, alphabet);
        let target = pseudo_random_low_alphabet(seed ^ 0xa5a5, target_len, alphabet);
        (source, target)
    }

    // ── The load-bearing differential check ──────────────────────────

    #[test]
    fn cover_structure_matches_the_naive_oracle() {
        for &(seed, source_len, target_len, alphabet) in CASES {
            let (source, target) = case_inputs(seed, source_len, target_len, alphabet);
            let matcher = SuperstringMatcher::build(&source, &target);
            let suffix_array_cover =
                greedy_cover(target.len(), |position| matcher.longest_match_at(position));
            let oracle_cover =
                greedy_cover(target.len(), |position| naive_longest_match_at(&source, &target, position));
            assert_eq!(
                cover_structure(&suffix_array_cover),
                cover_structure(&oracle_cover),
                "structure divergence at case seed {seed:#x}",
            );
        }
    }

    #[test]
    fn cover_reconstructs_the_target() {
        for &(seed, source_len, target_len, alphabet) in CASES {
            let (source, target) = case_inputs(seed, source_len, target_len, alphabet);
            let cover = vcdiff_cover(&source, &target);
            assert_eq!(
                reconstruct_from_cover(&source, &target, &cover),
                target,
                "reconstruction divergence at case seed {seed:#x}",
            );
        }
    }

    #[test]
    fn identical_source_and_target_is_a_single_copy() {
        let source = pseudo_random_bytes(0xc0de, 1000);
        let cover = vcdiff_cover(&source, &source);
        assert_eq!(cover.len(), 1);
        assert!(matches!(cover[0].kind, SegmentKind::Copy));
        assert_eq!(cover[0].offset, 0);
        assert_eq!(cover[0].length, 1000);
        assert_eq!(reconstruct_from_cover(&source, &source, &cover), source);
    }

    #[test]
    fn interleaved_source_chunks_round_trip() {
        // A target stitched from source slices in a shuffled order plus
        // an unmatched literal — the multi-segment crossing case, where
        // the cover must alternate copies and a literal and the copies
        // reach back into different parts of the source.
        let source: Vec<u8> = (0..200u32).map(|n| (n * 7) as u8).collect();
        let mut target = Vec::new();
        target.extend_from_slice(&source[120..160]);
        target.extend_from_slice(b"an unmatched literal stretch");
        target.extend_from_slice(&source[10..70]);
        target.extend_from_slice(&source[180..200]);
        let cover = vcdiff_cover(&source, &target);
        assert_eq!(reconstruct_from_cover(&source, &target, &cover), target);
        assert!(
            cover.iter().filter(|s| matches!(s.kind, SegmentKind::Copy)).count() >= 3,
            "expected several copies reaching into different source regions",
        );
    }

    #[test]
    fn handles_a_megabyte_pair() {
        // A megabyte target derived from a megabyte source: large enough
        // that the quadratic oracle would take minutes. The suffix-array
        // engine finishes in a blink (sub-second in release), and the
        // reconstruction confirms the cover is still exact at scale. The
        // generous time bound is a regression tripwire — a return to
        // quadratic behaviour here would run for far longer than this.
        let source = pseudo_random_low_alphabet(0x512e, 1 << 20, 64);
        let mut target = source.clone();
        for spot in (0..target.len()).step_by(4096) {
            target[spot] ^= 0x5a;
        }
        let started = std::time::Instant::now();
        let cover = vcdiff_cover(&source, &target);
        let elapsed = started.elapsed();
        assert_eq!(reconstruct_from_cover(&source, &target, &cover), target);
        assert!(elapsed < std::time::Duration::from_secs(30), "matcher took {elapsed:?}");
    }
}
