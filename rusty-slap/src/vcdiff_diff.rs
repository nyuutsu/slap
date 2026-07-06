//! VCDIFF cover construction: the segmentation of a target into copies
//! and literals that reconstruct it against a source.
//!
//! The cover is the seam between matching and emission — the matcher
//! segments the target, `Slap.VCDIFF.Create` serializes the segments to
//! wire bytes. This module owns the cover's shape (the [`CoverSegment`]
//! vocabulary and the greedy parse that lays segments down) and drives a
//! match engine to fill it. That engine is the cost-aware matcher in
//! [`crate::vcdiff_hash_chain`]: at each position the parse asks for a
//! copy worth its wire cost, takes what is offered, and otherwise grows
//! the current literal run by a byte. What "worth taking" means — and
//! why it is not "the longest match available" — is that module's
//! story; the parse holds no thresholds of its own.
//!
//! A patch's windows each get their own parse over their own slice
//! ([`vcdiff_windowed_covers`]): the matcher indexes the source once
//! and runs one session per window, so every copy stays inside
//! `source ++ that window's slice` — the engine's Windows note has the
//! why. [`vcdiff_cover`] is the one-window reading the RFC arc and the
//! custom-table inner delta use.

use crate::vcdiff_hash_chain::HashChainMatcher;

/// A match the engine stands behind at one target position: where it
/// begins in the superstring `U = source ++ target` and how long it
/// runs. The parse's query-answer vocabulary, owned here by the asker;
/// the engine answers in it.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Match {
    pub superstring_offset: usize,
    pub length: usize,
}

/// Whether a cover segment copies earlier bytes or carries literal
/// target bytes. Crosses the FFI seam as a single tag byte
/// (0 = `Literal`, 1 = `Copy`).
pub enum SegmentKind {
    Literal,
    Copy,
}

/// One segment of a cover. A copy reproduces `length` bytes from the
/// absolute `offset` in `U = source ++ window`; a literal carries
/// `length` bytes beginning at the `offset` into the window's slice.
/// Both offsets are window-relative (a one-window cover's window is
/// the whole target). The two share the (offset, length) shape, so the
/// cover crosses the FFI seam as one uniform triple stream tagged by
/// `kind`.
pub struct CoverSegment {
    pub kind: SegmentKind,
    pub offset: u64,
    pub length: u64,
}

/// Segment a target into a single-window cover against a source.
/// Total: every input yields a cover, the empty target included (the
/// empty cover). When nothing is worth copying, the whole target comes
/// back as a single literal.
pub fn vcdiff_cover(source: &[u8], target: &[u8]) -> Vec<CoverSegment> {
    vcdiff_windowed_covers(source, target, target.len().max(1))
        .into_iter()
        .next()
        .expect("windowed covers always hold at least one window")
}

/// Segment a target into one cover per window: equal slices of
/// `window_length` bytes, the final one the remainder, the empty
/// target one empty window (the emission the reference tool itself
/// writes for an empty target, and refuses the zero-window
/// alternative of). The matcher indexes the source once; each window's
/// session sees only its own slice, so no cover ever copies from an
/// earlier window's output.
pub fn vcdiff_windowed_covers<'pair>(
    source: &'pair [u8],
    target: &'pair [u8],
    window_length: usize,
) -> Vec<Vec<CoverSegment>> {
    assert!(window_length > 0, "vcdiff windowed covers: window length must be positive");
    if target.is_empty() {
        return vec![Vec::new()];
    }
    let mut matcher = HashChainMatcher::build(source, window_length.min(target.len()));
    target
        .chunks(window_length)
        .map(|window| {
            matcher.begin_window(window);
            greedy_cover(window.len(), |position| matcher.match_at(position))
        })
        .collect()
}

/// Greedily parse a target of `target_length` bytes into a cover: take
/// every match the engine offers, and extend the pending literal run by
/// one byte where it offers none. The engine is a parameter, and it
/// owns the whole worth-taking judgment — the parse decides only the
/// segmentation that follows from its answers, so a different engine
/// (the tests drive hand-shaped ones) changes what is found, never how
/// a cover is laid down.
fn greedy_cover(
    target_length: usize,
    mut worthwhile_match_at: impl FnMut(usize) -> Option<Match>,
) -> Vec<CoverSegment> {
    let mut segments = Vec::new();
    let mut literal_start = 0; // start, in the target, of the pending literal run
    let mut target_position = 0;
    while target_position < target_length {
        match worthwhile_match_at(target_position) {
            Some(taken) => {
                flush_literal(&mut segments, literal_start, target_position);
                segments.push(CoverSegment {
                    kind: SegmentKind::Copy,
                    offset: taken.superstring_offset as u64,
                    length: taken.length as u64,
                });
                target_position += taken.length;
                literal_start = target_position;
            }
            None => target_position += 1,
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

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{vcdiff_cover, vcdiff_windowed_covers, CoverSegment, SegmentKind};

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

    /// Rebuild the target from a cover, reading copies out of
    /// `source ++ produced-so-far` byte by byte (so a self-referential
    /// overlap resolves) and literals out of the target. This is the
    /// hard correctness bar: whatever the engine chose to find or skip,
    /// a cover that fails here is wrong.
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

    #[test]
    fn cover_reconstructs_the_target() {
        for &(seed, source_len, target_len, alphabet) in CASES {
            let source = pseudo_random_low_alphabet(seed, source_len, alphabet);
            let target = pseudo_random_low_alphabet(seed ^ 0xa5a5, target_len, alphabet);
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
    fn scattered_edits_stay_in_lockstep() {
        // A source with one byte flipped every 4 KiB: the shape of a
        // typical ROM edit, and the shape that exposed the old exact-
        // longest contract — its cover chased four-byte coincidences all
        // over the source, trading compressible literals for address
        // noise. The cover must be the boring one: a one-byte literal
        // and an aligned copy per flip, every copy in lockstep, nothing
        // reaching across the file.
        let source = pseudo_random_bytes(0x77, 1 << 18);
        let flip_stride = 4096;
        let mut target = source.clone();
        for spot in (0..target.len()).step_by(flip_stride) {
            target[spot] ^= 0x5a;
        }
        let cover = vcdiff_cover(&source, &target);
        assert_eq!(cover.len(), 2 * (target.len() / flip_stride));
        let mut output_cursor = 0u64;
        for segment in &cover {
            match segment.kind {
                SegmentKind::Literal => assert_eq!(segment.length, 1),
                SegmentKind::Copy => {
                    assert_eq!(
                        segment.offset, output_cursor,
                        "a copy left lockstep at output position {output_cursor}",
                    );
                    assert_eq!(segment.length, (flip_stride - 1) as u64);
                }
            }
            output_cursor += segment.length;
        }
        assert_eq!(reconstruct_from_cover(&source, &target, &cover), target);
    }

    #[test]
    fn an_empty_target_is_one_empty_window() {
        let source = pseudo_random_bytes(0x71, 64);
        let covers = vcdiff_windowed_covers(&source, &[], 4096);
        assert_eq!(covers.len(), 1);
        assert!(covers[0].is_empty());
    }

    #[test]
    fn windows_never_reference_earlier_windows() {
        // A 16-byte pattern repeated eight times over an empty source:
        // one window over the whole target copies the repeats, while
        // 16-byte windows each see only their own slice and must carry
        // their bytes literally — the cross-window copy does not exist
        // to find.
        let pattern = pseudo_random_bytes(0x72, 16);
        let mut target = Vec::new();
        for _ in 0..8 {
            target.extend_from_slice(&pattern);
        }
        let whole = vcdiff_cover(&[], &target);
        assert!(
            whole.iter().any(|segment| matches!(segment.kind, SegmentKind::Copy)),
            "a single window sees the repeats",
        );
        let windowed = vcdiff_windowed_covers(&[], &target, 16);
        assert_eq!(windowed.len(), 8);
        for cover in &windowed {
            assert_eq!(cover.len(), 1);
            assert!(matches!(cover[0].kind, SegmentKind::Literal));
        }
    }

    #[test]
    fn windowed_covers_reconstruct_every_window() {
        // Scattered edits with a window length deliberately unaligned
        // with the edit stride, so edits land at different offsets
        // within each window.
        let source = pseudo_random_bytes(0x73, 1 << 16);
        let mut target = source.clone();
        for spot in (0..target.len()).step_by(4096) {
            target[spot] ^= 0x5a;
        }
        let window_length = 10_000;
        let covers = vcdiff_windowed_covers(&source, &target, window_length);
        assert_eq!(covers.len(), target.len().div_ceil(window_length));
        for (window, cover) in target.chunks(window_length).zip(&covers) {
            assert_eq!(reconstruct_from_cover(&source, window, cover), window);
        }
    }

    #[test]
    fn a_padding_coincidence_does_not_lure_the_cover_off_lockstep() {
        // Long zero runs with one byte flipped, and the flip's window
        // recurring at a far zero position: an alignment-blind engine
        // would spend a noisy far address on that recurrence one byte
        // before pursuit resumes for free. The cover must be the
        // aligned one: copy to the flip, the flipped byte as a literal,
        // copy to the end.
        let mut source = vec![0u8; 20000];
        for (index, byte) in source[10000..10100].iter_mut().enumerate() {
            *byte = (index * 7) as u8;
        }
        source[15000] = 0x5a;
        let mut target = source.clone();
        target[5000] ^= 0x5a;
        let cover = vcdiff_cover(&source, &target);
        let shape: Vec<(bool, u64, u64)> = cover
            .iter()
            .map(|segment| {
                (matches!(segment.kind, SegmentKind::Copy), segment.offset, segment.length)
            })
            .collect();
        assert_eq!(
            shape,
            vec![(true, 0, 5000), (false, 5000, 1), (true, 5001, 14999)],
        );
        assert_eq!(reconstruct_from_cover(&source, &target, &cover), target);
    }

    #[test]
    fn interleaved_source_chunks_round_trip() {
        // A target stitched from source slices in a shuffled order plus
        // an unmatched literal — the multi-segment crossing case, where
        // the cover must alternate copies and a literal and the copies
        // reach back into different parts of the source.
        let source: Vec<u8> = (0..200u32).map(|position| (position * 7) as u8).collect();
        let mut target = Vec::new();
        target.extend_from_slice(&source[120..160]);
        target.extend_from_slice(b"an unmatched literal stretch");
        target.extend_from_slice(&source[10..70]);
        target.extend_from_slice(&source[180..200]);
        let cover = vcdiff_cover(&source, &target);
        assert_eq!(reconstruct_from_cover(&source, &target, &cover), target);
        assert!(
            cover.iter().filter(|segment| matches!(segment.kind, SegmentKind::Copy)).count() >= 3,
            "expected several copies reaching into different source regions",
        );
    }

    #[test]
    fn handles_a_megabyte_pair() {
        // A megabyte target derived from a megabyte source: large enough
        // to exercise the index at scale and confirm the cover is still
        // exact there. The generous time bound is a regression tripwire
        // — super-linear behaviour in the index or the probe would run
        // far past it.
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
