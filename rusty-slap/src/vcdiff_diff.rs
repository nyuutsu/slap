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
//! why. Every caller goes through the windowed entry, the RFC arc and
//! the custom-table inner delta slicing at the target's own length for
//! their one whole-target window.
//!
//! [`vcdiff_produced_target_covers`] is the same parse driven by the
//! other engine: each window covered against the output of the windows
//! before it, for the VCD_TARGET arm of RFC-flavor windowed creation.
//! The two entries share the greedy parse and the segment vocabulary;
//! what differs is the engine, and with it the coordinate space a
//! copy's offset lives in.

use crate::vcdiff_hash_chain::{HashChainMatcher, ProducedTargetMatcher};

/// A match the engine stands behind at one target position: where it
/// begins in the superstring `U = source ++ target`, how long it runs,
/// and how far back into the pending literal run it reaches. The
/// parse's query-answer vocabulary, owned here by the asker; the
/// engine answers in it.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Match {
    pub superstring_offset: usize,
    pub length: usize,
    /// How many bytes before the queried position the match begins:
    /// the engines extend an accepted match backward while the bytes
    /// before it agree, and never past the query's literal floor —
    /// everything earlier is already covered.
    pub starts_earlier_by: usize,
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

/// Segment a target into a single-window cover against a source: the
/// whole-target reading of [`vcdiff_windowed_covers`]. A test
/// convenience — production covers a patch's windows and always goes
/// through the windowed entry, even the RFC arc's one whole-target
/// window and the custom-table inner delta (both slice at the target's
/// length on the Haskell side).
#[cfg(test)]
fn vcdiff_cover(source: &[u8], target: &[u8]) -> Vec<CoverSegment> {
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
            greedy_cover(window.len(), |position, literal_floor| matcher.match_at(position, literal_floor))
        })
        .collect()
}

/// Segment a target into one cover per window against the target's own
/// earlier windows: the produced-target sibling of
/// [`vcdiff_windowed_covers`], for the VCD_TARGET arm of RFC-flavor
/// windowed creation. No source is involved — a VCD_TARGET window
/// draws only on produced output, which is exactly the target prefix
/// below the window's base. A copy's offset is therefore a position in
/// the target itself; a literal's offset indexes the window's slice,
/// as ever. Window slicing matches the sibling: equal slices, the
/// final one the remainder, the empty target one empty window.
pub fn vcdiff_produced_target_covers(
    target: &[u8],
    window_length: usize,
) -> Vec<Vec<CoverSegment>> {
    assert!(
        window_length > 0,
        "vcdiff produced-target covers: window length must be positive"
    );
    if target.is_empty() {
        return vec![Vec::new()];
    }
    let mut matcher = ProducedTargetMatcher::build(target);
    let mut window_base = 0;
    target
        .chunks(window_length)
        .map(|window| {
            matcher.begin_window(window_base, window.len());
            window_base += window.len();
            greedy_cover(window.len(), |position, literal_floor| matcher.match_at(position, literal_floor))
        })
        .collect()
}

/// Greedily parse a target of `target_length` bytes into a cover: take
/// every match the engine offers, and extend the pending literal run by
/// one byte where it offers none. The engine is a parameter, and it
/// owns the whole worth-taking judgment — the parse decides only the
/// segmentation that follows from its answers, so a different engine
/// (the tests drive hand-shaped ones) changes what is found, never how
/// a cover is laid down. The query carries the pending literal's start
/// so an offered match may begin inside the run ('starts_earlier_by');
/// the literal then flushes shorter, its tail absorbed into the copy.
fn greedy_cover(
    target_length: usize,
    mut worthwhile_match_at: impl FnMut(usize, usize) -> Option<Match>,
) -> Vec<CoverSegment> {
    let mut segments = Vec::new();
    let mut literal_start = 0; // start, in the target, of the pending literal run
    let mut target_position = 0;
    while target_position < target_length {
        match worthwhile_match_at(target_position, literal_start) {
            Some(taken) => {
                // The engine's contract: backward reach never passes the
                // literal floor. A reach past it would double-cover
                // bytes, quietly, so the parse holds the engine to it.
                let copy_start = target_position
                    .checked_sub(taken.starts_earlier_by)
                    .filter(|start| *start >= literal_start)
                    .expect("vcdiff cover: match reaches back past the pending literal floor (engine contract violation)");
                flush_literal(&mut segments, literal_start, copy_start);
                segments.push(CoverSegment {
                    kind: SegmentKind::Copy,
                    offset: taken.superstring_offset as u64,
                    length: taken.length as u64,
                });
                target_position = copy_start + taken.length;
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
    use super::{
        vcdiff_cover, vcdiff_produced_target_covers, vcdiff_windowed_covers, CoverSegment,
        SegmentKind,
    };

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
        // reaching across the file. The first flip sits one stride in,
        // not at position 0: this test is about lockstep, which is
        // pursuit's story, and a flip at the very start would instead
        // measure cold discovery meeting the tile alignment.
        let source = pseudo_random_bytes(0x77, 1 << 18);
        let flip_stride = 4096;
        let mut target = source.clone();
        for spot in (flip_stride..target.len()).step_by(flip_stride) {
            target[spot] ^= 0x5a;
        }
        let cover = vcdiff_cover(&source, &target);
        assert_eq!(cover.len(), 2 * (target.len() / flip_stride) - 1);
        let mut output_cursor = 0u64;
        for segment in &cover {
            match segment.kind {
                SegmentKind::Literal => assert_eq!(segment.length, 1),
                SegmentKind::Copy => {
                    assert_eq!(
                        segment.offset, output_cursor,
                        "a copy left lockstep at output position {output_cursor}",
                    );
                    let expected_length =
                        if output_cursor == 0 { flip_stride } else { flip_stride - 1 };
                    assert_eq!(segment.length, expected_length as u64);
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

    /// Rebuild the target from produced-target covers. Copies read at
    /// their flat target offsets out of the output built so far — the
    /// produced prefix and the window's own output are one buffer — and
    /// each is additionally held to legality: a copy starting before its
    /// window's base must not cross it, since the wire segment can only
    /// span produced output.
    fn reconstruct_from_produced_target_covers(
        target: &[u8],
        covers: &[Vec<CoverSegment>],
    ) -> Vec<u8> {
        let mut produced: Vec<u8> = Vec::with_capacity(target.len());
        for cover in covers {
            let window_base = produced.len();
            for segment in cover {
                let offset = segment.offset as usize;
                let length = segment.length as usize;
                match segment.kind {
                    SegmentKind::Literal => produced.extend_from_slice(
                        &target[window_base + offset..window_base + offset + length],
                    ),
                    SegmentKind::Copy => {
                        assert!(
                            offset >= window_base || offset + length <= window_base,
                            "a copy crossed its window's base: [{offset}, {})",
                            offset + length,
                        );
                        for step in 0..length {
                            produced.push(produced[offset + step]);
                        }
                    }
                }
            }
        }
        produced
    }

    #[test]
    fn produced_target_covers_reconstruct_every_window() {
        for &(seed, _source_length, target_length, alphabet) in CASES {
            let target = pseudo_random_low_alphabet(seed ^ 0x5a5a, target_length, alphabet);
            for window_length in [7usize, 64, 4096] {
                let covers = vcdiff_produced_target_covers(&target, window_length);
                assert_eq!(covers.len(), target.len().div_ceil(window_length).max(1));
                assert_eq!(
                    reconstruct_from_produced_target_covers(&target, &covers),
                    target,
                    "reconstruction divergence at seed {seed:#x}, window {window_length}",
                );
            }
        }
    }

    #[test]
    fn produced_target_covers_reach_across_windows() {
        // The repeated-pattern shape of windows_never_reference_earlier_windows,
        // through the other engine: 16-byte windows over a repeating
        // 16-byte pattern copy an earlier window instead of carrying
        // literals — the reference the source-pair engine must not find
        // is here the whole point.
        let pattern = pseudo_random_bytes(0x74, 16);
        let mut target = Vec::new();
        for _ in 0..8 {
            target.extend_from_slice(&pattern);
        }
        let covers = vcdiff_produced_target_covers(&target, 16);
        assert_eq!(covers.len(), 8);
        assert_eq!(covers[0].len(), 1);
        assert!(matches!(covers[0][0].kind, SegmentKind::Literal));
        for (window_index, cover) in covers.iter().enumerate().skip(1) {
            assert_eq!(cover.len(), 1);
            assert!(matches!(cover[0].kind, SegmentKind::Copy));
            assert_eq!(
                (cover[0].offset, cover[0].length),
                (((window_index - 1) * 16) as u64, 16),
                "window {window_index} copies the newest settled repeat",
            );
        }
        assert_eq!(reconstruct_from_produced_target_covers(&target, &covers), target);
    }

    #[test]
    fn an_empty_target_is_one_empty_produced_target_window() {
        let covers = vcdiff_produced_target_covers(&[], 4096);
        assert_eq!(covers.len(), 1);
        assert!(covers[0].is_empty());
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
