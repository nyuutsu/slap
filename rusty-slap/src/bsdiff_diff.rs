//! bsdiff differ: Colin Percival's approximate-region walk, with its
//! variables given their real names.
//!
//! Algorithm provenance: the walk follows the Android bsdiff tree
//! (`docs/bsdiff/upstream/bsdiff-android-22535836b12c.tar.gz`,
//! `bsdiff.cc`), which Percival endorses over his original reference.
//! The typed decomposition and the structured emission are slap's.
//!
//! The walk holds a settled boundary and its source alignment, and
//! carries two continuations as its own knowledge, each at one
//! decrement per step: how far the settled alignment keeps explaining
//! target bytes, and how far the current rival candidate keeps
//! running. The seeder (`bsdiff_hash_chain`) is asked at each position
//! only for fresh rivals — its tiled index answers at tile alignments,
//! and the carried continuations answer everywhere in between, which
//! the resumption break and the near-stationary escape both rely on.
//! Scanning forward, the walk keeps a running count of how many probed
//! bytes the settled alignment still explains, and breaks either when
//! the best answer is exactly the aligned continuation — an unedited
//! run resumed; the scan fast-forwards past it and emits nothing — or
//! when a rival out-explains the settled alignment by
//! [`REALIGNMENT_MARGIN`], which ends the region: extend the settled
//! side forward and the new seed backward, split the contested bytes,
//! and emit one instruction. The add region's bytes enter the diff
//! stream as target minus source — mostly zeros, a delta where a byte
//! truly changed, the stream bzip2 earns its keep on — and the gap
//! enters the extra stream verbatim.
//!
//! Crosses the FFI seam as parallel homogeneous buffers plus the two
//! raw streams; `Slap.BSDiff.FFI` reassembles them and
//! `Slap.BSDiff.Create` owns every wire byte (sign-magnitude fields,
//! bzip2 sections, the 32-byte header).

use crate::bsdiff_hash_chain::{SourceHashChainMatcher, ANCHOR_LENGTH};

/// A discovery must out-explain the settled alignment by this many
/// bytes before the walk re-aligns. Opening a region spends a 24-byte
/// control triple and a discontinuity in the diff stream, so a rival
/// alignment has to win by more than a coincidence. Also the width of
/// the near-stationary escape's "barely moved" bands, which are
/// defined by this margin (see [`near_stationary`]).
const REALIGNMENT_MARGIN: u64 = 8;

/// How many consecutive near-stationary probes the walk tolerates
/// before force-breaking. The escape is the Android tree's own,
/// earned in production: a large block differing from its alignment
/// by less than the margin can otherwise pin the scan crawling one
/// byte at a time. The walk-side partner of the seeder's probe cap.
const NEAR_STATIONARY_LIMIT: u32 = 100;

// ── Public surface ─────────────────────────────────────────────────────

/// One control triple, in the vocabulary `Slap.BSDiff.Types` speaks:
/// reconstruct `add_length` bytes as source plus diff-stream delta,
/// take `copy_length` bytes verbatim from the extra stream, then
/// displace the source cursor by `source_seek`.
pub struct ControlInstruction {
    pub add_length:  u64,
    pub copy_length: u64,
    pub source_seek: i64,
}

/// The differ's structured output. Crosses the FFI seam as parallel
/// homogeneous buffers (one per instruction field) plus the two raw
/// streams; this struct is the pre-serialization in-Rust shape.
pub struct BSDiffOutput {
    pub instructions: Vec<ControlInstruction>,
    pub diff_stream:  Vec<u8>,
    pub extra_stream: Vec<u8>,
}

/// Compute a bsdiff decomposition. Returns the pre-serialization
/// structured output for the FFI bridge.
///
/// Failures are internal-invariant violations only (an add region
/// escaping the source, emitted lengths not covering the target),
/// surfaced as `Err` rather than a panic; no input is refused —
/// bsdiff's 64-bit wire fields outreach anything a buffer can hold.
pub fn bsdiff_diff(source: &[u8], target: &[u8]) -> Result<BSDiffOutput, String> {
    if target.is_empty() {
        return Ok(BSDiffOutput {
            instructions: Vec::new(),
            diff_stream:  Vec::new(),
            extra_stream: Vec::new(),
        });
    }

    let matcher = SourceHashChainMatcher::build(source);
    let mut streams = RegionStreams::empty();
    let mut settled = SettledBoundary { target_start: 0, source_start: 0 };
    let mut scan: usize = 0;
    let mut discovered_length: usize = 0;
    let mut discovered_source_start: usize = 0;

    while scan < target.len() {
        // A fresh probe window: fast-forward past the region just
        // settled (or the resumed run just recognized), start the
        // aligned tally empty, and take up the aligned continuation
        // from here; the rival carry starts cold.
        scan += discovered_length;
        let mut aligned_tally_end = scan;
        let mut aligned_byte_count: u64 = 0;
        let mut near_stationary_probes: u32 = 0;
        let mut aligned_continuation = aligned_run_length(source, target, &settled, scan);
        let mut carried_rival_start: usize = 0;
        let mut carried_rival_length: usize = 0;

        while scan < target.len() {
            let previous = ProbeSnapshot {
                discovered_length,
                aligned_byte_count,
                discovered_source_start,
            };
            // The rival on offer: the seeder's fresh discovery where
            // one exists, otherwise the carried remainder of the last
            // one. The carried value is a floor on the truth — the
            // same run, one byte along — and fresh discoveries refresh
            // it at every tile alignment.
            let (rival_start, rival_length) =
                match matcher.longest_source_match(target, scan, settled.alignment() + scan as i64) {
                    Some(found) if found.length >= carried_rival_length => {
                        (found.source_start, found.length)
                    }
                    _ => (carried_rival_start, carried_rival_length),
                };
            // The longer explanation stands, the aligned continuation
            // taking ties — it is the side that spends no seek. Both
            // qualify from the seeder's own floor up, so a carried
            // answer stands exactly where a discovered one would.
            if rival_length >= ANCHOR_LENGTH && rival_length > aligned_continuation {
                discovered_length       = rival_length;
                discovered_source_start = rival_start;
            } else if aligned_continuation >= ANCHOR_LENGTH {
                discovered_length       = aligned_continuation;
                discovered_source_start = settled
                    .aligned_source_index(scan, source.len())
                    .expect("bsdiff differ: a nonzero aligned continuation names an in-range source index");
            } else {
                discovered_length       = 0;
                discovered_source_start = 0;
            }
            carried_rival_start  = rival_start;
            carried_rival_length = rival_length;

            // Extend the tally's right edge across the probe window,
            // counting bytes the settled alignment also explains. The
            // sweep stops at the first position whose aligned source
            // index falls outside the source and stays stopped — the
            // aligned index only grows with the position.
            while aligned_tally_end < scan + discovered_length {
                match settled.aligned_source_index(aligned_tally_end, source.len()) {
                    Some(source_index) => {
                        if source[source_index] == target[aligned_tally_end] {
                            aligned_byte_count += 1;
                        }
                        aligned_tally_end += 1;
                    }
                    None => break,
                }
            }

            let resumed_aligned_run = discovered_length as u64 == aligned_byte_count
                && discovered_length != 0;
            let cleared_the_margin =
                discovered_length as u64 >= aligned_byte_count + REALIGNMENT_MARGIN;
            if resumed_aligned_run || cleared_the_margin {
                break;
            }

            // The left edge leaves the window: drop `scan`'s
            // contribution from the tally, but only within the counted
            // region (`scan < aligned_tally_end`) and only where it was
            // an aligned match — never subtract a byte the sweep never
            // added. The sweep advances its right edge on a seeder hit,
            // and the seeder floors matches at the anchor width, so a
            // position it passed over sits outside the count.
            if scan < aligned_tally_end {
                if let Some(source_index) = settled.aligned_source_index(scan, source.len()) {
                    if source[source_index] == target[scan] {
                        aligned_byte_count -= 1;
                    }
                }
            }

            near_stationary_probes = if near_stationary(
                &previous,
                discovered_length,
                aligned_byte_count,
                discovered_source_start,
            ) {
                near_stationary_probes + 1
            } else {
                0
            };
            if near_stationary_probes > NEAR_STATIONARY_LIMIT {
                break;
            }
            scan += 1;
            // Both carries step with the scan. The aligned one is
            // recomputed where it runs out — an unedited run costs one
            // pass, a disagreeing byte one comparison; the rival one
            // simply drains until a fresh discovery replaces it.
            aligned_continuation = if aligned_continuation > 1 {
                aligned_continuation - 1
            } else {
                aligned_run_length(source, target, &settled, scan)
            };
            if carried_rival_length > 1 {
                carried_rival_start += 1;
                carried_rival_length -= 1;
            } else {
                carried_rival_length = 0;
            }
        }

        // Emit unless the walk broke for a resumed aligned run mid-
        // target: there the settled alignment already explains
        // everything scanned, and the fast-forward above is the whole
        // response. (A force-break always lands here — the resumption
        // test ran first, so its equality cannot hold.)
        if discovered_length as u64 != aligned_byte_count || scan == target.len() {
            let settled_forward_reach = forward_extension(source, target, &settled, scan);
            let seed_backward_reach = if scan < target.len() {
                backward_extension(source, target, &settled, scan, discovered_source_start)
            } else {
                0
            };
            let (add_length, seed_backward_reach) =
                if settled.target_start + settled_forward_reach > scan - seed_backward_reach {
                    split_contested_bytes(
                        source,
                        target,
                        &settled,
                        scan,
                        discovered_source_start,
                        settled_forward_reach,
                        seed_backward_reach,
                    )
                } else {
                    (settled_forward_reach, seed_backward_reach)
                };
            let copy_length = (scan - seed_backward_reach) - (settled.target_start + add_length);
            // At end of target, `discovered_source_start` is stale —
            // left over from the last probe, possibly regions back.
            // Nothing follows the final region, so the seek it feeds
            // is dead; the formula stays uniform rather than
            // special-casing the last iteration.
            let source_seek = (discovered_source_start as i64 - seed_backward_reach as i64)
                - (settled.source_start as i64 + add_length as i64);
            streams.emit_region(source, target, &settled, add_length, copy_length, source_seek)?;
            settled = SettledBoundary {
                target_start: scan - seed_backward_reach,
                source_start: discovered_source_start - seed_backward_reach,
            };
        }
    }

    streams.into_output_checked(target.len())
}

// ── The settled boundary ───────────────────────────────────────────────

/// Where the walk last settled: the first target byte not yet emitted,
/// with the source position that pairs with it. The alignment the pair
/// names (source index = target index + alignment) is what the walk
/// scores rival discoveries against.
struct SettledBoundary {
    target_start: usize,
    source_start: usize,
}

impl SettledBoundary {
    /// The signed displacement from a target index to its aligned
    /// source index.
    fn alignment(&self) -> i64 {
        self.source_start as i64 - self.target_start as i64
    }

    /// The source index the alignment names for a target position, or
    /// `None` when it falls outside the source on either side.
    fn aligned_source_index(&self, target_position: usize, source_length: usize) -> Option<usize> {
        let source_index = target_position as i64 + self.alignment();
        (0 <= source_index && source_index < source_length as i64).then(|| source_index as usize)
    }
}

/// How far the settled alignment keeps explaining target bytes from
/// `from` — the walk's own carried continuation. Compared a register
/// at a time; the walk recomputes this only where the previous carry
/// ran out, so each byte is visited once.
fn aligned_run_length(
    source: &[u8],
    target: &[u8],
    settled: &SettledBoundary,
    from: usize,
) -> usize {
    let Some(source_index) = settled.aligned_source_index(from, source.len()) else {
        return 0;
    };
    let reach = (source.len() - source_index).min(target.len() - from);
    matched_prefix_length(&source[source_index..source_index + reach], &target[from..from + reach])
}

/// Length of the common prefix of two slices, compared a register at a
/// time, the shorter's length its ceiling.
fn matched_prefix_length(left: &[u8], right: &[u8]) -> usize {
    let limit = left.len().min(right.len());
    // A first-byte disagreement is the usual answer at a recompute
    // point; take it with one load before the word loop reads sixteen.
    if limit == 0 || left[0] != right[0] {
        return 0;
    }
    let mut length = 0;
    while length + 8 <= limit {
        let left_word = u64::from_le_bytes(left[length..length + 8].try_into().unwrap());
        let right_word = u64::from_le_bytes(right[length..length + 8].try_into().unwrap());
        let disagreement = left_word ^ right_word;
        if disagreement != 0 {
            return length + (disagreement.trailing_zeros() / 8) as usize;
        }
        length += 8;
    }
    while length < limit && left[length] == right[length] {
        length += 1;
    }
    length
}

// ── The near-stationary escape ─────────────────────────────────────────

/// What one probe looked like, kept so the next can ask whether the
/// walk is crawling in place.
struct ProbeSnapshot {
    discovered_length:       usize,
    aligned_byte_count:      u64,
    discovered_source_start: usize,
}

/// Whether a probe barely moved from the one before it: length and
/// aligned count fell by at most the margin, the discovered start
/// crept forward by at most the margin, and the length sits inside
/// the margin band above the count — the exact bands of the endorsed
/// source's escape, its unsigned-wrap subtractions spelled as
/// explicit floors.
fn near_stationary(
    previous: &ProbeSnapshot,
    discovered_length: usize,
    aligned_byte_count: u64,
    discovered_source_start: usize,
) -> bool {
    let margin = REALIGNMENT_MARGIN as usize;
    let length_barely_fell = previous.discovered_length >= margin
        && previous.discovered_length - margin <= discovered_length
        && discovered_length <= previous.discovered_length;
    let count_barely_fell = previous.aligned_byte_count >= REALIGNMENT_MARGIN
        && previous.aligned_byte_count - REALIGNMENT_MARGIN <= aligned_byte_count
        && aligned_byte_count <= previous.aligned_byte_count;
    let start_barely_crept = previous.discovered_source_start <= discovered_source_start
        && discovered_source_start <= previous.discovered_source_start + margin;
    let inside_the_margin_band = aligned_byte_count <= discovered_length as u64
        && discovered_length as u64 <= aligned_byte_count + REALIGNMENT_MARGIN;
    length_barely_fell && count_barely_fell && start_barely_crept && inside_the_margin_band
}

// ── Region extension ───────────────────────────────────────────────────

/// How far the settled region extends forward under its own alignment:
/// walk toward `scan`, and keep the reach where matched-bytes-doubled-
/// minus-length peaked. Strictly-better keeps the earliest peak, and
/// beating the empty reach demands strictly more than half the bytes
/// matching.
fn forward_extension(
    source: &[u8],
    target: &[u8],
    settled: &SettledBoundary,
    scan: usize,
) -> usize {
    let mut matched: i64 = 0;
    let mut best_net: i64 = 0;
    let mut peak_reach: usize = 0;
    let mut reach: usize = 0;
    while settled.target_start + reach < scan && settled.source_start + reach < source.len() {
        if source[settled.source_start + reach] == target[settled.target_start + reach] {
            matched += 1;
        }
        reach += 1;
        let net = matched * 2 - reach as i64;
        if net > best_net {
            best_net = net;
            peak_reach = reach;
        }
    }
    peak_reach
}

/// How far the new seed extends backward under its own alignment: the
/// mirror of [`forward_extension`], walking down toward the settled
/// boundary and the source's start.
fn backward_extension(
    source: &[u8],
    target: &[u8],
    settled: &SettledBoundary,
    scan: usize,
    discovered_source_start: usize,
) -> usize {
    let mut matched: i64 = 0;
    let mut best_net: i64 = 0;
    let mut peak_reach: usize = 0;
    let mut reach: usize = 1;
    while scan >= settled.target_start + reach && discovered_source_start >= reach {
        if source[discovered_source_start - reach] == target[scan - reach] {
            matched += 1;
        }
        let net = matched * 2 - reach as i64;
        if net > best_net {
            best_net = net;
            peak_reach = reach;
        }
        reach += 1;
    }
    peak_reach
}

/// When the two extensions overlap, split the contested bytes at the
/// point maximizing settled-side matches minus seed-side matches —
/// both indexings address the same target byte, so the running score
/// is exactly "how many more bytes the settled alignment explains up
/// to here". The strict peak with a zero floor defaults the whole
/// contest to the seed side unless the settled side is strictly ahead
/// somewhere. Returns the adjusted (add length, seed backward reach);
/// the two regions tile exactly afterwards.
fn split_contested_bytes(
    source: &[u8],
    target: &[u8],
    settled: &SettledBoundary,
    scan: usize,
    discovered_source_start: usize,
    settled_forward_reach: usize,
    seed_backward_reach: usize,
) -> (usize, usize) {
    let contested = (settled.target_start + settled_forward_reach) - (scan - seed_backward_reach);
    let mut score: i64 = 0;
    let mut best_score: i64 = 0;
    let mut awarded_to_settled: usize = 0;
    for step in 0..contested {
        let settled_side = settled_forward_reach - contested + step;
        if target[settled.target_start + settled_side] == source[settled.source_start + settled_side] {
            score += 1;
        }
        if target[scan - seed_backward_reach + step]
            == source[discovered_source_start - seed_backward_reach + step]
        {
            score -= 1;
        }
        if score > best_score {
            best_score = score;
            awarded_to_settled = step + 1;
        }
    }
    (
        settled_forward_reach + awarded_to_settled - contested,
        seed_backward_reach - awarded_to_settled,
    )
}

// ── Emission ───────────────────────────────────────────────────────────

/// The three streams a walk accumulates, still uncompressed and
/// unframed — the wire is Haskell's.
struct RegionStreams {
    instructions: Vec<ControlInstruction>,
    diff_stream:  Vec<u8>,
    extra_stream: Vec<u8>,
}

impl RegionStreams {
    fn empty() -> Self {
        RegionStreams {
            instructions: Vec::new(),
            diff_stream:  Vec::new(),
            extra_stream: Vec::new(),
        }
    }

    /// Emit one region: the add bytes as target minus source
    /// (byte-wise, wrapping — the inverse of apply's addition), the
    /// gap verbatim into extra, and the triple. The extensions bound
    /// the add region inside the source, so the differ's output never
    /// leans on apply's zero-extension tolerance; the check makes a
    /// walk bug an `Err` instead of an out-of-range read.
    fn emit_region(
        &mut self,
        source: &[u8],
        target: &[u8],
        settled: &SettledBoundary,
        add_length: usize,
        copy_length: usize,
        source_seek: i64,
    ) -> Result<(), String> {
        if settled.source_start + add_length > source.len() {
            return Err(format!(
                "bsdiff differ: add region [{}, {}) reaches past the {}-byte source \
                 (internal invariant violation)",
                settled.source_start,
                settled.source_start + add_length,
                source.len()
            ));
        }
        for step in 0..add_length {
            self.diff_stream.push(
                target[settled.target_start + step].wrapping_sub(source[settled.source_start + step]),
            );
        }
        let extra_start = settled.target_start + add_length;
        self.extra_stream
            .extend_from_slice(&target[extra_start..extra_start + copy_length]);
        self.instructions.push(ControlInstruction {
            add_length:  add_length as u64,
            copy_length: copy_length as u64,
            source_seek,
        });
        Ok(())
    }

    /// Surface the final structured output, checking that the emitted
    /// regions cover the target exactly. Catches a class of "differ
    /// silently dropped or duplicated bytes" bugs before they reach
    /// the wire encoder.
    fn into_output_checked(self, target_length: usize) -> Result<BSDiffOutput, String> {
        let covered: u64 = self
            .instructions
            .iter()
            .map(|instruction| instruction.add_length + instruction.copy_length)
            .sum();
        if covered != target_length as u64 {
            return Err(format!(
                "bsdiff differ: instructions cover {covered} bytes of a {target_length}-byte \
                 target (internal invariant violation)"
            ));
        }
        Ok(BSDiffOutput {
            instructions: self.instructions,
            diff_stream:  self.diff_stream,
            extra_stream: self.extra_stream,
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Reference apply, mirroring `Slap.BSDiff.Apply`: add regions read
    /// source plus diff delta (zero past either source end), copy
    /// regions read extra verbatim, the seek displaces the source
    /// cursor after each add.
    fn reference_apply(source: &[u8], output: &BSDiffOutput) -> Vec<u8> {
        let mut reconstructed = Vec::new();
        let mut source_cursor: i64 = 0;
        let mut diff_cursor: usize = 0;
        let mut extra_cursor: usize = 0;
        for instruction in &output.instructions {
            for step in 0..instruction.add_length as usize {
                let source_index = source_cursor + step as i64;
                let source_byte = if 0 <= source_index && (source_index as usize) < source.len() {
                    source[source_index as usize]
                } else {
                    0
                };
                reconstructed.push(source_byte.wrapping_add(output.diff_stream[diff_cursor + step]));
            }
            diff_cursor += instruction.add_length as usize;
            source_cursor += instruction.add_length as i64 + instruction.source_seek;
            let copy_length = instruction.copy_length as usize;
            reconstructed.extend_from_slice(&output.extra_stream[extra_cursor..extra_cursor + copy_length]);
            extra_cursor += copy_length;
        }
        reconstructed
    }

    fn assert_round_trip(source: &[u8], target: &[u8]) -> BSDiffOutput {
        let output = bsdiff_diff(source, target).expect("differ should succeed");
        assert_eq!(reference_apply(source, &output), target, "reconstructed target differs");
        output
    }

    #[test]
    fn empty_target_is_zero_triples() {
        let output = bsdiff_diff(b"anything", &[]).expect("differ should succeed");
        assert!(output.instructions.is_empty());
        assert!(output.diff_stream.is_empty());
        assert!(output.extra_stream.is_empty());
    }

    #[test]
    fn empty_source_is_all_extra() {
        let target = pseudo_random_bytes(0x71, 300);
        let output = assert_round_trip(&[], &target);
        assert_eq!(output.extra_stream, target);
        assert!(output.diff_stream.iter().all(|&delta| delta == 0));
    }

    #[test]
    fn identical_buffers_are_one_silent_region() {
        let buffer = pseudo_random_bytes(0x72, 8192);
        let output = assert_round_trip(&buffer, &buffer);
        assert_eq!(output.instructions.len(), 1);
        assert!(output.diff_stream.iter().all(|&delta| delta == 0));
        assert!(output.extra_stream.is_empty());
    }

    #[test]
    fn scattered_small_edits_stay_few_long_regions() {
        // The format's signature input: a large file, a scatter of
        // small edits. The regions must stay long (one per edit
        // cluster, give or take) and the diff stream nearly all zeros.
        let source = pseudo_random_bytes(0x73, 1 << 18);
        let mut target = source.clone();
        for edit_index in 0..20usize {
            let position = 5000 + edit_index * 12000;
            target[position] ^= 0x5A;
        }
        let output = assert_round_trip(&source, &target);
        assert!(
            output.instructions.len() <= 25,
            "expected few regions, got {}",
            output.instructions.len()
        );
        let nonzero_deltas = output.diff_stream.iter().filter(|&&delta| delta != 0).count();
        assert!(
            nonzero_deltas <= 20,
            "expected at most one nonzero delta per edit, got {nonzero_deltas}"
        );
        assert!(output.extra_stream.len() <= 64, "scattered edits should not spill into extra");
    }

    #[test]
    fn a_block_move_re_aligns() {
        let source = pseudo_random_bytes(0x74, 1 << 16);
        let mut target = source.clone();
        let block: Vec<u8> = source[0x2000..0x3000].to_vec();
        target[0x8000..0x9000].copy_from_slice(&block);
        let output = assert_round_trip(&source, &target);
        assert!(
            output.extra_stream.len() <= 64,
            "a moved block should be found in source, not carried as {} extra bytes",
            output.extra_stream.len()
        );
    }

    #[test]
    fn an_insertion_lands_in_the_extra_stream() {
        let source = pseudo_random_bytes(0x75, 1 << 14);
        let inserted = pseudo_random_bytes(0x76, 100);
        let mut target = source[..0x1000].to_vec();
        target.extend_from_slice(&inserted);
        target.extend_from_slice(&source[0x1000..]);
        let output = assert_round_trip(&source, &target);
        assert!(
            output.extra_stream.len() >= 90 && output.extra_stream.len() <= 200,
            "a 100-byte insertion should cost about that much extra, got {}",
            output.extra_stream.len()
        );
    }

    #[test]
    fn padding_heavy_input_completes_quickly() {
        // A ROM-shaped worst case: megabytes of one repeated byte with
        // sparse content islands. Every window hashes into one bucket;
        // the seeder's probe cap is what keeps the walk linear. The
        // observable here is completion at test speed at all.
        let mut source = vec![0xFFu8; 4 << 20];
        let mut target = source.clone();
        for island_index in 0..8usize {
            let position = 100_000 + island_index * 500_000;
            let content = pseudo_random_bytes(island_index as u64, 4096);
            source[position..position + 4096].copy_from_slice(&content);
            let shifted = position + 1000;
            target[shifted..shifted + 4096].copy_from_slice(&content);
        }
        assert_round_trip(&source, &target);
    }

    #[test]
    fn a_misaligned_resumption_fast_forwards() {
        // One flipped byte whose unedited run resumes off tile
        // alignment: the seeder cannot see the resumption for up to
        // seven bytes, so the walk's own carried continuation is what
        // fast-forwards the run — a handful of probes, not one per
        // byte. The observable is completion at test speed on a
        // multi-megabyte run, and the one-edit shape staying a couple
        // of regions.
        let source = pseudo_random_bytes(0x90, 4 << 20);
        let mut target = source.clone();
        target[5003] ^= 0x5A;
        let output = assert_round_trip(&source, &target);
        assert!(
            output.instructions.len() <= 3,
            "one edit should stay a couple of regions, got {}",
            output.instructions.len()
        );
    }

    #[test]
    fn a_near_duplicate_block_completes_quickly() {
        // A long block differing from its alignment by fewer flipped
        // bytes than the re-alignment margin, while an exact copy sits
        // later in the source: the rogue copy out-explains the settled
        // alignment by less than the margin at every position, so only
        // the near-stationary escape frees the walk — and the escape
        // needs an answer at every position, which the carried
        // continuations supply where the tiled seeder cannot.
        let clean = pseudo_random_bytes(0x91, 2 << 20);
        let mut with_flips = clean.clone();
        for spot in [4096usize, 500_000, 1_000_000, 1_500_000] {
            with_flips[spot] ^= 0x5A;
        }
        let mut source = with_flips;
        source.extend_from_slice(&clean);
        let target = clean;
        assert_round_trip(&source, &target);
    }

    #[test]
    fn a_small_relocation_after_a_misaligned_edit_still_realigns() {
        // A 12-byte relocation from a tile-aligned source spot clears
        // the re-alignment margin on its own; an unrelated misaligned
        // flip earlier in the walk must not inflate that margin with
        // stale aligned credit and swallow the relocation into the
        // diff stream.
        let source = pseudo_random_bytes(0x92, 1 << 17);
        let mut target = source.clone();
        target[5000] ^= 0x5A;
        target[60000..60012].copy_from_slice(&source[8192..8204]);
        let output = assert_round_trip(&source, &target);
        assert!(
            output.instructions.len() >= 3,
            "the relocation should open its own region, got {} instructions",
            output.instructions.len()
        );
    }

    #[test]
    fn round_trip_random_shapes() {
        for &(source_seed, target_seed, source_length, target_length) in &[
            (0x80u64, 0x81u64, 0usize, 64usize),
            (0x82, 0x83, 64, 0),
            (0x84, 0x85, 7, 100),
            (0x86, 0x87, 1024, 1024),
            (0x88, 0x89, 4096, 1000),
            (0x8A, 0x8B, 1000, 4096),
        ] {
            let source = pseudo_random_bytes(source_seed, source_length);
            let target = pseudo_random_bytes(target_seed, target_length);
            assert_round_trip(&source, &target);
        }
    }

    #[test]
    fn related_halves_round_trip() {
        // Target shares its first half with source and diverges after:
        // exercises emission with both extension directions active.
        let source = pseudo_random_bytes(0x8C, 4096);
        let mut target = source[..2048].to_vec();
        target.extend_from_slice(&pseudo_random_bytes(0x8D, 2048));
        assert_round_trip(&source, &target);
    }
}
