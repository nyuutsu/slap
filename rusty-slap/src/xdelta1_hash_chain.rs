//! xdelta1's match finder: the source-span query the differ in
//! `xdelta1_diff.rs` asks at each target position.
//!
//! ## Simpler than its siblings: one source, no self-reference
//!
//! xdelta1 has exactly two sources — the inline data segment (literal
//! bytes) and the file source (the source ROM) — and a file-source
//! instruction copies from the source ROM alone. There is no
//! copy-from-produced-target, so this finder needs no target-side
//! index and no per-window session: it indexes the source once and
//! answers "the longest run of source that prefixes `target[pos..]`",
//! nothing more. That makes it the leanest of slap's three hash-chain
//! matchers (the VCDIFF and BPS ones both carry a second, output-side
//! index for self-reference).
//!
//! ## Two tiers, biased toward staying in lockstep
//!
//! * **Pursuit** — the continuation of the last accepted match's
//!   source alignment. An unedited stretch of the target keeps reading
//!   consecutive source bytes, so pursuit carries a ROM hack across its
//!   unchanged runs at O(1) per position and emits matches in ascending
//!   source order — which is exactly the shape xdelta1's sequential
//!   offset mode encodes for free (every per-instruction offset varint
//!   becomes a zero), so the bias toward pursuit shrinks the patch as
//!   well as the work.
//! * **Discovery** — a hash chain over [`ANCHOR_LENGTH`]-byte source
//!   windows, probed when pursuit falls short of [`MIN_MATCH_LENGTH`].
//!   Source anchors are indexed in reverse, so each bucket leads with
//!   its lowest source offset: among equal-length matches the finder
//!   keeps the smallest offset, which packs into the fewest varint
//!   bytes under the absolute offset mode. A discovery must also beat
//!   staying aligned — the pursuit match here, or a literal byte and
//!   the pursuit match one position on — or a coincidental short match
//!   in a large source would splinter an aligned run at every edit and,
//!   since one far offset forces the whole patch out of sequential
//!   mode, balloon every offset varint. A substitution edit thus stays
//!   one literal byte between two long aligned runs, not a scatter of
//!   spurious far copies.
//!
//! [`MIN_MATCH_LENGTH`] is the floor both tiers accept from — the
//! shortest run xdelta1 spends a file-source instruction on. Below it
//! the differ writes a literal byte and moves on, so the finder never
//! offers a match it should not take.

/// Shortest source run the finder offers as a match. Matches canonical
/// xdelta1's setting: below eight bytes, a file-source instruction's
/// per-record overhead outweighs writing the bytes literally.
const MIN_MATCH_LENGTH: usize = 8;

/// A pursuit match at least this long is taken without probing the
/// chain: a longer match could exist elsewhere, but leaving the source
/// alignment for it trades sequential mode's free offsets for an
/// out-of-order jump. Generous enough that discovery still fires
/// wherever an edit truly moved a run.
const GOOD_ENOUGH_PURSUIT_LENGTH: usize = 64;

/// The window a chain anchor covers. Equal to [`MIN_MATCH_LENGTH`]: no
/// shorter run is worth offering, and eight bytes hash as one register.
const ANCHOR_LENGTH: usize = 8;

/// How many chain entries one probe walks before giving up. Bounds the
/// work a repetitive source — a padding run hashing every window into
/// one bucket — can demand per target position.
const PROBE_CAP: usize = 32;

// ── Public surface ───────────────────────────────────────────────────

/// A source match the finder stands behind: where it begins in the
/// source and how many bytes it runs. Both fit `u32` — the differ
/// rejects a source past the `u32`-addressable range xdelta1's wire
/// offsets (32-bit EDSIO varints) can name — but ride as `usize` here,
/// the walk's natural width.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SourceMatch {
    pub source_offset: usize,
    pub length:        usize,
}

/// A longest-source-run index over the source ROM, asked one query per
/// target position in walk order. Queries are `&mut self`: an accepted
/// match becomes the next pursuit base.
pub struct SourceHashChainMatcher<'src> {
    source:       &'src [u8],
    /// Newest anchor per bucket; `CHAIN_END` for an untouched bucket.
    bucket_heads: Vec<u32>,
    /// Per-source-position next-older-anchor link, same bucket.
    chain_links:  Vec<u32>,
    /// Right-shift turning a folded anchor's hash into a bucket index.
    hash_shift:   u32,
    pursuit:      Option<Pursuit>,
}

/// The end-of-chain sentinel. The differ caps the source strictly
/// below `u32::MAX`, so the largest real source position is below it
/// and this value stays free.
const CHAIN_END: u32 = u32::MAX;

/// The pursuit base: the last accepted match, as the alignment it
/// established. At a later query the continuation candidate is
/// `source_offset + (position - target_position)` — the source byte
/// that match would have reached had it kept running.
#[derive(Copy, Clone)]
struct Pursuit {
    source_offset:   usize,
    target_position: usize,
}

impl<'src> SourceHashChainMatcher<'src> {
    /// Index the source. Fails when the source is longer than
    /// xdelta1's wire offsets can name (32-bit).
    pub fn build(source: &'src [u8]) -> Result<Self, String> {
        if source.len() >= u32::MAX as usize {
            return Err(format!(
                "xdelta1 differ: source length {} exceeds the 32-bit range xdelta1's \
                 wire offsets can address (max {})",
                source.len(),
                u32::MAX - 1,
            ));
        }
        let bucket_bits = bucket_bits_for(source.len());
        let mut matcher = SourceHashChainMatcher {
            source,
            bucket_heads: vec![CHAIN_END; 1 << bucket_bits],
            chain_links:  vec![CHAIN_END; source.len()],
            hash_shift:   u64::BITS - bucket_bits,
            pursuit:      None,
        };
        // Built in reverse: prepending walks each bucket newest-first,
        // so reverse order leaves the lowest source offsets at the
        // front — the smallest-offset preference among equal-length
        // matches, and the front of a repetitive run ahead of the probe
        // cap.
        if source.len() >= ANCHOR_LENGTH {
            for anchor_start in (0..=source.len() - ANCHOR_LENGTH).rev() {
                matcher.insert_anchor(anchor_start);
            }
        }
        Ok(matcher)
    }

    /// The best source match for `target[position..]`, or `None` when
    /// nothing reaches [`MIN_MATCH_LENGTH`]. An accepted match updates
    /// the pursuit base.
    pub fn match_at(&mut self, target: &[u8], position: usize) -> Option<SourceMatch> {
        if target.len() - position < MIN_MATCH_LENGTH {
            return None;
        }
        let pursued = self.pursue(target, position);
        if let Some(found) = pursued {
            if found.length >= GOOD_ENOUGH_PURSUIT_LENGTH {
                return Some(self.adopt(found, position));
            }
        }
        // A discovery is taken only when it beats the lockstep hold, so a
        // coincidental short far match never displaces an aligned run.
        let hold = self.lockstep_hold_length(target, position, pursued);
        let discovered = self
            .probe(target, position)
            .filter(|found| found.length > hold);
        // Pursuit wins ties: staying in source alignment keeps the
        // emit order ascending, and sequential mode with it.
        let best = match (pursued, discovered) {
            (None, None) => return None,
            (Some(found), None) => found,
            (None, Some(found)) => found,
            (Some(pursued_match), Some(discovered_match)) =>
                if discovered_match.length > pursued_match.length {
                    discovered_match
                } else {
                    pursued_match
                },
        };
        Some(self.adopt(best, position))
    }

    /// The run length staying aligned already earns without a discovery:
    /// the pursuit match here, or the pursuit match one position on less
    /// the literal byte spent reaching it, whichever is longer, and `0`
    /// when neither pursues. A discovery must clear this to be worth
    /// leaving the source alignment for.
    fn lockstep_hold_length(&self, target: &[u8], position: usize, pursued: Option<SourceMatch>) -> usize {
        let held_here = pursued.map(|found| found.length);
        let held_next = self
            .pursue(target, position + 1)
            .map(|resumed| resumed.length.saturating_sub(1));
        held_here.into_iter().chain(held_next).max().unwrap_or(0)
    }

    /// Record an accepted match as the new pursuit base and hand it back.
    fn adopt(&mut self, found: SourceMatch, position: usize) -> SourceMatch {
        self.pursuit = Some(Pursuit {
            source_offset:   found.source_offset,
            target_position: position,
        });
        found
    }

    /// The pursuit-tier candidate: continue the last accepted match's
    /// source alignment at this position, if it still reaches the floor.
    /// An alignment whose continuation has run off the source's end has
    /// nothing left to read.
    fn pursue(&self, target: &[u8], position: usize) -> Option<SourceMatch> {
        let pursuit = self.pursuit?;
        let candidate = pursuit.source_offset + (position - pursuit.target_position);
        if candidate >= self.source.len() {
            return None;
        }
        let length = self.extend(candidate, target, position);
        (length >= MIN_MATCH_LENGTH).then_some(SourceMatch { source_offset: candidate, length })
    }

    /// The discovery tier: walk the query anchor's chain and keep the
    /// longest extension that reaches the floor, smallest offset winning
    /// ties (the chain leads with the smallest offsets, and only a
    /// strictly longer match displaces the incumbent).
    fn probe(&self, target: &[u8], position: usize) -> Option<SourceMatch> {
        if position + ANCHOR_LENGTH > target.len() {
            return None;
        }
        let bucket = self.bucket_of(&target[position..position + ANCHOR_LENGTH]);
        let mut best: Option<SourceMatch> = None;
        let mut cursor = self.bucket_heads[bucket];
        for _ in 0..PROBE_CAP {
            if cursor == CHAIN_END {
                break;
            }
            let candidate = cursor as usize;
            let length = self.extend(candidate, target, position);
            if length >= MIN_MATCH_LENGTH
                && best.is_none_or(|incumbent| length > incumbent.length)
            {
                best = Some(SourceMatch { source_offset: candidate, length });
            }
            cursor = self.chain_links[candidate];
        }
        best
    }

    /// The matched run length at a source candidate: byte agreement
    /// between `target[position..]` and `source[candidate..]`, capped at
    /// the source's end and the target's end.
    fn extend(&self, candidate: usize, target: &[u8], position: usize) -> usize {
        let reach = (self.source.len() - candidate).min(target.len() - position);
        matched_length(
            &self.source[candidate..candidate + reach],
            &target[position..position + reach],
        )
    }

    fn insert_anchor(&mut self, source_position: usize) {
        let bucket = self.bucket_of(&self.source[source_position..source_position + ANCHOR_LENGTH]);
        self.chain_links[source_position] = self.bucket_heads[bucket];
        self.bucket_heads[bucket] = source_position as u32;
    }

    /// Fold the anchor window into one register and Fibonacci-hash it
    /// down to a bucket index.
    fn bucket_of(&self, window: &[u8]) -> usize {
        let folded =
            u64::from_be_bytes(window.try_into().expect("xdelta1 differ: an anchor window is eight bytes"));
        (folded.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> self.hash_shift) as usize
    }
}

/// Length of the common prefix of two slices, compared a register at a
/// time.
fn matched_length(left: &[u8], right: &[u8]) -> usize {
    let limit = left.len().min(right.len());
    // A first-byte disagreement is the usual answer on a failed probe;
    // take it with one load before the word loop reads sixteen.
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

/// Bucket-count bits for a source length: roughly one bucket per
/// position, held between 16 Ki buckets (below which even tiny sources
/// would chain needlessly) and 8 Mi (above which the head table's own
/// memory stops paying).
fn bucket_bits_for(source_length: usize) -> u32 {
    let wanted = usize::BITS - source_length.max(1).leading_zeros();
    wanted.clamp(14, 23)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::SourceHashChainMatcher;

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

    #[test]
    fn identical_source_is_one_long_pursuit() {
        let source = pseudo_random_bytes(0x11, 4096);
        let mut matcher = SourceHashChainMatcher::build(&source).expect("builds");
        let found = matcher.match_at(&source, 0).expect("identical bytes match");
        assert_eq!((found.source_offset, found.length), (0, 4096));
    }

    #[test]
    fn a_relocated_run_is_discovered_at_its_smallest_offset() {
        // The same 40-byte run planted at two source offsets; the target
        // is that run, so discovery must find it and prefer the lower
        // offset (fewer varint bytes on the wire).
        let mut source = pseudo_random_bytes(0x21, 4096);
        let run = pseudo_random_bytes(0x22, 40);
        source[500..540].copy_from_slice(&run);
        source[3000..3040].copy_from_slice(&run);
        let target = run;
        let mut matcher = SourceHashChainMatcher::build(&source).expect("builds");
        let found = matcher.match_at(&target, 0).expect("the planted run matches");
        assert_eq!(found.source_offset, 500);
        assert!(found.length >= 40);
    }

    #[test]
    fn a_short_coincidence_is_left_below_the_floor() {
        // Only seven shared bytes, one under the floor: no match offered.
        let source = pseudo_random_bytes(0x31, 512);
        let mut target = pseudo_random_bytes(0x32, 64);
        target[10..17].copy_from_slice(&source[100..107]);
        let mut matcher = SourceHashChainMatcher::build(&source).expect("builds");
        assert_eq!(matcher.match_at(&target, 10), None);
    }

    #[test]
    fn pursuit_continues_across_a_one_byte_edit() {
        // An unedited prefix, one flipped byte, then more unedited source:
        // pursuit carries the first run, the flip falls below the floor,
        // and pursuit resumes right after it.
        let source = pseudo_random_bytes(0x41, 4096);
        let mut target = source.clone();
        target[2000] ^= 0x5a;
        let mut matcher = SourceHashChainMatcher::build(&source).expect("builds");
        let opening = matcher.match_at(&target, 0).expect("the unedited prefix matches");
        assert_eq!((opening.source_offset, opening.length), (0, 2000));
        assert_eq!(matcher.match_at(&target, 2000), None, "the flipped byte alone");
        let resumed = matcher.match_at(&target, 2001).expect("pursuit resumes past the edit");
        assert_eq!(resumed.source_offset, 2001);
    }

    #[test]
    fn scattered_edits_stay_aligned_not_fragmented() {
        // A byte flipped every 4 KiB, the shape a coincidental short far
        // match would splinter: each flip must be one literal between two
        // long aligned runs (pursuit resumes right after it), so the
        // match count is one long run per gap, never a scatter of spurious
        // far copies. The lockstep hold is what holds this line.
        let source = pseudo_random_bytes(0x61, 1 << 16);
        let stride = 4096;
        let mut target = source.clone();
        for spot in (0..target.len()).step_by(stride) {
            target[spot] ^= 0x5a;
        }
        let mut matcher = SourceHashChainMatcher::build(&source).expect("builds");
        let mut position = 0;
        let mut matches = Vec::new();
        while position < target.len() {
            match matcher.match_at(&target, position) {
                Some(found) => {
                    matches.push(found);
                    position += found.length;
                }
                None => position += 1,
            }
        }
        // One aligned run per gap (the leading flip at 0 makes the first
        // run start at offset 1), and every match ascending in source
        // offset — the sequential-mode shape.
        assert_eq!(matches.len(), target.len() / stride);
        for pair in matches.windows(2) {
            assert!(
                pair[1].source_offset > pair[0].source_offset,
                "matches must ascend to keep sequential mode: {} then {}",
                pair[0].source_offset,
                pair[1].source_offset,
            );
        }
        assert!(matches.iter().all(|found| found.length >= 4000), "each run spans its gap");
    }

    #[test]
    fn an_empty_source_offers_nothing() {
        let target = pseudo_random_bytes(0x51, 64);
        let mut matcher = SourceHashChainMatcher::build(&[]).expect("builds");
        for position in 0..target.len() {
            assert_eq!(matcher.match_at(&target, position), None);
        }
    }
}
