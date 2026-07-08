//! BPS's match finder: the engine behind the candidate query the diff
//! walk in `bps_diff.rs` asks at every output position.
//!
//! A finder, not a judge. BPS prices every emit-or-literal decision in
//! exact wire bytes (`bps_diff::match_beats_literal`), so this engine
//! only has to surface the best candidate cheaply; the ranking inside a
//! probe uses the same varint and delta arithmetic the emitter spends
//! (`bps_diff::varint_cost`, `bps_diff::encode_delta`), imported rather
//! than re-derived, so the finder's idea of "cheaper" and the wire's
//! never disagree.
//!
//! ## Three free probes, then discovery
//!
//! BPS's action vocabulary hands the finder three candidates that cost
//! nothing to locate:
//!
//! * **Identity** — source at exactly the output position, the offset-
//!   free `SourceRead`. The dominant candidate on the locally-edited
//!   inputs BPS mostly sees; long enough
//!   ([`GOOD_ENOUGH_ALIGNED_LENGTH`]) and the table is never consulted.
//! * **The two copy cursors** — `SourceCopy` and `TargetCopy` offsets
//!   are deltas from the previous copy's end, so the positions at those
//!   cursors are the cheapest non-aligned candidates there are (a
//!   zero delta), and the walk hands both cursors in with each query.
//!
//! When the free probes come up short, discovery walks a hash chain
//! over [`ANCHOR_LENGTH`]-byte windows: source anchors indexed once at
//! build, in reverse so each bucket leads with run-start candidates
//! (the probe cap then trims a padding run's tail, not its head), and
//! target anchors indexed lazily as the walk settles output, so a
//! candidate in the not-yet-written zone is never in the table at all.
//! Chain cells hold positions at the width the pair's size selects
//! (`u32` whenever it fits, `u64` beyond), so the finder stays total
//! without paying eight-byte cells on ordinary inputs.
//!
//! ## The short table
//!
//! A second, [`SHORT_ANCHOR_LENGTH`]-byte table over settled output
//! alone, consulted only when everything above nets less than
//! [`SHORT_REPEAT_CEILING_NET`]. It exists for the dense-small-edit
//! shape real patches are full of: a changed four-byte pattern that
//! repeats a few writes later, worth a `TargetCopy` because the delta
//! from the last copy is a byte or two. Newest-first order is the
//! point — recency is proximity, and proximity is what makes a short
//! repeat cheap — so this table takes the natural prepend order the
//! long table's source half deliberately reverses.

use crate::bps_diff::{encode_delta, varint_cost};

/// The window a chain anchor covers: wide enough to hash as one
/// register, and no wider than the shortest match discovery should
/// bother with — anything shorter only ever pays from the free probes'
/// cheap offsets, which don't go through the table.
const ANCHOR_LENGTH: usize = 8;

/// How many chain entries one probe walks before giving up. Bounds the
/// work a repetitive region — a padding run hashing every window into
/// one bucket — can demand per position.
const PROBE_CAP: usize = 32;

/// A free-probe match at least this long is taken without consulting
/// the hash table: a longer match elsewhere could exist, but it would
/// spend delta bytes the aligned or cursor-adjacent candidate does not,
/// to save bytes the walk was already getting.
const GOOD_ENOUGH_ALIGNED_LENGTH: usize = 64;

/// The short table's anchor width: the smallest match a one-byte
/// header can carry, and the width of the repeated fragments dense
/// edits produce.
const SHORT_ANCHOR_LENGTH: usize = 4;

/// How many short-table entries one probe walks. Shorter than
/// [`PROBE_CAP`]: a worthwhile short repeat is nearby or nowhere, and
/// newest-first order puts nearby at the front.
const SHORT_PROBE_CAP: usize = 16;

/// The best net above which the short table is not consulted: a short
/// repeat saves at most its few bytes minus a delta, so once the other
/// probes clear this, nothing the short table holds can win.
const SHORT_REPEAT_CEILING_NET: i64 = 8;

// ── Public surface ───────────────────────────────────────────────────

/// Which buffer a candidate reads from — the finder's half of the
/// action decision. `bps_diff` classifies a source-side candidate at
/// exactly the output position as the offset-free `SourceRead`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MatchSide {
    FromSource,
    FromWrittenTarget,
}

/// The best candidate the finder can offer at one output position: the
/// side it reads from, the file-relative position it starts at, and how
/// many bytes it matches. The emit gate prices it against the pending
/// literal; the finder never emits.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct FoundMatch {
    pub side: MatchSide,
    pub file_position: usize,
    pub length: usize,
}

/// A candidate index over a `(source, target)` pair, asked one query
/// per output position, in walk order. Queries are `&mut self`: each
/// one settles more of the target into the lazy index.
pub struct HashChainMatcher<'pair> {
    engine: EngineWidth<'pair>,
}

/// The cell-width dispatch, chosen once at build (see the module's
/// storage note).
enum EngineWidth<'pair> {
    Narrow(Engine<'pair, u32>),
    Wide(Engine<'pair, u64>),
}

impl<'pair> HashChainMatcher<'pair> {
    /// Build the finder for a `(source, target)` pair. An empty target
    /// has no positions to query and skips indexing entirely.
    pub fn build(source: &'pair [u8], target: &'pair [u8]) -> Self {
        let combined_length = source
            .len()
            .checked_add(target.len())
            .expect("bps matcher: source + target overflows usize");
        let engine = if combined_length < u32::MAX as usize {
            EngineWidth::Narrow(Engine::build(source, target))
        } else {
            EngineWidth::Wide(Engine::build(source, target))
        };
        HashChainMatcher { engine }
    }

    /// The best candidate at `position`, ranked by matched length minus
    /// the delta bytes its offset would spend from the given copy
    /// cursors, or `None` when nothing matches even one byte. The emit
    /// gate makes the final worth-it call.
    pub fn match_at(
        &mut self,
        position: usize,
        last_source_copy_end: usize,
        last_target_copy_end: usize,
    ) -> Option<FoundMatch> {
        match &mut self.engine {
            EngineWidth::Narrow(engine) => {
                engine.match_at(position, last_source_copy_end, last_target_copy_end)
            }
            EngineWidth::Wide(engine) => {
                engine.match_at(position, last_source_copy_end, last_target_copy_end)
            }
        }
    }
}

// ── Chain cells ──────────────────────────────────────────────────────

/// An integer wide enough to hold a combined-buffer position in the
/// bucket heads and chain links. Two impls: `u32` for pairs up to 4 GB,
/// `u64` beyond; `build` chooses once. Each type's `MAX` stays free as
/// the end-of-chain sentinel — the dispatcher caps the narrow path's
/// input strictly below it.
trait ChainCell: Copy {
    const CHAIN_END: Self;
    fn from_index(index: usize) -> Self;
    fn as_index(self) -> usize;
    fn is_chain_end(self) -> bool;
}

impl ChainCell for u32 {
    const CHAIN_END: u32 = u32::MAX;

    fn from_index(index: usize) -> Self {
        debug_assert!(
            index < u32::MAX as usize,
            "u32 chain cell cannot hold index {index} (u32::MAX is the end-of-chain sentinel); \
             dispatch should have chosen u64"
        );
        index as u32
    }

    fn as_index(self) -> usize {
        self as usize
    }

    fn is_chain_end(self) -> bool {
        self == u32::MAX
    }
}

impl ChainCell for u64 {
    const CHAIN_END: u64 = u64::MAX;

    fn from_index(index: usize) -> Self {
        debug_assert!(
            index != usize::MAX,
            "u64 chain cell cannot hold usize::MAX (reserved as the end-of-chain sentinel)"
        );
        index as u64
    }

    fn as_index(self) -> usize {
        self as usize
    }

    fn is_chain_end(self) -> bool {
        self == u64::MAX
    }
}

// ── The engine ───────────────────────────────────────────────────────

struct Engine<'pair, Cell> {
    source: &'pair [u8],
    target: &'pair [u8],
    /// Newest anchor per bucket; `CHAIN_END` for an untouched bucket.
    bucket_heads: Vec<Cell>,
    /// Per-combined-position next-older-anchor link, same bucket.
    /// Source anchors sit at their source position; target anchors at
    /// `source.len() + target position`.
    chain_links: Vec<Cell>,
    /// Right-shift turning a folded anchor's hash into a bucket index.
    hash_shift: u32,
    /// The short table (see the module's short-table note): newest
    /// anchor per bucket over settled output, and per-target-position
    /// links. Target-only, so links index target positions directly.
    short_bucket_heads: Vec<Cell>,
    short_chain_links: Vec<Cell>,
    short_hash_shift: u32,
    /// First target position whose anchors are not yet in the tables;
    /// the lazy indexing high-water mark, shared by both.
    next_target_anchor: usize,
}

/// A candidate paired with the net saving its offset arithmetic leaves:
/// matched length minus the delta bytes spent naming it. The free
/// probes and the chain walk all rank in this one currency.
#[derive(Copy, Clone)]
struct RankedCandidate {
    found: FoundMatch,
    net: i64,
}

impl<'pair, Cell: ChainCell> Engine<'pair, Cell> {
    fn build(source: &'pair [u8], target: &'pair [u8]) -> Self {
        // No positions will ever be queried, so no table is built: the
        // empty-target diff should not pay for indexing a large source.
        if target.is_empty() {
            return Engine {
                source,
                target,
                bucket_heads: Vec::new(),
                chain_links: Vec::new(),
                hash_shift: u64::BITS,
                short_bucket_heads: Vec::new(),
                short_chain_links: Vec::new(),
                short_hash_shift: u64::BITS,
                next_target_anchor: 0,
            };
        }
        let combined_length = source.len() + target.len();
        let bucket_bits = bucket_bits_for(combined_length);
        let short_bucket_bits = bucket_bits_for(target.len());
        let mut engine = Engine {
            source,
            target,
            bucket_heads: vec![Cell::CHAIN_END; 1 << bucket_bits],
            chain_links: vec![Cell::CHAIN_END; combined_length],
            hash_shift: u64::BITS - bucket_bits,
            short_bucket_heads: vec![Cell::CHAIN_END; 1 << short_bucket_bits],
            short_chain_links: vec![Cell::CHAIN_END; target.len()],
            short_hash_shift: u64::BITS - short_bucket_bits,
            next_target_anchor: 0,
        };
        // Built in reverse: prepending walks each bucket newest-first, so
        // reverse order leaves the lowest positions at the front — for
        // repeated content (a padding run hashing every window into one
        // bucket) those are the run-start candidates with the longest
        // reach, and the probe cap then trims the tail of the run, not
        // its head.
        if source.len() >= ANCHOR_LENGTH {
            for anchor_start in (0..=source.len() - ANCHOR_LENGTH).rev() {
                engine.insert_anchor(anchor_start, &source[anchor_start..anchor_start + ANCHOR_LENGTH]);
            }
        }
        engine
    }

    fn match_at(
        &mut self,
        position: usize,
        last_source_copy_end: usize,
        last_target_copy_end: usize,
    ) -> Option<FoundMatch> {
        self.index_settled_target_anchors(position);

        let identity = self.source_candidate(position, position, last_source_copy_end);
        if let Some(aligned) = identity {
            if aligned.found.length >= GOOD_ENOUGH_ALIGNED_LENGTH {
                return Some(aligned.found);
            }
        }
        let at_source_cursor =
            self.source_candidate(last_source_copy_end, position, last_source_copy_end);
        let at_target_cursor =
            self.target_candidate(last_target_copy_end, position, last_target_copy_end);
        let free_probes = best_of([identity, at_source_cursor, at_target_cursor]);
        if let Some(cheap) = free_probes {
            if cheap.found.length >= GOOD_ENOUGH_ALIGNED_LENGTH {
                return Some(cheap.found);
            }
        }

        let mut discovered =
            self.probe(position, last_source_copy_end, last_target_copy_end);
        if discovered.map_or(true, |held| held.net < SHORT_REPEAT_CEILING_NET) {
            discovered = best_of([discovered, self.probe_short(position, last_target_copy_end)]);
        }
        // A discovered candidate must also beat the lockstep alternative
        // — a one-byte literal with the offset-free SourceRead resuming
        // at the next position — or a repeated region would spend a
        // delta one byte before alignment comes back for free.
        let discovered = discovered
            .filter(|ranked| ranked.net > self.lockstep_hold_net(position));
        best_of([free_probes, discovered]).map(|ranked| ranked.found)
    }

    /// What lockstep earns without any discovery: the identity
    /// alignment one position on, minus the literal byte spent getting
    /// there; `i64::MIN` when it does not resume. Real relocations pass
    /// this hold untouched — where content truly moved, identity does
    /// not resume next byte.
    fn lockstep_hold_net(&self, position: usize) -> i64 {
        self.source_candidate(position + 1, position + 1, 0)
            .map_or(i64::MIN, |resumed| resumed.net - 1)
    }

    /// Feed the tables every target anchor the walk has settled: anchor
    /// starts strictly before `position` whose window lies inside the
    /// target. Nothing at or past the output position is ever inserted,
    /// so neither table can answer from the not-yet-written zone. The
    /// target's last few positions fit a short anchor after the long
    /// one no longer fits, so the long insert carries its own width
    /// check inside the shared walk.
    fn index_settled_target_anchors(&mut self, position: usize) {
        while self.next_target_anchor < position
            && self.next_target_anchor + SHORT_ANCHOR_LENGTH <= self.target.len()
        {
            let anchor_start = self.next_target_anchor;
            if anchor_start + ANCHOR_LENGTH <= self.target.len() {
                self.insert_anchor(
                    self.source.len() + anchor_start,
                    &self.target[anchor_start..anchor_start + ANCHOR_LENGTH],
                );
            }
            self.insert_short_anchor(
                anchor_start,
                &self.target[anchor_start..anchor_start + SHORT_ANCHOR_LENGTH],
            );
            self.next_target_anchor += 1;
        }
    }

    /// Walk the short table for a nearby repeat of the next few output
    /// bytes. Only consulted when nothing better is on offer (see
    /// [`SHORT_REPEAT_CEILING_NET`]); the ranking arithmetic is the
    /// same one every other candidate goes through.
    fn probe_short(
        &self,
        position: usize,
        last_target_copy_end: usize,
    ) -> Option<RankedCandidate> {
        if position + SHORT_ANCHOR_LENGTH > self.target.len() {
            return None;
        }
        let bucket = bucket_for_short(
            &self.target[position..position + SHORT_ANCHOR_LENGTH],
            self.short_hash_shift,
        );
        let mut best: Option<RankedCandidate> = None;
        let mut cursor = self.short_bucket_heads[bucket];
        for _ in 0..SHORT_PROBE_CAP {
            if cursor.is_chain_end() {
                break;
            }
            let file_position = cursor.as_index();
            let candidate = self.target_candidate(file_position, position, last_target_copy_end);
            best = best_of([best, candidate]);
            cursor = self.short_chain_links[file_position];
        }
        best
    }

    /// Walk the query anchor's chain and keep the best-net candidate.
    /// Anything the chain holds is legal (source anchors wholly within
    /// source, target anchors only from settled output), so ranking is
    /// the only judgment made here.
    fn probe(
        &self,
        position: usize,
        last_source_copy_end: usize,
        last_target_copy_end: usize,
    ) -> Option<RankedCandidate> {
        if position + ANCHOR_LENGTH > self.target.len() {
            return None;
        }
        let bucket = self.bucket_of(&self.target[position..position + ANCHOR_LENGTH]);
        let mut best: Option<RankedCandidate> = None;
        let mut cursor = self.bucket_heads[bucket];
        for _ in 0..PROBE_CAP {
            if cursor.is_chain_end() {
                break;
            }
            let combined_position = cursor.as_index();
            let candidate = if combined_position < self.source.len() {
                self.source_candidate(combined_position, position, last_source_copy_end)
            } else {
                self.target_candidate(
                    combined_position - self.source.len(),
                    position,
                    last_target_copy_end,
                )
            };
            best = best_of([best, candidate]);
            cursor = self.chain_links[combined_position];
        }
        best
    }

    /// Rank a source-side candidate: extend it, then charge the delta
    /// its offset would spend — nothing when it sits at the output
    /// position (the offset-free `SourceRead`), the cursor delta
    /// otherwise.
    fn source_candidate(
        &self,
        file_position: usize,
        position: usize,
        last_source_copy_end: usize,
    ) -> Option<RankedCandidate> {
        if file_position >= self.source.len() {
            return None;
        }
        let reach = (self.source.len() - file_position).min(self.target.len() - position);
        let length = matched_length(
            &self.source[file_position..file_position + reach],
            &self.target[position..position + reach],
        );
        if length == 0 {
            return None;
        }
        let delta_bytes = if file_position == position {
            0
        } else {
            varint_cost(encode_delta(last_source_copy_end, file_position))
        };
        Some(RankedCandidate {
            found: FoundMatch {
                side: MatchSide::FromSource,
                file_position,
                length,
            },
            net: length as i64 - delta_bytes as i64,
        })
    }

    /// Rank a written-target candidate: extend it (the read may run
    /// past the output position — the overlapped forward copy the
    /// format blesses, and comparing final target bytes is exact
    /// there), then charge its cursor delta.
    fn target_candidate(
        &self,
        file_position: usize,
        position: usize,
        last_target_copy_end: usize,
    ) -> Option<RankedCandidate> {
        if file_position >= position {
            return None;
        }
        let reach = self.target.len() - position;
        let length = matched_length(
            &self.target[file_position..file_position + reach],
            &self.target[position..position + reach],
        );
        if length == 0 {
            return None;
        }
        let delta_bytes = varint_cost(encode_delta(last_target_copy_end, file_position));
        Some(RankedCandidate {
            found: FoundMatch {
                side: MatchSide::FromWrittenTarget,
                file_position,
                length,
            },
            net: length as i64 - delta_bytes as i64,
        })
    }

    fn insert_anchor(&mut self, combined_position: usize, window: &[u8]) {
        let bucket = bucket_for(window, self.hash_shift);
        self.chain_links[combined_position] = self.bucket_heads[bucket];
        self.bucket_heads[bucket] = Cell::from_index(combined_position);
    }

    fn insert_short_anchor(&mut self, target_position: usize, window: &[u8]) {
        let bucket = bucket_for_short(window, self.short_hash_shift);
        self.short_chain_links[target_position] = self.short_bucket_heads[bucket];
        self.short_bucket_heads[bucket] = Cell::from_index(target_position);
    }

    fn bucket_of(&self, window: &[u8]) -> usize {
        bucket_for(window, self.hash_shift)
    }
}

/// Fold a long-table anchor window into one register and
/// Fibonacci-hash it down to a bucket index under the given shift.
fn bucket_for(window: &[u8], hash_shift: u32) -> usize {
    let folded =
        u64::from_be_bytes(window.try_into().expect("bps matcher: a long anchor window is eight bytes"));
    (folded.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> hash_shift) as usize
}

/// The short table's fold: four bytes, same hash.
fn bucket_for_short(window: &[u8], hash_shift: u32) -> usize {
    let folded =
        u32::from_be_bytes(window.try_into().expect("bps matcher: a short anchor window is four bytes"));
    (u64::from(folded).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> hash_shift) as usize
}

/// The best-net candidate among some options, earliest winning a tie —
/// callers list the cheapest-to-encode candidates first, so a tie stays
/// with the cheaper offset.
fn best_of<const N: usize>(candidates: [Option<RankedCandidate>; N]) -> Option<RankedCandidate> {
    let mut best: Option<RankedCandidate> = None;
    for candidate in candidates.into_iter().flatten() {
        if best.map_or(true, |held| candidate.net > held.net) {
            best = Some(candidate);
        }
    }
    best
}

/// Length of the common prefix of two slices, compared a register at a
/// time — exact on overlapping slices of one buffer, where both sides
/// read the same final bytes either way.
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

/// Bucket-count bits for a pair's combined size: roughly one bucket per
/// indexed position, held between 16 Ki buckets (below which even tiny
/// inputs would chain needlessly) and 8 Mi (above which the head
/// table's own memory stops paying).
fn bucket_bits_for(combined_length: usize) -> u32 {
    let wanted = usize::BITS - combined_length.max(1).leading_zeros();
    wanted.clamp(14, 23)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{HashChainMatcher, MatchSide};

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
    fn identity_alignment_needs_no_table() {
        let source = pseudo_random_bytes(0x51, 500);
        let mut matcher = HashChainMatcher::build(&source, &source);
        let found = matcher.match_at(0, 0, 0).expect("identical buffers match");
        assert_eq!(found.side, MatchSide::FromSource);
        assert_eq!((found.file_position, found.length), (0, 500));
    }

    #[test]
    fn a_relocated_block_is_discovered() {
        let source = pseudo_random_bytes(0x52, 4096);
        let mut target = pseudo_random_bytes(0x53, 1024);
        target[500..564].copy_from_slice(&source[2000..2064]);
        let mut matcher = HashChainMatcher::build(&source, &target);
        let found = matcher.match_at(500, 0, 0).expect("a 64-byte relocation is findable");
        assert_eq!(found.side, MatchSide::FromSource);
        assert_eq!(found.file_position, 2000);
        assert!(found.length >= 64);
    }

    #[test]
    fn equal_matches_prefer_the_cheaper_delta() {
        // The same 32-byte block at two source positions; with the copy
        // cursor parked at one of them, that one's delta is a byte and
        // the other's is three, so the ranking must keep the parked one.
        let mut source = pseudo_random_bytes(0x54, 4096);
        let block = pseudo_random_bytes(0x55, 32);
        source[1000..1032].copy_from_slice(&block);
        source[3000..3032].copy_from_slice(&block);
        let target = block;
        let mut matcher = HashChainMatcher::build(&source, &target);
        let found = matcher.match_at(0, 3000, 0).expect("the planted block matches");
        assert_eq!(found.side, MatchSide::FromSource);
        assert_eq!(found.file_position, 3000);
    }

    #[test]
    fn a_nearby_short_repeat_is_found_through_the_short_table() {
        // A four-byte fragment repeating 60 bytes after its first
        // appearance, in otherwise unrelated bytes: below the long
        // anchor, invisible to the free probes, and worth one byte of
        // delta once the copy cursor sits nearby.
        let source = pseudo_random_bytes(0x56, 2048);
        let mut target = pseudo_random_bytes(0x57, 256);
        let fragment = [0xAA, 0xBB, 0xCC, 0xDD];
        target[40..44].copy_from_slice(&fragment);
        target[100..104].copy_from_slice(&fragment);
        let mut matcher = HashChainMatcher::build(&source, &target);
        let found = matcher.match_at(100, 0, 44).expect("the nearby repeat is worth its delta");
        assert_eq!(found.side, MatchSide::FromWrittenTarget);
        assert_eq!(found.file_position, 40);
        assert!(found.length >= 4);
    }

    #[test]
    fn written_target_candidates_stop_at_the_output_position() {
        // A period-3 run with an empty source: nothing is written yet at
        // position 0, so the first two positions have no candidate at
        // all, and position 3 reads the run's start — an overlapped
        // forward copy.
        let target: Vec<u8> = b"abcabcabcabcabcabc".to_vec();
        let mut matcher = HashChainMatcher::build(&[], &target);
        for position in 0..3 {
            assert_eq!(matcher.match_at(position, 0, 0), None, "nothing settled at {position}");
        }
        let found = matcher.match_at(3, 0, 0).expect("the period-3 run recurs from the start");
        assert_eq!(found.side, MatchSide::FromWrittenTarget);
        assert_eq!((found.file_position, found.length), (0, 15));
    }
}
