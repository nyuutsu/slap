//! GDIFF's match finder: the source-span query the differ in
//! `gdiff_diff.rs` asks at each target position.
//!
//! ## One source, no self-reference
//!
//! A GDIFF COPY reads the old file alone — the format has no
//! copy-from-produced-target — so this finder indexes the source once
//! and answers "the longest run of source that prefixes
//! `target[pos..]`", nothing more.
//!
//! ## Two tiers, biased toward staying in lockstep
//!
//! * **Pursuit** — the continuation of the last accepted match's
//!   source alignment. An unedited stretch of the target keeps reading
//!   consecutive source bytes, so pursuit carries a ROM hack across
//!   its unchanged runs at O(1) per position.
//! * **Discovery** — a hash chain over the [`ANCHOR_LENGTH`]-byte
//!   tiling of the source, probed when pursuit falls short of
//!   [`MIN_MATCH_LENGTH`]. Tiles are indexed in reverse, so each
//!   bucket leads with its lowest source offset: among equal-length
//!   candidates the finder keeps the smallest offset in view, and
//!   small offsets are cheap on GDIFF's wire — a two-byte field up to
//!   0xFFFF, four or eight beyond. A discovery must also beat staying
//!   aligned — the pursuit match here, or a literal byte and the
//!   pursuit match one position on — or a coincidental short match in
//!   a large source would splinter an aligned run at every edit,
//!   spending a fresh COPY command's bytes on each fragment. A
//!   substitution edit thus stays one literal byte between two long
//!   aligned runs.
//!
//! An accepted match reaches backward into the pending literal while
//! the preceding bytes agree, reclaiming the true start a tile-aligned
//! landing can sit a few bytes past.
//!
//! Every offered match pays its wire: a COPY command spends four to
//! thirteen bytes depending on its field widths, and a candidate that
//! saves fewer literal bytes than its command costs is kept off the
//! table ([`pays_its_wire_cost`]).
//!
//! ## Chain cells widen with the source
//!
//! GDIFF's COPY 255 carries a signed 64-bit offset, so the format
//! admits sources past the reach of `u32` tile ordinals. Chain cells
//! are `u32` while the tile count fits — tens of gigabytes of source —
//! and `u64` beyond ([`ChainCell`]); `build` chooses once and never
//! refuses an input.

/// Shortest source run either tier offers as a match. Equal to
/// [`ANCHOR_LENGTH`] — the tiling cannot see shorter runs — and the
/// break-even at four-byte offset fields, which any source past
/// 64 KiB needs: below eight bytes such a COPY saves less than it
/// spends.
const MIN_MATCH_LENGTH: usize = 8;

/// A pursuit match at least this long is taken without probing the
/// chain: across a long unedited run the probe's per-position work
/// buys nothing the continuation doesn't already give. Generous
/// enough that discovery still fires wherever an edit truly moved a
/// run.
const GOOD_ENOUGH_PURSUIT_LENGTH: usize = 64;

/// The window a chain anchor covers, and the stride anchors are filed
/// at: the source is tiled by contiguous anchor-sized blocks, one
/// filed card per tile — an eighth of a per-position index's cards.
/// Equal to [`MIN_MATCH_LENGTH`] — no shorter run is worth offering,
/// and eight bytes hash as one register. Any run of 2×ANCHOR_LENGTH−1
/// bytes contains a whole tile and is discoverable at every alignment;
/// the walk advances byte by byte through unmatched territory, so a
/// query meets a tile's alignment within seven steps, and backward
/// extension reclaims what a late landing skipped.
const ANCHOR_LENGTH: usize = 8;

/// How many chain entries one probe walks before giving up. Bounds the
/// work a repetitive source — a padding run hashing every window into
/// one bucket — can demand per target position.
const PROBE_CAP: usize = 32;

/// The DATA header a mid-run copy leaves behind: taking a copy splits
/// one DATA command into two, and a run under 247 bytes heads with a
/// single byte.
const SPLIT_DATA_HEADER_ALLOWANCE: usize = 1;

// ── Public surface ───────────────────────────────────────────────────

/// A source match the finder stands behind: where it begins in the
/// source, how many bytes it runs, and how far it reached back into
/// the pending literal — the match begins `starts_earlier_by` bytes
/// before the query position, absorbing bytes the literal would have
/// carried.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SourceMatch {
    pub source_offset:     usize,
    pub length:            usize,
    pub starts_earlier_by: usize,
}

/// A longest-source-run index over the source, asked one query per
/// target position in walk order. Queries are `&mut self`: an accepted
/// match becomes the next pursuit base.
pub struct SourceHashChainMatcher<'src> {
    engine: EngineWidth<'src>,
}

/// The cell-width dispatch, chosen once at build (see the module's
/// widening note).
enum EngineWidth<'src> {
    Narrow(Engine<'src, u32>),
    Wide(Engine<'src, u64>),
}

impl<'src> SourceHashChainMatcher<'src> {
    pub fn build(source: &'src [u8]) -> Self {
        let engine = if tile_count_of(source.len()) < u32::MAX as usize {
            EngineWidth::Narrow(Engine::build(source))
        } else {
            EngineWidth::Wide(Engine::build(source))
        };
        SourceHashChainMatcher { engine }
    }

    /// The best source match for `target[position..]`, or `None` when
    /// nothing reaches [`MIN_MATCH_LENGTH`] and pays its wire.
    /// `literal_floor` is where the pending literal run began — an
    /// accepted match may reach back that far
    /// ('SourceMatch::starts_earlier_by'), never further. An accepted
    /// match updates the pursuit base.
    pub fn match_at(&mut self, target: &[u8], position: usize, literal_floor: usize) -> Option<SourceMatch> {
        match &mut self.engine {
            EngineWidth::Narrow(engine) => engine.match_at(target, position, literal_floor),
            EngineWidth::Wide(engine)   => engine.match_at(target, position, literal_floor),
        }
    }
}

// ── Chain cells ──────────────────────────────────────────────────────

/// An integer wide enough to hold a tile ordinal in the bucket heads
/// and chain links. Two impls: `u32` while the tile count stays below
/// it, `u64` beyond; `build` chooses once. Each type's `MAX` stays
/// free as the end-of-chain sentinel — the dispatcher caps the narrow
/// path's tile count strictly below it.
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

struct Engine<'src, Cell> {
    source:       &'src [u8],
    /// Newest anchor per bucket, as a tile ordinal; `CHAIN_END` for an
    /// untouched bucket.
    bucket_heads: Vec<Cell>,
    /// Per-tile next-older-anchor link, same bucket, keyed by tile
    /// ordinal (position = ordinal × ANCHOR_LENGTH, recomputed at the
    /// probe).
    chain_links:  Vec<Cell>,
    /// Right-shift turning a folded anchor's hash into a bucket index.
    hash_shift:   u32,
    pursuit:      Option<Pursuit>,
}

/// The pursuit base: the last accepted match, as the alignment it
/// established. At a later query the continuation candidate is
/// `source_offset + (position - target_position)` — the source byte
/// that match would have reached had it kept running.
#[derive(Copy, Clone)]
struct Pursuit {
    source_offset:   usize,
    target_position: usize,
}

impl<'src, Cell: ChainCell> Engine<'src, Cell> {
    fn build(source: &'src [u8]) -> Self {
        let tile_count = tile_count_of(source.len());
        let bucket_bits = bucket_bits_for(tile_count);
        let mut engine = Engine {
            source,
            bucket_heads: vec![Cell::CHAIN_END; 1 << bucket_bits],
            chain_links:  vec![Cell::CHAIN_END; tile_count],
            hash_shift:   u64::BITS - bucket_bits,
            pursuit:      None,
        };
        // Built in reverse: prepending walks each bucket newest-first,
        // so reverse order leaves the lowest source offsets at the
        // front — the smallest-offset preference among equal-length
        // matches, and the front of a repetitive run ahead of the probe
        // cap.
        for tile_ordinal in (0..tile_count).rev() {
            engine.insert_anchor(tile_ordinal);
        }
        engine
    }

    fn match_at(&mut self, target: &[u8], position: usize, literal_floor: usize) -> Option<SourceMatch> {
        if target.len() - position < MIN_MATCH_LENGTH {
            return None;
        }
        let pursued = self.pursue(target, position);
        let best = match pursued {
            Some(found) if found.length >= GOOD_ENOUGH_PURSUIT_LENGTH => found,
            _ => {
                // A discovery is taken only when it beats the lockstep
                // hold, so a coincidental short far match never
                // displaces an aligned run.
                let hold = self.lockstep_hold_length(target, position, pursued);
                let discovered = self
                    .probe(target, position)
                    .filter(|found| found.length > hold);
                // Pursuit wins ties: staying in source alignment keeps
                // later continuations open at no command cost.
                match (pursued, discovered) {
                    (None, None) => return None,
                    (Some(found), None) => found,
                    (None, Some(found)) => found,
                    (Some(pursued_match), Some(discovered_match)) =>
                        if discovered_match.length > pursued_match.length {
                            discovered_match
                        } else {
                            pursued_match
                        },
                }
            }
        };
        let reaching = self.extend_backward(best, target, position, literal_floor);
        Some(self.adopt(reaching, position - reaching.starts_earlier_by))
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
    /// The base is the match's own start, so a backward-reaching match
    /// records the same alignment its forward continuation will pursue.
    fn adopt(&mut self, found: SourceMatch, match_start_position: usize) -> SourceMatch {
        self.pursuit = Some(Pursuit {
            source_offset:   found.source_offset,
            target_position: match_start_position,
        });
        found
    }

    /// Reach an accepted match backward into the pending literal run:
    /// while the byte before the match agrees with the byte before the
    /// query, both step back, and the copy absorbs what the literal
    /// would have carried. Bounded by the literal floor (everything
    /// earlier is already covered) and by the source's start.
    fn extend_backward(
        &self,
        found: SourceMatch,
        target: &[u8],
        position: usize,
        literal_floor: usize,
    ) -> SourceMatch {
        let limit = (position - literal_floor).min(found.source_offset);
        let mut backset = 0;
        while backset < limit
            && self.source[found.source_offset - backset - 1] == target[position - backset - 1]
        {
            backset += 1;
        }
        SourceMatch {
            source_offset:     found.source_offset - backset,
            length:            found.length + backset,
            starts_earlier_by: backset,
        }
    }

    /// The pursuit-tier candidate: continue the last accepted match's
    /// source alignment at this position, if it still reaches the floor
    /// and pays its wire. An alignment whose continuation has run off
    /// the source's end has nothing left to read.
    fn pursue(&self, target: &[u8], position: usize) -> Option<SourceMatch> {
        let pursuit = self.pursuit?;
        let candidate = pursuit.source_offset + (position - pursuit.target_position);
        if candidate >= self.source.len() {
            return None;
        }
        let length = self.extend(candidate, target, position);
        (length >= MIN_MATCH_LENGTH && pays_its_wire_cost(candidate, length))
            .then_some(SourceMatch { source_offset: candidate, length, starts_earlier_by: 0 })
    }

    /// The discovery tier: walk the query anchor's chain and keep the
    /// longest wire-paying extension that reaches the floor, smallest
    /// offset winning ties (the chain leads with the smallest offsets,
    /// and only a strictly longer match displaces the incumbent).
    fn probe(&self, target: &[u8], position: usize) -> Option<SourceMatch> {
        if position + ANCHOR_LENGTH > target.len() {
            return None;
        }
        let bucket = self.bucket_of(&target[position..position + ANCHOR_LENGTH]);
        let mut best: Option<SourceMatch> = None;
        let mut cursor = self.bucket_heads[bucket];
        for _ in 0..PROBE_CAP {
            if cursor.is_chain_end() {
                break;
            }
            let tile_ordinal = cursor.as_index();
            let candidate = tile_ordinal * ANCHOR_LENGTH;
            let length = self.extend(candidate, target, position);
            if length >= MIN_MATCH_LENGTH
                && pays_its_wire_cost(candidate, length)
                && best.is_none_or(|incumbent| length > incumbent.length)
            {
                best = Some(SourceMatch { source_offset: candidate, length, starts_earlier_by: 0 });
            }
            cursor = self.chain_links[tile_ordinal];
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

    fn insert_anchor(&mut self, tile_ordinal: usize) {
        let tile_start = tile_ordinal * ANCHOR_LENGTH;
        let bucket = self.bucket_of(&self.source[tile_start..tile_start + ANCHOR_LENGTH]);
        self.chain_links[tile_ordinal] = self.bucket_heads[bucket];
        self.bucket_heads[bucket] = Cell::from_index(tile_ordinal);
    }

    /// Fold the anchor window into one register and Fibonacci-hash it
    /// down to a bucket index.
    fn bucket_of(&self, window: &[u8]) -> usize {
        let folded =
            u64::from_be_bytes(window.try_into().expect("gdiff differ: an anchor window is eight bytes"));
        (folded.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> self.hash_shift) as usize
    }
}

/// Whether a copy is worth its wire: it must save more literal bytes
/// than its own command costs, plus the DATA header its split leaves
/// behind. At two- and four-byte offset fields [`MIN_MATCH_LENGTH`]
/// already clears this; past the four-byte range a COPY spends
/// thirteen bytes, and only a longer run pays for it.
fn pays_its_wire_cost(source_offset: usize, length: usize) -> bool {
    length > copy_command_wire_cost(source_offset, length) + SPLIT_DATA_HEADER_ALLOWANCE
}

/// The wire bytes a COPY command spends at this offset and length: one
/// opcode byte plus the narrowest offset and length fields that fit —
/// the ladder of COPY 249–255, the same one create's opcode selection
/// climbs. An eight-byte offset rides COPY 255, the one opcode at that
/// width, whose length field is a fixed four-byte int.
fn copy_command_wire_cost(source_offset: usize, length: usize) -> usize {
    let offset_field_bytes =
        if source_offset <= 0xFFFF { 2 } else if source_offset <= 0xFFFF_FFFF { 4 } else { 8 };
    let length_field_bytes = if offset_field_bytes == 8 {
        4
    } else if length <= 0xFF {
        1
    } else if length <= 0xFFFF {
        2
    } else {
        4
    };
    1 + offset_field_bytes + length_field_bytes
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

/// Bucket-count bits for a tile count: one bucket per tile, rounded up
/// to a power of two, so the table's load stays at or under one and a
/// bucket's chain holds only true repeats and hash collisions —
/// [`PROBE_CAP`] bounds repetition, never reach. No ceiling: a capped
/// table saturates on large inputs and buries deep positions below the
/// probe cap. The two-tile floor only keeps the hash shift legal.
fn bucket_bits_for(tile_count: usize) -> u32 {
    tile_count.max(2).next_power_of_two().trailing_zeros()
}

/// How many whole anchor tiles the source holds: one per
/// [`ANCHOR_LENGTH`] bytes, counting only tiles that fit entirely.
fn tile_count_of(source_length: usize) -> usize {
    source_length / ANCHOR_LENGTH
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{copy_command_wire_cost, pays_its_wire_cost, SourceHashChainMatcher};

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
        let mut matcher = SourceHashChainMatcher::build(&source);
        let found = matcher.match_at(&source, 0, 0).expect("identical bytes match");
        assert_eq!((found.source_offset, found.length), (0, 4096));
    }

    #[test]
    fn a_relocated_run_is_discovered_at_its_smallest_visible_offset() {
        // The same 40-byte run planted at two tile-aligned source
        // offsets; the target is that run, so discovery must find it
        // and prefer the lower offset (the narrower wire field). Tile
        // alignment decides which of a run's duplicates the index can
        // see at all — visibility of the aligned plants is the part
        // this test owns.
        let mut source = pseudo_random_bytes(0x21, 4096);
        let run = pseudo_random_bytes(0x22, 40);
        source[496..536].copy_from_slice(&run);
        source[3000..3040].copy_from_slice(&run);
        let target = run;
        let mut matcher = SourceHashChainMatcher::build(&source);
        let found = matcher.match_at(&target, 0, 0).expect("the planted run matches");
        assert_eq!(found.source_offset, 496);
        assert!(found.length >= 40);
    }

    #[test]
    fn a_misaligned_run_is_reclaimed_by_backward_extension() {
        // A 40-byte run planted off tile alignment: the first whole tile
        // inside it sits four bytes past its start, so discovery lands
        // there — and backward extension walks the match back through
        // the pending literal to the run's true beginning.
        let mut source = pseudo_random_bytes(0x71, 4096);
        let run = pseudo_random_bytes(0x72, 40);
        source[500..540].copy_from_slice(&run);
        let target = run;
        let mut matcher = SourceHashChainMatcher::build(&source);
        for early_position in 0..4 {
            assert_eq!(
                matcher.match_at(&target, early_position, 0),
                None,
                "no whole tile is visible at {early_position}",
            );
        }
        let found = matcher.match_at(&target, 4, 0).expect("the tile at 504 is visible");
        assert_eq!(
            (found.source_offset, found.length, found.starts_earlier_by),
            (500, 40, 4),
            "the copy reaches back to the run's true start",
        );
    }

    #[test]
    fn a_short_coincidence_is_left_below_the_floor() {
        // Only seven shared bytes, one under the floor: no match offered.
        let source = pseudo_random_bytes(0x31, 512);
        let mut target = pseudo_random_bytes(0x32, 64);
        target[10..17].copy_from_slice(&source[100..107]);
        let mut matcher = SourceHashChainMatcher::build(&source);
        assert_eq!(matcher.match_at(&target, 10, 0), None);
    }

    #[test]
    fn pursuit_continues_across_a_one_byte_edit() {
        // An unedited prefix, one flipped byte, then more unedited source:
        // pursuit carries the first run, the flip falls below the floor,
        // and pursuit resumes right after it.
        let source = pseudo_random_bytes(0x41, 4096);
        let mut target = source.clone();
        target[2000] ^= 0x5a;
        let mut matcher = SourceHashChainMatcher::build(&source);
        let opening = matcher.match_at(&target, 0, 0).expect("the unedited prefix matches");
        assert_eq!((opening.source_offset, opening.length), (0, 2000));
        assert_eq!(matcher.match_at(&target, 2000, 2000), None, "the flipped byte alone");
        let resumed = matcher.match_at(&target, 2001, 2000).expect("pursuit resumes past the edit");
        assert_eq!(resumed.source_offset, 2001);
        assert_eq!(resumed.starts_earlier_by, 0, "the flipped byte stays a literal");
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
        let mut matcher = SourceHashChainMatcher::build(&source);
        let mut position = 0;
        let mut literal_floor = 0;
        let mut matches = Vec::new();
        while position < target.len() {
            match matcher.match_at(&target, position, literal_floor) {
                Some(found) => {
                    matches.push(found);
                    position = position - found.starts_earlier_by + found.length;
                    literal_floor = position;
                }
                None => position += 1,
            }
        }
        // One aligned run per gap (the leading flip at 0 makes the first
        // run start at offset 1), and every match ascending in source
        // offset — the fewest-commands shape.
        assert_eq!(matches.len(), target.len() / stride);
        for pair in matches.windows(2) {
            assert!(
                pair[1].source_offset > pair[0].source_offset,
                "matches must stay aligned, not fragment: {} then {}",
                pair[0].source_offset,
                pair[1].source_offset,
            );
        }
        assert!(matches.iter().all(|found| found.length >= 4000), "each run spans its gap");
    }

    #[test]
    fn an_empty_source_offers_nothing() {
        let target = pseudo_random_bytes(0x51, 64);
        let mut matcher = SourceHashChainMatcher::build(&[]);
        for position in 0..target.len() {
            assert_eq!(matcher.match_at(&target, position, 0), None);
        }
    }

    #[test]
    fn the_wire_cost_ladder_matches_the_copy_opcode_table() {
        // One rung per COPY opcode, 249 through 255.
        assert_eq!(copy_command_wire_cost(0xFFFF, 0xFF), 4);
        assert_eq!(copy_command_wire_cost(0xFFFF, 0xFFFF), 5);
        assert_eq!(copy_command_wire_cost(0xFFFF, 0x10000), 7);
        assert_eq!(copy_command_wire_cost(0x10000, 0xFF), 6);
        assert_eq!(copy_command_wire_cost(0x10000, 0xFFFF), 7);
        assert_eq!(copy_command_wire_cost(0x10000, 0x10000), 9);
        // COPY 255's length field is a fixed four-byte int, so the cost
        // holds at 13 however short the run.
        assert_eq!(copy_command_wire_cost(0x1_0000_0000, 0xFF), 13);
        assert_eq!(copy_command_wire_cost(0x1_0000_0000, 0x10000), 13);
    }

    #[test]
    fn an_eight_byte_match_pays_at_narrow_offsets_but_not_at_wide_ones() {
        assert!(pays_its_wire_cost(0xFFFF, 8), "two-byte offset: 8 > 4 + 1");
        assert!(pays_its_wire_cost(0xFFFF_FFFF, 8), "four-byte offset: 8 > 6 + 1");
        assert!(!pays_its_wire_cost(0x1_0000_0000, 8), "eight-byte offset: 8 < 13 + 1");
        assert!(!pays_its_wire_cost(0x1_0000_0000, 14), "a wash is not paying");
        assert!(pays_its_wire_cost(0x1_0000_0000, 15), "an eight-byte offset needs fifteen to pay");
    }
}
