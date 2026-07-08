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
//! over the [`ANCHOR_LENGTH`]-byte tiling of source and settled
//! target: source tiles indexed once at build, in reverse so each
//! bucket leads with run-start candidates (the probe cap then trims a
//! padding run's tail, not its head), and target tiles indexed lazily
//! as the walk settles output, so a candidate in the not-yet-written
//! zone is never in the table at all. One filed card per tile — an
//! eighth of a per-position index's cards — keeps the index scaling
//! with the pair and the bucket table scaled to its load; a query
//! meets a tile's alignment within
//! seven steps of byte-by-byte advance, and an accepted match then
//! reaches backward into the pending literal while the preceding
//! bytes agree, reclaiming the true start a tile-aligned landing can
//! sit a few bytes past. Chain cells hold tile ordinals — source
//! tiles first, then target tiles, no tile spanning the seam — at the
//! width the pair selects (`u32` whenever it fits, `u64` beyond), so
//! the finder stays total without paying eight-byte cells on ordinary
//! inputs.
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
//! long table's source half deliberately reverses. It remembers
//! [`SHORT_REACH_HORIZON`] bytes back, a ring rather than the whole
//! output, so its footprint stays flat however large the output
//! grows.

use crate::bps_diff::{encode_delta, varint_cost};

/// The window a chain anchor covers, and the stride long-table anchors
/// are filed at: source and settled target are tiled by contiguous
/// anchor-sized blocks, one filed card per tile. Wide enough to hash
/// as one register, and no wider than the shortest match discovery
/// should bother with — anything shorter only ever pays from the free
/// probes' cheap offsets or the short table, which don't tile.
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

/// How far back the short table remembers: the widest delta a
/// sub-anchor copy can strictly pay for beside a pending literal is
/// [`ANCHOR_LENGTH`]−4 varint bytes, and this is the last zigzag
/// distance that fits them (pinned to the emitter's arithmetic by
/// test). Rarer configurations could in theory pay from farther — no
/// literal pending, a cursor parked far from the write position, a
/// longer repeat the long table's tiles straddle — and that value
/// stays on the table.
const SHORT_REACH_HORIZON: usize = 135_274_559;

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
/// side it reads from, the file-relative position it starts at, how
/// many bytes it matches, and how far it reached back into the pending
/// literal — the match begins `starts_earlier_by` bytes before the
/// query position, absorbing bytes the literal would have carried. The
/// emit gate prices it against the pending literal; the finder never
/// emits.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct FoundMatch {
    pub side: MatchSide,
    pub file_position: usize,
    pub length: usize,
    pub starts_earlier_by: usize,
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
        // Narrow cells hold the long table's tile ordinals; the short
        // table's ring is u32 at any size.
        let total_tile_count = tile_count_of(source.len()) + tile_count_of(target.len());
        let engine = if total_tile_count < u32::MAX as usize {
            EngineWidth::Narrow(Engine::build(source, target))
        } else {
            EngineWidth::Wide(Engine::build(source, target))
        };
        HashChainMatcher { engine }
    }

    /// The best candidate at `position`, ranked by matched length minus
    /// the delta bytes its offset would spend from the given copy
    /// cursors, or `None` when nothing matches even one byte.
    /// `literal_floor` is where the pending literal run began — the
    /// accepted candidate may reach back that far
    /// ('FoundMatch::starts_earlier_by'), never further. The emit gate
    /// makes the final worth-it call.
    pub fn match_at(
        &mut self,
        position: usize,
        literal_floor: usize,
        last_source_copy_end: usize,
        last_target_copy_end: usize,
    ) -> Option<FoundMatch> {
        match &mut self.engine {
            EngineWidth::Narrow(engine) => {
                engine.match_at(position, literal_floor, last_source_copy_end, last_target_copy_end)
            }
            EngineWidth::Wide(engine) => {
                engine.match_at(position, literal_floor, last_source_copy_end, last_target_copy_end)
            }
        }
    }
}

// ── Chain cells ──────────────────────────────────────────────────────

/// An integer wide enough to hold a long-table tile ordinal in the
/// bucket heads and chain links. Two impls: `u32` while the total tile
/// count stays below it (tens of gigabytes of indexed bytes), `u64`
/// beyond; `build` chooses once. Each type's `MAX` stays free as the
/// end-of-chain sentinel — the dispatcher caps the narrow path's tile
/// count strictly below it.
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
    /// Newest anchor per bucket, as a tile ordinal; `CHAIN_END` for an
    /// untouched bucket.
    bucket_heads: Vec<Cell>,
    /// Per-tile next-older-anchor link, same bucket, keyed by tile
    /// ordinal: source tiles first (position = ordinal × ANCHOR_LENGTH),
    /// then target tiles (position = (ordinal − source_tile_count) ×
    /// ANCHOR_LENGTH), recomputed at the probe.
    chain_links: Vec<Cell>,
    /// Where target tile ordinals begin in `chain_links`.
    source_tile_count: usize,
    /// Right-shift turning a folded anchor's hash into a bucket index.
    hash_shift: u32,
    /// The short table (see the module's short-table note): newest
    /// anchor per bucket over settled output, and a ring of links
    /// spanning [`SHORT_REACH_HORIZON`]. Cells hold the low half of
    /// absolute target positions; the probe verifies each by distance,
    /// so a cell the ring has reused — or the one-in-four-billion
    /// position whose low half collides with the sentinel — merely
    /// ends the walk early.
    short_bucket_heads: Vec<u32>,
    short_chain_links: Vec<u32>,
    short_ring_mask: usize,
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
                source_tile_count: 0,
                hash_shift: u64::BITS,
                short_bucket_heads: Vec::new(),
                short_chain_links: Vec::new(),
                short_ring_mask: 0,
                short_hash_shift: u64::BITS,
                next_target_anchor: 0,
            };
        }
        let source_tile_count = tile_count_of(source.len());
        let total_tile_count = source_tile_count + tile_count_of(target.len());
        let bucket_bits = bucket_bits_for(total_tile_count);
        let short_bucket_bits = short_bucket_bits_for(target.len());
        // The ring must outlast the horizon — a card may only be
        // overwritten once no probe could still profit from it — and a
        // target shorter than the horizon gets a ring it can never
        // wrap: the bounded memory changes nothing below that size.
        let short_ring_slots = target.len().min(SHORT_REACH_HORIZON + 1).next_power_of_two();
        let mut engine = Engine {
            source,
            target,
            bucket_heads: vec![Cell::CHAIN_END; 1 << bucket_bits],
            chain_links: vec![Cell::CHAIN_END; total_tile_count],
            source_tile_count,
            hash_shift: u64::BITS - bucket_bits,
            short_bucket_heads: vec![u32::MAX; 1 << short_bucket_bits],
            short_chain_links: vec![u32::MAX; short_ring_slots],
            short_ring_mask: short_ring_slots - 1,
            short_hash_shift: u64::BITS - short_bucket_bits,
            next_target_anchor: 0,
        };
        // Built in reverse: prepending walks each bucket newest-first, so
        // reverse order leaves the lowest positions at the front — for
        // repeated content (a padding run hashing every tile into one
        // bucket) those are the run-start candidates with the longest
        // reach, and the probe cap then trims the tail of the run, not
        // its head.
        for tile_ordinal in (0..source_tile_count).rev() {
            let tile_start = tile_ordinal * ANCHOR_LENGTH;
            engine.insert_long_anchor(tile_ordinal, &source[tile_start..tile_start + ANCHOR_LENGTH]);
        }
        engine
    }

    fn match_at(
        &mut self,
        position: usize,
        literal_floor: usize,
        last_source_copy_end: usize,
        last_target_copy_end: usize,
    ) -> Option<FoundMatch> {
        self.index_settled_target_anchors(position);

        let identity = self.source_candidate(position, position, last_source_copy_end);
        let winner = match identity {
            Some(aligned) if aligned.found.length >= GOOD_ENOUGH_ALIGNED_LENGTH => aligned,
            _ => {
                let at_source_cursor =
                    self.source_candidate(last_source_copy_end, position, last_source_copy_end);
                let at_target_cursor =
                    self.target_candidate(last_target_copy_end, position, last_target_copy_end);
                let free_probes = best_of([identity, at_source_cursor, at_target_cursor]);
                match free_probes {
                    Some(cheap) if cheap.found.length >= GOOD_ENOUGH_ALIGNED_LENGTH => cheap,
                    _ => {
                        let mut discovered =
                            self.probe(position, last_source_copy_end, last_target_copy_end);
                        if discovered.map_or(true, |held| held.net < SHORT_REPEAT_CEILING_NET) {
                            discovered =
                                best_of([discovered, self.probe_short(position, last_target_copy_end)]);
                        }
                        // A discovered candidate must also beat the lockstep
                        // alternative — a one-byte literal with the offset-free
                        // SourceRead resuming at the next position — or a
                        // repeated region would spend a delta one byte before
                        // alignment comes back for free.
                        let discovered = discovered
                            .filter(|ranked| ranked.net > self.lockstep_hold_net(position));
                        best_of([free_probes, discovered])?
                    }
                }
            }
        };
        Some(self.extend_backward(
            winner.found,
            position,
            literal_floor,
            last_source_copy_end,
            last_target_copy_end,
        ))
    }

    /// Reach an accepted candidate backward into the pending literal
    /// run — the copy absorbs bytes the literal would have carried —
    /// and settle where the reach nets best, priced in the same wire
    /// bytes as every other candidate: each step back saves a literal
    /// byte, may widen the copy's cursor delta, and absorbing the run
    /// whole saves its flush. Ties keep the shorter reach. Bounded by
    /// the literal floor (everything earlier is already covered) and by
    /// the candidate's own region's start. The next cursor position is
    /// unchanged — the moved-back start and the grown length cancel.
    fn extend_backward(
        &self,
        found: FoundMatch,
        position: usize,
        literal_floor: usize,
        last_source_copy_end: usize,
        last_target_copy_end: usize,
    ) -> FoundMatch {
        let limit = (position - literal_floor).min(found.file_position);
        // The offset-free SourceRead stays offset-free as both ends
        // slide together, so its reach never widens a delta.
        let offset_free =
            found.side == MatchSide::FromSource && found.file_position == position;
        let cursor = match found.side {
            MatchSide::FromSource => last_source_copy_end,
            MatchSide::FromWrittenTarget => last_target_copy_end,
        };
        let delta_cost = |file_position: usize| {
            if offset_free {
                0
            } else {
                varint_cost(encode_delta(cursor, file_position)) as i64
            }
        };
        let whole_run_flush_credit =
            |backset: usize| i64::from(backset > 0 && backset == position - literal_floor);
        let mut best_backset = 0;
        let mut best_net = -delta_cost(found.file_position);
        let mut backset = 0;
        while backset < limit
            && self.byte_on_side(found.side, found.file_position - backset - 1)
                == self.target[position - backset - 1]
        {
            backset += 1;
            let net = backset as i64 + whole_run_flush_credit(backset)
                - delta_cost(found.file_position - backset);
            if net > best_net {
                best_net = net;
                best_backset = backset;
            }
        }
        FoundMatch {
            side: found.side,
            file_position: found.file_position - best_backset,
            length: found.length + best_backset,
            starts_earlier_by: best_backset,
        }
    }

    fn byte_on_side(&self, side: MatchSide, file_position: usize) -> u8 {
        match side {
            MatchSide::FromSource => self.source[file_position],
            MatchSide::FromWrittenTarget => self.target[file_position],
        }
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
    /// short table takes every settled position — recency is its job —
    /// while the long table files only tile-aligned starts whose whole
    /// tile fits, one card per settled tile, inside the same per-byte
    /// walk.
    fn index_settled_target_anchors(&mut self, position: usize) {
        while self.next_target_anchor < position
            && self.next_target_anchor + SHORT_ANCHOR_LENGTH <= self.target.len()
        {
            let anchor_start = self.next_target_anchor;
            if anchor_start % ANCHOR_LENGTH == 0 && anchor_start + ANCHOR_LENGTH <= self.target.len() {
                self.insert_long_anchor(
                    self.source_tile_count + anchor_start / ANCHOR_LENGTH,
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
            if cursor == u32::MAX {
                break;
            }
            // Cells hold the low half of a position; the distance says
            // whether this one is still the position it claims. Past
            // the horizon or at zero it is a reused or aliased cell,
            // and the chain ends here; the beyond-the-start arm cannot
            // fire, and exists only to keep the reconstruction total.
            let distance = (position as u32).wrapping_sub(cursor) as usize;
            if distance == 0 || distance > SHORT_REACH_HORIZON || distance > position {
                break;
            }
            let file_position = position - distance;
            let candidate = self.target_candidate(file_position, position, last_target_copy_end);
            best = best_of([best, candidate]);
            cursor = self.short_chain_links[file_position & self.short_ring_mask];
        }
        best
    }

    /// Walk the query anchor's chain and keep the best-net candidate.
    /// Anything the chain holds is legal (source tiles wholly within
    /// source, target tiles only from settled output), so ranking is
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
            let tile_ordinal = cursor.as_index();
            let candidate = if tile_ordinal < self.source_tile_count {
                self.source_candidate(tile_ordinal * ANCHOR_LENGTH, position, last_source_copy_end)
            } else {
                self.target_candidate(
                    (tile_ordinal - self.source_tile_count) * ANCHOR_LENGTH,
                    position,
                    last_target_copy_end,
                )
            };
            best = best_of([best, candidate]);
            cursor = self.chain_links[tile_ordinal];
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
                starts_earlier_by: 0,
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
                starts_earlier_by: 0,
            },
            net: length as i64 - delta_bytes as i64,
        })
    }

    fn insert_long_anchor(&mut self, tile_ordinal: usize, window: &[u8]) {
        let bucket = bucket_for(window, self.hash_shift);
        self.chain_links[tile_ordinal] = self.bucket_heads[bucket];
        self.bucket_heads[bucket] = Cell::from_index(tile_ordinal);
    }

    fn insert_short_anchor(&mut self, target_position: usize, window: &[u8]) {
        let bucket = bucket_for_short(window, self.short_hash_shift);
        self.short_chain_links[target_position & self.short_ring_mask] =
            self.short_bucket_heads[bucket];
        self.short_bucket_heads[bucket] = target_position as u32;
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

/// Bucket-count bits for the long table's tile count: one bucket per
/// tile, rounded up to a power of two, so the table's load stays at or
/// under one and a bucket's chain holds only true repeats and hash
/// collisions — [`PROBE_CAP`] bounds repetition, never reach. No
/// ceiling: a capped table saturates on large inputs and buries deep
/// positions below the probe cap. The two-tile floor only keeps the
/// hash shift legal.
fn bucket_bits_for(tile_count: usize) -> u32 {
    tile_count.max(2).next_power_of_two().trailing_zeros()
}

/// Bucket-count bits for the short table's per-byte anchors over the
/// target: roughly one bucket per position, held between 16 Ki buckets
/// (below which even tiny targets would chain needlessly) and 8 Mi
/// (above which the head table's own memory stops paying — recency is
/// the short table's job, and [`SHORT_PROBE_CAP`] reads only a bucket's
/// newest few anyway).
fn short_bucket_bits_for(target_length: usize) -> u32 {
    let wanted = usize::BITS - target_length.max(1).leading_zeros();
    wanted.clamp(14, 23)
}

/// How many whole anchor tiles an indexed span holds: one per
/// [`ANCHOR_LENGTH`] bytes, counting only tiles that fit entirely.
fn tile_count_of(indexed_length: usize) -> usize {
    indexed_length / ANCHOR_LENGTH
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{HashChainMatcher, MatchSide, ANCHOR_LENGTH, SHORT_REACH_HORIZON};

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
    fn the_short_reach_horizon_sits_on_the_wire_frontier() {
        // The widest delta a sub-anchor copy can strictly pay for
        // beside a pending literal: length ANCHOR_LENGTH−1 against the
        // gate's header, strict-improvement, and flush bytes leaves
        // ANCHOR_LENGTH−4 varint bytes, and the horizon is the last
        // backward zigzag distance that fits them. If the varint, the
        // zigzag, or the anchor width ever moves, this pins the
        // constant to the arithmetic it was derived from.
        use crate::bps_diff::{encode_delta, varint_cost};
        let widest_paying_delta_bytes = ANCHOR_LENGTH - 4;
        assert_eq!(
            varint_cost(encode_delta(SHORT_REACH_HORIZON, 0)),
            widest_paying_delta_bytes,
        );
        assert_eq!(
            varint_cost(encode_delta(SHORT_REACH_HORIZON + 1, 0)),
            widest_paying_delta_bytes + 1,
        );
    }

    #[test]
    fn identity_alignment_needs_no_table() {
        let source = pseudo_random_bytes(0x51, 500);
        let mut matcher = HashChainMatcher::build(&source, &source);
        let found = matcher.match_at(0, 0, 0, 0).expect("identical buffers match");
        assert_eq!(found.side, MatchSide::FromSource);
        assert_eq!((found.file_position, found.length), (0, 500));
    }

    #[test]
    fn a_relocated_block_is_discovered() {
        let source = pseudo_random_bytes(0x52, 4096);
        let mut target = pseudo_random_bytes(0x53, 1024);
        target[500..564].copy_from_slice(&source[2000..2064]);
        let mut matcher = HashChainMatcher::build(&source, &target);
        let found = matcher.match_at(500, 500, 0, 0).expect("a 64-byte relocation is findable");
        assert_eq!(found.side, MatchSide::FromSource);
        assert_eq!(found.file_position, 2000);
        assert!(found.length >= 64);
    }

    #[test]
    fn a_misaligned_relocation_is_reclaimed_by_backward_extension() {
        // A 64-byte block copied from a source position off tile
        // alignment: the first whole source tile inside it sits seven
        // bytes past its start, so discovery lands there — and backward
        // extension walks the match back through the pending literal to
        // the block's true beginning.
        let mut source = pseudo_random_bytes(0x58, 4096);
        let mut target = pseudo_random_bytes(0x59, 1024);
        target[501..565].copy_from_slice(&source[2001..2065]);
        source[2000] = 0xAA;
        target[500] = 0x55;
        source[2065] = 0x01;
        target[565] = 0x02;
        let mut matcher = HashChainMatcher::build(&source, &target);
        let found = matcher
            .match_at(508, 501, 0, 0)
            .expect("the tile at source 2008 is visible");
        assert_eq!(found.side, MatchSide::FromSource);
        assert_eq!(
            (found.file_position, found.length, found.starts_earlier_by),
            (2001, 64, 7),
            "the copy reaches back to the block's true start",
        );
    }

    #[test]
    fn a_backward_reach_that_buys_nothing_stays_put() {
        // One agreeing byte sits before the block, but reaching for it
        // pushes the cursor delta across a varint boundary: the reach
        // saves one literal byte and spends one delta byte, a wash the
        // pricing must decline. The cursor parks at 3031 so the
        // unextended delta (back 63, zigzag 127) is one byte and the
        // extended one (back 64, zigzag 129) is two.
        let mut source = pseudo_random_bytes(0x77, 4096);
        let mut target = pseudo_random_bytes(0x88, 512);
        let block = pseudo_random_bytes(0x99, 32);
        source[2968..3000].copy_from_slice(&block);
        target[300..332].copy_from_slice(&block);
        source[2967] = 0xAB;
        target[299] = 0xAB;
        source[2966] = 0xFF;
        target[298] = 0x00;
        source[3000] = 0x01;
        target[332] = 0x02;
        let mut matcher = HashChainMatcher::build(&source, &target);
        let found = matcher
            .match_at(300, 298, 3031, 0)
            .expect("the planted block matches");
        assert_eq!(found.side, MatchSide::FromSource);
        assert_eq!(
            (found.file_position, found.length, found.starts_earlier_by),
            (2968, 32, 0),
            "a wash is not worth leaving the one-byte delta for",
        );
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
        let found = matcher.match_at(0, 0, 3000, 0).expect("the planted block matches");
        assert_eq!(found.side, MatchSide::FromSource);
        assert_eq!(found.file_position, 3000);
    }

    #[test]
    fn a_nearby_short_repeat_is_found_through_the_short_table() {
        // A four-byte fragment repeating 60 bytes after its first
        // appearance, in otherwise unrelated bytes: below the long
        // anchor, invisible to the free probes, and worth one byte of
        // delta once the copy cursor sits nearby. The bytes just before
        // the two appearances are forced apart so the reach-back stays
        // out of this test's frame.
        let source = pseudo_random_bytes(0x56, 2048);
        let mut target = pseudo_random_bytes(0x57, 256);
        let fragment = [0xAA, 0xBB, 0xCC, 0xDD];
        target[40..44].copy_from_slice(&fragment);
        target[100..104].copy_from_slice(&fragment);
        target[39] = 0x00;
        target[99] = 0xFF;
        let mut matcher = HashChainMatcher::build(&source, &target);
        let found = matcher.match_at(100, 44, 0, 44).expect("the nearby repeat is worth its delta");
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
            assert_eq!(matcher.match_at(position, 0, 0, 0), None, "nothing settled at {position}");
        }
        let found = matcher.match_at(3, 0, 0, 0).expect("the period-3 run recurs from the start");
        assert_eq!(found.side, MatchSide::FromWrittenTarget);
        assert_eq!((found.file_position, found.length), (0, 15));
    }
}
