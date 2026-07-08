//! VCDIFF's cost-aware matcher: the engine behind the worth-taking-match
//! query the cover greedy-parse in `vcdiff_diff.rs` asks at every
//! position of a window.
//!
//! ## The contract prices wire bytes, not match length
//!
//! The useful question is not "what is the longest run recurring earlier
//! in `U = source ++ window`" but "is there a copy here whose wire cost
//! beats writing the bytes as literals". A COPY spends an opcode, a
//! size, and an address, and a far address is a few near-random bytes
//! the secondary compressor cannot squeeze, while the literal bytes it
//! displaces usually compress well. A four-byte coincidence on the far
//! side of a large source is therefore a loss: taken greedily by an
//! exact longest-match engine, thousands of them enlarge the compressed
//! patch while the raw byte count barely moves. So this engine prices
//! every candidate in wire bytes and offers only matches it stands
//! behind; the parse takes whatever is offered.
//!
//! ## Two tiers
//!
//! * **Pursuit** — the continuation of the last accepted copy, advanced
//!   through any literal gap. The address resolver encodes consecutive
//!   lockstep addresses through the near cache for a byte or two, so a
//!   pursuit match is priced near ([`PURSUIT_ENCODED_COST`]) and
//!   accepted from [`PURSUIT_MATCH_FLOOR`] up. Local edits keep the
//!   encoder in this tier almost permanently, which also keeps the
//!   emitted streams regular — and regular streams are what the
//!   secondary compressor flattens.
//! * **Discovery** — a hash chain over the [`ANCHOR_LENGTH`]-byte
//!   tiling, probed when pursuit comes up short. A discovered candidate pays
//!   its real address arithmetic plus [`ADDRESS_NOISE_MARGIN`], so a
//!   relocation must be long enough to earn its address before it
//!   displaces literals — and it must also beat what lockstep already
//!   earns without it (the pursuit match here, or a literal byte and
//!   the pursuit match one position on), so a repeated region cannot
//!   lure the encoder off alignment one byte before pursuit resumes
//!   for free.
//!
//! ## Windows
//!
//! One matcher serves a whole create: the source index is built once,
//! and each emitted window runs its own session ([`begin_window`]) in
//! which the window-side index and the pursuit start empty. A window's
//! world is exactly `source ++ its own slice`, so a copy into an
//! earlier window's output — the cross-window self-reference an
//! xdelta3 window cannot express — is never found, rather than found
//! and filtered. Source tiles are indexed in reverse so each bucket
//! leads with run-start, cheapest-address candidates; window tiles
//! are indexed lazily, only where the parse has settled, so a
//! candidate at or past the write head is never in the table at all.
//! Chain cells hold tile ordinals at the width the tile count selects
//! (`u32` through tens of gigabytes of indexed bytes, `u64` beyond),
//! so the matcher stays total without paying eight-byte cells on
//! ordinary inputs.
//!
//! [`ProducedTargetMatcher`] is the second engine under the same
//! pricing, serving the VCD_TARGET arm of RFC-flavor windowed
//! creation; its own docs have the world it searches. The two engines
//! share the acceptance policy (`choose_offer`), the candidate pricing
//! (`fold_priced_candidate`), and the lockstep hold, so what "worth
//! taking" means cannot drift between them.
//!
//! [`begin_window`]: HashChainMatcher::begin_window

use crate::vcdiff_diff::Match;

/// Shortest pursuit continuation worth a COPY. Four is the smallest
/// size the default code table's COPY rows encode, and a near-priced
/// copy (opcode, size, short near operand) breaks even against four
/// literals.
const PURSUIT_MATCH_FLOOR: usize = 4;

/// A pursuit match at least this long is taken without consulting the
/// hash table: a longer match elsewhere could exist, but leaving
/// lockstep for it would spend a fat address to save bytes the
/// compressor was already getting cheaply. Generous enough that
/// discovery still fires wherever an edit truly moved a block.
const GOOD_ENOUGH_PURSUIT_LENGTH: usize = 64;

/// The wire bytes a pursuit-tier copy is priced at: opcode, size, and
/// the short near-cache operand consecutive lockstep addresses resolve
/// to.
const PURSUIT_ENCODED_COST: usize = 4;

/// The surcharge a discovered candidate pays on top of its arithmetic
/// wire cost. An address is post-compression noise in an otherwise
/// regular stream, so a relocation must beat literals by a clear
/// margin, not a rounding error.
const ADDRESS_NOISE_MARGIN: usize = 4;

/// The window a chain anchor covers, and the stride anchors are filed
/// at: the indexed space is tiled by contiguous anchor-sized blocks,
/// one filed card per tile. Wide enough that the table never holds
/// runs shorter than any priced acceptance could take, narrow enough
/// to hash as one register. The tiling is what keeps the index a
/// fixed fraction of the input at any size — and any run of
/// 2×ANCHOR_LENGTH−1 bytes contains a whole tile, so it is
/// discoverable at every alignment; the parse advances byte by byte
/// through unmatched territory, so a query meets a tile's alignment
/// within ANCHOR_LENGTH−1 steps.
const ANCHOR_LENGTH: usize = 8;

/// How many chain entries one probe walks before giving up. Bounds the
/// work a repetitive region — a padding run hashing every window into
/// one bucket — can demand per position.
const PROBE_CAP: usize = 32;

/// How many source-tile inserts hash ahead of their table writes at
/// build time. An insert's one cache-hostile touch is its bucket head;
/// hashing a batch first and prefetching those heads lets the misses
/// overlap instead of serializing. Behavior-neutral: the inserts land
/// in the same order either way.
const INSERT_BATCH: usize = 64;

// ── Public surface ───────────────────────────────────────────────────

/// A worth-taking-match index over `U = source ++ current window`,
/// asked one query per window position, in parse order. Queries are
/// `&mut self`: each one settles more of the window into the lazy
/// index and an accepted match becomes the next pursuit base.
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
    /// Index the source and size the window-side buffers for the
    /// largest window a session will bring. Done once per create,
    /// however many windows follow.
    pub fn build(source: &'pair [u8], largest_window_length: usize) -> Self {
        let widest_ordinal =
            tile_count_of(source.len()).max(tile_count_of(largest_window_length));
        let engine = if widest_ordinal < u32::MAX as usize {
            EngineWidth::Narrow(Engine::build(source, largest_window_length))
        } else {
            EngineWidth::Wide(Engine::build(source, largest_window_length))
        };
        HashChainMatcher { engine }
    }

    /// Start a session over one window: the window-side index and the
    /// pursuit reset, the source index persists.
    pub fn begin_window(&mut self, window: &'pair [u8]) {
        match &mut self.engine {
            EngineWidth::Narrow(engine) => engine.begin_window(window),
            EngineWidth::Wide(engine) => engine.begin_window(window),
        }
    }

    /// A match at `window[position..]` worth its wire cost, or `None`
    /// when literals are the better spend. The parse takes every match
    /// returned; the pricing lives here. `literal_floor` is where the
    /// pending literal run began — the accepted match may reach back
    /// that far ('Match::starts_earlier_by'), never further.
    pub fn match_at(&mut self, position: usize, literal_floor: usize) -> Option<Match> {
        match &mut self.engine {
            EngineWidth::Narrow(engine) => engine.match_at(position, literal_floor),
            EngineWidth::Wide(engine) => engine.match_at(position, literal_floor),
        }
    }
}

/// A worth-taking-match index over `U = produced target ++ current
/// window`, for the VCD_TARGET arm of RFC-flavor windowed creation:
/// windows that copy from earlier windows' output instead of the
/// source file. Same query contract and pricing as
/// [`HashChainMatcher`]; what differs is the world a window sees.
///
/// Offsets are positions in the flat target — the output produced
/// before a window is exactly the target prefix below its base, so the
/// target is its own superstring and no second coordinate space
/// exists. One lazy index serves every session, retaining settled
/// positions across windows: the memory [`HashChainMatcher::begin_window`]
/// must discard, kept here because it is the very thing a VCD_TARGET
/// window references.
pub struct ProducedTargetMatcher<'target> {
    engine: ProducedTargetWidth<'target>,
}

/// The cell-width dispatch, chosen once at build, as [`EngineWidth`] is.
enum ProducedTargetWidth<'target> {
    Narrow(ProducedTargetEngine<'target, u32>),
    Wide(ProducedTargetEngine<'target, u64>),
}

impl<'target> ProducedTargetMatcher<'target> {
    /// Size the index for the whole target. Done once per create,
    /// however many windows follow.
    pub fn build(target: &'target [u8]) -> Self {
        let engine = if tile_count_of(target.len()) < u32::MAX as usize {
            ProducedTargetWidth::Narrow(ProducedTargetEngine::build(target))
        } else {
            ProducedTargetWidth::Wide(ProducedTargetEngine::build(target))
        };
        ProducedTargetMatcher { engine }
    }

    /// Start a session over the window at
    /// `target[window_base .. window_base + window_length]`. Sessions
    /// must arrive in target order — each leans on the settled index
    /// the ones before it grew.
    pub fn begin_window(&mut self, window_base: usize, window_length: usize) {
        match &mut self.engine {
            ProducedTargetWidth::Narrow(engine) => engine.begin_window(window_base, window_length),
            ProducedTargetWidth::Wide(engine) => engine.begin_window(window_base, window_length),
        }
    }

    /// A match at `window[position..]` worth its wire cost, or `None`
    /// when literals are the better spend — [`HashChainMatcher::match_at`]'s
    /// contract, answered from the produced target.
    pub fn match_at(&mut self, position: usize, literal_floor: usize) -> Option<Match> {
        match &mut self.engine {
            ProducedTargetWidth::Narrow(engine) => engine.match_at(position, literal_floor),
            ProducedTargetWidth::Wide(engine) => engine.match_at(position, literal_floor),
        }
    }
}

// ── Chain cells ──────────────────────────────────────────────────────

/// An integer wide enough to hold a tile ordinal in the bucket heads
/// and chain links. Two impls: `u32` while the tile count stays below
/// `u32::MAX` (tens of gigabytes of indexed bytes), `u64` beyond;
/// `build` chooses once. Each type's `MAX` stays free as the
/// end-of-chain sentinel — the dispatchers cap the narrow path's tile
/// counts strictly below it.
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

/// The pursuit base: the last accepted copy, as the alignment it
/// established. At a later query the continuation candidate is
/// `u_offset + (position - window_position)` — the address that copy
/// would have reached had it kept running through the gap.
#[derive(Copy, Clone)]
struct Pursuit {
    u_offset: usize,
    window_position: usize,
}

struct Engine<'pair, Cell> {
    source: &'pair [u8],
    /// The current session's window; empty until the first
    /// `begin_window`.
    window: &'pair [u8],
    /// The source index, built once: newest tile per bucket, and
    /// per-tile next-older-tile links, keyed by tile ordinal
    /// (position = ordinal × ANCHOR_LENGTH, recomputed at the probe).
    source_bucket_heads: Vec<Cell>,
    source_chain_links: Vec<Cell>,
    source_hash_shift: u32,
    /// The window index, reset per session: heads refilled, links
    /// overwritten as tiles settle. Keyed by tile ordinal within the
    /// window; a candidate's `U` offset is `source.len() +` its position.
    window_bucket_heads: Vec<Cell>,
    window_chain_links: Vec<Cell>,
    window_hash_shift: u32,
    /// First window tile start not yet in the table; the lazy indexing
    /// high-water mark, advancing a tile at a time.
    next_window_anchor: usize,
    pursuit: Option<Pursuit>,
}

impl<'pair, Cell: ChainCell> Engine<'pair, Cell> {
    fn build(source: &'pair [u8], largest_window_length: usize) -> Self {
        let source_tile_count = tile_count_of(source.len());
        let window_tile_count = tile_count_of(largest_window_length);
        let source_bucket_bits = bucket_bits_for(source_tile_count);
        let window_bucket_bits = bucket_bits_for(window_tile_count);
        let source_hash_shift = u64::BITS - source_bucket_bits;
        let mut source_bucket_heads = vec![Cell::CHAIN_END; 1 << source_bucket_bits];
        let mut source_chain_links = vec![Cell::CHAIN_END; source_tile_count];
        // Tiles never span the source's end ('tile_count_of' counts only
        // whole ones): a copy starting in the source segment may not
        // cross it (core invariant 2), so a spanning tile could only
        // describe copies no window may make.
        //
        // Built in reverse: prepending walks each bucket newest-first, so
        // reverse order leaves the lowest positions at the front — for
        // repeated content (a padding run hashing every tile into one
        // bucket) those are the run-start candidates with the longest
        // reach and the cheapest SELF addresses, and the probe cap then
        // trims the tail of the run, not its head. Inserts run a batch
        // at a time (INSERT_BATCH): hash the batch, prefetch its bucket
        // heads, then write.
        let mut batch_buckets = [0usize; INSERT_BATCH];
        let mut unfiled = source_tile_count;
        while unfiled > 0 {
            let batch = INSERT_BATCH.min(unfiled);
            for slot in 0..batch {
                let tile_start = (unfiled - 1 - slot) * ANCHOR_LENGTH;
                let bucket =
                    bucket_for(&source[tile_start..tile_start + ANCHOR_LENGTH], source_hash_shift);
                batch_buckets[slot] = bucket;
                prefetch_for_write(&source_bucket_heads[bucket]);
            }
            for slot in 0..batch {
                let tile_ordinal = unfiled - 1 - slot;
                let bucket = batch_buckets[slot];
                source_chain_links[tile_ordinal] = source_bucket_heads[bucket];
                source_bucket_heads[bucket] = Cell::from_index(tile_ordinal);
            }
            unfiled -= batch;
        }
        Engine {
            source,
            window: &[],
            source_bucket_heads,
            source_chain_links,
            source_hash_shift,
            window_bucket_heads: vec![Cell::CHAIN_END; 1 << window_bucket_bits],
            window_chain_links: vec![Cell::CHAIN_END; window_tile_count],
            window_hash_shift: u64::BITS - window_bucket_bits,
            next_window_anchor: 0,
            pursuit: None,
        }
    }

    fn begin_window(&mut self, window: &'pair [u8]) {
        debug_assert!(
            tile_count_of(window.len()) <= self.window_chain_links.len(),
            "vcdiff matcher: a window longer than the largest the build sized for"
        );
        self.window = window;
        self.window_bucket_heads.fill(Cell::CHAIN_END);
        self.next_window_anchor = 0;
        self.pursuit = None;
    }

    fn match_at(&mut self, position: usize, literal_floor: usize) -> Option<Match> {
        self.index_settled_window_anchors(position);
        if self.window.len() - position < PURSUIT_MATCH_FLOOR {
            return None;
        }
        let pursued = self.pursue(position);
        let offer = choose_offer(pursued, || self.probe(position), || {
            lockstep_hold_net(pursued, self.pursue(position + 1))
        });
        offer.map(|found| {
            let reaching = self.extend_backward(found, position, literal_floor);
            self.adopt(reaching, position - reaching.starts_earlier_by)
        })
    }

    /// Record an accepted match as the new pursuit base and hand it back.
    /// The base is the match's own start, so a backward-reaching match
    /// records the same alignment its forward continuation will pursue.
    fn adopt(&mut self, found: Match, match_start_position: usize) -> Match {
        self.pursuit = Some(Pursuit {
            u_offset: found.superstring_offset,
            window_position: match_start_position,
        });
        found
    }

    /// Reach an accepted match backward into the pending literal run:
    /// while the byte before the match agrees with the byte before the
    /// query, both step back, and the copy absorbs what the literal
    /// would have carried. Bounded by the literal floor (everything
    /// earlier is already covered), and by the candidate's own region —
    /// a source-anchored match stops at the source's start, a
    /// window-anchored one at the window's, since a copy may not cross
    /// the region seam.
    fn extend_backward(&self, found: Match, position: usize, literal_floor: usize) -> Match {
        let candidate = found.superstring_offset;
        let candidate_floor = if candidate < self.source.len() { 0 } else { self.source.len() };
        let limit = (position - literal_floor).min(candidate - candidate_floor);
        let mut backset = 0;
        while backset < limit
            && self.byte_in_superstring(candidate - backset - 1) == self.window[position - backset - 1]
        {
            backset += 1;
        }
        Match {
            superstring_offset: candidate - backset,
            length: found.length + backset,
            starts_earlier_by: backset,
        }
    }

    fn byte_in_superstring(&self, u_offset: usize) -> u8 {
        if u_offset < self.source.len() {
            self.source[u_offset]
        } else {
            self.window[u_offset - self.source.len()]
        }
    }

    /// Feed the table every window tile the parse has settled: tile
    /// starts strictly before `position` whose span lies inside the
    /// window. Nothing at or past the write head is ever inserted, so
    /// the table cannot answer with a copy no window may make.
    fn index_settled_window_anchors(&mut self, position: usize) {
        while self.next_window_anchor < position
            && self.next_window_anchor + ANCHOR_LENGTH <= self.window.len()
        {
            let tile_start = self.next_window_anchor;
            self.insert_window_anchor(
                tile_start / ANCHOR_LENGTH,
                &self.window[tile_start..tile_start + ANCHOR_LENGTH],
            );
            self.next_window_anchor += ANCHOR_LENGTH;
        }
    }

    /// The pursuit-tier candidate: extend the last accepted copy's
    /// alignment at this position, accepted from the floor up. A
    /// source-anchored alignment whose continuation has run off the
    /// source's end has nothing left to continue.
    fn pursue(&self, position: usize) -> Option<Match> {
        let pursuit = self.pursuit?;
        let candidate = pursuit.u_offset + (position - pursuit.window_position);
        if pursuit.u_offset < self.source.len() && candidate >= self.source.len() {
            return None;
        }
        let length = self.extend(candidate, position);
        if length >= PURSUIT_MATCH_FLOOR {
            Some(Match { superstring_offset: candidate, length, starts_earlier_by: 0 })
        } else {
            None
        }
    }

    /// The discovery tier: walk the query anchor's source and window
    /// chains and keep the candidate with the best net saving, provided
    /// it clears its own priced threshold. Returns the winner with its
    /// net, for the lockstep comparison at the caller.
    fn probe(&self, position: usize) -> Option<(Match, i64)> {
        if position + ANCHOR_LENGTH > self.window.len() {
            return None;
        }
        let here = self.source.len() + position;
        let anchor = &self.window[position..position + ANCHOR_LENGTH];
        let mut best: Option<(Match, i64)> = None;

        let mut source_cursor =
            self.source_bucket_heads[bucket_for(anchor, self.source_hash_shift)];
        for _ in 0..PROBE_CAP {
            if source_cursor.is_chain_end() {
                break;
            }
            let tile_ordinal = source_cursor.as_index();
            let candidate = tile_ordinal * ANCHOR_LENGTH;
            best = fold_priced_candidate(best, candidate, self.extend(candidate, position), here);
            source_cursor = self.source_chain_links[tile_ordinal];
        }

        let mut window_cursor =
            self.window_bucket_heads[bucket_for(anchor, self.window_hash_shift)];
        for _ in 0..PROBE_CAP {
            if window_cursor.is_chain_end() {
                break;
            }
            let tile_ordinal = window_cursor.as_index();
            let candidate = self.source.len() + tile_ordinal * ANCHOR_LENGTH;
            best = fold_priced_candidate(best, candidate, self.extend(candidate, position), here);
            window_cursor = self.window_chain_links[tile_ordinal];
        }

        best
    }

    /// The matched run length at a candidate: byte agreement between
    /// `window[position..]` and `U[candidate..]`, capped at the window
    /// bytes still to be produced and, for a source-anchored candidate,
    /// at the source's end (core invariant 2). A window-anchored
    /// candidate may run past the write head — the self-referential
    /// overlap the format blesses — and comparing against the final
    /// window bytes is exact there, because that overlapped copy
    /// reproduces those very bytes.
    fn extend(&self, candidate: usize, position: usize) -> usize {
        let query = &self.window[position..];
        if candidate < self.source.len() {
            let reach = query.len().min(self.source.len() - candidate);
            common_prefix_length(&self.source[candidate..candidate + reach], &query[..reach])
        } else {
            common_prefix_length(&self.window[candidate - self.source.len()..], query)
        }
    }

    fn insert_window_anchor(&mut self, tile_ordinal: usize, tile_bytes: &[u8]) {
        let bucket = bucket_for(tile_bytes, self.window_hash_shift);
        self.window_chain_links[tile_ordinal] = self.window_bucket_heads[bucket];
        self.window_bucket_heads[bucket] = Cell::from_index(tile_ordinal);
    }
}

// ── The produced-target engine ───────────────────────────────────────

struct ProducedTargetEngine<'target, Cell> {
    target: &'target [u8],
    /// One index over the whole target: bucket heads, and per-tile
    /// next-older-tile links, keyed by tile ordinal
    /// (position = ordinal × ANCHOR_LENGTH, recomputed at the probe).
    bucket_heads: Vec<Cell>,
    chain_links: Vec<Cell>,
    hash_shift: u32,
    /// First target tile start not yet in the table: the lazy
    /// high-water mark, advancing a tile at a time. Never reset — the
    /// settled tiles of earlier windows are exactly what a VCD_TARGET
    /// window draws on.
    next_anchor: usize,
    /// The current session's window, as its bounds in the target.
    window_base: usize,
    window_end: usize,
    pursuit: Option<Pursuit>,
}

impl<'target, Cell: ChainCell> ProducedTargetEngine<'target, Cell> {
    fn build(target: &'target [u8]) -> Self {
        let tile_count = tile_count_of(target.len());
        let bucket_bits = bucket_bits_for(tile_count);
        ProducedTargetEngine {
            target,
            bucket_heads: vec![Cell::CHAIN_END; 1 << bucket_bits],
            chain_links: vec![Cell::CHAIN_END; tile_count],
            hash_shift: u64::BITS - bucket_bits,
            next_anchor: 0,
            window_base: 0,
            window_end: 0,
            pursuit: None,
        }
    }

    fn begin_window(&mut self, window_base: usize, window_length: usize) {
        debug_assert!(
            window_base + window_length <= self.target.len(),
            "vcdiff produced-target matcher: a window past the target's end"
        );
        self.window_base = window_base;
        self.window_end = window_base + window_length;
        self.pursuit = None;
    }

    fn match_at(&mut self, position: usize, literal_floor: usize) -> Option<Match> {
        let write_head = self.window_base + position;
        self.index_settled_anchors(write_head);
        if self.window_end - write_head < PURSUIT_MATCH_FLOOR {
            return None;
        }
        let pursued = self.pursue(position);
        let offer = choose_offer(pursued, || self.probe(position), || {
            lockstep_hold_net(pursued, self.pursue(position + 1))
        });
        offer.map(|found| {
            let reaching = self.extend_backward(found, position, literal_floor);
            self.adopt(reaching, position - reaching.starts_earlier_by)
        })
    }

    /// Record an accepted match as the new pursuit base and hand it back.
    /// The base is the match's own start, so a backward-reaching match
    /// records the same alignment its forward continuation will pursue.
    fn adopt(&mut self, found: Match, match_start_position: usize) -> Match {
        self.pursuit = Some(Pursuit {
            u_offset: found.superstring_offset,
            window_position: match_start_position,
        });
        found
    }

    /// Reach an accepted match backward into the pending literal run, as
    /// [`Engine::extend_backward`] — the region seam here is the window
    /// base: a prior-target match stops at the target's start, a
    /// self-referential one at the base, since a copy that starts in the
    /// segment may not cross into the window's own output or the reverse.
    fn extend_backward(&self, found: Match, position: usize, literal_floor: usize) -> Match {
        let candidate = found.superstring_offset;
        let candidate_floor = if candidate < self.window_base { 0 } else { self.window_base };
        let limit = (position - literal_floor).min(candidate - candidate_floor);
        let write_head = self.window_base + position;
        let mut backset = 0;
        while backset < limit
            && self.target[candidate - backset - 1] == self.target[write_head - backset - 1]
        {
            backset += 1;
        }
        Match {
            superstring_offset: candidate - backset,
            length: found.length + backset,
            starts_earlier_by: backset,
        }
    }

    /// Feed the table every tile the parse has settled: tile starts
    /// strictly before the write head whose span lies inside the
    /// target. Nothing at or past the head is ever inserted, so the
    /// table cannot answer with a copy no window may make — and nothing
    /// is ever removed, so the mark only rises, across windows.
    fn index_settled_anchors(&mut self, write_head: usize) {
        while self.next_anchor < write_head
            && self.next_anchor + ANCHOR_LENGTH <= self.target.len()
        {
            let tile_start = self.next_anchor;
            self.insert_anchor(
                tile_start / ANCHOR_LENGTH,
                &self.target[tile_start..tile_start + ANCHOR_LENGTH],
            );
            self.next_anchor += ANCHOR_LENGTH;
        }
    }

    /// The pursuit-tier candidate, as [`Engine::pursue`] — minus its
    /// region-seam check: the produced target and the window are one
    /// contiguous buffer, so an alignment that advances past the window
    /// base becomes a self-referential one, still byte-exact.
    fn pursue(&self, position: usize) -> Option<Match> {
        let pursuit = self.pursuit?;
        let candidate = pursuit.u_offset + (position - pursuit.window_position);
        let length = self.extend(candidate, position);
        if length >= PURSUIT_MATCH_FLOOR {
            Some(Match { superstring_offset: candidate, length, starts_earlier_by: 0 })
        } else {
            None
        }
    }

    /// The discovery tier: one chain walk, the produced target and the
    /// window's settled prefix being one candidate space here.
    fn probe(&self, position: usize) -> Option<(Match, i64)> {
        let write_head = self.window_base + position;
        if write_head + ANCHOR_LENGTH > self.window_end {
            return None;
        }
        let anchor = &self.target[write_head..write_head + ANCHOR_LENGTH];
        let mut best: Option<(Match, i64)> = None;
        let mut cursor = self.bucket_heads[bucket_for(anchor, self.hash_shift)];
        for _ in 0..PROBE_CAP {
            if cursor.is_chain_end() {
                break;
            }
            let tile_ordinal = cursor.as_index();
            let candidate = tile_ordinal * ANCHOR_LENGTH;
            best = fold_priced_candidate(best, candidate, self.extend(candidate, position), write_head);
            cursor = self.chain_links[tile_ordinal];
        }
        best
    }

    /// The matched run length at a candidate: byte agreement between
    /// `window[position..]` and `target[candidate..]`, capped at the
    /// window bytes still to be produced and, for a candidate before
    /// the window base, at the base itself — a copy starting in the
    /// segment may not cross its end (core invariant 2), and the
    /// declared segment can reach no further than the output produced
    /// before this window. A candidate at or past the base may run past
    /// the write head: the self-referential overlap, exact against the
    /// final bytes because the overlapped copy reproduces them.
    fn extend(&self, candidate: usize, position: usize) -> usize {
        let write_head = self.window_base + position;
        let mut reach = self.window_end - write_head;
        if candidate < self.window_base {
            reach = reach.min(self.window_base - candidate);
        }
        common_prefix_length(
            &self.target[candidate..candidate + reach],
            &self.target[write_head..write_head + reach],
        )
    }

    fn insert_anchor(&mut self, tile_ordinal: usize, tile_bytes: &[u8]) {
        let bucket = bucket_for(tile_bytes, self.hash_shift);
        self.chain_links[tile_ordinal] = self.bucket_heads[bucket];
        self.bucket_heads[bucket] = Cell::from_index(tile_ordinal);
    }
}

// ── The shared tier policy ───────────────────────────────────────────

/// Decide one query from the two tiers' offers: a good-enough pursuit
/// is taken outright without consulting the table; otherwise a
/// discovery wins only by strictly beating what lockstep already earns
/// (a tie keeps lockstep: staying aligned keeps the streams regular),
/// and the pursuit is the fallback. Both engines answer through this,
/// so when each tier wins is decided once.
fn choose_offer(
    pursued: Option<Match>,
    probe: impl FnOnce() -> Option<(Match, i64)>,
    lockstep_hold: impl FnOnce() -> i64,
) -> Option<Match> {
    if let Some(found) = pursued {
        if found.length >= GOOD_ENOUGH_PURSUIT_LENGTH {
            return Some(found);
        }
    }
    let worthwhile_discovery =
        probe().and_then(|(found, net)| (net > lockstep_hold()).then_some(found));
    worthwhile_discovery.or(pursued)
}

/// What lockstep already earns without a discovery: the pursuit match
/// here, or a one-byte literal and the pursuit match one position on —
/// whichever nets more, and `i64::MIN` with no pursuit to hold. A
/// repeated region can hand the table a long candidate at a noisy
/// address exactly one byte before pursuit resumes for free; a
/// discovery that cannot beat this hold would trade a literal byte for
/// address entropy.
fn lockstep_hold_net(pursued: Option<Match>, pursued_one_on: Option<Match>) -> i64 {
    let pursuit_net = |found: Match| found.length as i64 - PURSUIT_ENCODED_COST as i64;
    let held_now = pursued.map(pursuit_net);
    let held_next = pursued_one_on.map(|resumed| pursuit_net(resumed) - 1);
    held_now.into_iter().chain(held_next).max().unwrap_or(i64::MIN)
}

/// Fold one discovery candidate into the running best: price its
/// measured run, and keep it only past its own threshold and the best
/// so far. The engines measure the run; the pricing lives once, here,
/// so a candidate costs the same whichever engine offers it.
fn fold_priced_candidate(
    best: Option<(Match, i64)>,
    candidate: usize,
    length: usize,
    here: usize,
) -> Option<(Match, i64)> {
    let cost = 1                                            // opcode
        + varint_length(length)                             // worst-case size varint
        + priced_address_bytes(candidate, here);
    if length >= cost + ADDRESS_NOISE_MARGIN {
        let net = length as i64 - cost as i64;
        if best.map_or(true, |(_, best_net)| net > best_net) {
            return Some((Match { superstring_offset: candidate, length, starts_earlier_by: 0 }, net));
        }
    }
    best
}

/// Hint the cache that a bucket head is about to be read and written.
/// Advice only, and a no-op where the intrinsic is unavailable, so
/// behavior never depends on it.
#[inline(always)]
fn prefetch_for_write<Cell>(head: *const Cell) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_prefetch(head as *const i8, core::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = head;
}

/// Fold an anchor window into one register and Fibonacci-hash it down
/// to a bucket index under the given shift.
fn bucket_for(window_bytes: &[u8], hash_shift: u32) -> usize {
    let folded =
        u64::from_be_bytes(window_bytes.try_into().expect("vcdiff matcher: an anchor tile is eight bytes"));
    (folded.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> hash_shift) as usize
}

/// Bucket-count bits for a tile count: one bucket per tile, rounded up
/// to a power of two, so the table's load stays at or under one and a
/// bucket's chain holds only true repeats and hash collisions —
/// 'PROBE_CAP' bounds repetition, never reach. No ceiling: a capped
/// table saturates on large inputs and buries deep positions below the
/// probe cap. The two-tile floor only keeps the hash shift legal.
fn bucket_bits_for(tile_count: usize) -> u32 {
    tile_count.max(2).next_power_of_two().trailing_zeros()
}

/// How many whole anchor tiles an indexed space holds: one per
/// ANCHOR_LENGTH bytes, counting only tiles that fit entirely.
fn tile_count_of(indexed_length: usize) -> usize {
    indexed_length / ANCHOR_LENGTH
}

/// The byte length of the common prefix of two slices, compared a
/// register at a time. Behaviorally the byte loop it replaces —
/// including on overlapping slices of one buffer, where both sides
/// read the same final bytes either way.
fn common_prefix_length(left: &[u8], right: &[u8]) -> usize {
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

/// The bytes a VCDIFF varint spends on a value: one per 7-bit group.
fn varint_length(value: usize) -> usize {
    let mut groups = 1;
    let mut rest = value >> 7;
    while rest > 0 {
        groups += 1;
        rest >>= 7;
    }
    groups
}

/// The address bytes a discovered candidate would spend: the cheaper of
/// SELF (the absolute offset) and HERE (the distance back from the
/// write head), the two modes always on offer. The near and same caches
/// can beat this for an address the recent past happens to hold, so the
/// price is a mild overestimate — which only ever makes discovery more
/// demanding, never lets a bad match through.
fn priced_address_bytes(candidate: usize, here: usize) -> usize {
    varint_length(candidate).min(varint_length(here - candidate))
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{HashChainMatcher, ProducedTargetMatcher};

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

    fn matcher_over<'pair>(
        source: &'pair [u8],
        window: &'pair [u8],
    ) -> HashChainMatcher<'pair> {
        let mut matcher = HashChainMatcher::build(source, window.len());
        matcher.begin_window(window);
        matcher
    }

    #[test]
    fn a_far_four_byte_coincidence_is_left_as_literal() {
        // Plant exactly four source bytes inside an otherwise unrelated
        // target: the old exact-longest contract took this copy, and its
        // address bytes were the whole disease.
        let source = pseudo_random_bytes(0x21, 4096);
        let mut target = pseudo_random_bytes(0x22, 1024);
        target[500..504].copy_from_slice(&source[2000..2004]);
        let mut matcher = matcher_over(&source, &target);
        assert_eq!(matcher.match_at(500, 0), None);
    }

    #[test]
    fn a_relocated_block_is_worth_its_address() {
        let source = pseudo_random_bytes(0x31, 4096);
        let mut target = pseudo_random_bytes(0x32, 1024);
        target[500..564].copy_from_slice(&source[2000..2064]);
        let mut matcher = matcher_over(&source, &target);
        let found = matcher.match_at(500, 0).expect("a 64-byte relocation pays for its address");
        assert_eq!(found.superstring_offset, 2000);
        assert!(found.length >= 64);
    }

    #[test]
    fn pursuit_reaches_where_discovery_cannot() {
        // A short tail behind a one-byte edit: too short for an anchor,
        // priced out for discovery, but the continuation of the copy
        // before it — so pursuit takes it, and only pursuit.
        let source = pseudo_random_bytes(0x41, 200);
        let mut target = source[..107].to_vec();
        target[100] ^= 0x5a;

        let mut cold = matcher_over(&source, &target);
        assert_eq!(cold.match_at(101, 0), None);

        let mut warm = matcher_over(&source, &target);
        let opening = warm.match_at(0, 0).expect("the unedited prefix matches");
        assert_eq!((opening.superstring_offset, opening.length), (0, 100));
        assert_eq!(warm.match_at(100, 100), None);
        let tail = warm.match_at(101, 100).expect("pursuit continues past the edit");
        assert_eq!((tail.superstring_offset, tail.length), (101, 6));
    }

    #[test]
    fn self_reference_still_answers_with_an_empty_source() {
        let target: Vec<u8> = b"abcabcabcabcabcabc".to_vec();
        let mut matcher = matcher_over(&[], &target);
        for position in 0..3 {
            assert_eq!(matcher.match_at(position, 0), None, "nothing earlier to copy at {position}");
        }
        let found = matcher.match_at(3, 0).expect("the period-3 run recurs from the start");
        assert_eq!(found.superstring_offset, 0);
        assert_eq!(found.length, 15);
    }

    #[test]
    fn a_new_session_forgets_the_previous_window() {
        // Two identical windows over an empty source: within the first,
        // position 8 copies the settled start; a fresh session over the
        // second window holds nothing settled, so the same query finds
        // nothing — the cross-window reference does not exist to find.
        let pattern = pseudo_random_bytes(0x61, 8);
        let mut window: Vec<u8> = pattern.clone();
        window.extend_from_slice(&pattern);
        let mut matcher = HashChainMatcher::build(&[], window.len());

        matcher.begin_window(&window);
        let within = matcher.match_at(8, 0).expect("the repeat is visible within one window");
        assert_eq!((within.superstring_offset, within.length), (0, 8));

        matcher.begin_window(&window);
        for warmup in 0..3 {
            assert_eq!(matcher.match_at(warmup, 0), None, "fresh session at {warmup}");
        }
    }

    #[test]
    fn the_produced_target_engine_remembers_earlier_windows() {
        // The same repeated-window shape the source-pair engine must
        // forget across sessions: here the second window's opening
        // position copies the first window whole — the reference
        // VCD_TARGET exists for.
        let pattern = pseudo_random_bytes(0x81, 8);
        let mut target: Vec<u8> = pattern.clone();
        target.extend_from_slice(&pattern);
        let mut matcher = ProducedTargetMatcher::build(&target);

        matcher.begin_window(0, 8);
        assert_eq!(matcher.match_at(0, 0), None, "window 0 has nothing settled to copy");

        matcher.begin_window(8, 8);
        let across = matcher.match_at(0, 0).expect("window 1 copies window 0 whole");
        assert_eq!((across.superstring_offset, across.length), (0, 8));
    }

    #[test]
    fn a_copy_from_the_produced_target_stops_at_the_window_base() {
        // target[12..36], [36..60], and [60..84] are the same 24 bytes,
        // so byte agreement from the tile at position 16 runs all the
        // way to the end of the target — but a copy starting before the
        // base may not cross it, so the offer must stop at the base.
        let run = pseudo_random_bytes(0x82, 24);
        let mut target = pseudo_random_bytes(0x83, 12);
        for _ in 0..3 {
            target.extend_from_slice(&run);
        }
        let mut matcher = ProducedTargetMatcher::build(&target);
        matcher.begin_window(0, 36);
        matcher.begin_window(36, 48);
        let capped = matcher.match_at(4, 0).expect("the run before the base is offered");
        assert_eq!(
            (capped.superstring_offset, capped.length, capped.starts_earlier_by),
            (12, 24, 4),
            "backward reach absorbs the four literal bytes, and the copy still ends at the base",
        );
    }

    #[test]
    fn window_zero_still_self_references() {
        let target: Vec<u8> = b"abcabcabcabcabcabc".to_vec();
        let mut matcher = ProducedTargetMatcher::build(&target);
        matcher.begin_window(0, target.len());
        for position in 0..3 {
            assert_eq!(matcher.match_at(position, 0), None, "nothing earlier to copy at {position}");
        }
        let found = matcher.match_at(3, 0).expect("the period-3 run recurs from the start");
        assert_eq!(found.superstring_offset, 0);
        assert_eq!(found.length, 15);
    }
}
