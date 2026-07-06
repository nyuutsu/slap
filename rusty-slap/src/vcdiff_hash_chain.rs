//! VCDIFF's cost-aware matcher: the engine behind the worth-taking-match
//! query the cover greedy-parse in `vcdiff_diff.rs` asks at every target
//! position.
//!
//! ## The contract prices wire bytes, not match length
//!
//! The useful question is not "what is the longest run recurring earlier
//! in `U = source ++ target`" but "is there a copy here whose wire cost
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
//! * **Discovery** — a hash chain over [`ANCHOR_LENGTH`]-byte windows,
//!   probed when pursuit comes up short. A discovered candidate pays
//!   its real address arithmetic plus [`ADDRESS_NOISE_MARGIN`], so a
//!   relocation must be long enough to earn its address before it
//!   displaces literals — and it must also beat what lockstep already
//!   earns without it (the pursuit match here, or a literal byte and
//!   the pursuit match one position on), so a repeated region cannot
//!   lure the encoder off alignment one byte before pursuit resumes
//!   for free.
//!
//! Source anchors are indexed once at build; target anchors are indexed
//! lazily, only for positions the parse has settled, so a candidate
//! starting at or past the write head is never in the table at all.
//! Chain cells hold positions at the width the pair's size selects
//! (`u32` whenever `U` fits, `u64` beyond), so the matcher stays total
//! without paying eight-byte cells on ordinary inputs.

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

/// The window a chain anchor covers. Wide enough that the table never
/// holds runs shorter than any priced acceptance could take (every
/// acceptable discovered match is longer than the anchor), narrow
/// enough to hash as one register.
const ANCHOR_LENGTH: usize = 8;

/// How many chain entries one probe walks before giving up. Bounds the
/// work a repetitive region — a padding run hashing every window to the
/// same bucket — can demand per position.
const PROBE_CAP: usize = 32;

// ── Public surface ───────────────────────────────────────────────────

/// A worth-taking-match index over the superstring `U = source ++ target`,
/// asked one query per target position, in parse order. Queries are
/// `&mut self`: each one settles more of the target into the lazy index
/// and an accepted match becomes the next pursuit base.
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
    /// Build the matcher for a `(source, target)` pair. An empty target
    /// has no positions to query and skips indexing entirely.
    pub fn build(source: &'pair [u8], target: &'pair [u8]) -> Self {
        let superstring_length = source
            .len()
            .checked_add(target.len())
            .expect("vcdiff matcher: source + target overflows usize");
        let engine = if superstring_length < u32::MAX as usize {
            EngineWidth::Narrow(Engine::build(source, target))
        } else {
            EngineWidth::Wide(Engine::build(source, target))
        };
        HashChainMatcher { engine }
    }

    /// A match at `target[position..]` worth its wire cost, or `None`
    /// when literals are the better spend. The parse takes every match
    /// returned; the pricing lives here.
    pub fn match_at(&mut self, position: usize) -> Option<Match> {
        match &mut self.engine {
            EngineWidth::Narrow(engine) => engine.match_at(position),
            EngineWidth::Wide(engine) => engine.match_at(position),
        }
    }
}

// ── Chain cells ──────────────────────────────────────────────────────

/// An integer wide enough to hold a `U` position in the bucket heads
/// and chain links. Two impls: `u32` for pairs up to 4 GB, `u64`
/// beyond; `build` chooses once. Each type's `MAX` stays free as the
/// end-of-chain sentinel — the dispatcher caps the narrow path's input
/// strictly below it.
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
/// `u_offset + (position - target_position)` — the address that copy
/// would have reached had it kept running through the gap.
#[derive(Copy, Clone)]
struct Pursuit {
    u_offset: usize,
    target_position: usize,
}

struct Engine<'pair, Cell> {
    source: &'pair [u8],
    target: &'pair [u8],
    /// Newest anchor per bucket; `CHAIN_END` for an untouched bucket.
    bucket_heads: Vec<Cell>,
    /// Per-`U`-position next-older-anchor link, same bucket.
    chain_links: Vec<Cell>,
    /// Right-shift turning a folded anchor's hash into a bucket index.
    hash_shift: u32,
    /// First target position whose anchor is not yet in the table; the
    /// lazy indexing high-water mark.
    next_target_anchor: usize,
    pursuit: Option<Pursuit>,
}

impl<'pair, Cell: ChainCell> Engine<'pair, Cell> {
    fn build(source: &'pair [u8], target: &'pair [u8]) -> Self {
        // No positions will ever be queried, so no table is built: the
        // empty-target create should not pay for indexing a large source.
        if target.is_empty() {
            return Engine {
                source,
                target,
                bucket_heads: Vec::new(),
                chain_links: Vec::new(),
                hash_shift: u64::BITS,
                next_target_anchor: 0,
                pursuit: None,
            };
        }
        let superstring_length = source.len() + target.len();
        let bucket_bits = bucket_bits_for(superstring_length);
        let mut engine = Engine {
            source,
            target,
            bucket_heads: vec![Cell::CHAIN_END; 1 << bucket_bits],
            chain_links: vec![Cell::CHAIN_END; superstring_length],
            hash_shift: u64::BITS - bucket_bits,
            next_target_anchor: 0,
            pursuit: None,
        };
        // Anchors never span the source/target boundary: a copy starting
        // in the source segment may not cross its end (core invariant 2),
        // so a spanning window could only describe copies no window may
        // make.
        //
        // Built in reverse: prepending walks each bucket newest-first, so
        // reverse order leaves the lowest positions at the front — for
        // repeated content (a padding run hashing every window into one
        // bucket) those are the run-start candidates with the longest
        // reach and the cheapest SELF addresses, and the probe cap then
        // trims the tail of the run, not its head.
        if source.len() >= ANCHOR_LENGTH {
            for anchor_start in (0..=source.len() - ANCHOR_LENGTH).rev() {
                engine.insert_anchor(anchor_start, &source[anchor_start..anchor_start + ANCHOR_LENGTH]);
            }
        }
        engine
    }

    fn match_at(&mut self, position: usize) -> Option<Match> {
        self.index_settled_target_anchors(position);
        if self.target.len() - position < PURSUIT_MATCH_FLOOR {
            return None;
        }
        let pursued = self.pursue(position);
        if let Some(found) = pursued {
            if found.length >= GOOD_ENOUGH_PURSUIT_LENGTH {
                return Some(self.adopt(found, position));
            }
        }
        let worthwhile_discovery = self.probe(position).and_then(|(found, net)| {
            // A tie keeps lockstep: staying aligned keeps the streams regular.
            (net > self.lockstep_hold_net(position, pursued)).then_some(found)
        });
        worthwhile_discovery
            .or(pursued)
            .map(|found| self.adopt(found, position))
    }

    /// What lockstep already earns without a discovery: the pursuit
    /// match here, or a one-byte literal and the pursuit match one
    /// position on — whichever nets more, and `i64::MIN` with no
    /// pursuit to hold. A repeated region can hand the table a long
    /// candidate at a noisy address exactly one byte before pursuit
    /// resumes for free; a discovery that cannot beat this hold would
    /// trade a literal byte for address entropy.
    fn lockstep_hold_net(&self, position: usize, pursued: Option<Match>) -> i64 {
        let pursuit_net = |found: Match| found.length as i64 - PURSUIT_ENCODED_COST as i64;
        let held_now = pursued.map(pursuit_net);
        let held_next = self.pursue(position + 1).map(|resumed| pursuit_net(resumed) - 1);
        held_now.into_iter().chain(held_next).max().unwrap_or(i64::MIN)
    }

    /// Record an accepted match as the new pursuit base and hand it back.
    fn adopt(&mut self, found: Match, position: usize) -> Match {
        self.pursuit = Some(Pursuit {
            u_offset: found.superstring_offset,
            target_position: position,
        });
        found
    }

    /// Feed the table every target anchor the parse has settled: anchor
    /// starts strictly before `position` whose window lies inside the
    /// target. Nothing at or past the write head is ever inserted, so
    /// the table cannot answer with a copy no window may make.
    fn index_settled_target_anchors(&mut self, position: usize) {
        while self.next_target_anchor < position
            && self.next_target_anchor + ANCHOR_LENGTH <= self.target.len()
        {
            let anchor_start = self.next_target_anchor;
            self.insert_anchor(
                self.source.len() + anchor_start,
                &self.target[anchor_start..anchor_start + ANCHOR_LENGTH],
            );
            self.next_target_anchor += 1;
        }
    }

    /// The pursuit-tier candidate: extend the last accepted copy's
    /// alignment at this position, accepted from the floor up. A
    /// source-anchored alignment whose continuation has run off the
    /// source's end has nothing left to continue.
    fn pursue(&self, position: usize) -> Option<Match> {
        let pursuit = self.pursuit?;
        let candidate = pursuit.u_offset + (position - pursuit.target_position);
        if pursuit.u_offset < self.source.len() && candidate >= self.source.len() {
            return None;
        }
        let length = self.extend(candidate, position);
        if length >= PURSUIT_MATCH_FLOOR {
            Some(Match { superstring_offset: candidate, length })
        } else {
            None
        }
    }

    /// The discovery tier: walk the query anchor's chain and keep the
    /// candidate with the best net saving, provided it clears its own
    /// priced threshold. Returns the winner with its net, for the
    /// pursuit comparison at the caller.
    fn probe(&self, position: usize) -> Option<(Match, i64)> {
        if position + ANCHOR_LENGTH > self.target.len() {
            return None;
        }
        let here = self.source.len() + position;
        let bucket = self.bucket_of(&self.target[position..position + ANCHOR_LENGTH]);
        let mut best: Option<(Match, i64)> = None;
        let mut cursor = self.bucket_heads[bucket];
        for _ in 0..PROBE_CAP {
            if cursor.is_chain_end() {
                break;
            }
            let candidate = cursor.as_index();
            let length = self.extend(candidate, position);
            let cost = 1                                            // opcode
                + varint_length(length)                             // worst-case size varint
                + priced_address_bytes(candidate, here);
            if length >= cost + ADDRESS_NOISE_MARGIN {
                let net = length as i64 - cost as i64;
                if best.map_or(true, |(_, best_net)| net > best_net) {
                    best = Some((Match { superstring_offset: candidate, length }, net));
                }
            }
            cursor = self.chain_links[candidate];
        }
        best
    }

    /// The matched run length at a candidate: byte-wise agreement
    /// between `target[position..]` and `U[candidate..]`, capped at the
    /// target bytes still to be produced and, for a source-anchored
    /// candidate, at the source's end (core invariant 2). A
    /// target-anchored candidate may run past the write head — the
    /// self-referential overlap the format blesses — and comparing
    /// against the final target bytes is exact there, because that
    /// overlapped copy reproduces those very bytes.
    fn extend(&self, candidate: usize, position: usize) -> usize {
        let mut reach = self.target.len() - position;
        if candidate < self.source.len() {
            reach = reach.min(self.source.len() - candidate);
        }
        let mut length = 0;
        while length < reach
            && self.byte_in_superstring(candidate + length) == self.target[position + length]
        {
            length += 1;
        }
        length
    }

    fn byte_in_superstring(&self, u_offset: usize) -> u8 {
        if u_offset < self.source.len() {
            self.source[u_offset]
        } else {
            self.target[u_offset - self.source.len()]
        }
    }

    fn insert_anchor(&mut self, u_offset: usize, window: &[u8]) {
        let bucket = self.bucket_of(window);
        self.chain_links[u_offset] = self.bucket_heads[bucket];
        self.bucket_heads[bucket] = Cell::from_index(u_offset);
    }

    /// Fold the anchor window into one register and Fibonacci-hash it
    /// down to a bucket index.
    fn bucket_of(&self, window: &[u8]) -> usize {
        let mut folded = 0u64;
        for &byte in window {
            folded = folded << 8 | byte as u64;
        }
        (folded.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> self.hash_shift) as usize
    }
}

/// Bucket-count bits for a pair's combined size: roughly one bucket per
/// indexed position, held between 16 Ki buckets (below which even tiny
/// inputs would chain needlessly) and 8 Mi (above which the head table's
/// own memory stops paying).
fn bucket_bits_for(superstring_length: usize) -> u32 {
    let wanted = usize::BITS - superstring_length.max(1).leading_zeros();
    wanted.clamp(14, 23)
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
    use super::HashChainMatcher;

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
    fn a_far_four_byte_coincidence_is_left_as_literal() {
        // Plant exactly four source bytes inside an otherwise unrelated
        // target: the old exact-longest contract took this copy, and its
        // address bytes were the whole disease.
        let source = pseudo_random_bytes(0x21, 4096);
        let mut target = pseudo_random_bytes(0x22, 1024);
        target[500..504].copy_from_slice(&source[2000..2004]);
        let mut matcher = HashChainMatcher::build(&source, &target);
        assert_eq!(matcher.match_at(500), None);
    }

    #[test]
    fn a_relocated_block_is_worth_its_address() {
        let source = pseudo_random_bytes(0x31, 4096);
        let mut target = pseudo_random_bytes(0x32, 1024);
        target[500..564].copy_from_slice(&source[2000..2064]);
        let mut matcher = HashChainMatcher::build(&source, &target);
        let found = matcher.match_at(500).expect("a 64-byte relocation pays for its address");
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

        let mut cold = HashChainMatcher::build(&source, &target);
        assert_eq!(cold.match_at(101), None);

        let mut warm = HashChainMatcher::build(&source, &target);
        let opening = warm.match_at(0).expect("the unedited prefix matches");
        assert_eq!((opening.superstring_offset, opening.length), (0, 100));
        assert_eq!(warm.match_at(100), None);
        let tail = warm.match_at(101).expect("pursuit continues past the edit");
        assert_eq!((tail.superstring_offset, tail.length), (101, 6));
    }

    #[test]
    fn self_reference_still_answers_with_an_empty_source() {
        let target: Vec<u8> = b"abcabcabcabcabcabc".to_vec();
        let mut matcher = HashChainMatcher::build(&[], &target);
        for position in 0..3 {
            assert_eq!(matcher.match_at(position), None, "nothing earlier to copy at {position}");
        }
        let found = matcher.match_at(3).expect("the period-3 run recurs from the start");
        assert_eq!(found.superstring_offset, 0);
        assert_eq!(found.length, 15);
    }
}
