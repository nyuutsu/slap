//! bsdiff's match finder: the source index behind the one question the
//! diff walk in `bsdiff_diff.rs` asks at every unsettled target
//! position — the longest source match for the target suffix, where
//! and how long.
//!
//! The leanest of slap's hash-chain finders. It indexes the source
//! once and answers statelessly (`&self`): no pursuit tier, no
//! lockstep hold, no wire pricing. bsdiff's own scan loop carries the
//! current alignment and prices staying put against re-aligning (the
//! re-alignment margin in `bsdiff_diff`), so alignment judgment lives
//! in exactly one place, the differ.
//!
//! The chain sees nothing shorter than [`ANCHOR_LENGTH`], and the
//! answer is always at least that long or nothing: a shorter match
//! can neither clear the differ's re-alignment margin nor mark an
//! aligned resumption, except in the target's last few bytes, which
//! fall to the extra stream anyway. A hash collision whose real match
//! runs shorter than the anchor is discarded rather than surfaced, so
//! the answer never depends on which windows happened to collide.
//!
//! Source anchors are inserted in reverse so each bucket leads with
//! its run-start candidates — for repeated content (a padding run
//! hashing every window into one bucket) those have the longest
//! reach, and the probe cap then trims the run's tail, not its head.
//! Chain cells hold positions at the width the source's size selects
//! (`u32` whenever it fits, `u64` beyond), chosen once at build.
//! bsdiff's sign-magnitude wire fields are 64-bit, so no source is
//! refused for size: a wider source just buys wider links.

/// The window a chain anchor covers: wide enough to hash as one
/// register, and exactly the differ's re-alignment margin — the
/// shortest discovery that could ever out-explain a settled alignment.
const ANCHOR_LENGTH: usize = 8;

/// How many chain entries one probe walks before giving up. Bounds the
/// work a repetitive region — a padding run hashing every window into
/// one bucket — can demand per position; the walk asks at every
/// position of a mismatched stretch, so this cap is what holds the
/// differ's runtime line.
const PROBE_CAP: usize = 32;

// ── Public surface ───────────────────────────────────────────────────

/// The best source match the finder can offer at one target position:
/// where it starts in the source, and how many bytes it runs. Always
/// at least [`ANCHOR_LENGTH`] long.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SourceMatch {
    pub source_start: usize,
    pub length: usize,
}

/// A source-only candidate index for one diff. Built once, queried at
/// any target position in any order.
pub struct SourceHashChainMatcher<'source> {
    engine: EngineWidth<'source>,
}

/// The cell-width dispatch, chosen once at build (see the module's
/// storage note).
enum EngineWidth<'source> {
    Narrow(Engine<'source, u32>),
    Wide(Engine<'source, u64>),
}

impl<'source> SourceHashChainMatcher<'source> {
    /// Build the index over a source. A source shorter than one anchor
    /// window has nothing to index and every query answers `None`.
    pub fn build(source: &'source [u8]) -> Self {
        let engine = if source.len() < u32::MAX as usize {
            EngineWidth::Narrow(Engine::build(source))
        } else {
            EngineWidth::Wide(Engine::build(source))
        };
        SourceHashChainMatcher { engine }
    }

    /// The longest source match for `target[scan..]`, or `None` when
    /// nothing at least [`ANCHOR_LENGTH`] long exists in the chain's
    /// reach. Equal lengths prefer the start nearest
    /// `aligned_source_start` — the source position the walk's settled
    /// alignment names for `scan` — because a nearer start becomes a
    /// smaller seek magnitude on the wire, and small seeks are the
    /// zeros bzip2 crushes.
    pub fn longest_source_match(
        &self,
        target: &[u8],
        scan: usize,
        aligned_source_start: i64,
    ) -> Option<SourceMatch> {
        match &self.engine {
            EngineWidth::Narrow(engine) => engine.longest_source_match(target, scan, aligned_source_start),
            EngineWidth::Wide(engine)   => engine.longest_source_match(target, scan, aligned_source_start),
        }
    }
}

// ── Chain cells ──────────────────────────────────────────────────────

/// An integer wide enough to hold a source position in the bucket
/// heads and chain links. Two impls: `u32` for sources up to 4 GB,
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

struct Engine<'source, Cell> {
    source: &'source [u8],
    /// Newest anchor per bucket; `CHAIN_END` for an untouched bucket.
    /// Reverse-order insertion makes "newest" the lowest source
    /// position (see the module's run-start note).
    bucket_heads: Vec<Cell>,
    /// Per-source-position next-older-anchor link, same bucket.
    chain_links: Vec<Cell>,
    /// Right-shift turning a folded anchor's hash into a bucket index.
    hash_shift: u32,
}

impl<'source, Cell: ChainCell> Engine<'source, Cell> {
    fn build(source: &'source [u8]) -> Self {
        if source.len() < ANCHOR_LENGTH {
            return Engine {
                source,
                bucket_heads: Vec::new(),
                chain_links: Vec::new(),
                hash_shift: u64::BITS,
            };
        }
        let bucket_bits = bucket_bits_for(source.len());
        let mut engine = Engine {
            source,
            bucket_heads: vec![Cell::CHAIN_END; 1 << bucket_bits],
            chain_links: vec![Cell::CHAIN_END; source.len()],
            hash_shift: u64::BITS - bucket_bits,
        };
        for anchor_start in (0..=source.len() - ANCHOR_LENGTH).rev() {
            let bucket = bucket_for(&source[anchor_start..anchor_start + ANCHOR_LENGTH], engine.hash_shift);
            engine.chain_links[anchor_start] = engine.bucket_heads[bucket];
            engine.bucket_heads[bucket] = Cell::from_index(anchor_start);
        }
        engine
    }

    fn longest_source_match(
        &self,
        target: &[u8],
        scan: usize,
        aligned_source_start: i64,
    ) -> Option<SourceMatch> {
        if self.bucket_heads.is_empty() || scan + ANCHOR_LENGTH > target.len() {
            return None;
        }
        let target_suffix = &target[scan..];
        let bucket = bucket_for(&target_suffix[..ANCHOR_LENGTH], self.hash_shift);
        let mut best: Option<SourceMatch> = None;
        let mut cursor = self.bucket_heads[bucket];
        for _ in 0..PROBE_CAP {
            if cursor.is_chain_end() {
                break;
            }
            let source_start = cursor.as_index();
            let reach = (self.source.len() - source_start).min(target_suffix.len());
            let length = matched_length(&self.source[source_start..source_start + reach], target_suffix);
            if length >= ANCHOR_LENGTH && wins(best, source_start, length, aligned_source_start) {
                best = Some(SourceMatch { source_start, length });
            }
            cursor = self.chain_links[source_start];
        }
        best
    }
}

/// Whether a candidate beats the held best: strictly longer, or equal
/// and nearer the aligned source position (the seek-magnitude
/// preference from the query's doc).
fn wins(best: Option<SourceMatch>, source_start: usize, length: usize, aligned_source_start: i64) -> bool {
    match best {
        None => true,
        Some(held) => {
            length > held.length
                || (length == held.length
                    && seek_distance(source_start, aligned_source_start)
                        < seek_distance(held.source_start, aligned_source_start))
        }
    }
}

/// How far a candidate's start sits from the aligned source position —
/// the magnitude the emitted seek would roughly spend.
fn seek_distance(source_start: usize, aligned_source_start: i64) -> u64 {
    (source_start as i64).abs_diff(aligned_source_start)
}

/// Fold an anchor window into one register and Fibonacci-hash it down
/// to a bucket index under the given shift.
fn bucket_for(window: &[u8], hash_shift: u32) -> usize {
    let folded =
        u64::from_be_bytes(window.try_into().expect("bsdiff matcher: an anchor window is eight bytes"));
    (folded.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> hash_shift) as usize
}

/// Length of the common prefix of two slices, the shorter's length its
/// ceiling, compared a register at a time.
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

/// Bucket-count bits for a source's size: roughly one bucket per
/// indexed position, held between 16 Ki buckets (below which even tiny
/// inputs would chain needlessly) and 8 Mi (above which the head
/// table's own memory stops paying).
fn bucket_bits_for(source_length: usize) -> u32 {
    let wanted = usize::BITS - source_length.max(1).leading_zeros();
    wanted.clamp(14, 23)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{SourceHashChainMatcher, ANCHOR_LENGTH};

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
    fn a_relocated_block_is_discovered() {
        let source = pseudo_random_bytes(0x61, 4096);
        let mut target = pseudo_random_bytes(0x62, 1024);
        target[500..564].copy_from_slice(&source[2000..2064]);
        let matcher = SourceHashChainMatcher::build(&source);
        let found = matcher
            .longest_source_match(&target, 500, 500)
            .expect("a 64-byte relocation is findable");
        assert_eq!(found.source_start, 2000);
        assert!(found.length >= 64);
    }

    #[test]
    fn nothing_shorter_than_the_anchor_is_offered() {
        // Plant a 5-byte fragment of source into otherwise unrelated
        // target bytes: under the anchor width, so the finder must
        // answer None rather than surface it.
        let source = pseudo_random_bytes(0x63, 2048);
        let mut target = pseudo_random_bytes(0x64, 256);
        target[100..105].copy_from_slice(&source[700..705]);
        let matcher = SourceHashChainMatcher::build(&source);
        assert_eq!(matcher.longest_source_match(&target, 100, 100), None);
    }

    #[test]
    fn equal_lengths_prefer_the_nearer_start() {
        // The same 32-byte block at two source positions, unrelated
        // bytes ending both so neither extends further. With the
        // aligned position parked by the second copy, the second must
        // win the tie: its seek is the small one.
        let mut source = pseudo_random_bytes(0x65, 4096);
        let block = pseudo_random_bytes(0x66, 32);
        source[1000..1032].copy_from_slice(&block);
        source[3000..3032].copy_from_slice(&block);
        let target = block;
        let matcher = SourceHashChainMatcher::build(&source);
        let found = matcher
            .longest_source_match(&target, 0, 2980)
            .expect("the planted block matches");
        assert_eq!(found.source_start, 3000);
    }

    #[test]
    fn a_padding_run_answers_from_its_start() {
        // One long zero run: every window hashes into one bucket, and
        // reverse-order insertion leaves the run's start at the front
        // of the chain — the candidate with the longest reach.
        let source = vec![0u8; 8192];
        let target = vec![0u8; 512];
        let matcher = SourceHashChainMatcher::build(&source);
        let found = matcher
            .longest_source_match(&target, 0, 0)
            .expect("a zero run matches a zero run");
        assert_eq!(found.source_start, 0);
        assert_eq!(found.length, 512);
    }

    #[test]
    fn a_source_under_one_anchor_answers_none() {
        let source = [1u8, 2, 3];
        let target = pseudo_random_bytes(0x67, 64);
        let matcher = SourceHashChainMatcher::build(&source);
        assert_eq!(matcher.longest_source_match(&target, 0, 0), None);
    }

    #[test]
    fn the_last_target_bytes_answer_none() {
        // Fewer than one anchor window left at the query position:
        // nothing to hash, so None — those bytes are the extra
        // stream's to carry.
        let source = pseudo_random_bytes(0x68, 1024);
        let target = source.clone();
        let matcher = SourceHashChainMatcher::build(&source);
        let last_full_window = target.len() - ANCHOR_LENGTH;
        assert!(matcher.longest_source_match(&target, last_full_window, 0).is_some());
        assert_eq!(matcher.longest_source_match(&target, last_full_window + 1, 0), None);
    }
}
