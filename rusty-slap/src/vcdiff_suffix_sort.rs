//! VCDIFF's own suffix-array matcher: the engine behind the
//! longest-match query the cover greedy-parse in `vcdiff_diff.rs` asks
//! at every target position. It answers, for the suffix beginning at a
//! target position, the longest run that recurs earlier in the
//! superstring `U = source ++ target` — the same span a VCDIFF COPY
//! reproduces.
//!
//! ## Why VCDIFF wants its own
//!
//! The sibling `xdelta1_suffix_array` matches against the source alone,
//! so every source position is a candidate and the query is a plain
//! binary search for the best common prefix. VCDIFF matches against the
//! superstring, which carries two constraints a source-only index never
//! meets:
//!
//!   * **Write head.** A COPY may only reach bytes already settled or
//!     being produced — never target bytes ahead of the position it is
//!     writing. So a candidate must *begin earlier* than the current
//!     write head `source.len() + position`. This is the longest-
//!     previous-factor shape, not the unconstrained longest-match shape.
//!   * **Source-segment end.** A COPY anchored in the source segment may
//!     not run past the source's end into the target region; the apply
//!     path reads such a copy as a single source read and would run off
//!     the end. A source-anchored match is capped at `source.len()`.
//!
//! ## The augmented string folds both constraints in
//!
//! We build the suffix array over
//!
//! ```text
//!     source ++ [separator] ++ target ++ [terminator]
//! ```
//!
//! where the separator and terminator are two symbols distinct from
//! every byte. Then the matcher is the textbook *longest previous
//! factor*: for the suffix at the query's position, the longest common
//! prefix with any suffix whose text position is smaller.
//!
//!   * The **separator** caps a source-anchored match exactly at the
//!     source's end — a source suffix, compared past `source.len()`,
//!     hits the separator, which equals no target byte, so the common
//!     prefix stops there.
//!   * "Text position smaller than the query's" is exactly the **write-
//!     head** constraint once the coordinates are lined up: a candidate
//!     earlier than the query in the augmented string is a source byte,
//!     or a target byte the patch has already produced. A self-
//!     referential / run-length overlap (a copy reading bytes it is
//!     itself emitting) is found naturally, because the augmented
//!     string holds the whole target and the LCP simply runs into it.
//!   * The **terminator** is the smallest symbol and unique, so every
//!     suffix is distinct and the suffix array is total.
//!
//! With the caps folded into the string, the per-candidate match length
//! is just the LCP, which is monotone along suffix-array order. So the
//! best earlier-starting candidate on each side of the query is the
//! *nearest* one in suffix-array order whose text position is smaller —
//! a previous/next-smaller-value walk with the running LCP carried
//! alongside.
//!
//! ## Storage
//!
//! Construction is this module's own SA-IS (Nong, Zhang, Chan 2009),
//! over the augmented string as `u16` symbols. Everything built on it —
//! the suffix array, ranks, LCPs, the two nearest-smaller scans, the
//! retained answers — runs at the cell width the input's size selects:
//! `u32` whenever the augmented string fits, `u64` beyond, so the
//! matcher stays total without paying eight-byte cells on the passes
//! that dominate memory bandwidth. The quadratic reference this engine
//! replaced lives on as the differential oracle in `vcdiff_diff.rs`.

// ── Public surface ───────────────────────────────────────────────────

/// The longest match found for a target position: where it begins in
/// the superstring `U = source ++ target` and how long it runs. Shared
/// with `vcdiff_diff.rs`, which feeds it to the cover's greedy parse,
/// and with that module's differential oracle.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Match {
    pub superstring_offset: usize,
    pub length: usize,
}

/// A longest-match index over the superstring `U = source ++ target`,
/// answering one query per target position. Construction does all the
/// work up front and keeps only the per-position answers, so the
/// retained footprint is two `target`-sized arrays.
pub struct SuperstringMatcher {
    answers: MatchAnswers,
}

/// The retained per-position answers, at the width construction chose
/// (see the module's Storage note). `match_length[p]` is the length of
/// the longest run beginning at `target[p]` that recurs earlier in `U`,
/// `0` meaning no recurrence (the position begins a literal);
/// `match_u_offset[p]` is the absolute offset into `U` at which that
/// recurrence begins, meaningful only where the length is positive.
enum MatchAnswers {
    Narrow {
        match_length: Vec<u32>,
        match_u_offset: Vec<u32>,
    },
    Wide {
        match_length: Vec<u64>,
        match_u_offset: Vec<u64>,
    },
}

impl SuperstringMatcher {
    /// Build the matcher for a `(source, target)` pair. An empty target
    /// has no positions to query and skips the suffix array entirely.
    pub fn build(source: &[u8], target: &[u8]) -> Self {
        if target.is_empty() {
            return SuperstringMatcher {
                answers: MatchAnswers::Narrow {
                    match_length: Vec::new(),
                    match_u_offset: Vec::new(),
                },
            };
        }
        let augmented = build_augmented_string(source, target);
        let answers = if augmented.len() <= U32_INTERNAL_THRESHOLD {
            let sorted_positions =
                suffix_sort_over_alphabet::<u32>(&augmented, AUGMENTED_ALPHABET_SIZE);
            let (match_length, match_u_offset) =
                build_match_answers(&augmented, &sorted_positions, source.len(), target.len());
            MatchAnswers::Narrow { match_length, match_u_offset }
        } else {
            let sorted_positions =
                suffix_sort_over_alphabet::<u64>(&augmented, AUGMENTED_ALPHABET_SIZE);
            let (match_length, match_u_offset) =
                build_match_answers(&augmented, &sorted_positions, source.len(), target.len());
            MatchAnswers::Wide { match_length, match_u_offset }
        };
        SuperstringMatcher { answers }
    }

    /// The longest match of `target[position..]` recurring earlier in
    /// `U = source ++ target`, or `None` when nothing recurs. The cover
    /// applies its own minimum-match floor; this reports the true
    /// longest regardless of length, the same contract the differential
    /// oracle holds.
    pub fn longest_match_at(&self, position: usize) -> Option<Match> {
        let (length, superstring_offset) = match &self.answers {
            MatchAnswers::Narrow { match_length, match_u_offset } => {
                (match_length[position] as usize, match_u_offset[position] as usize)
            }
            MatchAnswers::Wide { match_length, match_u_offset } => {
                (match_length[position] as usize, match_u_offset[position] as usize)
            }
        };
        if length == 0 {
            None
        } else {
            Some(Match { superstring_offset, length })
        }
    }
}

// ── The augmented string ─────────────────────────────────────────────

/// The separator between the source and target regions. Its only job is
/// to stop a source-anchored common prefix at the source's end.
const SEPARATOR: u16 = 1;

/// The terminator closing the augmented string: the unique smallest
/// symbol, making every suffix distinct.
const TERMINATOR: u16 = 0;

/// Real bytes shift up by this much to sit above the two sentinels.
const SYMBOL_SHIFT: u16 = 2;

/// The augmented alphabet: 256 shifted byte values plus the two
/// sentinels below them.
const AUGMENTED_ALPHABET_SIZE: usize = 258;

/// Map a `(source, target)` pair to the augmented symbol string the
/// suffix array is built over. Real bytes become `2..=257`; the
/// separator is `1` and the terminator `0`, both distinct from every
/// byte and from each other.
fn build_augmented_string(source: &[u8], target: &[u8]) -> Vec<u16> {
    // Checked: a sum past usize must die loudly, never wrap into a tiny
    // buffer. Slap's create path refuses such pairs before this.
    let augmented_length = source
        .len()
        .checked_add(target.len())
        .and_then(|combined| combined.checked_add(2))
        .expect("vcdiff matcher: source + target + two sentinels overflows usize");
    let mut augmented = Vec::with_capacity(augmented_length);
    augmented.extend(source.iter().map(|&byte| byte as u16 + SYMBOL_SHIFT));
    augmented.push(SEPARATOR);
    augmented.extend(target.iter().map(|&byte| byte as u16 + SYMBOL_SHIFT));
    augmented.push(TERMINATOR);
    augmented
}

/// Translate an augmented-string text position into an offset into
/// `U = source ++ target`. Source bytes keep their position; target
/// bytes sit one further along in the augmented string (the separator
/// between the regions), so they shift back by one. The separator's own
/// position never reaches here — it shares no prefix with any target
/// byte, so it is never a positive-length neighbour.
fn superstring_offset_of(text_position: usize, source_length: usize) -> usize {
    if text_position < source_length {
        text_position
    } else {
        text_position - 1
    }
}

// ── Longest previous factor over the sorted suffixes ─────────────────

/// Build the per-target-position answers from the sorted suffix
/// positions: invert to ranks, take Kasai's LCP, run the two
/// nearest-smaller scans, and keep each target position's better side.
fn build_match_answers<P: InternalPosition>(
    augmented: &[u16],
    sorted_positions: &[P],
    source_length: usize,
    target_length: usize,
) -> (Vec<P>, Vec<P>) {
    let rank_of_position = invert_to_rank_array(sorted_positions);
    let lcp_with_previous =
        build_lcp_with_previous(augmented, sorted_positions, &rank_of_position);

    let previous_smaller = nearest_smaller_with_carried_lcp(
        sorted_positions,
        &lcp_with_previous,
        ScanDirection::Leftward,
    );
    let next_smaller = nearest_smaller_with_carried_lcp(
        sorted_positions,
        &lcp_with_previous,
        ScanDirection::Rightward,
    );

    // The augmented index where the target's bytes begin: past the
    // source and its trailing separator.
    let target_region_start = source_length + 1;

    let mut match_length = vec![P::from_index(0); target_length];
    let mut match_u_offset = vec![P::from_index(0); target_length];
    for rank in 0..sorted_positions.len() {
        let text_position = sorted_positions[rank].as_index();
        // Only target bytes are queried; skip source bytes, the
        // separator, and the terminator.
        if text_position < target_region_start
            || text_position >= target_region_start + target_length
        {
            continue;
        }
        // The better earlier-starting candidate is whichever of the
        // two suffix-array neighbours (previous-smaller / next-
        // smaller text position) shares the longer prefix.
        let (length, neighbour_position) =
            if previous_smaller.lcp[rank] >= next_smaller.lcp[rank] {
                (previous_smaller.lcp[rank].as_index(), previous_smaller.text_position[rank])
            } else {
                (next_smaller.lcp[rank].as_index(), next_smaller.text_position[rank])
            };
        if length == 0 {
            continue;
        }
        let target_position = text_position - target_region_start;
        match_length[target_position] = P::from_index(length);
        match_u_offset[target_position] = P::from_index(superstring_offset_of(
            neighbour_position.as_index(),
            source_length,
        ));
    }

    (match_length, match_u_offset)
}

// ── Kasai's LCP and the rank inverse ─────────────────────────────────

/// Invert the suffix array: `rank_of_position[p]` is the suffix-array
/// rank of the suffix beginning at text position `p`.
fn invert_to_rank_array<P: InternalPosition>(sorted_positions: &[P]) -> Vec<P> {
    let mut rank_of_position = vec![P::from_index(0); sorted_positions.len()];
    for (rank, position) in sorted_positions.iter().enumerate() {
        rank_of_position[position.as_index()] = P::from_index(rank);
    }
    rank_of_position
}

/// Kasai et al. (2001): the longest common prefix between each suffix
/// and its suffix-array predecessor, in linear time. Walking positions
/// in input order, the running LCP can shrink by at most one from one
/// position to the next, so the counter carries over with a single
/// decrement per step. `lcp_with_previous[0]` is `0` (the first suffix
/// has no predecessor).
fn build_lcp_with_previous<P: InternalPosition>(
    text: &[u16],
    sorted_positions: &[P],
    rank_of_position: &[P],
) -> Vec<P> {
    let length = text.len();
    let mut lcp_with_previous = vec![P::from_index(0); length];
    let mut running_lcp = 0usize;
    for position in 0..length {
        let rank = rank_of_position[position].as_index();
        if rank == 0 {
            running_lcp = 0;
            continue;
        }
        let predecessor_position = sorted_positions[rank - 1].as_index();
        while position + running_lcp < length
            && predecessor_position + running_lcp < length
            && text[position + running_lcp] == text[predecessor_position + running_lcp]
        {
            running_lcp += 1;
        }
        lcp_with_previous[rank] = P::from_index(running_lcp);
        if running_lcp > 0 {
            running_lcp -= 1;
        }
    }
    lcp_with_previous
}

// ── Longest previous factor via nearest-smaller text positions ───────

/// Which way the nearest-smaller scan runs: toward lower suffix-array
/// ranks (the previous-smaller neighbour) or higher ranks (the next-
/// smaller neighbour).
#[derive(Copy, Clone, Eq, PartialEq)]
enum ScanDirection {
    Leftward,
    Rightward,
}

/// The per-rank result of a nearest-smaller scan: two arrays indexed by
/// suffix-array rank. `lcp[rank]` is the common-prefix length the suffix
/// at `rank` shares with its nearest smaller-text-position neighbour
/// (`0` where none exists); `text_position[rank]` is that neighbour's
/// text position, meaningful only where `lcp[rank]` is positive.
struct NearestSmallerNeighbours<P> {
    lcp: Vec<P>,
    text_position: Vec<P>,
}

/// One entry of the monotonic stack: a suffix-array rank still awaiting
/// the smaller-text-position neighbour that will close it, paired with
/// the running-minimum LCP telescoped from that rank down to the entry
/// beneath it on the stack.
#[derive(Copy, Clone)]
struct StackFrame {
    rank: usize,
    carried_minimum_lcp: usize,
}

/// For every suffix-array rank, find the nearest rank on one side whose
/// suffix begins at a *smaller text position*, and the length of the
/// common prefix the two suffixes share.
///
/// The nearest such neighbour is the best earlier-starting match on
/// that side: the common prefix between two suffixes is the minimum
/// `lcp_with_previous` across the ranks between them, which only shrinks
/// as the neighbour moves further away, so the closest qualifying
/// neighbour shares the longest prefix.
///
/// A monotonic stack of ranks with increasing text position carries the
/// answer in one pass. Because every rank is pushed as it is visited,
/// the stack top entering each step is the just-visited neighbouring
/// rank, so the running minimum — seeded with the LCP across that one
/// step and folded with each popped entry's own carried minimum —
/// telescopes to exactly the common prefix with the surviving smaller-
/// position neighbour. Entries store that carried minimum so a later
/// pop reuses it instead of rescanning. Returns the per-rank prefix
/// length (`0` where no smaller-position neighbour exists) and that
/// neighbour's text position (meaningful only where the length is
/// positive).
fn nearest_smaller_with_carried_lcp<P: InternalPosition>(
    sorted_positions: &[P],
    lcp_with_previous: &[P],
    direction: ScanDirection,
) -> NearestSmallerNeighbours<P> {
    let length = sorted_positions.len();
    let mut neighbours = NearestSmallerNeighbours {
        lcp: vec![P::from_index(0); length],
        text_position: vec![P::from_index(0); length],
    };
    let mut stack: Vec<StackFrame> = Vec::new();

    let ranks_in_scan_order: Vec<usize> = match direction {
        ScanDirection::Leftward => (0..length).collect(),
        ScanDirection::Rightward => (0..length).rev().collect(),
    };

    for &rank in &ranks_in_scan_order {
        // The LCP across the single step from the just-visited
        // neighbour to here. Leftward, that step's value lives at
        // `lcp_with_previous[rank]` (the gap rank-1 .. rank); rightward,
        // at `lcp_with_previous[rank + 1]` (the gap rank .. rank+1).
        let mut running_minimum = match direction {
            ScanDirection::Leftward => lcp_with_previous[rank].as_index(),
            ScanDirection::Rightward => {
                if rank + 1 < length {
                    lcp_with_previous[rank + 1].as_index()
                } else {
                    0
                }
            }
        };
        while let Some(&StackFrame { rank: top_rank, carried_minimum_lcp: top_minimum }) =
            stack.last()
        {
            if sorted_positions[top_rank] > sorted_positions[rank] {
                running_minimum = running_minimum.min(top_minimum);
                stack.pop();
            } else {
                break;
            }
        }
        if let Some(&StackFrame { rank: smaller_neighbour_rank, .. }) = stack.last() {
            neighbours.lcp[rank] = P::from_index(running_minimum);
            neighbours.text_position[rank] = sorted_positions[smaller_neighbour_rank];
        }
        stack.push(StackFrame { rank, carried_minimum_lcp: running_minimum });
    }

    neighbours
}

// ── Suffix array by SA-IS ────────────────────────────────────────────

/// Whether a suffix starting at a given position sorts smaller than the
/// suffix at the next position.
///
/// In the SA-IS literature this is the L/S type classification; we use
/// the comparative names because they're what the algorithm actually
/// reasons about.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum SuffixComparison {
    /// The suffix here is larger than the suffix one position later.
    /// (Literature: "L-type", short for "Larger".)
    LargerThanSuccessor,
    /// The suffix here is smaller than the suffix one position later.
    /// (Literature: "S-type", short for "Smaller".)
    SmallerThanSuccessor,
}

/// Bucket layout for one alphabet. Each symbol gets a contiguous range
/// in the suffix array; the bucket for symbol c is `[starts[c], ends[c])`.
/// Computed from symbol frequencies and used during induction passes to
/// know where to place each suffix.
struct BucketLayout {
    /// Inclusive start position of each symbol's bucket in the SA.
    starts: Vec<usize>,
    /// Exclusive end position of each symbol's bucket in the SA.
    ends: Vec<usize>,
}

/// A suffix that is locally-minimal: smaller than its predecessor and
/// smaller-than-or-equal to its successor. In the SA-IS literature these
/// are "LMS" (LeftMost Smaller) suffixes; their relative order determines
/// the entire SA, so the algorithm's recursive step sorts them first and
/// induces everything else.
struct LeftmostSmallerPositions {
    positions: Vec<usize>,
}

/// One symbol of an alphabet that suffix-sorting can run over. The
/// augmented string uses `u16` (bytes plus two sentinels); the
/// recursive call uses `u32` to fit up to n/2 distinct LMS-substring
/// names.
trait Symbol: Copy + Eq + Ord {
    fn alphabet_index(self) -> usize;
}

impl Symbol for u16 {
    fn alphabet_index(self) -> usize {
        self as usize
    }
}

impl Symbol for u32 {
    fn alphabet_index(self) -> usize {
        self as usize
    }
}

/// Largest input length that the `u32`-internal path can address. Equal
/// to `u32::MAX`, leaving the all-ones value free as `UNPLACED_SLOT`.
const U32_INTERNAL_THRESHOLD: usize = u32::MAX as usize;

/// An integer wide enough to index the augmented string, during SA
/// construction and in the tables built on it. Two impls live in this
/// module: `u32` for inputs up to 4 GB, `u64` for larger; `build`
/// chooses once, so the suffix array, ranks, LCPs, and answers never
/// pay wider cells than the positions they hold. It also serves as
/// construction-time discipline against mixing positions with byte
/// counts and bucket indices, which are all structurally `usize`.
trait InternalPosition: Copy + Eq + Ord {
    /// Sentinel marking a not-yet-placed slot in the SA under construction.
    /// Both impls use the type's `MAX`. The dispatcher caps each path's input length at its `MAX`,
    /// so the largest real position is one below it and `MAX` stays free as the sentinel.
    const UNPLACED_SLOT: Self;

    fn from_index(index: usize) -> Self;
    fn as_index(self) -> usize;
    fn is_placed(self) -> bool;
}

impl InternalPosition for u32 {
    const UNPLACED_SLOT: u32 = u32::MAX;

    fn from_index(index: usize) -> Self {
        debug_assert!(
            index < u32::MAX as usize,
            "u32 InternalPosition cannot represent index {index} \
             (u32::MAX is the unplaced-slot sentinel); dispatch should have chosen u64"
        );
        index as u32
    }

    fn as_index(self) -> usize {
        self as usize
    }

    fn is_placed(self) -> bool {
        self != u32::MAX
    }
}

impl InternalPosition for u64 {
    const UNPLACED_SLOT: u64 = u64::MAX;

    fn from_index(index: usize) -> Self {
        debug_assert!(
            index != usize::MAX,
            "u64 InternalPosition cannot represent usize::MAX (reserved as the unplaced-slot sentinel)"
        );
        index as u64
    }

    fn as_index(self) -> usize {
        self as usize
    }

    fn is_placed(self) -> bool {
        self != u64::MAX
    }
}

/// Recursive entry. Input is a slice of names assigned by the parent
/// call's LMS-naming step; alphabet size is the number of distinct names.
/// The internal-position type is inherited from the parent call: once
/// the dispatcher has decided the input fits in `P`, the recursive
/// input (always shorter) fits too.
fn suffix_sort_name_alphabet<P: InternalPosition>(
    names: &[u32],
    alphabet_size: usize,
) -> Vec<P> {
    suffix_sort_over_alphabet_generic::<u32, P>(names, alphabet_size)
}

/// Level-0 entry over the augmented `u16` alphabet.
fn suffix_sort_over_alphabet<P: InternalPosition>(
    input: &[u16],
    alphabet_size: usize,
) -> Vec<P> {
    suffix_sort_over_alphabet_generic::<u16, P>(input, alphabet_size)
}

/// SA-IS body, generic over the symbol type. The algorithm:
///   1. Classify every position as Larger or Smaller.
///   2. Find the leftmost-smaller positions.
///   3. Approximately sort the LMS positions, then induce L then S to
///      fill the rest of the SA approximately.
///   4. Name LMS substrings from the approximate SA.
///   5. If all names are distinct, invert directly; otherwise recurse on
///      the named string.
///   6. Re-place LMS positions in their exact order, induce L then S to
///      fill the rest of the SA exactly.
fn suffix_sort_over_alphabet_generic<S: Symbol, P: InternalPosition>(
    input: &[S],
    alphabet_size: usize,
) -> Vec<P> {
    let n = input.len();
    let comparisons = compute_suffix_comparisons(input);
    let leftmost_smaller = find_leftmost_smaller_positions(&comparisons);
    let buckets = compute_bucket_layout(input, alphabet_size);

    // Approximate sort. Place LMS at bucket-ends in input order, then induce.
    let mut suffix_array = vec![P::UNPLACED_SLOT; n];
    place_leftmost_smaller_positions(
        input,
        &mut suffix_array,
        &leftmost_smaller.positions,
        &buckets,
    );
    place_left_induced_suffixes(input, &mut suffix_array, &comparisons, &buckets);
    place_right_induced_suffixes(input, &mut suffix_array, &comparisons, &buckets);

    // Name LMS substrings from the approximate-sorted SA.
    let (names_in_lms_order, distinct_names) =
        name_leftmost_smaller_substrings(input, &suffix_array, &comparisons, &leftmost_smaller);

    // Sort LMS positions exactly: recurse if any names collide, else invert.
    let leftmost_smaller_in_sorted_order = sort_leftmost_smaller_by_names::<P>(
        &leftmost_smaller,
        &names_in_lms_order,
        distinct_names,
    );

    // Exact sort. Re-place LMS in correct order at bucket-ends, induce.
    suffix_array.iter_mut().for_each(|slot| *slot = P::UNPLACED_SLOT);
    place_leftmost_smaller_positions(
        input,
        &mut suffix_array,
        &leftmost_smaller_in_sorted_order,
        &buckets,
    );
    place_left_induced_suffixes(input, &mut suffix_array, &comparisons, &buckets);
    place_right_induced_suffixes(input, &mut suffix_array, &comparisons, &buckets);

    debug_assert!(
        suffix_array.iter().all(|slot| slot.is_placed()),
        "every SA slot must be filled at this point"
    );
    suffix_array
}

/// Walk the input right-to-left, classifying each position as Larger or
/// Smaller relative to its successor. The implicit sentinel one past the
/// end is smaller than any real symbol, so the last position always
/// classifies as Larger.
fn compute_suffix_comparisons<S: Symbol>(input: &[S]) -> Vec<SuffixComparison> {
    let n = input.len();
    let mut comparisons = vec![SuffixComparison::LargerThanSuccessor; n];
    for position in (0..n.saturating_sub(1)).rev() {
        comparisons[position] = if input[position] < input[position + 1] {
            SuffixComparison::SmallerThanSuccessor
        } else if input[position] > input[position + 1] {
            SuffixComparison::LargerThanSuccessor
        } else {
            comparisons[position + 1]
        };
    }
    comparisons
}

/// Filter for positions classified as Smaller whose predecessor is
/// classified as Larger. Position 0 is excluded (no predecessor).
fn find_leftmost_smaller_positions(
    comparisons: &[SuffixComparison],
) -> LeftmostSmallerPositions {
    let mut positions = Vec::new();
    for position in 1..comparisons.len() {
        if is_leftmost_smaller(comparisons, position) {
            positions.push(position);
        }
    }
    LeftmostSmallerPositions { positions }
}

/// True iff position is Smaller and its predecessor is Larger.
fn is_leftmost_smaller(comparisons: &[SuffixComparison], position: usize) -> bool {
    position > 0
        && comparisons[position] == SuffixComparison::SmallerThanSuccessor
        && comparisons[position - 1] == SuffixComparison::LargerThanSuccessor
}

/// One frequency pass plus one prefix-sum pass to build the bucket
/// boundaries for `input` over an alphabet of `alphabet_size` symbols.
fn compute_bucket_layout<S: Symbol>(input: &[S], alphabet_size: usize) -> BucketLayout {
    let mut frequencies = vec![0usize; alphabet_size];
    for symbol in input {
        frequencies[symbol.alphabet_index()] += 1;
    }
    let mut starts = Vec::with_capacity(alphabet_size);
    let mut ends = Vec::with_capacity(alphabet_size);
    let mut running_total = 0;
    for &count in &frequencies {
        starts.push(running_total);
        running_total += count;
        ends.push(running_total);
    }
    BucketLayout { starts, ends }
}

/// Place a list of LMS positions at the high end of their respective
/// buckets, iterating in reverse so that earlier-listed positions land
/// in lower SA slots within each bucket. Used both for the approximate
/// pass (input order) and the exact pass (sorted order).
fn place_leftmost_smaller_positions<S: Symbol, P: InternalPosition>(
    input: &[S],
    sa: &mut [P],
    positions_to_place: &[usize],
    buckets: &BucketLayout,
) {
    let mut bucket_end_cursors = buckets.ends.clone();
    for &position in positions_to_place.iter().rev() {
        let symbol_index = input[position].alphabet_index();
        bucket_end_cursors[symbol_index] -= 1;
        sa[bucket_end_cursors[symbol_index]] = P::from_index(position);
    }
}

/// L-type induction. Scans the SA left-to-right; for each placed
/// position p with comparisons[p-1] = Larger, places p-1 at the next
/// available slot from the start of its bucket. The implicit sentinel
/// one past the end seeds the predecessor n-1 unconditionally — that
/// position is always Larger, and without seeding, no real position
/// could trigger its placement.
fn place_left_induced_suffixes<S: Symbol, P: InternalPosition>(
    input: &[S],
    sa: &mut [P],
    comparisons: &[SuffixComparison],
    buckets: &BucketLayout,
) {
    let n = input.len();
    let mut bucket_start_cursors = buckets.starts.clone();

    if n > 0 {
        let last_position = n - 1;
        let symbol_index = input[last_position].alphabet_index();
        sa[bucket_start_cursors[symbol_index]] = P::from_index(last_position);
        bucket_start_cursors[symbol_index] += 1;
    }

    for rank in 0..n {
        let placed = sa[rank];
        if !placed.is_placed() {
            continue;
        }
        let position = placed.as_index();
        if position == 0 {
            continue;
        }
        let predecessor = position - 1;
        if comparisons[predecessor] == SuffixComparison::LargerThanSuccessor {
            let symbol_index = input[predecessor].alphabet_index();
            sa[bucket_start_cursors[symbol_index]] = P::from_index(predecessor);
            bucket_start_cursors[symbol_index] += 1;
        }
    }
}

/// S-type induction. Scans the SA right-to-left; for each placed
/// position p with comparisons[p-1] = Smaller, places p-1 at the next
/// available slot from the end of its bucket. By design this overwrites
/// the approximate LMS placements — they served their purpose during
/// L-induction and S-induction places each LMS at its final rank.
fn place_right_induced_suffixes<S: Symbol, P: InternalPosition>(
    input: &[S],
    sa: &mut [P],
    comparisons: &[SuffixComparison],
    buckets: &BucketLayout,
) {
    let n = input.len();
    let mut bucket_end_cursors = buckets.ends.clone();

    for rank in (0..n).rev() {
        let placed = sa[rank];
        if !placed.is_placed() {
            continue;
        }
        let position = placed.as_index();
        if position == 0 {
            continue;
        }
        let predecessor = position - 1;
        if comparisons[predecessor] == SuffixComparison::SmallerThanSuccessor {
            let symbol_index = input[predecessor].alphabet_index();
            bucket_end_cursors[symbol_index] -= 1;
            sa[bucket_end_cursors[symbol_index]] = P::from_index(predecessor);
        }
    }
}

/// After induction, the LMS positions appear in the SA in the order of
/// their LMS substrings. Walk the SA, identify LMS positions, compare
/// each LMS substring against the previous one, and assign names.
/// Substrings with identical characters AND identical type-classification
/// receive the same name.
///
/// Returns the names in LMS-input-order (parallel to `lms.positions`)
/// and the count of distinct names.
fn name_leftmost_smaller_substrings<S: Symbol, P: InternalPosition>(
    input: &[S],
    sa: &[P],
    comparisons: &[SuffixComparison],
    lms: &LeftmostSmallerPositions,
) -> (Vec<u32>, usize) {
    let n = input.len();
    let mut name_at_position = vec![0u32; n];
    let mut current_name: u32 = 0;
    let mut previous_lms_position: Option<usize> = None;

    for slot in sa {
        if !slot.is_placed() {
            continue;
        }
        let position = slot.as_index();
        if !is_leftmost_smaller(comparisons, position) {
            continue;
        }
        let differs_from_previous = match previous_lms_position {
            None => false,
            Some(previous) => {
                !leftmost_smaller_substrings_equal(input, comparisons, previous, position)
            }
        };
        if differs_from_previous {
            current_name += 1;
        }
        name_at_position[position] = current_name;
        previous_lms_position = Some(position);
    }

    let distinct_names = if previous_lms_position.is_some() {
        current_name as usize + 1
    } else {
        0
    };

    let names_in_lms_order: Vec<u32> = lms
        .positions
        .iter()
        .map(|&position| name_at_position[position])
        .collect();

    (names_in_lms_order, distinct_names)
}

/// Two LMS substrings are equal iff they have identical symbols AND
/// identical suffix-comparison classifications at each offset, and they
/// terminate at the same offset (both reaching the next LMS position
/// simultaneously). Reaching the implicit sentinel one past the end
/// before the other reaches a real LMS boundary marks them as unequal.
fn leftmost_smaller_substrings_equal<S: Symbol>(
    input: &[S],
    comparisons: &[SuffixComparison],
    a: usize,
    b: usize,
) -> bool {
    let n = input.len();
    let mut offset = 0usize;
    loop {
        let a_position = a + offset;
        let b_position = b + offset;
        if a_position >= n || b_position >= n {
            return false;
        }
        if input[a_position] != input[b_position]
            || comparisons[a_position] != comparisons[b_position]
        {
            return false;
        }
        if offset > 0 {
            let a_at_lms_boundary = is_leftmost_smaller(comparisons, a_position);
            let b_at_lms_boundary = is_leftmost_smaller(comparisons, b_position);
            match (a_at_lms_boundary, b_at_lms_boundary) {
                (true, true) => return true,
                (false, false) => {}
                _ => return false,
            }
        }
        offset += 1;
    }
}

/// Produce the LMS positions in their final lexicographic order.
/// If naming saw collisions, recurse on the named string; otherwise
/// invert the names directly.
fn sort_leftmost_smaller_by_names<P: InternalPosition>(
    leftmost_smaller: &LeftmostSmallerPositions,
    names_in_lms_order: &[u32],
    distinct_names: usize,
) -> Vec<usize> {
    let lms_count = leftmost_smaller.positions.len();
    if distinct_names < lms_count {
        let recursive_suffix_array =
            suffix_sort_name_alphabet::<P>(names_in_lms_order, distinct_names);
        recursive_suffix_array
            .iter()
            .map(|&sorted_lms_rank| leftmost_smaller.positions[sorted_lms_rank.as_index()])
            .collect()
    } else {
        let mut in_sorted_order = vec![0usize; lms_count];
        for (lms_rank, &original_position) in leftmost_smaller.positions.iter().enumerate() {
            let name = names_in_lms_order[lms_rank] as usize;
            in_sorted_order[name] = original_position;
        }
        in_sorted_order
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// SplitMix64, matching the house pseudo-random helper used by the
    /// sibling suffix-array tests.
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

    /// Bytes drawn from a deliberately tiny alphabet, to force the long
    /// repeats and self-referential overlaps that exercise the matcher's
    /// interesting paths.
    fn pseudo_random_low_alphabet(seed: u64, length: usize, alphabet: u8) -> Vec<u8> {
        pseudo_random_bytes(seed, length)
            .into_iter()
            .map(|byte| byte % alphabet)
            .collect()
    }

    fn naive_suffix_array(text: &[u16]) -> Vec<usize> {
        let mut positions: Vec<usize> = (0..text.len()).collect();
        positions.sort_by(|&left, &right| text[left..].cmp(&text[right..]));
        positions
    }

    /// The SA-IS at narrow width, widened to the `usize` positions the
    /// naive reference speaks.
    fn sorted_positions_of(text: &[u16]) -> Vec<usize> {
        suffix_sort_over_alphabet::<u32>(text, AUGMENTED_ALPHABET_SIZE)
            .into_iter()
            .map(|position| position as usize)
            .collect()
    }

    fn longest_common_prefix(left: &[u16], right: &[u16]) -> usize {
        let bound = left.len().min(right.len());
        let mut shared = 0usize;
        while shared < bound && left[shared] == right[shared] {
            shared += 1;
        }
        shared
    }

    /// The matcher's contract, computed exhaustively: the longest run at
    /// `position` that begins strictly before the write head, capped at
    /// the source end for source-anchored candidates and at the
    /// remaining target either way. The augmented-string matcher must
    /// agree with this on length for every position.
    fn brute_force_longest_match_length(source: &[u8], target: &[u8], position: usize) -> usize {
        let write_head = source.len() + position;
        let remaining_target = target.len() - position;
        let byte_in_superstring = |offset: usize| -> u8 {
            if offset < source.len() { source[offset] } else { target[offset - source.len()] }
        };
        let mut best = 0usize;
        for candidate in 0..write_head {
            let reach = if candidate < source.len() {
                (source.len() - candidate).min(remaining_target)
            } else {
                remaining_target
            };
            let mut run = 0usize;
            while run < reach && byte_in_superstring(candidate + run) == target[position + run] {
                run += 1;
            }
            best = best.max(run);
        }
        best
    }

    #[test]
    fn suffix_array_matches_naive_on_words() {
        for word in [b"banana".as_slice(), b"mississippi", b"abracadabra", b"aaaaaa", b"a"] {
            let text: Vec<u16> = word.iter().map(|&b| b as u16 + SYMBOL_SHIFT).collect();
            assert_eq!(sorted_positions_of(&text), naive_suffix_array(&text), "{word:?}");
        }
    }

    #[test]
    fn suffix_array_matches_naive_on_augmented_strings() {
        for length in [0usize, 1, 2, 5, 33, 200, 1500] {
            let source = pseudo_random_low_alphabet(0xa11ce ^ length as u64, length, 4);
            let target = pseudo_random_low_alphabet(0xb0b ^ length as u64, length + 7, 4);
            let augmented = build_augmented_string(&source, &target);
            assert_eq!(
                sorted_positions_of(&augmented),
                naive_suffix_array(&augmented),
                "augmented SA mismatch at length {length}"
            );
        }
    }

    #[test]
    fn lcp_matches_direct_recomputation() {
        let source = pseudo_random_bytes(0xfeed, 300);
        let target = pseudo_random_bytes(0xf00d, 400);
        let augmented = build_augmented_string(&source, &target);
        let sorted_positions =
            suffix_sort_over_alphabet::<u32>(&augmented, AUGMENTED_ALPHABET_SIZE);
        let rank_of_position = invert_to_rank_array(&sorted_positions);
        let lcp = build_lcp_with_previous(&augmented, &sorted_positions, &rank_of_position);
        for rank in 1..sorted_positions.len() {
            let previous = &augmented[sorted_positions[rank - 1] as usize..];
            let current = &augmented[sorted_positions[rank] as usize..];
            assert_eq!(
                lcp[rank] as usize,
                longest_common_prefix(previous, current),
                "rank {rank}"
            );
        }
    }

    #[test]
    fn longest_match_length_matches_brute_force() {
        let cases: &[(u64, usize, usize, u8)] = &[
            (1, 0, 40, 2),     // empty source, tiny alphabet: pure self-reference
            (2, 40, 40, 2),    // related source and target, heavy repetition
            (3, 64, 90, 6),    // medium alphabet
            (4, 120, 30, 255), // source longer than target, full alphabet
            (5, 10, 200, 3),   // target much longer than source
            (6, 0, 1, 2),      // single target byte
        ];
        for &(seed, source_len, target_len, alphabet) in cases {
            let source = pseudo_random_low_alphabet(seed, source_len, alphabet);
            let target = pseudo_random_low_alphabet(seed ^ 0xff, target_len, alphabet);
            let matcher = SuperstringMatcher::build(&source, &target);
            for position in 0..target.len() {
                let expected = brute_force_longest_match_length(&source, &target, position);
                let found = matcher.longest_match_at(position).map_or(0, |m| m.length);
                assert_eq!(found, expected, "length at position {position}, case seed {seed}");
            }
        }
    }

    #[test]
    fn reported_offsets_reproduce_the_matched_bytes() {
        let source = pseudo_random_low_alphabet(0x5eed, 80, 5);
        let target = pseudo_random_low_alphabet(0xd0e, 160, 5);
        let matcher = SuperstringMatcher::build(&source, &target);
        for position in 0..target.len() {
            if let Some(found) = matcher.longest_match_at(position) {
                // Read the claimed match out of U = source ++ target,
                // byte by byte so a self-referential overlap resolves,
                // and confirm it equals the target slice it covers.
                let byte_in_superstring = |offset: usize| -> u8 {
                    if offset < source.len() { source[offset] } else { target[offset - source.len()] }
                };
                for step in 0..found.length {
                    assert_eq!(
                        byte_in_superstring(found.superstring_offset + step),
                        target[position + step],
                        "offset {} step {step} at position {position}",
                        found.superstring_offset
                    );
                }
            }
        }
    }

    #[test]
    fn empty_target_has_no_matches() {
        let matcher = SuperstringMatcher::build(b"anything", b"");
        assert!(matches!(
            matcher.answers,
            MatchAnswers::Narrow { ref match_length, .. } if match_length.is_empty()
        ));
    }

    /// The wide path can't be reached through `build` without a 4 GB
    /// pair, but the generic bodies it runs are directly callable: pin
    /// that both widths produce the same suffix array and the same
    /// answers, so the only thing the dispatch boundary changes is cell
    /// width.
    #[test]
    fn wide_and_narrow_widths_agree() {
        let source = pseudo_random_low_alphabet(0x717, 90, 4);
        let target = pseudo_random_low_alphabet(0x818, 130, 4);
        let augmented = build_augmented_string(&source, &target);

        let narrow_positions =
            suffix_sort_over_alphabet::<u32>(&augmented, AUGMENTED_ALPHABET_SIZE);
        let wide_positions =
            suffix_sort_over_alphabet::<u64>(&augmented, AUGMENTED_ALPHABET_SIZE);
        let widened_positions: Vec<u64> =
            narrow_positions.iter().map(|&position| position as u64).collect();
        assert_eq!(widened_positions, wide_positions);

        let (narrow_lengths, narrow_offsets) =
            build_match_answers(&augmented, &narrow_positions, source.len(), target.len());
        let (wide_lengths, wide_offsets) =
            build_match_answers(&augmented, &wide_positions, source.len(), target.len());
        let widened_lengths: Vec<u64> =
            narrow_lengths.iter().map(|&length| length as u64).collect();
        let widened_offsets: Vec<u64> =
            narrow_offsets.iter().map(|&offset| offset as u64).collect();
        assert_eq!(widened_lengths, wide_lengths);
        assert_eq!(widened_offsets, wide_offsets);
    }
}
