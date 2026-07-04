//! Suffix array construction via SA-IS (Nong, Zhang, Chan 2009).
//!
//! Given a byte slice of length n, produces a permutation of [0, n) such
//! that the suffixes starting at the listed positions are in ascending
//! lexicographic order. Used by the BPS diff engine to find longest
//! common substrings between source and target ROMs in linear time.

// ── Public surface ─────────────────────────────────────────────────────

/// The result of suffix-sorting a buffer. Entry at rank `r` is the
/// position in the original buffer where the `r`-th lexicographically
/// smallest suffix begins.
///
/// Stored at `u32` or `u64` width (the variants say which), an implementation detail that earns narrow-storage memory savings on the dominant induction passes.
/// Consumers see `usize` positions through the accessors.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SuffixArray {
    /// Suffix array stored at `u32` width. Used when the input length
    /// fits in a `u32` (≤ 4 GB).
    Narrow(Vec<u32>),
    /// Suffix array stored at `u64` width. Used for inputs larger than
    /// 4 GB.
    Wide(Vec<u64>),
}

impl SuffixArray {
    /// Number of suffixes — equal to the length of the input the SA was
    /// built from.
    pub fn len(&self) -> usize {
        match self {
            SuffixArray::Narrow(positions) => positions.len(),
            SuffixArray::Wide(positions) => positions.len(),
        }
    }

    // Staticlib: rustc can't see FFI consumers, so any unused-internally
    // pub method trips dead_code; len/is_empty go together by convention.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The position in the input at which the `rank`-th lexicographically
    /// smallest suffix begins. Panics if `rank >= self.len()`.
    pub fn position_at_rank(&self, rank: usize) -> usize {
        match self {
            SuffixArray::Narrow(positions) => positions[rank] as usize,
            SuffixArray::Wide(positions) => positions[rank] as usize,
        }
    }

    /// Iterate positions in ascending rank order, widened to `usize`.
    /// Lets callers walk the entire SA without branching on the variant
    /// per element — useful when building a reverse rank index.
    pub fn iter_positions(&self) -> SuffixPositionIter<'_> {
        match self {
            SuffixArray::Narrow(positions) => SuffixPositionIter::Narrow(positions.iter()),
            SuffixArray::Wide(positions) => SuffixPositionIter::Wide(positions.iter()),
        }
    }
}

/// Iterator over a [`SuffixArray`]'s positions, widened to `usize`.
/// Variants mirror the array's storage so each step is a direct load
/// and zero-extend, with no boxing.
pub enum SuffixPositionIter<'a> {
    Narrow(std::slice::Iter<'a, u32>),
    Wide(std::slice::Iter<'a, u64>),
}

impl<'a> Iterator for SuffixPositionIter<'a> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        match self {
            SuffixPositionIter::Narrow(iter) => iter.next().map(|&position| position as usize),
            SuffixPositionIter::Wide(iter) => iter.next().map(|&position| position as usize),
        }
    }
}

/// Build the suffix array of `data` in linear time. The empty input
/// produces an empty [`SuffixArray::Narrow`].
///
/// Dispatches on input size to the storage width [`SuffixArray`] documents.
#[must_use]
pub fn suffix_sort(data: &[u8]) -> SuffixArray {
    if data.is_empty() {
        return SuffixArray::Narrow(Vec::new());
    }
    if data.len() <= U32_INTERNAL_THRESHOLD {
        SuffixArray::Narrow(suffix_sort_byte_alphabet::<u32>(data))
    } else {
        SuffixArray::Wide(suffix_sort_byte_alphabet::<u64>(data))
    }
}

/// Largest input length that the `u32`-internal path can address. Equal
/// to `u32::MAX`, leaving the all-ones value free as `UNPLACED_SLOT`.
const U32_INTERNAL_THRESHOLD: usize = u32::MAX as usize;

// ── Internal types ─────────────────────────────────────────────────────

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

/// One symbol of an alphabet that suffix-sorting can run over. The byte
/// alphabet uses `u8` (256 values); the recursive call uses `u32` to fit
/// up to n/2 distinct LMS-substring names.
trait Symbol: Copy + Eq + Ord {
    fn alphabet_index(self) -> usize;
}

impl Symbol for u8 {
    fn alphabet_index(self) -> usize {
        self as usize
    }
}

impl Symbol for u32 {
    fn alphabet_index(self) -> usize {
        self as usize
    }
}

const BYTE_ALPHABET_SIZE: usize = 256;

/// An integer wide enough to index the SA scratch space during
/// construction. Two impls live in this module: `u32` for inputs up to
/// 4 GB, `u64` for larger. The chosen width survives all the way to
/// the public [`SuffixArray`], which wraps the constructed `Vec<P>`
/// directly — the trait exists to specialise internal allocation,
/// halving memory bandwidth on the dominant induction passes when the
/// input fits in `u32`. It also serves as construction-time discipline
/// against mixing positions with byte counts and bucket indices, which
/// are all structurally `usize`.
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
            index <= u32::MAX as usize,
            "u32 InternalPosition cannot represent index {index}; \
             dispatcher should have routed to u64"
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

// ── Algorithm ──────────────────────────────────────────────────────────

/// Top-level entry for byte input. Specialized so the dominant outer
/// pass works directly on `&[u8]` without widening to a wider integer
/// type.
fn suffix_sort_byte_alphabet<P: InternalPosition>(data: &[u8]) -> Vec<P> {
    suffix_sort_over_alphabet::<u8, P>(data, BYTE_ALPHABET_SIZE)
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
    suffix_sort_over_alphabet::<u32, P>(names, alphabet_size)
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
fn suffix_sort_over_alphabet<S: Symbol, P: InternalPosition>(
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

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference suffix-array implementation: sort indices by their
    /// suffix lexicographically. O(n² log n); used as truth source.
    fn naive_suffix_array(data: &[u8]) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..data.len()).collect();
        indices.sort_by(|&left, &right| data[left..].cmp(&data[right..]));
        indices
    }

    /// Deterministic PRNG (SplitMix64).
    fn pseudo_random(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state.wrapping_add(0x9e3779b97f4a7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
                z ^= z >> 31;
                z as u8
            })
            .collect()
    }

    fn ranks_of(data: &[u8]) -> Vec<usize> {
        suffix_sort(data).iter_positions().collect()
    }

    #[test]
    fn empty_input() {
        assert!(suffix_sort(&[]).is_empty());
    }

    #[test]
    fn single_byte() {
        let sa = suffix_sort(&[42]);
        assert_eq!(sa.len(), 1);
        assert_eq!(sa.position_at_rank(0), 0);
    }

    #[test]
    fn two_bytes_distinct() {
        assert_eq!(ranks_of(&[1, 0]), vec![1, 0]);
    }

    #[test]
    fn two_bytes_equal() {
        assert_eq!(ranks_of(&[5, 5]), vec![1, 0]);
    }

    #[test]
    fn banana() {
        assert_eq!(ranks_of(b"banana"), vec![5, 3, 1, 0, 4, 2]);
    }

    #[test]
    fn mississippi() {
        assert_eq!(
            ranks_of(b"mississippi"),
            vec![10, 7, 4, 1, 0, 9, 8, 6, 3, 5, 2]
        );
    }

    #[test]
    fn all_same() {
        assert_eq!(ranks_of(&[b'a'; 4]), vec![3, 2, 1, 0]);
    }

    #[test]
    fn random_fuzz_against_naive() {
        for length in [1usize, 2, 8, 64, 256, 1024] {
            let data = pseudo_random(0xdeadbeef ^ length as u64, length);
            let actual: Vec<usize> = suffix_sort(&data).iter_positions().collect();
            let expected = naive_suffix_array(&data);
            assert_eq!(actual, expected, "mismatch at length {length}");
        }
    }

    /// The dispatcher routes inputs ≤ `u32::MAX` through `Vec<u32>`-typed
    /// scratch space. Verify it on a multi-KB input — large enough that the recursive
    /// step actually engages, small enough that the naive reference is
    /// still tractable. Inputs large enough to require the `u64` path
    /// (> 4 GB) aren't checkable this way, but the algorithm is identical
    /// across both impls: only the integer width differs.
    #[test]
    fn fuzz_large_input_u32_path() {
        let data = pseudo_random(0xfeed, 8192);
        let actual: Vec<usize> = suffix_sort(&data).iter_positions().collect();
        let expected = naive_suffix_array(&data);
        assert_eq!(actual, expected);
    }
}
