//! Suffix-array index over xdelta1's source bytes. The differ in
//! `xdelta1_diff.rs` queries this index at each target position to
//! find the longest source span that prefixes the remaining target.
//! Every byte position in source is a candidate match start, and
//! every match length the wire admits is reachable.
//!
//! Built by SA-IS (Nong, Zhang & Chan 2009) over the source plus
//! Kasai's LCP construction. Storage is `u32` throughout; build
//! rejects sources whose byte length exceeds `u32::MAX` with a
//! typed error rather than truncating silently. A wide-index path
//! would be additive future work.

use std::cmp::Ordering;

// ── Public surface ───────────────────────────────────────────────────

/// Sorted-suffix-positions array and adjacent-suffix LCP array over
/// a source byte buffer. Both are needed at query time: the binary
/// search consults `sorted_positions`, and the LCP-plateau walk
/// consults `lcp_with_previous` to pick the smallest source offset
/// among equal-length match candidates.
///
/// The inverse-rank array Kasai's LCP construction uses is local
/// to that construction — it doesn't need to outlive `build`.
pub struct SourceSuffixArrayIndex {
    /// `sorted_positions[rank]` is the position in `source` at which
    /// the suffix of lexicographic rank `rank` begins. Length equals
    /// the source's byte length.
    sorted_positions: Vec<u32>,

    /// `lcp_with_previous[rank]` is the length of the longest common
    /// prefix between the suffix at rank `rank` and the suffix at
    /// rank `rank - 1`. `lcp_with_previous[0]` is `0` by convention
    /// (no predecessor). The query uses this to walk outward across
    /// the contiguous LCP plateau around its landing rank.
    lcp_with_previous: Vec<u32>,
}

/// A source-side match candidate: the byte offset in source at which
/// the match begins and its byte length.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SourceMatchCandidate {
    pub source_offset: u32,
    pub match_length:  u32,
}

impl SourceSuffixArrayIndex {
    /// Build the index over `source`. Fails when the source length
    /// exceeds `u32::MAX` (the storage width's representable range).
    pub fn build(source: &[u8]) -> Result<Self, String> {
        if source.len() > u32::MAX as usize {
            return Err(format!(
                "xdelta1 differ: source length {} exceeds u32-indexed suffix array \
                 (max {}); wide-index path not implemented",
                source.len(),
                u32::MAX,
            ));
        }
        let sorted_positions  = build_byte_suffix_array(source);
        let rank_of_position  = invert_to_rank_array(&sorted_positions);
        let lcp_with_previous = build_lcp_with_previous(source, &sorted_positions, &rank_of_position);
        Ok(SourceSuffixArrayIndex { sorted_positions, lcp_with_previous })
    }

    /// Find the longest source span whose first bytes match the
    /// start of `target_suffix`. Returns `None` if no source byte
    /// matches `target_suffix[0]` (or if the index is empty, or the
    /// target suffix is empty).
    ///
    /// Strategy: binary-search the sorted-suffix list for
    /// `target_suffix`'s lexicographic position, then measure
    /// directly the common prefix of `target_suffix` against the
    /// two suffixes immediately adjacent to the insertion point.
    /// The longest match length over all source suffixes is
    /// achieved by one of those two — any further-away suffix
    /// shares at most as long a prefix.
    ///
    /// On tie of length, pick the smallest source offset. Smaller
    /// offsets pack into fewer varint bytes on the wire under the
    /// absolute-offset encoding mode. Finding the smallest offset
    /// requires walking outward from the binary-search landing
    /// rank across the contiguous range of source suffixes that
    /// share the same prefix length — bounded by
    /// `lcp_with_previous`, which tells us when adjacent source
    /// suffixes diverge below the longest match length found.
    pub fn longest_match_for_target_suffix(
        &self,
        source:        &[u8],
        target_suffix: &[u8],
    ) -> Option<SourceMatchCandidate> {
        if self.sorted_positions.is_empty() || target_suffix.is_empty() {
            return None;
        }
        let insertion_rank = self.binary_search_insertion_rank(source, target_suffix);

        let lcp_below = if insertion_rank > 0 {
            self.lcp_of_neighbor_with_target(source, target_suffix, insertion_rank - 1)
        } else { 0 };
        let lcp_above = if insertion_rank < self.sorted_positions.len() {
            self.lcp_of_neighbor_with_target(source, target_suffix, insertion_rank)
        } else { 0 };

        let best_lcp = lcp_below.max(lcp_above);
        if best_lcp == 0 {
            return None;
        }
        let starting_rank = if lcp_above >= lcp_below {
            insertion_rank
        } else {
            insertion_rank - 1
        };
        let smallest_offset_in_plateau =
            self.smallest_offset_across_lcp_plateau(starting_rank, best_lcp as u32);
        Some(SourceMatchCandidate {
            source_offset: smallest_offset_in_plateau,
            match_length:  best_lcp as u32,
        })
    }

    /// Standard lexicographic binary search. Returns the smallest
    /// rank `r` such that `source[sorted_positions[r]..] >=
    /// target_suffix`. When all source suffixes compare smaller, the
    /// returned rank equals `sorted_positions.len()` (a half-open
    /// upper bound, never indexable).
    fn binary_search_insertion_rank(&self, source: &[u8], target_suffix: &[u8]) -> usize {
        let mut lo = 0usize;
        let mut hi = self.sorted_positions.len();
        while lo < hi {
            let mid          = lo + (hi - lo) / 2;
            let suffix_start = self.sorted_positions[mid] as usize;
            match source[suffix_start..].cmp(target_suffix) {
                Ordering::Less                      => lo = mid + 1,
                Ordering::Equal | Ordering::Greater => hi = mid,
            }
        }
        lo
    }

    /// Direct LCP computation between the target suffix and the
    /// source suffix at one SA rank.
    fn lcp_of_neighbor_with_target(
        &self,
        source:        &[u8],
        target_suffix: &[u8],
        neighbor_rank: usize,
    ) -> usize {
        let neighbor_offset = self.sorted_positions[neighbor_rank] as usize;
        longest_common_prefix_length(&source[neighbor_offset..], target_suffix)
    }

    /// Walk outward from `starting_rank` across every rank whose
    /// adjacent-LCP value is `>= plateau_length`, returning the
    /// smallest source offset found across the range. The
    /// contiguous range of source suffixes with adjacent LCP at
    /// least `plateau_length` is exactly the set of source suffixes
    /// whose first `plateau_length` bytes agree — i.e., they all
    /// match the target suffix's first `plateau_length` bytes
    /// equally well. Picking the smallest offset among them is what
    /// keeps the absolute-mode wire offset varint small.
    fn smallest_offset_across_lcp_plateau(
        &self,
        starting_rank:    usize,
        plateau_length:   u32,
    ) -> u32 {
        let mut smallest_offset = self.sorted_positions[starting_rank];

        let mut walk_rank = starting_rank;
        while walk_rank > 0 && self.lcp_with_previous[walk_rank] >= plateau_length {
            walk_rank -= 1;
            smallest_offset = smallest_offset.min(self.sorted_positions[walk_rank]);
        }

        let mut walk_rank = starting_rank;
        while walk_rank + 1 < self.sorted_positions.len()
            && self.lcp_with_previous[walk_rank + 1] >= plateau_length
        {
            walk_rank += 1;
            smallest_offset = smallest_offset.min(self.sorted_positions[walk_rank]);
        }

        smallest_offset
    }
}

/// Byte-by-byte common prefix length, short-circuiting at the first
/// mismatch or whichever buffer runs out first.
fn longest_common_prefix_length(left: &[u8], right: &[u8]) -> usize {
    let max_prefix = left.len().min(right.len());
    let mut prefix_length = 0usize;
    while prefix_length < max_prefix && left[prefix_length] == right[prefix_length] {
        prefix_length += 1;
    }
    prefix_length
}

// ── Kasai's LCP construction ─────────────────────────────────────────

/// Invert a permutation: `inverse[positions[r]] = r`. Used to translate
/// "the suffix starting at byte position `p`" into "the rank that
/// suffix occupies in `sorted_positions`."
fn invert_to_rank_array(sorted_positions: &[u32]) -> Vec<u32> {
    let mut rank_of_position = vec![0u32; sorted_positions.len()];
    for (rank, &position) in sorted_positions.iter().enumerate() {
        rank_of_position[position as usize] = rank as u32;
    }
    rank_of_position
}

/// Kasai et al. (2001). Builds the adjacent-suffix LCP array in
/// linear time by walking positions in input order, using the rank
/// array to find each suffix's predecessor in SA order, and observing
/// that the LCP can only shrink by one when moving from suffix `i`
/// to suffix `i + 1` — the running counter `running_lcp` carries
/// over with a single decrement per step.
fn build_lcp_with_previous(
    source:           &[u8],
    sorted_positions: &[u32],
    rank_of_position: &[u32],
) -> Vec<u32> {
    let length = source.len();
    let mut lcp_with_previous = vec![0u32; length];
    let mut running_lcp        = 0usize;
    for position in 0..length {
        let rank = rank_of_position[position] as usize;
        if rank == 0 {
            running_lcp = 0;
            continue;
        }
        let predecessor_position = sorted_positions[rank - 1] as usize;
        while position           + running_lcp < length
            && predecessor_position + running_lcp < length
            && source[position           + running_lcp]
            == source[predecessor_position + running_lcp]
        {
            running_lcp += 1;
        }
        lcp_with_previous[rank] = running_lcp as u32;
        if running_lcp > 0 {
            running_lcp -= 1;
        }
    }
    lcp_with_previous
}

// ── SA-IS over bytes (and recursively over u32 names) ────────────────

/// Top-level entry: build the suffix array of a byte buffer. The empty
/// input produces the empty SA.
fn build_byte_suffix_array(source: &[u8]) -> Vec<u32> {
    if source.is_empty() {
        return Vec::new();
    }
    sa_is_over_alphabet::<u8>(source, BYTE_ALPHABET_SIZE)
}

const BYTE_ALPHABET_SIZE: usize = 256;

/// Recursive entry for the SA-IS sub-problem: build the SA over the
/// named-substring buffer produced by the parent call. Alphabet
/// size is the number of distinct names assigned at that level.
fn build_named_suffix_array(names: &[u32], alphabet_size: usize) -> Vec<u32> {
    sa_is_over_alphabet::<u32>(names, alphabet_size)
}

/// SA-IS body, generic over the symbol type (`u8` at the top level,
/// `u32` in the recursive call on named leftmost-smaller substrings).
///
/// The algorithm in five lines:
///   1. Classify each suffix as Larger-or-Smaller-than-its-successor.
///   2. Find the leftmost-smaller positions: Smaller-typed positions
///      whose predecessor is Larger-typed.
///   3. Approximately sort: place the leftmost-smaller positions in
///      input order at bucket ends, induce L (left → right), induce
///      S (right → left).
///   4. Name leftmost-smaller substrings from the approximate SA;
///      recurse if any names collide, otherwise the inversion is
///      exact.
///   5. Exactly sort: re-place the leftmost-smaller positions in
///      sorted order, re-induce L and S.
fn sa_is_over_alphabet<Symbol: SaIsSymbol>(input: &[Symbol], alphabet_size: usize) -> Vec<u32> {
    let length                          = input.len();
    let suffix_types                    = classify_each_suffix(input);
    let leftmost_smaller_in_input_order = leftmost_smaller_positions(&suffix_types);
    let bucket_layout                   = compute_bucket_layout(input, alphabet_size);

    let mut suffix_array = vec![UNPLACED_SLOT; length];
    place_leftmost_smaller_at_bucket_ends(input, &mut suffix_array, &leftmost_smaller_in_input_order, &bucket_layout);
    induce_l_type_suffixes(input, &mut suffix_array, &suffix_types, &bucket_layout);
    induce_s_type_suffixes(input, &mut suffix_array, &suffix_types, &bucket_layout);

    let (names_in_leftmost_smaller_order, distinct_name_count) =
        name_leftmost_smaller_substrings(input, &suffix_array, &suffix_types, &leftmost_smaller_in_input_order);

    let leftmost_smaller_in_sorted_order = sort_leftmost_smaller_by_names(
        &leftmost_smaller_in_input_order,
        &names_in_leftmost_smaller_order,
        distinct_name_count,
    );

    suffix_array.iter_mut().for_each(|slot| *slot = UNPLACED_SLOT);
    place_leftmost_smaller_at_bucket_ends(input, &mut suffix_array, &leftmost_smaller_in_sorted_order, &bucket_layout);
    induce_l_type_suffixes(input, &mut suffix_array, &suffix_types, &bucket_layout);
    induce_s_type_suffixes(input, &mut suffix_array, &suffix_types, &bucket_layout);

    debug_assert!(
        suffix_array.iter().all(|&slot| slot != UNPLACED_SLOT),
        "SA-IS post-condition: every suffix array slot must be filled"
    );
    suffix_array
}

/// Sentinel marking a not-yet-placed slot in the SA under construction.
/// The dispatcher rejects inputs whose length would make `u32::MAX` a
/// legitimate position, leaving the value free for this role.
const UNPLACED_SLOT: u32 = u32::MAX;

/// Whether a suffix sorts smaller than the suffix one position later.
/// (In the SA-IS literature: the "L/S type" classification, named
/// here by the comparison the algorithm actually performs.)
#[derive(Copy, Clone, Eq, PartialEq)]
enum SuffixComparisonWithSuccessor {
    LargerThanSuccessor,
    SmallerThanSuccessor,
}

/// One symbol of an alphabet over which SA-IS can run: bytes at the
/// top level, `u32` names in the recursive call.
trait SaIsSymbol: Copy + Eq + Ord {
    fn alphabet_index(self) -> usize;
}

impl SaIsSymbol for u8  { fn alphabet_index(self) -> usize { self as usize } }
impl SaIsSymbol for u32 { fn alphabet_index(self) -> usize { self as usize } }

/// Per-alphabet bucket boundaries: each symbol `c` claims SA slots
/// `[starts[c], ends[c])`. Computed once per call from symbol
/// frequencies; both induction passes consult it.
struct BucketLayout {
    starts: Vec<usize>,
    ends:   Vec<usize>,
}

/// Walk the input right-to-left, marking each suffix as Larger or
/// Smaller relative to its successor. The implicit sentinel one past
/// the end sorts smaller than any real symbol, so the last real
/// suffix is unconditionally Larger-typed.
fn classify_each_suffix<Symbol: SaIsSymbol>(input: &[Symbol]) -> Vec<SuffixComparisonWithSuccessor> {
    let length = input.len();
    let mut classifications = vec![SuffixComparisonWithSuccessor::LargerThanSuccessor; length];
    for position in (0..length.saturating_sub(1)).rev() {
        classifications[position] = match input[position].cmp(&input[position + 1]) {
            Ordering::Less    => SuffixComparisonWithSuccessor::SmallerThanSuccessor,
            Ordering::Greater => SuffixComparisonWithSuccessor::LargerThanSuccessor,
            Ordering::Equal   => classifications[position + 1],
        };
    }
    classifications
}

/// Filter for Smaller-typed positions whose predecessor is Larger-
/// typed. (In the SA-IS literature these are the "LMS" — leftmost-
/// smaller — suffixes; their relative order determines the entire
/// SA.) Position 0 has no predecessor and is excluded.
fn leftmost_smaller_positions(
    classifications: &[SuffixComparisonWithSuccessor],
) -> Vec<usize> {
    let mut positions = Vec::new();
    for position in 1..classifications.len() {
        if is_leftmost_smaller(classifications, position) {
            positions.push(position);
        }
    }
    positions
}

fn is_leftmost_smaller(
    classifications: &[SuffixComparisonWithSuccessor],
    position:        usize,
) -> bool {
    position > 0
        && classifications[position]     == SuffixComparisonWithSuccessor::SmallerThanSuccessor
        && classifications[position - 1] == SuffixComparisonWithSuccessor::LargerThanSuccessor
}

/// One frequency pass plus one prefix-sum pass.
fn compute_bucket_layout<Symbol: SaIsSymbol>(
    input:         &[Symbol],
    alphabet_size: usize,
) -> BucketLayout {
    let mut frequencies = vec![0usize; alphabet_size];
    for symbol in input {
        frequencies[symbol.alphabet_index()] += 1;
    }
    let mut starts = Vec::with_capacity(alphabet_size);
    let mut ends   = Vec::with_capacity(alphabet_size);
    let mut running_total = 0usize;
    for &frequency in &frequencies {
        starts.push(running_total);
        running_total += frequency;
        ends  .push(running_total);
    }
    BucketLayout { starts, ends }
}

/// Place each leftmost-smaller position at the high end of its
/// bucket, iterating the list in reverse so that earlier-listed
/// positions land in lower SA slots within each bucket. Used twice
/// per call: once with the input-order list (approximate pass) and
/// once with the sorted-order list (exact pass).
fn place_leftmost_smaller_at_bucket_ends<Symbol: SaIsSymbol>(
    input:               &[Symbol],
    suffix_array:        &mut [u32],
    positions_to_place:  &[usize],
    bucket_layout:       &BucketLayout,
) {
    let mut bucket_end_cursors = bucket_layout.ends.clone();
    for &position in positions_to_place.iter().rev() {
        let symbol_index = input[position].alphabet_index();
        bucket_end_cursors[symbol_index] -= 1;
        suffix_array[bucket_end_cursors[symbol_index]] = position as u32;
    }
}

/// L-type induction. Scan the SA left-to-right; for each placed
/// position `p` whose predecessor is Larger-typed, place `p - 1` at
/// the next free slot from the start of its bucket. The implicit
/// sentinel seeds the last real position (always Larger) so the
/// chain can begin.
fn induce_l_type_suffixes<Symbol: SaIsSymbol>(
    input:           &[Symbol],
    suffix_array:    &mut [u32],
    classifications: &[SuffixComparisonWithSuccessor],
    bucket_layout:   &BucketLayout,
) {
    let length = input.len();
    let mut bucket_start_cursors = bucket_layout.starts.clone();

    if length > 0 {
        let last_position = length - 1;
        let symbol_index  = input[last_position].alphabet_index();
        suffix_array[bucket_start_cursors[symbol_index]] = last_position as u32;
        bucket_start_cursors[symbol_index] += 1;
    }

    for rank in 0..length {
        let placed_position = suffix_array[rank];
        if placed_position == UNPLACED_SLOT || placed_position == 0 {
            continue;
        }
        let predecessor = placed_position as usize - 1;
        if classifications[predecessor] == SuffixComparisonWithSuccessor::LargerThanSuccessor {
            let symbol_index = input[predecessor].alphabet_index();
            suffix_array[bucket_start_cursors[symbol_index]] = predecessor as u32;
            bucket_start_cursors[symbol_index] += 1;
        }
    }
}

/// S-type induction. Scan right-to-left; for each placed position
/// `p` whose predecessor is Smaller-typed, place `p - 1` at the
/// next free slot from the end of its bucket. Overwrites the
/// approximate leftmost-smaller placements by design — they served
/// their role seeding L-induction, and the S-pass places each
/// leftmost-smaller position at its final rank.
fn induce_s_type_suffixes<Symbol: SaIsSymbol>(
    input:           &[Symbol],
    suffix_array:    &mut [u32],
    classifications: &[SuffixComparisonWithSuccessor],
    bucket_layout:   &BucketLayout,
) {
    let length = input.len();
    let mut bucket_end_cursors = bucket_layout.ends.clone();

    for rank in (0..length).rev() {
        let placed_position = suffix_array[rank];
        if placed_position == UNPLACED_SLOT || placed_position == 0 {
            continue;
        }
        let predecessor = placed_position as usize - 1;
        if classifications[predecessor] == SuffixComparisonWithSuccessor::SmallerThanSuccessor {
            let symbol_index = input[predecessor].alphabet_index();
            bucket_end_cursors[symbol_index] -= 1;
            suffix_array[bucket_end_cursors[symbol_index]] = predecessor as u32;
        }
    }
}

/// After induction, the leftmost-smaller positions occupy the SA
/// in the order their substrings sort. Walk that order, comparing
/// each leftmost-smaller substring against the previous one,
/// assigning a fresh name on any difference. Two substrings are
/// "equal" iff they have identical symbols and identical suffix-
/// type classifications at each offset and they terminate at the
/// same offset.
///
/// Returns the names in input order (parallel to
/// `leftmost_smaller_in_input_order`) and the number of distinct
/// names.
fn name_leftmost_smaller_substrings<Symbol: SaIsSymbol>(
    input:                           &[Symbol],
    suffix_array:                    &[u32],
    classifications:                 &[SuffixComparisonWithSuccessor],
    leftmost_smaller_in_input_order: &[usize],
) -> (Vec<u32>, usize) {
    let length = input.len();
    let mut name_at_position:          Vec<u32>      = vec![0u32; length];
    let mut current_name:              u32           = 0;
    let mut previous_leftmost_smaller: Option<usize> = None;

    for &slot in suffix_array {
        if slot == UNPLACED_SLOT {
            continue;
        }
        let position = slot as usize;
        if !is_leftmost_smaller(classifications, position) {
            continue;
        }
        let differs_from_previous = match previous_leftmost_smaller {
            None           => false,
            Some(previous) =>
                !leftmost_smaller_substrings_equal(input, classifications, previous, position),
        };
        if differs_from_previous {
            current_name += 1;
        }
        name_at_position[position] = current_name;
        previous_leftmost_smaller  = Some(position);
    }

    let distinct_name_count = if previous_leftmost_smaller.is_some() {
        current_name as usize + 1
    } else {
        0
    };

    let names_in_leftmost_smaller_order: Vec<u32> = leftmost_smaller_in_input_order
        .iter()
        .map(|&position| name_at_position[position])
        .collect();

    (names_in_leftmost_smaller_order, distinct_name_count)
}

fn leftmost_smaller_substrings_equal<Symbol: SaIsSymbol>(
    input:           &[Symbol],
    classifications: &[SuffixComparisonWithSuccessor],
    a:               usize,
    b:               usize,
) -> bool {
    let length = input.len();
    let mut offset = 0usize;
    loop {
        let a_position = a + offset;
        let b_position = b + offset;
        if a_position >= length || b_position >= length {
            return false;
        }
        if input[a_position] != input[b_position]
            || classifications[a_position] != classifications[b_position]
        {
            return false;
        }
        if offset > 0 {
            let a_at_leftmost_smaller_boundary = is_leftmost_smaller(classifications, a_position);
            let b_at_leftmost_smaller_boundary = is_leftmost_smaller(classifications, b_position);
            match (a_at_leftmost_smaller_boundary, b_at_leftmost_smaller_boundary) {
                (true,  true)  => return true,
                (false, false) => {}
                _              => return false,
            }
        }
        offset += 1;
    }
}

/// Recover the leftmost-smaller positions in their final
/// lexicographic order. When all names were distinct, the inversion
/// is direct. Otherwise we recurse on the named-substring string to
/// break the ties.
fn sort_leftmost_smaller_by_names(
    leftmost_smaller_in_input_order: &[usize],
    names_in_leftmost_smaller_order: &[u32],
    distinct_name_count:             usize,
) -> Vec<usize> {
    let leftmost_smaller_count = leftmost_smaller_in_input_order.len();
    if distinct_name_count < leftmost_smaller_count {
        let recursive_sa = build_named_suffix_array(names_in_leftmost_smaller_order, distinct_name_count);
        recursive_sa
            .iter()
            .map(|&sorted_leftmost_smaller_rank|
                leftmost_smaller_in_input_order[sorted_leftmost_smaller_rank as usize])
            .collect()
    } else {
        let mut in_sorted_order = vec![0usize; leftmost_smaller_count];
        for (leftmost_smaller_rank, &original_position) in
            leftmost_smaller_in_input_order.iter().enumerate()
        {
            let name = names_in_leftmost_smaller_order[leftmost_smaller_rank] as usize;
            in_sorted_order[name] = original_position;
        }
        in_sorted_order
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn naive_suffix_array(data: &[u8]) -> Vec<u32> {
        let mut indices: Vec<u32> = (0..data.len() as u32).collect();
        indices.sort_by(|&left, &right| data[left as usize..].cmp(&data[right as usize..]));
        indices
    }

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

    #[test]
    fn empty_input_has_empty_sa() {
        let index = SourceSuffixArrayIndex::build(&[]).expect("empty source must succeed");
        assert!(index.sorted_positions.is_empty());
        assert!(index.lcp_with_previous.is_empty());
    }

    #[test]
    fn banana_matches_naive() {
        let index = SourceSuffixArrayIndex::build(b"banana").expect("succeed");
        assert_eq!(index.sorted_positions, naive_suffix_array(b"banana"));
    }

    #[test]
    fn mississippi_matches_naive() {
        let data = b"mississippi";
        let index = SourceSuffixArrayIndex::build(data).expect("succeed");
        assert_eq!(index.sorted_positions, naive_suffix_array(data));
    }

    #[test]
    fn random_fuzz_matches_naive() {
        for length in [1usize, 2, 8, 64, 256, 1024, 8192] {
            let data  = pseudo_random(0xc0ffee ^ length as u64, length);
            let index = SourceSuffixArrayIndex::build(&data).expect("succeed");
            assert_eq!(index.sorted_positions, naive_suffix_array(&data), "mismatch at length {length}");
        }
    }

    #[test]
    fn lcp_matches_direct_recomputation() {
        let data  = pseudo_random(0xfeedf00d, 4096);
        let index = SourceSuffixArrayIndex::build(&data).expect("succeed");
        for rank in 1..index.sorted_positions.len() {
            let prev = index.sorted_positions[rank - 1] as usize;
            let here = index.sorted_positions[rank]     as usize;
            let recomputed = longest_common_prefix_length(&data[prev..], &data[here..]);
            assert_eq!(index.lcp_with_previous[rank] as usize, recomputed, "rank {rank}");
        }
    }

    #[test]
    fn longest_match_finds_the_long_run() {
        // Source contains a 16-byte signature at offset 100; target's
        // suffix should match it exactly.
        let mut source = vec![0u8; 500];
        let signature: [u8; 16] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x11,
        ];
        source[100..116].copy_from_slice(&signature);
        let index = SourceSuffixArrayIndex::build(&source).expect("succeed");
        let candidate = index
            .longest_match_for_target_suffix(&source, &signature)
            .expect("must find a match");
        assert_eq!(candidate.source_offset, 100);
        assert_eq!(candidate.match_length, 16);
    }

    #[test]
    fn longest_match_returns_none_on_empty_inputs() {
        let index = SourceSuffixArrayIndex::build(&[]).expect("succeed");
        assert!(index.longest_match_for_target_suffix(&[], b"abc").is_none());

        let index = SourceSuffixArrayIndex::build(b"abcdef").expect("succeed");
        assert!(index.longest_match_for_target_suffix(b"abcdef", &[]).is_none());
    }

    #[test]
    fn tie_breaker_prefers_smaller_offset() {
        // Two copies of "ABCDEF" in source — query should return the
        // earlier one.
        let source = b"ABCDEF......ABCDEF";
        let index  = SourceSuffixArrayIndex::build(source).expect("succeed");
        let candidate = index
            .longest_match_for_target_suffix(source, b"ABCDEF")
            .expect("match exists");
        assert_eq!(candidate.source_offset, 0);
        assert_eq!(candidate.match_length, 6);
    }
}
