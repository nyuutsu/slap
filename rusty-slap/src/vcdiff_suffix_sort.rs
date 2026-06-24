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
//! `usize` throughout. The matcher is total — the cover contract has no
//! error channel to report an overflow through, unlike
//! `xdelta1_suffix_array`'s fallible `build` — so it does not narrow to
//! `u32`.
//! Construction is prefix doubling with counting sort (O(n log n)); the
//! quadratic reference it replaces lives on as the differential oracle
//! in `vcdiff_diff.rs`.

// ── Public surface ───────────────────────────────────────────────────

/// The longest match found for a target position: where it begins in
/// the superstring `U = source ++ target` and how long it runs. Shared
/// with `vcdiff_diff.rs`, which feeds it to the cover's greedy parse,
/// and with that module's differential oracle.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Match {
    pub u_offset: usize,
    pub length:   usize,
}

/// A longest-match index over the superstring `U = source ++ target`,
/// answering one query per target position. Construction does all the
/// work up front and keeps only the per-position answers, so the
/// retained footprint is two `target`-sized arrays.
pub struct SuperstringMatcher {
    /// `match_length[p]` is the length of the longest run beginning at
    /// `target[p]` that recurs earlier in `U`; `0` means no recurrence
    /// (the position begins a literal).
    match_length: Vec<usize>,

    /// `match_u_offset[p]` is the absolute offset into `U` at which that
    /// recurrence begins. Meaningful only where `match_length[p] > 0`.
    match_u_offset: Vec<usize>,
}

impl SuperstringMatcher {
    /// Build the matcher for a `(source, target)` pair. An empty target
    /// has no positions to query and skips the suffix array entirely.
    pub fn build(source: &[u8], target: &[u8]) -> Self {
        let target_length = target.len();
        if target_length == 0 {
            return SuperstringMatcher { match_length: Vec::new(), match_u_offset: Vec::new() };
        }
        let source_length = source.len();
        let augmented = build_augmented_string(source, target);

        let sorted_positions  = build_suffix_array(&augmented);
        let rank_of_position  = invert_to_rank_array(&sorted_positions);
        let lcp_with_previous = build_lcp_with_previous(&augmented, &sorted_positions, &rank_of_position);

        let previous_smaller =
            nearest_smaller_with_carried_lcp(&sorted_positions, &lcp_with_previous, ScanDirection::Leftward);
        let next_smaller =
            nearest_smaller_with_carried_lcp(&sorted_positions, &lcp_with_previous, ScanDirection::Rightward);

        // The augmented index where the target's bytes begin: past the
        // source and its trailing separator.
        let target_region_start = source_length + 1;

        let mut match_length   = vec![0usize; target_length];
        let mut match_u_offset = vec![0usize; target_length];
        for rank in 0..sorted_positions.len() {
            let text_position = sorted_positions[rank];
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
                    (previous_smaller.lcp[rank], previous_smaller.text_position[rank])
                } else {
                    (next_smaller.lcp[rank], next_smaller.text_position[rank])
                };
            if length == 0 {
                continue;
            }
            let target_position = text_position - target_region_start;
            match_length[target_position]   = length;
            match_u_offset[target_position] =
                superstring_offset_of(neighbour_position, source_length);
        }

        SuperstringMatcher { match_length, match_u_offset }
    }

    /// The longest match of `target[position..]` recurring earlier in
    /// `U = source ++ target`, or `None` when nothing recurs. The cover
    /// applies its own minimum-match floor; this reports the true
    /// longest regardless of length, the same contract the differential
    /// oracle holds.
    pub fn longest_match_at(&self, position: usize) -> Option<Match> {
        let length = self.match_length[position];
        if length == 0 {
            None
        } else {
            Some(Match { u_offset: self.match_u_offset[position], length })
        }
    }
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

/// Map a `(source, target)` pair to the augmented symbol string the
/// suffix array is built over. Real bytes become `2..=257`; the
/// separator is `1` and the terminator `0`, both distinct from every
/// byte and from each other. The separator's only job is to stop a
/// source-anchored common prefix at the source's end; the terminator,
/// as the unique smallest symbol, makes every suffix distinct.
fn build_augmented_string(source: &[u8], target: &[u8]) -> Vec<usize> {
    const SEPARATOR: usize = 1;
    const TERMINATOR: usize = 0;
    let mut augmented = Vec::with_capacity(source.len() + target.len() + 2);
    augmented.extend(source.iter().map(|&byte| byte as usize + 2));
    augmented.push(SEPARATOR);
    augmented.extend(target.iter().map(|&byte| byte as usize + 2));
    augmented.push(TERMINATOR);
    augmented
}

// ── Suffix array by prefix doubling ──────────────────────────────────

/// Build the suffix array of a small-integer symbol string by prefix
/// doubling with counting sort: each round sorts the suffixes by their
/// first `2 * prefix_length` symbols, reusing the previous round's
/// ranks as the two sort keys, until every suffix has a distinct rank.
/// O(n log n).
fn build_suffix_array(text: &[usize]) -> Vec<usize> {
    let length = text.len();
    if length == 0 {
        return Vec::new();
    }

    // Initial ranks: the symbols themselves, compressed to a dense
    // range so the counting-sort key range stays bounded by `length`.
    let mut rank = compress_to_dense_ranks(text);
    let mut sorted_positions: Vec<usize> = (0..length).collect();
    let mut next_rank = vec![0usize; length];

    let mut prefix_length = 1usize;
    loop {
        // The second sort key: the rank of the suffix half a prefix
        // ahead, shifted up by one so that "ran off the end" can be the
        // smallest key, `0`.
        let trailing_rank: Vec<usize> = (0..length)
            .map(|position| {
                if position + prefix_length < length {
                    rank[position + prefix_length] + 1
                } else {
                    0
                }
            })
            .collect();

        // Least-significant key first: sort by the trailing rank, then
        // stably by the leading rank, leaving the order sorted by the
        // pair.
        let key_range = length + 1;
        counting_sort_by_key(&mut sorted_positions, &trailing_rank, key_range);
        counting_sort_by_key(&mut sorted_positions, &rank,         key_range);

        // Re-rank: walk the freshly sorted order, advancing the class
        // whenever the full `(leading, trailing)` key changes.
        next_rank[sorted_positions[0]] = 0;
        let mut distinct_classes = 1usize;
        for adjacent in 1..length {
            let earlier = sorted_positions[adjacent - 1];
            let later   = sorted_positions[adjacent];
            let key_changed =
                rank[earlier] != rank[later] || trailing_rank[earlier] != trailing_rank[later];
            if key_changed {
                distinct_classes += 1;
            }
            next_rank[later] = distinct_classes - 1;
        }
        std::mem::swap(&mut rank, &mut next_rank);

        if distinct_classes == length || prefix_length >= length {
            break;
        }
        prefix_length <<= 1;
    }

    sorted_positions
}

/// Compress a symbol string to dense ranks in `[0, distinct_symbols)`,
/// preserving order. Keeps the counting-sort key range bounded by the
/// string length even when the raw alphabet (bytes plus the two
/// sentinels) is sparse.
fn compress_to_dense_ranks(text: &[usize]) -> Vec<usize> {
    let mut distinct_symbols: Vec<usize> = text.to_vec();
    distinct_symbols.sort_unstable();
    distinct_symbols.dedup();
    text.iter()
        .map(|symbol| distinct_symbols.binary_search(symbol).expect("symbol present"))
        .collect()
}

/// Stable counting sort of `order` by `key[element]`, with keys in
/// `[0, key_range)`. Stable because elements are scanned in their
/// current order and placed at ascending offsets within each key's
/// bucket — the property prefix doubling relies on to keep the
/// least-significant pass's order under the most-significant pass.
fn counting_sort_by_key(order: &mut Vec<usize>, key: &[usize], key_range: usize) {
    let mut bucket_offset = vec![0usize; key_range + 1];
    for &element in order.iter() {
        bucket_offset[key[element]] += 1;
    }
    let mut running_total = 0usize;
    for slot in bucket_offset.iter_mut() {
        let count = *slot;
        *slot = running_total;
        running_total += count;
    }
    let mut sorted = vec![0usize; order.len()];
    for &element in order.iter() {
        let bucket = key[element];
        sorted[bucket_offset[bucket]] = element;
        bucket_offset[bucket] += 1;
    }
    *order = sorted;
}

// ── Kasai's LCP and the rank inverse ─────────────────────────────────

/// Invert the suffix array: `rank_of_position[p]` is the suffix-array
/// rank of the suffix beginning at text position `p`.
fn invert_to_rank_array(sorted_positions: &[usize]) -> Vec<usize> {
    let mut rank_of_position = vec![0usize; sorted_positions.len()];
    for (rank, &position) in sorted_positions.iter().enumerate() {
        rank_of_position[position] = rank;
    }
    rank_of_position
}

/// Kasai et al. (2001): the longest common prefix between each suffix
/// and its suffix-array predecessor, in linear time. Walking positions
/// in input order, the running LCP can shrink by at most one from one
/// position to the next, so the counter carries over with a single
/// decrement per step. `lcp_with_previous[0]` is `0` (the first suffix
/// has no predecessor).
fn build_lcp_with_previous(
    text:             &[usize],
    sorted_positions: &[usize],
    rank_of_position: &[usize],
) -> Vec<usize> {
    let length = text.len();
    let mut lcp_with_previous = vec![0usize; length];
    let mut running_lcp = 0usize;
    for position in 0..length {
        let rank = rank_of_position[position];
        if rank == 0 {
            running_lcp = 0;
            continue;
        }
        let predecessor_position = sorted_positions[rank - 1];
        while position + running_lcp < length
            && predecessor_position + running_lcp < length
            && text[position + running_lcp] == text[predecessor_position + running_lcp]
        {
            running_lcp += 1;
        }
        lcp_with_previous[rank] = running_lcp;
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
struct NearestSmallerNeighbours {
    lcp: Vec<usize>,
    text_position: Vec<usize>,
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
fn nearest_smaller_with_carried_lcp(
    sorted_positions: &[usize],
    lcp_with_previous: &[usize],
    direction: ScanDirection,
) -> NearestSmallerNeighbours {
    let length = sorted_positions.len();
    let mut neighbours = NearestSmallerNeighbours {
        lcp: vec![0usize; length],
        text_position: vec![0usize; length],
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
            ScanDirection::Leftward => lcp_with_previous[rank],
            ScanDirection::Rightward => {
                if rank + 1 < length { lcp_with_previous[rank + 1] } else { 0 }
            }
        };
        while let Some(&StackFrame { rank: top_rank, carried_minimum_lcp: top_minimum }) = stack.last() {
            if sorted_positions[top_rank] > sorted_positions[rank] {
                running_minimum = running_minimum.min(top_minimum);
                stack.pop();
            } else {
                break;
            }
        }
        if let Some(&StackFrame { rank: smaller_neighbour_rank, .. }) = stack.last() {
            neighbours.lcp[rank] = running_minimum;
            neighbours.text_position[rank] = sorted_positions[smaller_neighbour_rank];
        }
        stack.push(StackFrame { rank, carried_minimum_lcp: running_minimum });
    }

    neighbours
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

    fn naive_suffix_array(text: &[usize]) -> Vec<usize> {
        let mut positions: Vec<usize> = (0..text.len()).collect();
        positions.sort_by(|&left, &right| text[left..].cmp(&text[right..]));
        positions
    }

    fn longest_common_prefix(left: &[usize], right: &[usize]) -> usize {
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
            let text: Vec<usize> = word.iter().map(|&b| b as usize + 2).collect();
            assert_eq!(build_suffix_array(&text), naive_suffix_array(&text), "{word:?}");
        }
    }

    #[test]
    fn suffix_array_matches_naive_on_augmented_strings() {
        for length in [0usize, 1, 2, 5, 33, 200, 1500] {
            let source = pseudo_random_low_alphabet(0xa11ce ^ length as u64, length, 4);
            let target = pseudo_random_low_alphabet(0xb0b ^ length as u64, length + 7, 4);
            let augmented = build_augmented_string(&source, &target);
            assert_eq!(
                build_suffix_array(&augmented),
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
        let sorted_positions = build_suffix_array(&augmented);
        let rank_of_position = invert_to_rank_array(&sorted_positions);
        let lcp = build_lcp_with_previous(&augmented, &sorted_positions, &rank_of_position);
        for rank in 1..sorted_positions.len() {
            let previous = &augmented[sorted_positions[rank - 1]..];
            let current  = &augmented[sorted_positions[rank]..];
            assert_eq!(lcp[rank], longest_common_prefix(previous, current), "rank {rank}");
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
                        byte_in_superstring(found.u_offset + step),
                        target[position + step],
                        "offset {} step {step} at position {position}",
                        found.u_offset
                    );
                }
            }
        }
    }

    #[test]
    fn empty_target_has_no_matches() {
        let matcher = SuperstringMatcher::build(b"anything", b"");
        assert!(matcher.match_length.is_empty());
    }
}
