//! BPS diff engine based on Alcaro's suffix-array approach from Flips
//! (`libbps-suf.cpp`).
//!
//! Concatenates target (windowed) + source, suffix-sorts, then walks the
//! target left-to-right choosing the cheapest BPS action at each position.

use crate::suffix_sort::{self, SuffixArray};

// BPS action tags.
const SOURCE_READ: u64 = 0;
const TARGET_READ: u64 = 1;
const SOURCE_COPY: u64 = 2;
const TARGET_COPY: u64 = 3;

/// Encode a value as a byuu varint (NOT standard LEB128).
///
/// Non-final bytes have bit 7 clear; final byte has bit 7 set.
/// Between bytes, subtract 1 from the remaining value.
#[inline]
fn encode_varint(out: &mut Vec<u8>, mut val: u64) {
    while val >= 0x80 {
        out.push((val & 0x7F) as u8);
        val >>= 7;
        val -= 1;
    }
    out.push((val | 0x80) as u8);
}

/// Number of bytes a byuu varint occupies.
#[inline]
#[must_use]
fn varint_cost(mut val: u64) -> usize {
    let mut n = 1;
    while val >= 0x80 {
        val >>= 7;
        val -= 1;
        n += 1;
    }
    n
}

/// Zigzag-encode a signed delta: bit 0 = sign, bits 1+ = magnitude.
#[inline]
#[must_use]
fn encode_delta(prev: usize, next: usize) -> u64 {
    if next >= prev {
        ((next - prev) as u64) << 1
    } else {
        (((prev - next) as u64) << 1) | 1
    }
}

/// Length of the common prefix between two slices.
/// Iterator version chosen over manual loop after profiling showed no
/// meaningful difference.
#[inline]
#[must_use]
fn match_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

/// Suffix-sorted concatenation of a target window and source buffer,
/// with a reverse index for O(1) rank lookup.
struct SortedIndex {
    concat: Vec<u8>,
    suffix_array: SuffixArray,
    rank_at_position: Vec<usize>,
}

/// Build concatenated buffer (target window + source), suffix-sort, and
/// build reverse index for O(1) rank lookup.
fn build_index(target: &[u8], source: &[u8], sortedsize: usize) -> SortedIndex {
    let mut concat = Vec::with_capacity(sortedsize + source.len());
    concat.extend_from_slice(&target[..sortedsize]);
    concat.extend_from_slice(source);
    let suffix_array = suffix_sort::suffix_sort(&concat);
    let mut rank_at_position = vec![0usize; concat.len()];
    for (rank, position) in suffix_array.iter_positions().enumerate() {
        rank_at_position[position] = rank;
    }
    SortedIndex { concat, suffix_array, rank_at_position }
}

/// Given two SA candidate positions, pick the one that better matches
/// the search string. Returns (position, match_length).
#[inline]
fn pick_best(concat: &[u8], search: &[u8], pos_a: usize, pos_b: usize) -> (usize, usize) {
    let common = match_len(&concat[pos_a..], &concat[pos_b..]);
    if common >= search.len() {
        return (pos_a, search.len());
    }
    // The candidate whose byte at the divergence point matches search wins.
    let a_extends =
        pos_a + common < concat.len() && concat[pos_a + common] == search[common];
    let winner = if a_extends { pos_a } else { pos_b };
    let extra = match_len(&concat[winner + common..], &search[common..]);
    (winner, common + extra)
}

/// Compute BPS diff, returning the encoded action byte stream.
///
/// The stream contains byuu-varint-encoded BPS actions ready to splice
/// between the metadata and CRC footer in a BPS file.
#[must_use]
pub fn bps_diff(source: &[u8], target: &[u8]) -> Vec<u8> {
    let target_len = target.len();
    let mut out = Vec::new();

    if target_len == 0 {
        return out;
    }

    let mut outpos: usize = 0;
    let mut src_rel: usize = 0; // last SourceCopy end position
    let mut tgt_rel: usize = 0; // last TargetCopy end position
    let mut pending: Option<usize> = None; // start of pending TargetRead

    // Progressive sorting: shrink initial window so the first sort is fast.
    let mut sortedsize = target_len;
    while sortedsize / 4 > source.len() && sortedsize > 1024 {
        sortedsize >>= 2;
    }

    let SortedIndex { mut concat, mut suffix_array, mut rank_at_position } =
        build_index(target, source, sortedsize);

    while outpos < target_len {
        // Grow window when approaching the sorted boundary.
        if outpos + 256 >= sortedsize && sortedsize < target_len {
            while outpos + 256 >= sortedsize && sortedsize < target_len {
                sortedsize = (sortedsize * 4 + 3).min(target_len);
            }
            let idx = build_index(target, source, sortedsize);
            concat = idx.concat;
            suffix_array = idx.suffix_array;
            rank_at_position = idx.rank_at_position;
        }

        let sa_len = suffix_array.len();
        let search = &target[outpos..sortedsize];
        let rank = rank_at_position[outpos];

        // Scan SA neighbors for nearest valid match.
        // Invalid zone: [outpos, sortedsize) — not-yet-written target bytes.
        let mut up: Option<usize> = None;
        let mut dn: Option<usize> = None;

        {
            let mut i = rank;
            while i > 0 {
                i -= 1;
                let p = suffix_array.position_at_rank(i);
                if p < outpos || p >= sortedsize {
                    up = Some(p);
                    break;
                }
            }
        }
        {
            let mut i = rank + 1;
            while i < sa_len {
                let p = suffix_array.position_at_rank(i);
                if p < outpos || p >= sortedsize {
                    dn = Some(p);
                    break;
                }
                i += 1;
            }
        }

        // Pick the best match from up/down candidates.
        let best = match (up, dn) {
            (None, None) => None,
            (Some(p), None) | (None, Some(p)) => {
                let mlen = match_len(&concat[p..], search);
                if mlen > 0 {
                    Some((p, mlen))
                } else {
                    None
                }
            }
            (Some(a), Some(b)) => {
                let (winner, mlen) = pick_best(&concat, search, a, b);
                if mlen > 0 {
                    Some((winner, mlen))
                } else {
                    None
                }
            }
        };

        // Classify the match and decide whether encoding it beats staying
        // in TargetRead mode.  `cost` counts bytes of the encoded action:
        // a flat 1 for the action-prefix varint (approximated — its true
        // width depends on `mlen`), plus the delta varint's width for
        // SourceCopy / TargetCopy.  The `has_pending` term pays for the
        // forced TargetRead flush that emitting would cause; the `mlen == 1`
        // term breaks ties against a one-byte copy.  Formula traced from
        // Alcaro's `use_match` in `libbps-suf.cpp` — it's heuristic, not
        // derived, hence the trial-and-error shape.
        let emit = best.and_then(|(pos, mlen)| {
            let is_source = pos >= sortedsize;
            let file_pos = if is_source { pos - sortedsize } else { pos };
            let has_pending = pending.is_some() as usize;

            let (tag, cost) = if is_source && file_pos == outpos {
                (SOURCE_READ, 1)
            } else if is_source {
                (SOURCE_COPY, 1 + varint_cost(encode_delta(src_rel, file_pos)))
            } else {
                (TARGET_COPY, 1 + varint_cost(encode_delta(tgt_rel, file_pos)))
            };

            if mlen >= 1 + cost + has_pending + usize::from(mlen == 1) {
                Some((tag, file_pos, mlen))
            } else {
                None
            }
        });

        match emit {
            Some((tag, pos, mlen)) => {
                // Flush pending TargetRead.
                if let Some(start) = pending.take() {
                    let n = outpos - start;
                    encode_varint(&mut out, ((n as u64 - 1) << 2) | TARGET_READ);
                    out.extend_from_slice(&target[start..outpos]);
                }
                encode_varint(&mut out, ((mlen as u64 - 1) << 2) | tag);
                if tag == SOURCE_COPY {
                    encode_varint(&mut out, encode_delta(src_rel, pos));
                    src_rel = pos + mlen;
                } else if tag == TARGET_COPY {
                    encode_varint(&mut out, encode_delta(tgt_rel, pos));
                    tgt_rel = pos + mlen;
                }
                outpos += mlen;
            }
            None => {
                if pending.is_none() {
                    pending = Some(outpos);
                }
                outpos += 1;
            }
        }
    }

    // Flush final TargetRead.
    if let Some(start) = pending {
        let n = target_len - start;
        encode_varint(&mut out, ((n as u64 - 1) << 2) | TARGET_READ);
        out.extend_from_slice(&target[start..]);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic PRNG (SplitMix64).
    fn pseudo_random(seed: u64, n: usize) -> Vec<u8> {
        let mut state = seed;
        (0..n)
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

    fn decode_varint(data: &[u8], pos: &mut usize) -> u64 {
        let mut val: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = data[*pos];
            *pos += 1;
            val += u64::from(b & 0x7F) << shift;
            if b & 0x80 != 0 {
                return val;
            }
            shift += 7;
            val += 1u64 << shift;
        }
    }

    #[test]
    fn empty_target() {
        assert!(bps_diff(&[1, 2, 3], &[]).is_empty());
        assert!(bps_diff(&[], &[]).is_empty());
    }

    #[test]
    fn identical() {
        let data = pseudo_random(0x1234, 256);
        let out = bps_diff(&data, &data);
        // Single SourceRead covering all 256 bytes.
        let mut pos = 0;
        let cmd = decode_varint(&out, &mut pos);
        assert_eq!(pos, out.len(), "expected exactly one action");
        assert_eq!(cmd & 3, SOURCE_READ);
        assert_eq!((cmd >> 2) + 1, 256);
    }

    #[test]
    fn empty_source() {
        let target = vec![10, 20, 30];
        let out = bps_diff(&[], &target);
        // Single TargetRead with the three literal bytes.
        let mut pos = 0;
        let cmd = decode_varint(&out, &mut pos);
        assert_eq!(cmd & 3, TARGET_READ);
        assert_eq!((cmd >> 2) + 1, 3);
        assert_eq!(&out[pos..], &[10, 20, 30]);
    }

    #[test]
    fn varint_encoding() {
        let mut buf = Vec::new();

        // 0 → [0x80]
        encode_varint(&mut buf, 0);
        assert_eq!(buf, [0x80]);

        // 0x7F → [0xFF]
        buf.clear();
        encode_varint(&mut buf, 0x7F);
        assert_eq!(buf, [0xFF]);

        // 0x80 → [0x00, 0x80]
        buf.clear();
        encode_varint(&mut buf, 0x80);
        assert_eq!(buf, [0x00, 0x80]);

        // Round-trip through decode.
        for val in [0u64, 0x7F, 0x80, 0x3FFF, 0x4000, 12345678] {
            buf.clear();
            encode_varint(&mut buf, val);
            let mut pos = 0;
            assert_eq!(decode_varint(&buf, &mut pos), val, "round-trip failed for {val}");
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn block_move() {
        let source = pseudo_random(0xbeef, 4096);
        let mut target = source.clone();
        // Overwrite target[0x800..0x900] with source[0x100..0x200].
        target[0x800..0x900].copy_from_slice(&source[0x100..0x200]);
        let out = bps_diff(&source, &target);
        // Mostly SourceRead with one SourceCopy — patch is very small.
        assert!(
            out.len() < 100,
            "expected compact patch, got {} bytes",
            out.len()
        );
    }
}
