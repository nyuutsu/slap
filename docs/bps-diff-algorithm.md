# BPS diff — algorithm notes

The diff engine in `rusty-slap/src/bps_diff.rs` is based on the
suffix-array approach from Alcaro's Flips (`libbps-suf.cpp`, GPL v3).
We studied the Flips source to understand the algorithm, then wrote
our own implementation in Rust. This document records how it works
for future reference.

The core ideas — concatenated suffix array, progressive sorting, the
cost heuristic — are Alcaro's. SA-IS itself is Nong, Zhang, and Chan
(2009). The BPS wire format is byuu's.

## Data structures

### Concatenated buffer

```
concat = target[0..window] ++ source[0..source_len]
         |--- sortedsize --|--- sourcelen ---|
```

Target comes first. Source comes after. Total length = `sortedsize +
sourcelen`. A position `p` in the concatenated buffer is:
- In the target region if `p < sortedsize`
- In the source region if `p >= sortedsize` (source offset = `p - sortedsize`)

### Suffix array

`sorted[i]` = position in `concat` of the i-th lexicographically
smallest suffix. Built by SA-IS over the concatenated buffer.

### Reverse index

`reverse[sorted[i]] = i` for all i. Gives O(1) lookup: "where does
position p sit in the sorted order?" Answer: `reverse[p]`.

## Main loop

```
outpos = 0
while outpos < target_len:
    1. Look up idx = reverse[outpos]

    2. Scan sorted[] upward from idx:
       find closest sorted[idx_up] where the position is either
         (a) in the source region (>= sortedsize), or
         (b) before outpos in the target (< outpos)
       Skip positions in target[outpos..sortedsize] — those are
       "future" target bytes we haven't written yet.

    3. Scan sorted[] downward similarly for idx_dn.

    4. pick_best_of_two(sorted[idx_up], sorted[idx_dn]):
       - Compute LCP between the two candidates (they share a
         common prefix since they're adjacent in sorted order
         after removing invalid entries).
       - The candidate whose next byte (beyond LCP) matches the
         query byte is better.
       - Extend the winner against the query to get match length.

    5. Decide: is the match in source or target?
       - source (pos >= sortedsize): candidate for SourceCopy,
         or SourceRead if pos - sortedsize == outpos.
       - target (pos < outpos): candidate for TargetCopy.

    6. Cost check — is the match worth encoding?
       Heuristic: len >= 1 + cost + has_pending + (len == 1)
       where cost = varint_cost(action).
       SourceRead cost = 1 varint (cheapest).
       SourceCopy cost = 1 varint + 1 signed varint (offset delta).
       TargetCopy cost = 1 varint + 1 signed varint (offset delta).

    7. If worth it: flush pending TargetRead, emit the action.
       If not: accumulate byte into pending TargetRead buffer.
       Advance outpos by match length (or 1 for TargetRead).
```

## Progressive sorting

Don't sort the full target upfront. This is the key speed trick.

```
sortedsize = target_len
while sortedsize / 4 > source_len and sortedsize > 1024:
    sortedsize >>= 2

-- sortedsize starts small (e.g. ~source_len for similar-size files)

when outpos >= sortedsize - 256 and sortedsize < target_len:
    sortedsize = min(sortedsize * 4 + 3, target_len)
    re-concatenate, re-sort, rebuild reverse index
```

Total sort cost across all iterations: O(n log n) because geometric
series. Each re-sort covers 4x more data, but happens 4x less often.

## pick_best_of_two (detail)

Given two SA positions `a` and `b`, and a query:

```
common = match_len(concat[a..], concat[b..])
if common >= query_len:
    return a  -- both match fully, pick either
if concat[a + common] == query[common]:
    return a  -- a extends further
else:
    return b  -- b extends further (or equal)
```

This avoids redundant comparisons: the LCP between a and b is shared,
so only the divergence point matters.

## BPS wire encoding

Actions encode as byuu varints:
- `(len-1) << 2 | tag` where tag: 0=SourceRead, 1=TargetRead,
  2=SourceCopy, 3=TargetCopy
- TargetRead: varint + literal bytes
- SourceCopy/TargetCopy: varint + signed delta varint
  (delta = current_pos - last_copy_pos, encoded as magnitude<<1 | sign)

Byuu varint: emit 7 bits at a time, low bits first. Each non-final
byte has bit 7 clear. Final byte has bit 7 set. Between bytes,
subtract 1 from the remaining value (this is NOT standard LEB128).

## State tracking

```
src_rel = 0    -- last SourceCopy end position (for delta encoding)
tgt_rel = 0    -- last TargetCopy end position
pending = None -- start of pending TargetRead region
```
